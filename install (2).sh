#!/bin/bash

# =============================================================================
# PTERODACTYL SECURITY PROTECTION INSTALLER
# Version: 4.0.0
# Author : Security Panel Hardening Script
# Desc   : Melindungi user & server dari penghapusan sembarangan oleh admin,
#          dengan sistem deteksi abuse otomatis + auto-suspend admin pelanggar.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# KONSTANTA GLOBAL
# -----------------------------------------------------------------------------
readonly SCRIPT_VERSION="4.0.0"
readonly PTERODACTYL_PATH="${PTERODACTYL_PATH:-/var/www/pterodactyl}"
readonly BACKUP_DIR="${PTERODACTYL_PATH}/backups"
readonly LOG_FILE="/var/log/pterodactyl-protection-install.log"
readonly TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
readonly REQUIRED_PHP_VERSION="8.1"
readonly PROTECTED_ADMIN_ID="${PROTECTED_ADMIN_ID:-1}"  # ID admin utama yg tidak bisa disentuh

# Warna & ikon output
readonly COLOR_RESET='\033[0m'
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_BOLD='\033[1m'
readonly ICON_SUCCESS="[+]"
readonly ICON_ERROR="[!]"
readonly ICON_INFO="[i]"
readonly ICON_WARN="[*]"
readonly ICON_STEP=">>>"

# Tracking
declare -i ERROR_COUNT=0
declare -i INSTALL_COUNT=0
declare -a INSTALLED_FILES=()
declare -a FAILED_FILES=()

# -----------------------------------------------------------------------------
# FUNGSI LOGGING & OUTPUT
# -----------------------------------------------------------------------------
log()           { echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] $*" | tee -a "$LOG_FILE"; }
print_header()  { echo ""; echo "================================================================================"; echo -e "${COLOR_BOLD}${COLOR_CYAN}$1${COLOR_RESET}"; echo "================================================================================"; echo ""; }
print_step()    { echo -e "${COLOR_BLUE}${ICON_STEP} $1${COLOR_RESET}"; log "STEP: $1"; }
print_success() { echo -e "${COLOR_GREEN}${ICON_SUCCESS} $1${COLOR_RESET}"; log "SUCCESS: $1"; }
print_error()   { echo -e "${COLOR_RED}${ICON_ERROR} $1${COLOR_RESET}" >&2; log "ERROR: $1"; ((ERROR_COUNT++)) || true; }
print_warn()    { echo -e "${COLOR_YELLOW}${ICON_WARN} $1${COLOR_RESET}"; log "WARNING: $1"; }
print_info()    { echo -e "${COLOR_CYAN}${ICON_INFO} $1${COLOR_RESET}"; }

# -----------------------------------------------------------------------------
# VALIDASI LINGKUNGAN
# -----------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Script ini harus dijalankan sebagai root"
        exit 1
    fi
}

check_pterodactyl_installation() {
    print_step "Memvalidasi instalasi Pterodactyl..."
    [[ -d "$PTERODACTYL_PATH" ]] || { print_error "Direktori Pterodactyl tidak ditemukan: $PTERODACTYL_PATH"; exit 1; }
    [[ -f "$PTERODACTYL_PATH/artisan" ]] || { print_error "Instalasi Pterodactyl tidak valid (artisan tidak ditemukan)"; exit 1; }
    print_success "Instalasi Pterodactyl tervalidasi"
}

check_php_version() {
    print_step "Memeriksa versi PHP..."
    command -v php &>/dev/null || { print_error "PHP tidak terinstal"; exit 1; }
    local php_version
    php_version=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo "0.0.0")
    printf '%s\n%s\n' "$REQUIRED_PHP_VERSION" "$php_version" | sort -V -C \
        || { print_error "PHP $php_version di bawah versi minimum $REQUIRED_PHP_VERSION"; exit 1; }
    print_success "PHP $php_version kompatibel"
}

check_permissions() {
    print_step "Memeriksa izin file..."
    [[ -w "$PTERODACTYL_PATH" ]] || { print_error "Tidak ada izin tulis untuk $PTERODACTYL_PATH"; exit 1; }
    print_success "Izin file tervalidasi"
}

# -----------------------------------------------------------------------------
# BACKUP & INSTALL FILE
# -----------------------------------------------------------------------------
create_backup_dir() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        chmod 750 "$BACKUP_DIR"
        print_success "Direktori backup dibuat: $BACKUP_DIR"
    fi
}

backup_file() {
    local file_path="$1"
    local backup_path="${file_path}.backup_${TIMESTAMP}"
    if [[ -f "$file_path" ]]; then
        cp "$file_path" "$backup_path" && print_success "Backup: $(basename "$file_path")" || { print_error "Gagal backup: $file_path"; return 1; }
    fi
    return 0
}

install_file() {
    local target_path="$1"
    local content="$2"
    local description="$3"

    print_step "Menginstal: $description"

    local dir_path
    dir_path=$(dirname "$target_path")
    [[ -d "$dir_path" ]] || { mkdir -p "$dir_path"; chmod 755 "$dir_path"; }

    backup_file "$target_path" || { FAILED_FILES+=("$description"); return 1; }

    if printf '%s' "$content" > "$target_path"; then
        chmod 644 "$target_path"
        chown www-data:www-data "$target_path" 2>/dev/null || true
        print_success "Terinstal: $description"
        INSTALLED_FILES+=("$description")
        ((INSTALL_COUNT++)) || true
    else
        print_error "Gagal menulis: $description"
        FAILED_FILES+=("$description")
        return 1
    fi
}

# =============================================================================
# PHP FILES — KONTEN YANG AKAN DIINSTALL
# =============================================================================

# -----------------------------------------------------------------------------
# 1. AbuseProtectionService — BARU: inti sistem deteksi & auto-suspend admin
# -----------------------------------------------------------------------------
get_abuse_protection_service() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Services\Security;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Pterodactyl\Models\User;
use Pterodactyl\Models\AbuseLog;
use Carbon\Carbon;

/**
 * AbuseProtectionService
 *
 * Mendeteksi admin yang menghapus user/server orang lain secara sembarangan,
 * mencatatnya ke tabel abuse_logs, dan otomatis men-suspend admin tersebut
 * jika ambang batas pelanggaran terlampaui.
 *
 * Cara kerja:
 *  1. Setiap aksi hapus user/server dipanggil via recordAction().
 *  2. Jika admin menghapus entitas yang BUKAN miliknya tanpa hak yang sah,
 *     aksi tersebut dicatat sebagai "abuse attempt".
 *  3. Setelah ABUSE_THRESHOLD kali pelanggaran dalam WINDOW_MINUTES menit,
 *     akun admin tersebut otomatis di-suspend.
 */
class AbuseProtectionService
{
    // Ambang pelanggaran sebelum auto-suspend
    private const ABUSE_THRESHOLD = 3;
    // Jendela waktu deteksi (menit)
    private const WINDOW_MINUTES  = 30;
    // ID admin utama — tidak bisa di-suspend oleh sistem ini
    private const ROOT_ADMIN_ID   = 1;

    /**
     * Catat aksi penghapusan dan evaluasi apakah ini abuse.
     *
     * @param  int    $actorId      ID admin yang melakukan aksi
     * @param  string $action       Jenis aksi: 'delete_user' | 'delete_server'
     * @param  int    $targetId     ID entitas yang dihapus
     * @param  int    $targetOwnerId ID pemilik sah entitas tersebut
     * @param  bool   $isLegitimate Apakah aksi ini sah (misal: owner hapus miliknya sendiri)
     */
    public function recordAction(
        int $actorId,
        string $action,
        int $targetId,
        int $targetOwnerId,
        bool $isLegitimate = true
    ): void {
        // Jangan proses jika bukan potensi abuse
        if ($isLegitimate) {
            return;
        }

        // Catat ke log abuse
        DB::table('abuse_logs')->insert([
            'actor_id'        => $actorId,
            'action'          => $action,
            'target_id'       => $targetId,
            'target_owner_id' => $targetOwnerId,
            'ip_address'      => request()->ip(),
            'user_agent'      => request()->userAgent(),
            'created_at'      => now(),
        ]);

        Log::channel('security')->warning(
            "[ABUSE DETECTED] Admin #{$actorId} mencoba {$action} pada entitas #{$targetId} milik user #{$targetOwnerId}",
            ['ip' => request()->ip(), 'ua' => request()->userAgent()]
        );

        // Hitung pelanggaran dalam jendela waktu
        $recentCount = DB::table('abuse_logs')
            ->where('actor_id', $actorId)
            ->where('created_at', '>=', Carbon::now()->subMinutes(self::WINDOW_MINUTES))
            ->count();

        if ($recentCount >= self::ABUSE_THRESHOLD) {
            $this->suspendAdmin($actorId);
        }
    }

    /**
     * Auto-suspend admin yang melanggar ambang batas.
     * Admin utama (ID=ROOT_ADMIN_ID) tidak bisa di-suspend.
     */
    private function suspendAdmin(int $adminId): void
    {
        if ($adminId === self::ROOT_ADMIN_ID) {
            Log::channel('security')->critical(
                "[CRITICAL] Upaya abuse terdeteksi dari ROOT ADMIN #{$adminId} — tidak di-suspend, perlu review manual."
            );
            return;
        }

        $updated = DB::table('users')
            ->where('id', $adminId)
            ->where('id', '!=', self::ROOT_ADMIN_ID)
            ->update([
                'suspended'  => true,
                'root_admin' => false,
                'updated_at' => now(),
            ]);

        if ($updated) {
            Log::channel('security')->critical(
                "[AUTO-SUSPEND] Admin #{$adminId} telah di-suspend otomatis karena " .
                self::ABUSE_THRESHOLD . "x pelanggaran dalam " . self::WINDOW_MINUTES . " menit."
            );

            // Kirim notifikasi ke root admin
            $this->notifyRootAdmin($adminId);
        }
    }

    /**
     * Kirim notifikasi ke root admin bahwa ada admin yang di-suspend.
     */
    private function notifyRootAdmin(int $suspendedAdminId): void
    {
        try {
            $rootAdmin = User::find(self::ROOT_ADMIN_ID);
            $suspendedAdmin = User::find($suspendedAdminId);

            if ($rootAdmin && $suspendedAdmin) {
                // Catat ke tabel notifikasi / kirim email jika mailer terkonfigurasi
                Log::channel('security')->info(
                    "[NOTIFY] Root admin #{$rootAdmin->id} ({$rootAdmin->email}) diberitahu bahwa " .
                    "admin #{$suspendedAdmin->id} ({$suspendedAdmin->email}) telah di-suspend otomatis."
                );

                // Opsional: kirim email jika mail terkonfigurasi
                // Mail::to($rootAdmin->email)->send(new AdminSuspendedMail($suspendedAdmin));
            }
        } catch (\Throwable $e) {
            Log::error("[ABUSE PROTECTION] Gagal mengirim notifikasi: " . $e->getMessage());
        }
    }

    /**
     * Cek apakah admin saat ini sedang dalam status suspended.
     */
    public function isAdminSuspended(int $adminId): bool
    {
        return DB::table('users')
            ->where('id', $adminId)
            ->where('suspended', true)
            ->exists();
    }
}
PHPEOF
}

# -----------------------------------------------------------------------------
# 2. AbuseLog Migration — tabel untuk menyimpan log pelanggaran
# -----------------------------------------------------------------------------
get_abuse_log_migration() {
    cat <<'PHPEOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Membuat tabel abuse_logs untuk mencatat setiap upaya penghapusan ilegal oleh admin.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (!Schema::hasTable('abuse_logs')) {
            Schema::create('abuse_logs', function (Blueprint $table) {
                $table->id();
                $table->unsignedBigInteger('actor_id')->comment('Admin yang melakukan aksi');
                $table->string('action', 64)->comment('Jenis aksi: delete_user, delete_server, dll');
                $table->unsignedBigInteger('target_id')->comment('ID entitas yang menjadi target');
                $table->unsignedBigInteger('target_owner_id')->comment('ID pemilik sah entitas');
                $table->string('ip_address', 45)->nullable();
                $table->text('user_agent')->nullable();
                $table->timestamp('created_at')->useCurrent();

                $table->index('actor_id');
                $table->index(['actor_id', 'created_at']);

                $table->foreign('actor_id')
                      ->references('id')->on('users')
                      ->onDelete('cascade');
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('abuse_logs');
    }
};
PHPEOF
}

# -----------------------------------------------------------------------------
# 3. ServerDeletionService — proteksi delete server + audit trail
# -----------------------------------------------------------------------------
get_server_deletion_service() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Services\Servers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Pterodactyl\Exceptions\DisplayException;
use Illuminate\Http\Response;
use Pterodactyl\Models\Server;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Services\Databases\DatabaseManagementService;
use Pterodactyl\Services\Security\AbuseProtectionService;
use Pterodactyl\Exceptions\Http\Connection\DaemonConnectionException;

class ServerDeletionService
{
    protected bool $force = false;

    public function __construct(
        private ConnectionInterface       $connection,
        private DaemonServerRepository    $daemonServerRepository,
        private DatabaseManagementService $databaseManagementService,
        private AbuseProtectionService    $abuseProtection
    ) {}

    public function withForce(bool $bool = true): self
    {
        $this->force = $bool;
        return $this;
    }

    /**
     * Menghapus server dengan proteksi penuh:
     *  - Hanya admin yang bisa hapus server orang lain
     *  - Setiap penghapusan dicatat ke audit log
     *  - Jika admin menghapus server orang lain tanpa hak, dicatat sebagai abuse
     */
    public function handle(Server $server): void
    {
        $user     = Auth::user();
        $ownerId  = $server->owner_id ?? $server->user_id ?? null;

        // — Autentikasi wajib —
        if (!$user) {
            abort(401, 'Autentikasi diperlukan.');
        }

        // — Cek apakah akun admin ini sedang suspended —
        if ($this->abuseProtection->isAdminSuspended($user->id)) {
            abort(403, 'Akun Anda telah di-suspend karena pelanggaran kebijakan. Hubungi root administrator.');
        }

        $isLegitimate = true;

        if ($user->root_admin !== true) {
            // User biasa: hanya bisa hapus server miliknya sendiri
            if ($ownerId && $ownerId !== $user->id) {
                // Catat sebagai abuse attempt
                $isLegitimate = false;
                $this->abuseProtection->recordAction(
                    $user->id,
                    'delete_server',
                    $server->id,
                    $ownerId,
                    false
                );
                abort(403, 'Anda tidak memiliki izin untuk menghapus server ini.');
            }
        } else {
            // Admin: cek apakah hapus server orang lain — catat audit
            if ($ownerId && $ownerId !== $user->id) {
                Log::channel('audit')->info(
                    "[ADMIN DELETE SERVER] Admin #{$user->id} ({$user->email}) menghapus server #{$server->id} milik user #{$ownerId}",
                    [
                        'server_name' => $server->name,
                        'server_uuid' => $server->uuid,
                        'ip'          => request()->ip(),
                    ]
                );
            }
        }

        // — Proses penghapusan —
        try {
            $this->daemonServerRepository->setServer($server)->delete();
        } catch (DaemonConnectionException $exception) {
            if (!$this->force && $exception->getStatusCode() !== Response::HTTP_NOT_FOUND) {
                throw $exception;
            }
            Log::warning('[ServerDeletion] Daemon connection error (diabaikan karena force mode): ' . $exception->getMessage());
        }

        $this->connection->transaction(function () use ($server) {
            foreach ($server->databases as $database) {
                try {
                    $this->databaseManagementService->delete($database);
                } catch (\Throwable $exception) {
                    if (!$this->force) {
                        throw $exception;
                    }
                    $database->delete();
                    Log::warning('[ServerDeletion] Database deletion error: ' . $exception->getMessage());
                }
            }
            $server->delete();
        });

        Log::channel('audit')->info(
            "[SERVER DELETED] Server #{$server->id} ({$server->name}) dihapus oleh user #{$user->id}"
        );
    }
}
PHPEOF
}

# -----------------------------------------------------------------------------
# 4. UserController — proteksi hapus user + audit
# -----------------------------------------------------------------------------
get_user_controller() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\View\View;
use Illuminate\Http\Request;
use Pterodactyl\Models\User;
use Pterodactyl\Models\Model;
use Illuminate\Support\Collection;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Prologue\Alerts\AlertsMessageBag;
use Spatie\QueryBuilder\QueryBuilder;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Exceptions\DisplayException;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Contracts\Translation\Translator;
use Pterodactyl\Services\Users\UserUpdateService;
use Pterodactyl\Traits\Helpers\AvailableLanguages;
use Pterodactyl\Services\Users\UserCreationService;
use Pterodactyl\Services\Users\UserDeletionService;
use Pterodactyl\Http\Requests\Admin\UserFormRequest;
use Pterodactyl\Http\Requests\Admin\NewUserFormRequest;
use Pterodactyl\Contracts\Repository\UserRepositoryInterface;
use Pterodactyl\Services\Security\AbuseProtectionService;

class UserController extends Controller
{
    use AvailableLanguages;

    // ID admin utama yang tidak boleh dihapus oleh siapapun
    private const PROTECTED_ADMIN_ID = 1;

    public function __construct(
        protected AlertsMessageBag       $alert,
        protected UserCreationService    $creationService,
        protected UserDeletionService    $deletionService,
        protected Translator             $translator,
        protected UserUpdateService      $updateService,
        protected UserRepositoryInterface $repository,
        protected ViewFactory            $view,
        protected AbuseProtectionService $abuseProtection
    ) {}

    public function index(Request $request): View
    {
        $users = QueryBuilder::for(
            User::query()->select('users.*')
                ->selectRaw('COUNT(DISTINCT(subusers.id)) as subuser_of_count')
                ->selectRaw('COUNT(DISTINCT(servers.id)) as servers_count')
                ->leftJoin('subusers', 'subusers.user_id', '=', 'users.id')
                ->leftJoin('servers', 'servers.owner_id', '=', 'users.id')
                ->groupBy('users.id')
        )
            ->allowedFilters(['username', 'email', 'uuid'])
            ->allowedSorts(['id', 'uuid'])
            ->paginate(50);

        return $this->view->make('admin.users.index', ['users' => $users]);
    }

    public function create(): View
    {
        return $this->view->make('admin.users.new', [
            'languages' => $this->getAvailableLanguages(true),
        ]);
    }

    public function view(User $user): View
    {
        return $this->view->make('admin.users.view', [
            'user'      => $user,
            'languages' => $this->getAvailableLanguages(true),
        ]);
    }

    public function delete(Request $request, User $user): RedirectResponse
    {
        $actor = $request->user();

        // — Wajib login —
        if (!$actor) {
            abort(401, 'Autentikasi diperlukan.');
        }

        // — Cek status suspended —
        if ($this->abuseProtection->isAdminSuspended($actor->id)) {
            abort(403, 'Akun Anda telah di-suspend. Hubungi root administrator.');
        }

        // — Proteksi: hanya root_admin yang boleh hapus user —
        if ($actor->root_admin !== true) {
            // Catat sebagai abuse attempt
            $this->abuseProtection->recordAction(
                $actor->id,
                'delete_user',
                $user->id,
                $user->id,
                false
            );
            abort(403, 'Hanya administrator utama yang dapat menghapus pengguna.');
        }

        // — Proteksi: admin utama tidak boleh dihapus —
        if ($user->id === self::PROTECTED_ADMIN_ID) {
            abort(403, 'Akun administrator utama tidak dapat dihapus.');
        }

        // — Tidak bisa hapus diri sendiri —
        if ($actor->id === $user->id) {
            throw new DisplayException($this->translator->get('admin/user.exceptions.user_has_servers'));
        }

        // — Audit log sebelum hapus —
        Log::channel('audit')->warning(
            "[USER DELETED] Admin #{$actor->id} ({$actor->email}) menghapus user #{$user->id} ({$user->email})",
            ['ip' => $request->ip(), 'target_servers_count' => $user->servers()->count()]
        );

        $this->deletionService->handle($user);

        $this->alert->success("Pengguna {$user->username} berhasil dihapus.")->flash();
        return redirect()->route('admin.users');
    }

    public function store(NewUserFormRequest $request): RedirectResponse
    {
        $user = $this->creationService->handle($request->normalize());
        $this->alert->success($this->translator->get('admin/user.notices.account_created'))->flash();
        return redirect()->route('admin.users.view', $user->id);
    }

    public function update(UserFormRequest $request, User $user): RedirectResponse
    {
        $actor = $request->user();

        // Hanya root_admin yang boleh mengubah field sensitif
        if (!$actor || $actor->root_admin !== true) {
            $restrictedFields = ['email', 'username', 'password', 'root_admin', 'suspended'];
            foreach ($restrictedFields as $field) {
                if ($request->filled($field)) {
                    // Catat percobaan modifikasi field sensitif
                    Log::channel('security')->warning(
                        "[UNAUTHORIZED UPDATE] User #{$actor?->id} mencoba mengubah field '{$field}' milik user #{$user->id}",
                        ['ip' => $request->ip()]
                    );
                    abort(403, 'Anda tidak memiliki izin untuk mengubah field ini.');
                }
            }
        }

        // Proteksi: tidak bisa mengubah status protected admin
        if ($user->id === self::PROTECTED_ADMIN_ID && $actor?->id !== self::PROTECTED_ADMIN_ID) {
            abort(403, 'Data administrator utama tidak dapat diubah.');
        }

        $this->updateService
            ->setUserLevel(User::USER_LEVEL_ADMIN)
            ->handle($user, $request->normalize());

        $this->alert->success(trans('admin/user.notices.account_updated'))->flash();
        return redirect()->route('admin.users.view', $user->id);
    }

    public function json(Request $request): Model|Collection
    {
        $users = QueryBuilder::for(User::query())->allowedFilters(['email'])->paginate(25);

        if ($request->query('user_id')) {
            $user = User::query()->findOrFail($request->input('user_id'));
            $user->md5 = md5(strtolower($user->email));
            return $user;
        }

        return $users->map(function ($item) {
            $item->md5 = md5(strtolower($item->email));
            return $item;
        });
    }
}
PHPEOF
}

# -----------------------------------------------------------------------------
# 5. LocationController
# -----------------------------------------------------------------------------
get_location_controller() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Pterodactyl\Models\Location;
use Prologue\Alerts\AlertsMessageBag;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Exceptions\DisplayException;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Http\Requests\Admin\LocationFormRequest;
use Pterodactyl\Services\Locations\LocationUpdateService;
use Pterodactyl\Services\Locations\LocationCreationService;
use Pterodactyl\Services\Locations\LocationDeletionService;
use Pterodactyl\Contracts\Repository\LocationRepositoryInterface;

class LocationController extends Controller
{
    public function __construct(
        protected AlertsMessageBag             $alert,
        protected LocationCreationService      $creationService,
        protected LocationDeletionService      $deletionService,
        protected LocationRepositoryInterface  $repository,
        protected LocationUpdateService        $updateService,
        protected ViewFactory                  $view
    ) {}

    private function requireRootAdmin(string $action = 'melakukan aksi ini'): void
    {
        $user = Auth::user();
        if (!$user || $user->root_admin !== true) {
            abort(403, "Akses ditolak. Hanya administrator yang dapat {$action}.");
        }
    }

    public function index(): View
    {
        $this->requireRootAdmin('mengelola lokasi');
        return $this->view->make('admin.locations.index', [
            'locations' => $this->repository->getAllWithDetails(),
        ]);
    }

    public function view(int $id): View
    {
        $this->requireRootAdmin('melihat detail lokasi');
        return $this->view->make('admin.locations.view', [
            'location' => $this->repository->getWithNodes($id),
        ]);
    }

    public function create(LocationFormRequest $request): RedirectResponse
    {
        $this->requireRootAdmin('membuat lokasi');
        $location = $this->creationService->handle($request->normalize());
        $this->alert->success('Lokasi berhasil dibuat.')->flash();
        return redirect()->route('admin.locations.view', $location->id);
    }

    public function update(LocationFormRequest $request, Location $location): RedirectResponse
    {
        $this->requireRootAdmin('memperbarui lokasi');
        if ($request->input('action') === 'delete') {
            return $this->delete($location);
        }
        $this->updateService->handle($location->id, $request->normalize());
        $this->alert->success('Lokasi berhasil diperbarui.')->flash();
        return redirect()->route('admin.locations.view', $location->id);
    }

    public function delete(Location $location): RedirectResponse
    {
        $this->requireRootAdmin('menghapus lokasi');
        try {
            $this->deletionService->handle($location->id);
            return redirect()->route('admin.locations');
        } catch (DisplayException $ex) {
            $this->alert->danger($ex->getMessage())->flash();
        }
        return redirect()->route('admin.locations.view', $location->id);
    }
}
PHPEOF
}

# -----------------------------------------------------------------------------
# 6. NodeController — proteksi admin check
# -----------------------------------------------------------------------------
get_node_controller() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin\Nodes;

use Illuminate\View\View;
use Illuminate\Http\Request;
use Pterodactyl\Models\Node;
use Illuminate\Support\Facades\Auth;
use Spatie\QueryBuilder\QueryBuilder;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Contracts\View\Factory as ViewFactory;

class NodeController extends Controller
{
    public function __construct(private ViewFactory $view) {}

    public function index(Request $request): View
    {
        $user = Auth::user();
        if (!$user || $user->root_admin !== true) {
            abort(403, 'Akses ditolak. Hanya administrator yang dapat mengelola node.');
        }

        $nodes = QueryBuilder::for(
            Node::query()->with('location')->withCount('servers')
        )
            ->allowedFilters(['uuid', 'name'])
            ->allowedSorts(['id'])
            ->paginate(25);

        return $this->view->make('admin.nodes.index', ['nodes' => $nodes]);
    }
}
PHPEOF
}

# -----------------------------------------------------------------------------
# 7. NestController — PERBAIKAN: proteksi destroy() yang sebelumnya BOLONG
# -----------------------------------------------------------------------------
get_nest_controller() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin\Nests;

use Illuminate\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Prologue\Alerts\AlertsMessageBag;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Services\Nests\NestUpdateService;
use Pterodactyl\Services\Nests\NestCreationService;
use Pterodactyl\Services\Nests\NestDeletionService;
use Pterodactyl\Contracts\Repository\NestRepositoryInterface;
use Pterodactyl\Http\Requests\Admin\Nest\StoreNestFormRequest;

class NestController extends Controller
{
    public function __construct(
        protected AlertsMessageBag       $alert,
        protected NestCreationService    $nestCreationService,
        protected NestDeletionService    $nestDeletionService,
        protected NestRepositoryInterface $repository,
        protected NestUpdateService      $nestUpdateService,
        protected ViewFactory            $view
    ) {}

    private function requireRootAdmin(): void
    {
        $user = Auth::user();
        if (!$user || $user->root_admin !== true) {
            abort(403, 'Akses ditolak. Hanya administrator yang dapat mengelola nests.');
        }
    }

    public function index(): View
    {
        $this->requireRootAdmin();
        return $this->view->make('admin.nests.index', [
            'nests' => $this->repository->getWithCounts(),
        ]);
    }

    public function create(): View
    {
        $this->requireRootAdmin();
        return $this->view->make('admin.nests.new');
    }

    public function store(StoreNestFormRequest $request): RedirectResponse
    {
        $this->requireRootAdmin();
        $nest = $this->nestCreationService->handle($request->normalize());
        $this->alert->success(trans('admin/nests.notices.created', ['name' => htmlspecialchars($nest->name)]))->flash();
        return redirect()->route('admin.nests.view', $nest->id);
    }

    public function view(int $nest): View
    {
        $this->requireRootAdmin();
        return $this->view->make('admin.nests.view', [
            'nest' => $this->repository->getWithEggServers($nest),
        ]);
    }

    public function update(StoreNestFormRequest $request, int $nest): RedirectResponse
    {
        $this->requireRootAdmin();
        $this->nestUpdateService->handle($nest, $request->normalize());
        $this->alert->success(trans('admin/nests.notices.updated'))->flash();
        return redirect()->route('admin.nests.view', $nest);
    }

    /**
     * PERBAIKAN: destroy() sebelumnya tidak ada cek admin sama sekali!
     * Sekarang wajib root_admin.
     */
    public function destroy(int $nest): RedirectResponse
    {
        $this->requireRootAdmin();
        $this->nestDeletionService->handle($nest);
        $this->alert->success(trans('admin/nests.notices.deleted'))->flash();
        return redirect()->route('admin.nests');
    }
}
PHPEOF
}

# -----------------------------------------------------------------------------
# 8. SettingsController
# -----------------------------------------------------------------------------
get_settings_controller() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin\Settings;

use Illuminate\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Prologue\Alerts\AlertsMessageBag;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Traits\Helpers\AvailableLanguages;
use Pterodactyl\Services\Helpers\SoftwareVersionService;
use Pterodactyl\Contracts\Repository\SettingsRepositoryInterface;
use Pterodactyl\Http\Requests\Admin\Settings\BaseSettingsFormRequest;

class IndexController extends Controller
{
    use AvailableLanguages;

    public function __construct(
        private AlertsMessageBag             $alert,
        private Kernel                       $kernel,
        private SettingsRepositoryInterface  $settings,
        private SoftwareVersionService       $versionService,
        private ViewFactory                  $view
    ) {}

    private function requireRootAdmin(): void
    {
        $user = Auth::user();
        if (!$user || $user->root_admin !== true) {
            abort(403, 'Akses ditolak. Hanya administrator yang dapat mengelola pengaturan panel.');
        }
    }

    public function index(): View
    {
        $this->requireRootAdmin();
        return $this->view->make('admin.settings.index', [
            'version'   => $this->versionService,
            'languages' => $this->getAvailableLanguages(true),
        ]);
    }

    public function update(BaseSettingsFormRequest $request): RedirectResponse
    {
        $this->requireRootAdmin();
        foreach ($request->normalize() as $key => $value) {
            $this->settings->set('settings::' . $key, $value);
        }
        $this->kernel->call('queue:restart');
        $this->alert->success('Pengaturan panel berhasil diperbarui. Queue worker direstart.')->flash();
        return redirect()->route('admin.settings');
    }
}
PHPEOF
}

# -----------------------------------------------------------------------------
# 9. FileController — validasi akses owner-based
# -----------------------------------------------------------------------------
get_file_controller() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Http\Controllers\Api\Client\Servers;

use Carbon\CarbonImmutable;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;
use Pterodactyl\Models\Server;
use Pterodactyl\Facades\Activity;
use Pterodactyl\Services\Nodes\NodeJWTService;
use Pterodactyl\Repositories\Wings\DaemonFileRepository;
use Pterodactyl\Transformers\Api\Client\FileObjectTransformer;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CopyFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\PullFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\ListFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\ChmodFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\DeleteFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\RenameFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CreateFolderRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CompressFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\DecompressFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\GetFileContentsRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\WriteFileContentRequest;

class FileController extends ClientApiController
{
    public function __construct(
        private NodeJWTService      $jwtService,
        private DaemonFileRepository $fileRepository
    ) {
        parent::__construct();
    }

    /**
     * Validasi akses user ke server:
     * - Harus terautentikasi
     * - Harus pemilik server, atau root_admin
     */
    private function validateServerAccess(mixed $request, Server $server): void
    {
        $user = $request->user();
        if (!$user) {
            abort(401, 'Autentikasi diperlukan.');
        }
        if ($user->root_admin !== true && $server->owner_id !== $user->id) {
            abort(403, 'Anda tidak memiliki izin untuk mengakses server ini.');
        }
    }

    public function directory(ListFilesRequest $request, Server $server): array
    {
        $this->validateServerAccess($request, $server);
        $contents = $this->fileRepository->setServer($server)->getDirectory($request->get('directory') ?? '/');
        return $this->fractal->collection($contents)
            ->transformWith($this->getTransformer(FileObjectTransformer::class))
            ->toArray();
    }

    public function contents(GetFileContentsRequest $request, Server $server): Response
    {
        $this->validateServerAccess($request, $server);
        $response = $this->fileRepository->setServer($server)->getContent(
            $request->get('file'),
            config('pterodactyl.files.max_edit_size')
        );
        Activity::event('server:file.read')->property('file', $request->get('file'))->log();
        return new Response($response, Response::HTTP_OK, ['Content-Type' => 'text/plain']);
    }

    public function download(GetFileContentsRequest $request, Server $server): array
    {
        $this->validateServerAccess($request, $server);
        $token = $this->jwtService
            ->setExpiresAt(CarbonImmutable::now()->addMinutes(15))
            ->setUser($request->user())
            ->setClaims([
                'file_path'   => rawurldecode($request->get('file')),
                'server_uuid' => $server->uuid,
            ])
            ->handle($server->node, $request->user()->id . $server->uuid);

        Activity::event('server:file.download')->property('file', $request->get('file'))->log();
        return [
            'object'     => 'signed_url',
            'attributes' => [
                'url' => sprintf('%s/download/file?token=%s', $server->node->getConnectionAddress(), $token->toString()),
            ],
        ];
    }

    public function write(WriteFileContentRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);
        $this->fileRepository->setServer($server)->putContent($request->get('file'), $request->getContent());
        Activity::event('server:file.write')->property('file', $request->get('file'))->log();
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function create(CreateFolderRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);
        $this->fileRepository->setServer($server)->createDirectory($request->input('name'), $request->input('root', '/'));
        Activity::event('server:file.create-directory')
            ->property('name', $request->input('name'))
            ->property('directory', $request->input('root'))
            ->log();
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function rename(RenameFileRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);
        $this->fileRepository->setServer($server)->renameFiles($request->input('root'), $request->input('files'));
        Activity::event('server:file.rename')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function copy(CopyFileRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);
        $this->fileRepository->setServer($server)->copyFile($request->input('location'));
        Activity::event('server:file.copy')->property('file', $request->input('location'))->log();
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function compress(CompressFilesRequest $request, Server $server): array
    {
        $this->validateServerAccess($request, $server);
        $file = $this->fileRepository->setServer($server)->compressFiles(
            $request->input('root'),
            $request->input('files')
        );
        Activity::event('server:file.compress')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();
        return $this->fractal->item($file)
            ->transformWith($this->getTransformer(FileObjectTransformer::class))
            ->toArray();
    }

    public function decompress(DecompressFilesRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);
        set_time_limit(300);
        $this->fileRepository->setServer($server)->decompressFile($request->input('root'), $request->input('file'));
        Activity::event('server:file.decompress')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('file'))
            ->log();
        return new JsonResponse([], JsonResponse::HTTP_NO_CONTENT);
    }

    public function delete(DeleteFileRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);
        $this->fileRepository->setServer($server)->deleteFiles($request->input('root'), $request->input('files'));
        Activity::event('server:file.delete')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function chmod(ChmodFilesRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);
        $this->fileRepository->setServer($server)->chmodFiles($request->input('root'), $request->input('files'));
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function pull(PullFileRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);
        $this->fileRepository->setServer($server)->pull(
            $request->input('url'),
            $request->input('directory'),
            $request->safe(['filename', 'use_header', 'foreground'])
        );
        Activity::event('server:file.pull')
            ->property('directory', $request->input('directory'))
            ->property('url', $request->input('url'))
            ->log();
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }
}
PHPEOF
}

# -----------------------------------------------------------------------------
# 10. ServerController (Client API)
# -----------------------------------------------------------------------------
get_server_controller() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Http\Controllers\Api\Client\Servers;

use Illuminate\Support\Facades\Auth;
use Pterodactyl\Models\Server;
use Pterodactyl\Transformers\Api\Client\ServerTransformer;
use Pterodactyl\Services\Servers\GetUserPermissionsService;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;
use Pterodactyl\Http\Requests\Api\Client\Servers\GetServerRequest;

class ServerController extends ClientApiController
{
    public function __construct(private GetUserPermissionsService $permissionsService)
    {
        parent::__construct();
    }

    public function index(GetServerRequest $request, Server $server): array
    {
        $user = Auth::user();

        if (!$user) {
            abort(401, 'Autentikasi diperlukan.');
        }

        if ($user->root_admin !== true && $server->owner_id !== $user->id) {
            abort(403, 'Anda tidak memiliki izin untuk mengakses server ini.');
        }

        return $this->fractal->item($server)
            ->transformWith($this->getTransformer(ServerTransformer::class))
            ->addMeta([
                'is_server_owner' => $request->user()->id === $server->owner_id,
                'user_permissions' => $this->permissionsService->handle($server, $request->user()),
            ])
            ->toArray();
    }
}
PHPEOF
}

# -----------------------------------------------------------------------------
# 11. DetailsModificationService
# -----------------------------------------------------------------------------
get_details_modification_service() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Services\Servers;

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Pterodactyl\Models\Server;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Traits\Services\ReturnsUpdatedModels;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Exceptions\Http\Connection\DaemonConnectionException;

class DetailsModificationService
{
    use ReturnsUpdatedModels;

    public function __construct(
        private ConnectionInterface      $connection,
        private DaemonServerRepository   $serverRepository
    ) {}

    public function handle(Server $server, array $data): Server
    {
        $user = Auth::user();

        if (!$user || $user->root_admin !== true) {
            abort(403, 'Hanya administrator yang dapat memodifikasi detail server.');
        }

        return $this->connection->transaction(function () use ($data, $server, $user) {
            $previousOwnerId = $server->owner_id;
            $newOwnerId      = Arr::get($data, 'owner_id');

            // Audit: catat perubahan owner
            if ($newOwnerId && (int)$newOwnerId !== (int)$previousOwnerId) {
                Log::channel('audit')->warning(
                    "[SERVER OWNER CHANGE] Admin #{$user->id} ({$user->email}) mengubah owner server #{$server->id} " .
                    "dari user #{$previousOwnerId} ke user #{$newOwnerId}",
                    ['server_name' => $server->name, 'ip' => request()->ip()]
                );
            }

            $server->forceFill([
                'external_id' => Arr::get($data, 'external_id'),
                'owner_id'    => $newOwnerId,
                'name'        => Arr::get($data, 'name'),
                'description' => Arr::get($data, 'description') ?? '',
            ])->saveOrFail();

            if ($server->owner_id !== $previousOwnerId) {
                try {
                    $this->serverRepository->setServer($server)->revokeUserJTI($previousOwnerId);
                } catch (DaemonConnectionException) {
                    // Abaikan error koneksi saat revoke JWT
                }
            }

            return $server;
        });
    }
}
PHPEOF
}

# =============================================================================
# PROSES INSTALASI & CACHE CLEAR
# =============================================================================

clear_laravel_cache() {
    print_step "Membersihkan Laravel cache..."
    cd "$PTERODACTYL_PATH" || return 1

    local commands=("cache:clear" "config:clear" "route:clear" "view:clear")
    for cmd in "${commands[@]}"; do
        if php artisan "$cmd" >> "$LOG_FILE" 2>&1; then
            print_success "Cache dibersihkan: $cmd"
        else
            print_warn "Gagal bersihkan: $cmd (mungkin tidak kritis)"
        fi
    done
    return 0
}

run_migrations() {
    print_step "Menjalankan migrasi database (tabel abuse_logs)..."
    cd "$PTERODACTYL_PATH" || return 1
    if php artisan migrate --force >> "$LOG_FILE" 2>&1; then
        print_success "Migrasi database berhasil"
    else
        print_warn "Migrasi gagal — jalankan manual: php artisan migrate --force"
    fi
}

print_summary() {
    echo ""
    print_header "RINGKASAN INSTALASI"

    print_info "Total file diproses  : $((INSTALL_COUNT + ${#FAILED_FILES[@]}))"
    print_success "Berhasil diinstal    : $INSTALL_COUNT"

    if [[ ${#FAILED_FILES[@]} -gt 0 ]]; then
        print_error "Gagal diinstal: ${#FAILED_FILES[@]}"
        for file in "${FAILED_FILES[@]}"; do echo "  - $file"; done
    fi

    echo ""
    print_info "FITUR KEAMANAN AKTIF:"
    echo "  [+] Hanya root_admin yang bisa hapus user / server orang lain"
    echo "  [+] Deteksi otomatis admin yang menyalahgunakan hak hapus"
    echo "  [+] Auto-suspend admin pelanggar setelah 3x abuse dalam 30 menit"
    echo "  [+] Semua aksi hapus tercatat di audit log (channel: audit)"
    echo "  [+] Proteksi admin utama (ID=$PROTECTED_ADMIN_ID) — tidak bisa dihapus/suspend"
    echo "  [+] Perbaikan celah keamanan: NestController::destroy() kini butuh auth"
    echo "  [+] Akses file server berbasis kepemilikan (owner-based access)"
    echo "  [+] Proteksi perubahan owner server dengan audit trail"
    echo "  [+] Semua controller admin menggunakan helper requireRootAdmin() terpusat"

    echo ""
    print_info "INFORMASI BACKUP:"
    echo "  Lokasi : $BACKUP_DIR"
    echo "  Pola   : [namafile].backup_$TIMESTAMP"

    echo ""
    print_info "LANGKAH SELANJUTNYA:"
    echo "  1. Periksa log instalasi    : $LOG_FILE"
    echo "  2. Periksa log audit        : /var/log/pterodactyl/ (channel audit)"
    echo "  3. Konfigurasi log channel  : config/logging.php — tambahkan channel 'audit' dan 'security'"
    echo "  4. Test login admin panel dan verifikasi proteksi berjalan"
    echo "  5. Cek tabel abuse_logs di database untuk monitoring"
    echo ""

    if [[ $ERROR_COUNT -eq 0 ]]; then
        print_success "Instalasi selesai tanpa error!"
    else
        print_error "Instalasi selesai dengan $ERROR_COUNT error — periksa log untuk detail"
    fi
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    print_header "PTERODACTYL SECURITY PROTECTION INSTALLER v${SCRIPT_VERSION}"
    print_info "Memulai instalasi pada $(date)"
    print_info "Log: $LOG_FILE"
    echo ""

    # Validasi
    check_root
    check_pterodactyl_installation
    check_php_version
    check_permissions
    create_backup_dir

    # -------------------------------------------------------------------------
    # Install semua file keamanan
    # -------------------------------------------------------------------------

    # [BARU] Service deteksi abuse
    install_file \
        "${PTERODACTYL_PATH}/app/Services/Security/AbuseProtectionService.php" \
        "$(get_abuse_protection_service)" \
        "AbuseProtectionService.php (BARU)"

    # [BARU] Migrasi tabel abuse_logs
    install_file \
        "${PTERODACTYL_PATH}/database/migrations/${TIMESTAMP}_create_abuse_logs_table.php" \
        "$(get_abuse_log_migration)" \
        "Migration: create_abuse_logs_table (BARU)"

    # [UPDATE] File-file yang diperbarui
    install_file \
        "${PTERODACTYL_PATH}/app/Services/Servers/ServerDeletionService.php" \
        "$(get_server_deletion_service)" \
        "ServerDeletionService.php"

    install_file \
        "${PTERODACTYL_PATH}/app/Http/Controllers/Admin/UserController.php" \
        "$(get_user_controller)" \
        "UserController.php"

    install_file \
        "${PTERODACTYL_PATH}/app/Http/Controllers/Admin/LocationController.php" \
        "$(get_location_controller)" \
        "LocationController.php"

    install_file \
        "${PTERODACTYL_PATH}/app/Http/Controllers/Admin/Nodes/NodeController.php" \
        "$(get_node_controller)" \
        "NodeController.php"

    install_file \
        "${PTERODACTYL_PATH}/app/Http/Controllers/Admin/Nests/NestController.php" \
        "$(get_nest_controller)" \
        "NestController.php (FIXED: celah destroy)"

    install_file \
        "${PTERODACTYL_PATH}/app/Http/Controllers/Admin/Settings/IndexController.php" \
        "$(get_settings_controller)" \
        "SettingsController.php"

    install_file \
        "${PTERODACTYL_PATH}/app/Http/Controllers/Api/Client/Servers/FileController.php" \
        "$(get_file_controller)" \
        "FileController.php"

    install_file \
        "${PTERODACTYL_PATH}/app/Http/Controllers/Api/Client/Servers/ServerController.php" \
        "$(get_server_controller)" \
        "ServerController.php"

    install_file \
        "${PTERODACTYL_PATH}/app/Services/Servers/DetailsModificationService.php" \
        "$(get_details_modification_service)" \
        "DetailsModificationService.php"

    # -------------------------------------------------------------------------
    run_migrations
    clear_laravel_cache
    print_summary
}

# Tangani interupsi
trap 'print_error "Instalasi dibatalkan"; exit 130' INT TERM

main "$@"
exit $?
