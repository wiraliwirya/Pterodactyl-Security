#!/bin/bash

set -euo pipefail

readonly PTERODACTYL_PATH="${PTERODACTYL_PATH:-/var/www/pterodactyl}"
readonly TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
readonly LOG_FILE="/var/log/pterodactyl-limits-install.log"

readonly C_RESET='\033[0m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'
readonly C_BOLD='\033[1m'

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

header() {
    echo ""
    echo "================================================================================"
    echo -e "${C_BOLD}${C_CYAN}$1${C_RESET}"
    echo "================================================================================"
    echo ""
}

success() {
    echo -e "${C_GREEN}[✓] $1${C_RESET}"
    log "SUCCESS: $1"
}

error() {
    echo -e "${C_RED}[✗] $1${C_RESET}" >&2
    log "ERROR: $1"
}

info() {
    echo -e "${C_CYAN}[i] $1${C_RESET}"
}

warn() {
    echo -e "${C_YELLOW}[!] $1${C_RESET}"
}

check_requirements() {
    info "mengecek sistem requirements..."
    
    if [[ $EUID -ne 0 ]]; then
        error "Script ini harus dijalankan sebagai root!"
        exit 1
    fi
    
    if [[ ! -d "$PTERODACTYL_PATH" ]]; then
        error "Pterodactyl tidak ditemukan di: $PTERODACTYL_PATH"
        exit 1
    fi
    
    if [[ ! -f "$PTERODACTYL_PATH/artisan" ]]; then
        error "File artisan tidak ditemukan. Pastikan Pterodactyl terinstall dengan benar!"
        exit 1
    fi
    
    success "sistem requirements OK"
}

backup_file() {
    local file="$1"
    local backup="${file}.backup_${TIMESTAMP}"
    
    if [[ -f "$file" ]]; then
        cp "$file" "$backup"
        success "Backup dibuat: $(basename "$file")"
        return 0
    fi
    return 0
}

get_server_creation_service() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Services\Servers;

use Ramsey\Uuid\Uuid;
use Illuminate\Support\Arr;
use Pterodactyl\Models\Server;
use Illuminate\Support\Facades\Auth;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Models\Objects\DeploymentObject;
use Pterodactyl\Repositories\Eloquent\ServerRepository;
use Pterodactyl\Repositories\Eloquent\ServerVariableRepository;
use Pterodactyl\Services\Deployment\FindViableNodesService;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Exceptions\Http\Connection\DaemonConnectionException;

class ServerCreationService
{
    public function __construct(
        private ConnectionInterface $connection,
        private DaemonServerRepository $daemonServerRepository,
        private FindViableNodesService $findViableNodesService,
        private ServerRepository $repository,
        private ServerVariableRepository $serverVariableRepository,
        private VariableValidatorService $validatorService
    ) {
    }

    public function handle(array $data, DeploymentObject $deployment = null): Server
    {
        $this->validateResourceLimits($data);

        return $this->connection->transaction(function () use ($data, $deployment) {
            $server = $this->createModel($data, $deployment);

            if (isset($data['start_on_completion']) && (bool) $data['start_on_completion']) {
                $this->daemonServerRepository->setServer($server)->reinstall();
            } else {
                try {
                    $this->daemonServerRepository->setServer($server)->create();
                } catch (DaemonConnectionException $exception) {
                    $server->delete();
                    throw $exception;
                }
            }

            if (isset($data['environment'])) {
                $this->validatorService->setUserLevel(User::USER_LEVEL_ADMIN);
                $results = $this->validatorService->handle($server->egg_id, $data['environment']);

                $records = $results->map(function ($result) use ($server) {
                    return [
                        'server_id' => $server->id,
                        'variable_id' => $result->id,
                        'variable_value' => $result->value ?? '',
                    ];
                })->toArray();

                if (!empty($records)) {
                    $this->serverVariableRepository->insert($records);
                }
            }

            return $server->refresh();
        });
    }

    private function validateResourceLimits(array $data): void
    {
        $user = Auth::user();
        
        if (!$user) {
            abort(401, 'Eh, lu belum login nih!');
        }

        // Kalo bukan super admin (ID 1), wajib kasih limit
        if ($user->id !== 1) {
            $memory = (int) Arr::get($data, 'memory', 0);
            $disk = (int) Arr::get($data, 'disk', 0);
            $cpu = (int) Arr::get($data, 'cpu', 0);

            $errors = [];

            if ($memory === 0) {
                $errors[] = 'RAM gak boleh unlimited (0 MB). Minimal kasih 128 MB lah!';
            }

            if ($disk === 0) {
                $errors[] = 'Disk gak boleh unlimited (0 MB). Minimal kasih 512 MB!';
            }

            if ($cpu === 0) {
                $errors[] = 'CPU gak boleh unlimited (0%). Minimal kasih 50% dong!';
            }

            if (!empty($errors)) {
                $message = "Waduh! Gagal bikin server nih:\n\n" . implode("\n", $errors);
                $message .= "\n\nCatatan: Cuma super admin yang bisa bikin server unlimited. Lu cuma admin biasa bro!";
                
                abort(403, $message);
            }
        }
    }

    private function createModel(array $data, DeploymentObject $deployment = null): Server
    {
        if (isset($data['node_id'])) {
            $node = $data['node_id'];
        } else {
            $node = $this->findViableNodesService->setLocations($data['location_ids'] ?? [])
                ->handle($deployment);
        }

        return $this->repository->create([
            'external_id' => Arr::get($data, 'external_id'),
            'uuid' => Uuid::uuid4()->toString(),
            'uuidShort' => substr(Uuid::uuid4()->toString(), 0, 8),
            'node_id' => $node,
            'name' => $data['name'],
            'description' => $data['description'] ?? '',
            'status' => Server::STATUS_INSTALLING,
            'skip_scripts' => Arr::get($data, 'skip_scripts') ?? isset($data['skip_scripts']),
            'owner_id' => $data['owner_id'],
            'memory' => (int) $data['memory'],
            'swap' => (int) $data['swap'],
            'disk' => (int) $data['disk'],
            'io' => (int) $data['io'],
            'cpu' => (int) $data['cpu'],
            'threads' => $data['threads'] ?? null,
            'oom_disabled' => Arr::get($data, 'oom_disabled') ?? true,
            'allocation_id' => $data['allocation_id'],
            'nest_id' => $data['nest_id'],
            'egg_id' => $data['egg_id'],
            'startup' => $data['startup'],
            'image' => $data['image'],
            'database_limit' => Arr::get($data, 'database_limit') ?? 0,
            'allocation_limit' => Arr::get($data, 'allocation_limit') ?? 0,
            'backup_limit' => Arr::get($data, 'backup_limit') ?? 0,
        ]);
    }
}
PHPEOF
}

get_build_modification_service() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Services\Servers;

use Illuminate\Support\Arr;
use Webmozart\Assert\Assert;
use Pterodactyl\Models\Server;
use Illuminate\Support\Facades\Auth;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Repositories\Eloquent\ServerRepository;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Exceptions\Http\Connection\DaemonConnectionException;

class BuildModificationService
{
    public function __construct(
        private ConnectionInterface $connection,
        private DaemonServerRepository $daemonServerRepository,
        private ServerRepository $repository
    ) {
    }

    public function handle(Server $server, array $data): Server
    {
        $this->validateResourceLimits($server, $data);

        Assert::notEmpty($data, 'Modify server build must have a non-empty data array passed in.');

        return $this->connection->transaction(function () use ($server, $data) {
            $this->processAllocations($server, $data);

            if (isset($data['allocation_id']) && $data['allocation_id'] != $server->allocation_id) {
                try {
                    $this->daemonServerRepository->setServer($server)->revokeUserJTI($server->owner_id);
                } catch (DaemonConnectionException $exception) {
                    // Ignore
                }
            }

            $server = $this->repository->update($server->id, [
                'memory' => Arr::get($data, 'memory') ?? $server->memory,
                'swap' => Arr::get($data, 'swap') ?? $server->swap,
                'io' => Arr::get($data, 'io') ?? $server->io,
                'cpu' => Arr::get($data, 'cpu') ?? $server->cpu,
                'threads' => Arr::get($data, 'threads') ?? $server->threads,
                'disk' => Arr::get($data, 'disk') ?? $server->disk,
                'allocation_id' => Arr::get($data, 'allocation_id') ?? $server->allocation_id,
                'backup_limit' => Arr::get($data, 'backup_limit') ?? $server->backup_limit,
                'database_limit' => Arr::get($data, 'database_limit') ?? $server->database_limit,
                'allocation_limit' => Arr::get($data, 'allocation_limit') ?? $server->allocation_limit,
                'oom_disabled' => Arr::get($data, 'oom_disabled') ?? $server->oom_disabled,
            ], true, true);

            try {
                $this->daemonServerRepository->setServer($server)->sync();
            } catch (DaemonConnectionException $exception) {
                // Ignore
            }

            return $server->refresh();
        });
    }

    private function validateResourceLimits(Server $server, array $data): void
    {
        $user = Auth::user();
        
        if (!$user) {
            abort(401, 'Authentication required.');
        }

        if ($user->id === 1) {
            return;
        }

        $newMemory = isset($data['memory']) ? (int) $data['memory'] : $server->memory;
        $newDisk = isset($data['disk']) ? (int) $data['disk'] : $server->disk;
        $newCpu = isset($data['cpu']) ? (int) $data['cpu'] : $server->cpu;

        $errors = [];

        if ($newMemory === 0) {
            $errors[] = 'RAM gak boleh diubah jadi unlimited (0 MB)!';
        }

        if ($newDisk === 0) {
            $errors[] = 'Disk gak boleh diubah jadi unlimited (0 MB)!';
        }

        if ($newCpu === 0) {
            $errors[] = 'CPU gak boleh diubah jadi unlimited (0%)!';
        }

        if (!empty($errors)) {
            $message = "Gagal update server build:\n\n" . implode("\n", $errors);
            $message .= "\n\nInfo: Cuma super admin (ID 1) yang bisa set resource unlimited.";
            
            abort(403, $message);
        }
    }

    private function processAllocations(Server $server, array &$data): void
    {
        if (empty($data['add_allocations']) && empty($data['remove_allocations'])) {
            return;
        }

        $assignments = $server->allocations->pluck('id')->all();

        if (!empty($data['add_allocations'])) {
            foreach ($data['add_allocations'] as $allocation) {
                if (!in_array($allocation, $assignments)) {
                    $assignments[] = $allocation;
                }
            }
        }

        if (!empty($data['remove_allocations'])) {
            foreach ($data['remove_allocations'] as $allocation) {
                if (($key = array_search($allocation, $assignments)) !== false) {
                    unset($assignments[$key]);
                }
            }
        }

        $server->allocations()->sync($assignments);
    }
}
PHPEOF
}

get_admin_server_controller() {
    cat <<'PHPEOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin\Servers;

use Illuminate\View\View;
use Illuminate\Http\Request;
use Pterodactyl\Models\Server;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Prologue\Alerts\AlertsMessageBag;
use Spatie\QueryBuilder\QueryBuilder;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Repositories\Eloquent\NestRepository;
use Pterodactyl\Repositories\Eloquent\NodeRepository;
use Pterodactyl\Repositories\Eloquent\ServerRepository;
use Pterodactyl\Http\Requests\Admin\Servers\ServerFormRequest;
use Pterodactyl\Http\Requests\Admin\Servers\ServerUpdateFormRequest;

class ServerController extends Controller
{
    public function __construct(
        protected AlertsMessageBag $alert,
        protected NodeRepository $nodeRepository,
        protected NestRepository $nestRepository,
        protected ServerRepository $repository,
        protected ViewFactory $view
    ) {
    }

    public function index(Request $request): View
    {
        $servers = QueryBuilder::for(Server::query()->with('node', 'user', 'allocation'))
            ->allowedFilters(['uuid', 'name', 'image'])
            ->paginate(25);

        return $this->view->make('admin.servers.index', ['servers' => $servers]);
    }

    public function create(): View
    {
        $user = Auth::user();
        
        // Info penting buat admin biasa
        $limitInfo = null;
        if ($user && $user->id !== 1) {
            $limitInfo = 'Perhatian: Lu gak bisa bikin server dengan resource unlimited (RAM/CPU/Disk = 0). Cuma super admin yang bisa!';
        }

        return $this->view->make('admin.servers.new', [
            'nodes' => $this->nodeRepository->all(),
            'nests' => $this->nestRepository->getWithEggs(),
            'limit_info' => $limitInfo,
        ]);
    }

    public function view(Server $server): View
    {
        return $this->view->make('admin.servers.view.index', compact('server'));
    }
}
PHPEOF
}

install_files() {
    header "INSTALASI PEMBATASAN PEMBUATAN SERVER PTERODACTYL"
    
    local files_installed=0
    
    info "Installing ServerCreationService.php..."
    local target="${PTERODACTYL_PATH}/app/Services/Servers/ServerCreationService.php"
    backup_file "$target"
    echo "$(get_server_creation_service)" > "$target"
    chmod 644 "$target"
    chown www-data:www-data "$target" 2>/dev/null || true
    success "ServerCreationService.php installed"
    ((files_installed++))
    
    info "Installing BuildModificationService.php..."
    target="${PTERODACTYL_PATH}/app/Services/Servers/BuildModificationService.php"
    backup_file "$target"
    echo "$(get_build_modification_service)" > "$target"
    chmod 644 "$target"
    chown www-data:www-data "$target" 2>/dev/null || true
    success "BuildModificationService.php installed"
    ((files_installed++))
    
    info "Installing Admin ServerController.php..."
    target="${PTERODACTYL_PATH}/app/Http/Controllers/Admin/Servers/ServerController.php"
    backup_file "$target"
    echo "$(get_admin_server_controller)" > "$target"
    chmod 644 "$target"
    chown www-data:www-data "$target" 2>/dev/null || true
    success "Admin ServerController.php installed"
    ((files_installed++))
    
    echo ""
    success "Total files installed: $files_installed"
}

clear_cache() {
    header "CLEARING CACHE"
    
    cd "$PTERODACTYL_PATH" || exit 1
    
    info "Clearing Laravel cache..."
    php artisan cache:clear >> "$LOG_FILE" 2>&1 && success "Cache cleared" || warn "Cache clear warning (mungkin gak masalah)"
    
    info "Clearing config cache..."
    php artisan config:clear >> "$LOG_FILE" 2>&1 && success "Config cleared" || warn "Config clear warning"
    
    info "Clearing route cache..."
    php artisan route:clear >> "$LOG_FILE" 2>&1 && success "Routes cleared" || warn "Route clear warning"
    
    info "Clearing view cache..."
    php artisan view:clear >> "$LOG_FILE" 2>&1 && success "Views cleared" || warn "View clear warning"
}

show_summary() {
    header "INSTALASI SELESAI!"
    
    echo ""
    echo -e "${C_GREEN}${C_BOLD}Yeay! Penbatasan Limit Pembuatan Server udah terinstall nih! 🎉${C_RESET}"
    echo ""
    
    info "FITUR YANG AKTIF:"
    echo "  ✓ Super Admin (ID 1) bebas bikin server unlimited"
    echo "  ✓ Admin biasa WAJIB kasih limit (RAM/CPU/Disk gak boleh 0)"
    echo "  ✓ Validasi otomatis pas bikin server baru"
    echo "  ✓ Validasi otomatis pas update server build"
    echo "  ✓ Error message yang jelas dan gampang dipahami"
    echo ""
    
    info "CONTOH PENGGUNAAN:"
    echo "  ${C_YELLOW}Super Admin:${C_RESET}"
    echo "    RAM: 0 MB (unlimited)     → ✓ BOLEH"
    echo "    CPU: 0%   (unlimited)     → ✓ BOLEH"
    echo "    Disk: 0 MB (unlimited)    → ✓ BOLEH"
    echo ""
    echo "  ${C_YELLOW}Admin Biasa:${C_RESET}"
    echo "    RAM: 0 MB (unlimited)     → ✗ DITOLAK!"
    echo "    RAM: 512 MB               → ✓ BOLEH"
    echo "    CPU: 0%   (unlimited)     → ✗ DITOLAK!"
    echo "    CPU: 100%                 → ✓ BOLEH"
    echo "    Disk: 0 MB (unlimited)    → ✗ DITOLAK!"
    echo "    Disk: 1024 MB             → ✓ BOLEH"
    echo ""
    
    info "BACKUP LOCATION:"
    echo "  File asli udah di-backup dengan suffix: .backup_${TIMESTAMP}"
    echo "  Kalo ada masalah, tinggal restore dari backup aja"
    echo ""
    
    info "TESTING:"
    echo "  1. Login sebagai admin biasa (bukan ID 1)"
    echo "  2. Coba bikin server dengan RAM = 0"
    echo "  3. Harusnya muncul error: 'RAM gak boleh unlimited'"
    echo "  4. Login sebagai super admin (ID 1)"
    echo "  5. Bikin server dengan RAM = 0 harusnya sukses"
    echo ""
    
    warn "CATATAN PENTING:"
    echo "  - Validasi cuma jalan pas bikin/update server"
    echo "  - Server yang udah ada sebelumnya gak akan terpengaruh"
    echo "  - Kalo mau rollback, restore file dari backup"
    echo ""
    
    success "Semua Selesai! Selamat menggunakan scriptnya! 🚀"
    echo ""
}

main() {
    header "PEMBATASAN PEMBUATAN SERVER PTERODACTLY"
    
    info "Mulai instalasi di: $(date)"
    info "Log file: $LOG_FILE"
    echo ""
    
    check_requirements
    install_files
    clear_cache
    show_summary
    
    success "Instalasi berhasil!"
    exit 0
}

main "$@"