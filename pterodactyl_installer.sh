#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_VERSION="3.0.0"
readonly PTERODACTYL_PATH="${PTERODACTYL_PATH:-/var/www/pterodactyl}"
readonly BACKUP_DIR="${PTERODACTYL_PATH}/backups"
readonly LOG_FILE="/var/log/pterodactyl-protection-install.log"
readonly TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
readonly REQUIRED_PHP_VERSION="8.1"

readonly PROTECTED_ADMIN_ID="${PROTECTED_ADMIN_ID:-1}"

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

declare -i ERROR_COUNT=0
declare -i INSTALL_COUNT=0
declare -a INSTALLED_FILES=()
declare -a FAILED_FILES=()

log() {
    echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] $*" | tee -a "$LOG_FILE"
}

print_header() {
    echo ""
    echo "================================================================================"
    echo -e "${COLOR_BOLD}${COLOR_CYAN}$1${COLOR_RESET}"
    echo "================================================================================"
    echo ""
}

print_step() {
    echo -e "${COLOR_BLUE}${ICON_STEP} $1${COLOR_RESET}"
    log "STEP: $1"
}

print_success() {
    echo -e "${COLOR_GREEN}${ICON_SUCCESS} $1${COLOR_RESET}"
    log "SUCCESS: $1"
}

print_error() {
    echo -e "${COLOR_RED}${ICON_ERROR} $1${COLOR_RESET}" >&2
    log "ERROR: $1"
    ((ERROR_COUNT++)) || true
}

print_warn() {
    echo -e "${COLOR_YELLOW}${ICON_WARN} $1${COLOR_RESET}"
    log "WARNING: $1"
}

print_info() {
    echo -e "${COLOR_CYAN}${ICON_INFO} $1${COLOR_RESET}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

check_pterodactyl_installation() {
    print_step "Validating Pterodactyl installation..."
    
    if [[ ! -d "$PTERODACTYL_PATH" ]]; then
        print_error "Pterodactyl directory not found: $PTERODACTYL_PATH"
        exit 1
    fi
    
    if [[ ! -f "$PTERODACTYL_PATH/artisan" ]]; then
        print_error "Invalid Pterodactyl installation (artisan not found)"
        exit 1
    fi
    
    print_success "Pterodactyl installation validated"
}

check_php_version() {
    print_step "Checking PHP version..."
    
    if ! command -v php &> /dev/null; then
        print_error "PHP is not installed"
        exit 1
    fi
    
    local php_version=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo "0.0.0")
    local required_version="$REQUIRED_PHP_VERSION"
    
    if ! printf '%s\n%s\n' "$required_version" "$php_version" | sort -V -C; then
        print_error "PHP version $php_version is below required $required_version"
        exit 1
    fi
    
    print_success "PHP version $php_version is compatible"
}

check_permissions() {
    print_step "Checking file permissions..."
    
    if [[ ! -w "$PTERODACTYL_PATH" ]]; then
        print_error "No write permission for $PTERODACTYL_PATH"
        exit 1
    fi
    
    print_success "File permissions validated"
}

create_backup_dir() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        chmod 755 "$BACKUP_DIR"
        print_success "Backup directory created: $BACKUP_DIR"
    fi
}

backup_file() {
    local file_path="$1"
    local backup_path="${file_path}.backup_${TIMESTAMP}"
    
    if [[ -f "$file_path" ]]; then
        if cp "$file_path" "$backup_path"; then
            print_success "Backed up: $(basename "$file_path")"
            return 0
        else
            print_error "Failed to backup: $file_path"
            return 1
        fi
    fi
    return 0
}

install_file() {
    local target_path="$1"
    local content="$2"
    local description="$3"
    
    print_step "Installing: $description"
    
    local dir_path=$(dirname "$target_path")
    if [[ ! -d "$dir_path" ]]; then
        mkdir -p "$dir_path"
        chmod 755 "$dir_path"
    fi
    
    if ! backup_file "$target_path"; then
        FAILED_FILES+=("$description")
        return 1
    fi
    
    if echo "$content" > "$target_path"; then
        chmod 644 "$target_path"
        chown www-data:www-data "$target_path" 2>/dev/null || true
        print_success "Installed: $description"
        INSTALLED_FILES+=("$description")
        ((INSTALL_COUNT++)) || true
        return 0
    else
        print_error "Failed to write: $description"
        FAILED_FILES+=("$description")
        return 1
    fi
}

get_server_deletion_service() {
    cat <<'EOF'
<?php

namespace Pterodactyl\Services\Servers;

use Illuminate\Support\Facades\Auth;
use Pterodactyl\Exceptions\DisplayException;
use Illuminate\Http\Response;
use Pterodactyl\Models\Server;
use Illuminate\Support\Facades\Log;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Services\Databases\DatabaseManagementService;
use Pterodactyl\Exceptions\Http\Connection\DaemonConnectionException;

class ServerDeletionService
{
    protected bool $force = false;

    public function __construct(
        private ConnectionInterface $connection,
        private DaemonServerRepository $daemonServerRepository,
        private DatabaseManagementService $databaseManagementService
    ) {
    }

    public function withForce(bool $bool = true): self
    {
        $this->force = $bool;
        return $this;
    }

    public function handle(Server $server): void
    {
        $user = Auth::user();

        if ($user && $user->root_admin !== true) {
            $ownerId = $server->owner_id ?? $server->user_id;
            if ($ownerId && $ownerId !== $user->id) {
                abort(403, 'You do not have permission to delete this server.');
            }
        }

        try {
            $this->daemonServerRepository->setServer($server)->delete();
        } catch (DaemonConnectionException $exception) {
            if (!$this->force && $exception->getStatusCode() !== Response::HTTP_NOT_FOUND) {
                throw $exception;
            }
            Log::warning($exception);
        }

        $this->connection->transaction(function () use ($server) {
            foreach ($server->databases as $database) {
                try {
                    $this->databaseManagementService->delete($database);
                } catch (\Exception $exception) {
                    if (!$this->force) {
                        throw $exception;
                    }
                    $database->delete();
                    Log::warning($exception);
                }
            }
            $server->delete();
        });
    }
}
EOF
}

get_user_controller() {
    cat <<'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\View\View;
use Illuminate\Http\Request;
use Pterodactyl\Models\User;
use Pterodactyl\Models\Model;
use Illuminate\Support\Collection;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
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

class UserController extends Controller
{
    use AvailableLanguages;

    public function __construct(
        protected AlertsMessageBag $alert,
        protected UserCreationService $creationService,
        protected UserDeletionService $deletionService,
        protected Translator $translator,
        protected UserUpdateService $updateService,
        protected UserRepositoryInterface $repository,
        protected ViewFactory $view
    ) {
    }

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
            'user' => $user,
            'languages' => $this->getAvailableLanguages(true),
        ]);
    }

    public function delete(Request $request, User $user): RedirectResponse
    {
        if (!$request->user() || $request->user()->root_admin !== true) {
            abort(403, 'Only the primary administrator can delete users.');
        }

        if ($request->user()->id === $user->id) {
            throw new DisplayException($this->translator->get('admin/user.exceptions.user_has_servers'));
        }

        $this->deletionService->handle($user);
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
        if (!$request->user() || $request->user()->root_admin !== true) {
            $restrictedFields = ['email', 'username', 'password', 'root_admin'];
            foreach ($restrictedFields as $field) {
                if ($request->filled($field)) {
                    abort(403, 'You do not have permission to modify this field.');
                }
            }
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
EOF
}

get_location_controller() {
    cat <<'EOF'
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
        protected AlertsMessageBag $alert,
        protected LocationCreationService $creationService,
        protected LocationDeletionService $deletionService,
        protected LocationRepositoryInterface $repository,
        protected LocationUpdateService $updateService,
        protected ViewFactory $view
    ) {
    }

    public function index(): View
    {
        $user = Auth::user();
        if (!$user || $user->root_admin !== true) {
            abort(403, 'Access denied. Only administrators can manage locations.');
        }

        return $this->view->make('admin.locations.index', [
            'locations' => $this->repository->getAllWithDetails(),
        ]);
    }

    public function view(int $id): View
    {
        $user = Auth::user();
        if (!$user || $user->root_admin !== true) {
            abort(403, 'Access denied. Only administrators can view locations.');
        }

        return $this->view->make('admin.locations.view', [
            'location' => $this->repository->getWithNodes($id),
        ]);
    }

    public function create(LocationFormRequest $request): RedirectResponse
    {
        if (!$request->user() || $request->user()->root_admin !== true) {
            abort(403, 'Access denied. Only administrators can create locations.');
        }

        $location = $this->creationService->handle($request->normalize());
        $this->alert->success('Location created successfully.')->flash();
        return redirect()->route('admin.locations.view', $location->id);
    }

    public function update(LocationFormRequest $request, Location $location): RedirectResponse
    {
        if (!$request->user() || $request->user()->root_admin !== true) {
            abort(403, 'Access denied. Only administrators can update locations.');
        }

        if ($request->input('action') === 'delete') {
            return $this->delete($location);
        }

        $this->updateService->handle($location->id, $request->normalize());
        $this->alert->success('Location updated successfully.')->flash();
        return redirect()->route('admin.locations.view', $location->id);
    }

    public function delete(Location $location): RedirectResponse
    {
        $user = Auth::user();
        if (!$user || $user->root_admin !== true) {
            abort(403, 'Access denied. Only administrators can delete locations.');
        }

        try {
            $this->deletionService->handle($location->id);
            return redirect()->route('admin.locations');
        } catch (DisplayException $ex) {
            $this->alert->danger($ex->getMessage())->flash();
        }

        return redirect()->route('admin.locations.view', $location->id);
    }
}
EOF
}

get_node_controller() {
    cat <<'EOF'
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
    public function __construct(private ViewFactory $view)
    {
    }

    public function index(Request $request): View
    {
        $user = Auth::user();
        if (!$user || $user->root_admin !== true) {
            abort(403, 'Access denied. Only administrators can manage nodes.');
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
EOF
}

get_nest_controller() {
    cat <<'EOF'
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
        protected AlertsMessageBag $alert,
        protected NestCreationService $nestCreationService,
        protected NestDeletionService $nestDeletionService,
        protected NestRepositoryInterface $repository,
        protected NestUpdateService $nestUpdateService,
        protected ViewFactory $view
    ) {
    }

    public function index(): View
    {
        $user = Auth::user();
        if (!$user || $user->root_admin !== true) {
            abort(403, 'Access denied. Only administrators can manage nests.');
        }

        return $this->view->make('admin.nests.index', [
            'nests' => $this->repository->getWithCounts(),
        ]);
    }

    public function create(): View
    {
        return $this->view->make('admin.nests.new');
    }

    public function store(StoreNestFormRequest $request): RedirectResponse
    {
        $nest = $this->nestCreationService->handle($request->normalize());
        $this->alert->success(trans('admin/nests.notices.created', ['name' => htmlspecialchars($nest->name)]))->flash();
        return redirect()->route('admin.nests.view', $nest->id);
    }

    public function view(int $nest): View
    {
        return $this->view->make('admin.nests.view', [
            'nest' => $this->repository->getWithEggServers($nest),
        ]);
    }

    public function update(StoreNestFormRequest $request, int $nest): RedirectResponse
    {
        $this->nestUpdateService->handle($nest, $request->normalize());
        $this->alert->success(trans('admin/nests.notices.updated'))->flash();
        return redirect()->route('admin.nests.view', $nest);
    }

    public function destroy(int $nest): RedirectResponse
    {
        $this->nestDeletionService->handle($nest);
        $this->alert->success(trans('admin/nests.notices.deleted'))->flash();
        return redirect()->route('admin.nests');
    }
}
EOF
}

get_settings_controller() {
    cat <<'EOF'
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
        private AlertsMessageBag $alert,
        private Kernel $kernel,
        private SettingsRepositoryInterface $settings,
        private SoftwareVersionService $versionService,
        private ViewFactory $view
    ) {
    }

    public function index(): View
    {
        $user = Auth::user();
        if (!$user || $user->root_admin !== true) {
            abort(403, 'Access denied. Only administrators can manage settings.');
        }

        return $this->view->make('admin.settings.index', [
            'version' => $this->versionService,
            'languages' => $this->getAvailableLanguages(true),
        ]);
    }

    public function update(BaseSettingsFormRequest $request): RedirectResponse
    {
        if (!$request->user() || $request->user()->root_admin !== true) {
            abort(403, 'Access denied. Only administrators can update settings.');
        }

        foreach ($request->normalize() as $key => $value) {
            $this->settings->set('settings::' . $key, $value);
        }

        $this->kernel->call('queue:restart');
        $this->alert->success(
            'Panel settings updated successfully. Queue worker restarted.'
        )->flash();

        return redirect()->route('admin.settings');
    }
}
EOF
}

get_file_controller() {
    cat <<'EOF'
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
        private NodeJWTService $jwtService,
        private DaemonFileRepository $fileRepository
    ) {
        parent::__construct();
    }

    private function validateServerAccess($request, Server $server): void
    {
        $user = $request->user();
        if (!$user) {
            abort(401, 'Authentication required.');
        }

        if ($user->root_admin !== true && $server->owner_id !== $user->id) {
            abort(403, 'You do not have permission to access this server.');
        }
    }

    public function directory(ListFilesRequest $request, Server $server): array
    {
        $this->validateServerAccess($request, $server);

        $contents = $this->fileRepository
            ->setServer($server)
            ->getDirectory($request->get('directory') ?? '/');

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
                'file_path' => rawurldecode($request->get('file')),
                'server_uuid' => $server->uuid,
            ])
            ->handle($server->node, $request->user()->id . $server->uuid);

        Activity::event('server:file.download')->property('file', $request->get('file'))->log();

        return [
            'object' => 'signed_url',
            'attributes' => [
                'url' => sprintf(
                    '%s/download/file?token=%s',
                    $server->node->getConnectionAddress(),
                    $token->toString()
                ),
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

        $this->fileRepository
            ->setServer($server)
            ->createDirectory($request->input('name'), $request->input('root', '/'));

        Activity::event('server:file.create-directory')
            ->property('name', $request->input('name'))
            ->property('directory', $request->input('root'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function rename(RenameFileRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);

        $this->fileRepository
            ->setServer($server)
            ->renameFiles($request->input('root'), $request->input('files'));

        Activity::event('server:file.rename')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function copy(CopyFileRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);

        $this->fileRepository
            ->setServer($server)
            ->copyFile($request->input('location'));

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

        $this->fileRepository->setServer($server)->decompressFile(
            $request->input('root'),
            $request->input('file')
        );

        Activity::event('server:file.decompress')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('file'))
            ->log();

        return new JsonResponse([], JsonResponse::HTTP_NO_CONTENT);
    }

    public function delete(DeleteFileRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);

        $this->fileRepository->setServer($server)->deleteFiles(
            $request->input('root'),
            $request->input('files')
        );

        Activity::event('server:file.delete')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function chmod(ChmodFilesRequest $request, Server $server): JsonResponse
    {
        $this->validateServerAccess($request, $server);

        $this->fileRepository->setServer($server)->chmodFiles(
            $request->input('root'),
            $request->input('files')
        );

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
EOF
}

get_server_controller() {
    cat <<'EOF'
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
            abort(401, 'Authentication required.');
        }

        if ($user->root_admin !== true && $server->owner_id !== $user->id) {
            abort(403, 'You do not have permission to access this server.');
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
EOF
}

get_details_modification_service() {
    cat <<'EOF'
<?php

namespace Pterodactyl\Services\Servers;

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Pterodactyl\Models\Server;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Traits\Services\ReturnsUpdatedModels;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Exceptions\Http\Connection\DaemonConnectionException;

class DetailsModificationService
{
    use ReturnsUpdatedModels;

    public function __construct(
        private ConnectionInterface $connection,
        private DaemonServerRepository $serverRepository
    ) {}

    public function handle(Server $server, array $data): Server
    {
        $user = Auth::user();

        if (!$user || $user->root_admin !== true) {
            abort(403, 'Only administrators can modify server details.');
        }

        return $this->connection->transaction(function () use ($data, $server) {
            $owner = $server->owner_id;

            $server->forceFill([
                'external_id' => Arr::get($data, 'external_id'),
                'owner_id' => Arr::get($data, 'owner_id'),
                'name' => Arr::get($data, 'name'),
                'description' => Arr::get($data, 'description') ?? '',
            ])->saveOrFail();

            if ($server->owner_id !== $owner) {
                try {
                    $this->serverRepository->setServer($server)->revokeUserJTI($owner);
                } catch (DaemonConnectionException $exception) {
                    // Ignore connection errors during JWT revocation
                }
            }

            return $server;
        });
    }
}
EOF
}

clear_laravel_cache() {
    print_step "Clearing Laravel caches..."
    
    cd "$PTERODACTYL_PATH" || return 1
    
    local commands=(
        "cache:clear"
        "config:clear"
        "route:clear"
        "view:clear"
    )
    
    for cmd in "${commands[@]}"; do
        if php artisan "$cmd" >> "$LOG_FILE" 2>&1; then
            print_success "Cleared: $cmd"
        else
            print_warn "Failed to clear: $cmd (may not be critical)"
        fi
    done
    
    return 0
}

main() {
    print_header "PTERODACTYL PROTECTION INSTALLER v${SCRIPT_VERSION}"
    
    print_info "Starting installation at $(date)"
    print_info "Log file: $LOG_FILE"
    echo ""
    
    check_root
    check_pterodactyl_installation
    check_php_version
    check_permissions
    
    create_backup_dir
    
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
        "NestController.php"
    
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
    
    clear_laravel_cache
    
    print_summary
}

print_summary() {
    echo ""
    print_header "INSTALLATION SUMMARY"
    
    print_info "Total files processed: $((INSTALL_COUNT + ${#FAILED_FILES[@]}))"
    print_success "Successfully installed: $INSTALL_COUNT"
    
    if [[ ${#FAILED_FILES[@]} -gt 0 ]]; then
        print_error "Failed installations: ${#FAILED_FILES[@]}"
        for file in "${FAILED_FILES[@]}"; do
            echo "  - $file"
        done
    fi
    
    echo ""
    print_info "PROTECTION FEATURES ENABLED:"
    echo "  - Administrator-only server deletion"
    echo "  - Administrator-only user management"
    echo "  - Administrator-only location management"
    echo "  - Administrator-only node management"
    echo "  - Administrator-only nest management"
    echo "  - Administrator-only settings access"
    echo "  - Owner-based server file access control"
    echo "  - Enhanced permission validation"
    
    echo ""
    print_info "BACKUP INFORMATION:"
    echo "  Location: $BACKUP_DIR"
    echo "  Pattern: [filename].backup_$TIMESTAMP"
    
    echo ""
    print_info "NEXT STEPS:"
    echo "  1. Review installation log: $LOG_FILE"
    echo "  2. Test admin panel functionality"
    echo "  3. Verify user permissions are working correctly"
    echo "  4. Check error logs: /var/log/pterodactyl/"
    
    echo ""
    
    if [[ $ERROR_COUNT -eq 0 ]]; then
        print_success "Installation completed successfully!"
        echo ""
        return 0
    else
        print_error "Installation completed with $ERROR_COUNT error(s)"
        print_warn "Please review the log file for details"
        echo ""
        return 1
    fi
}

trap 'print_error "Installation interrupted"; exit 130' INT TERM

main "$@"
exit $?