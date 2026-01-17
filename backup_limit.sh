#!/bin/bash

################################################################################
# PTERODACTYL RESOURCE LIMITER ROLLBACK
# Version: 1.0.0
# Date: 2026-01-17
# 
# Fungsi:
# - Restore file backup ke kondisi semula
# - Hapus semua modifikasi resource limiter
# - Balik ke default Pterodactyl
################################################################################

set -euo pipefail

################################################################################
# KONFIGURASI
################################################################################

readonly PTERODACTYL_PATH="${PTERODACTYL_PATH:-/var/www/pterodactyl}"
readonly TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
readonly LOG_FILE="/var/log/pterodactyl-rollback.log"

# Warna
readonly C_RESET='\033[0m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'
readonly C_BOLD='\033[1m'

# Counter
declare -i RESTORED=0
declare -i FAILED=0

################################################################################
# FUNGSI HELPER
################################################################################

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

################################################################################
# VALIDASI
################################################################################

check_requirements() {
    info "Checking system..."
    
    if [[ $EUID -ne 0 ]]; then
        error "Script ini harus dijalankan sebagai root!"
        exit 1
    fi
    
    if [[ ! -d "$PTERODACTYL_PATH" ]]; then
        error "Pterodactyl tidak ditemukan di: $PTERODACTYL_PATH"
        exit 1
    fi
    
    success "System check OK"
}

################################################################################
# KONFIRMASI USER
################################################################################

confirm_rollback() {
    header "KONFIRMASI ROLLBACK"
    
    warn "Script ini akan:"
    echo "  - Menghapus semua modifikasi resource limiter"
    echo "  - Restore file ke kondisi original Pterodactyl"
    echo "  - Clear semua cache Laravel"
    echo ""
    
    warn "File yang akan di-restore:"
    echo "  1. ServerCreationService.php"
    echo "  2. BuildModificationService.php"
    echo "  3. ServerController.php (Admin)"
    echo ""
    
    read -p "Lanjutkan rollback? (ketik 'yes' untuk lanjut): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        info "Rollback dibatalkan oleh user"
        exit 0
    fi
    
    success "Konfirmasi diterima, memulai rollback..."
}

################################################################################
# CARI BACKUP TERBARU
################################################################################

find_latest_backup() {
    local file_path="$1"
    local backup_pattern="${file_path}.backup_*"
    
    # Cari semua backup file
    local latest_backup=$(ls -t $backup_pattern 2>/dev/null | head -n1)
    
    if [[ -n "$latest_backup" && -f "$latest_backup" ]]; then
        echo "$latest_backup"
        return 0
    fi
    
    return 1
}

################################################################################
# RESTORE FILE
################################################################################

restore_file() {
    local file_path="$1"
    local description="$2"
    
    info "Restoring: $description"
    
    # Cari backup terbaru
    local backup_file=$(find_latest_backup "$file_path")
    
    if [[ -n "$backup_file" ]]; then
        # Backup file yang mau di-replace (just in case)
        if [[ -f "$file_path" ]]; then
            cp "$file_path" "${file_path}.before_rollback_${TIMESTAMP}"
        fi
        
        # Restore dari backup
        if cp "$backup_file" "$file_path"; then
            chmod 644 "$file_path"
            chown www-data:www-data "$file_path" 2>/dev/null || true
            success "Restored dari backup: $description"
            ((RESTORED++))
            return 0
        else
            error "Gagal restore: $description"
            ((FAILED++))
            return 1
        fi
    else
        warn "Backup tidak ditemukan untuk: $description"
        info "Mencoba download file original dari Pterodactyl..."
        
        if download_original_file "$file_path" "$description"; then
            success "Downloaded original: $description"
            ((RESTORED++))
            return 0
        else
            error "Gagal download original: $description"
            ((FAILED++))
            return 1
        fi
    fi
}

################################################################################
# DOWNLOAD FILE ORIGINAL
################################################################################

download_original_file() {
    local file_path="$1"
    local description="$2"
    
    # Deteksi versi Pterodactyl
    cd "$PTERODACTYL_PATH" || return 1
    local version=$(php artisan --version 2>/dev/null | grep -oP 'Pterodactyl Panel \K[0-9.]+' || echo "1.11.5")
    
    info "Detected Pterodactyl version: $version"
    
    # Tentukan URL berdasarkan file
    local github_url=""
    local relative_path="${file_path#$PTERODACTYL_PATH/}"
    
    case "$relative_path" in
        "app/Services/Servers/ServerCreationService.php")
            github_url="https://raw.githubusercontent.com/pterodactyl/panel/1.0-develop/app/Services/Servers/ServerCreationService.php"
            ;;
        "app/Services/Servers/BuildModificationService.php")
            github_url="https://raw.githubusercontent.com/pterodactyl/panel/1.0-develop/app/Services/Servers/BuildModificationService.php"
            ;;
        "app/Http/Controllers/Admin/Servers/ServerController.php")
            github_url="https://raw.githubusercontent.com/pterodactyl/panel/1.0-develop/app/Http/Controllers/Admin/Servers/ServerController.php"
            ;;
        *)
            warn "Unknown file, cannot download: $relative_path"
            return 1
            ;;
    esac
    
    # Backup current file
    if [[ -f "$file_path" ]]; then
        cp "$file_path" "${file_path}.before_rollback_${TIMESTAMP}"
    fi
    
    # Create directory if not exists
    mkdir -p "$(dirname "$file_path")"
    
    # Download original file
    if curl -fsSL "$github_url" -o "$file_path"; then
        chmod 644 "$file_path"
        chown www-data:www-data "$file_path" 2>/dev/null || true
        return 0
    else
        error "Failed to download from: $github_url"
        return 1
    fi
}

################################################################################
# RESTORE MANUAL (ALTERNATIF)
################################################################################

restore_original_files_manual() {
    header "RESTORE MANUAL (ALTERNATIF)"
    
    warn "Jika restore otomatis gagal, lu bisa restore manual dengan cara:"
    echo ""
    echo "1. Reinstall Pterodactyl (gak akan hapus data):"
    echo "   cd /var/www/pterodactyl"
    echo "   php artisan down"
    echo "   curl -L https://github.com/pterodactyl/panel/releases/latest/download/panel.tar.gz | tar -xzv"
    echo "   chmod -R 755 storage/* bootstrap/cache"
    echo "   composer install --no-dev --optimize-autoloader"
    echo "   php artisan view:clear"
    echo "   php artisan config:clear"
    echo "   php artisan migrate --seed --force"
    echo "   chown -R www-data:www-data /var/www/pterodactyl/*"
    echo "   php artisan up"
    echo ""
    echo "2. Atau download manual dari GitHub:"
    echo "   https://github.com/pterodactyl/panel/tree/1.0-develop/app/Services/Servers"
    echo ""
}

################################################################################
# CLEAR CACHE
################################################################################

clear_cache() {
    header "CLEARING CACHE"
    
    cd "$PTERODACTYL_PATH" || exit 1
    
    local commands=(
        "cache:clear"
        "config:clear"
        "route:clear"
        "view:clear"
    )
    
    for cmd in "${commands[@]}"; do
        info "Running: php artisan $cmd"
        if php artisan "$cmd" >> "$LOG_FILE" 2>&1; then
            success "Cleared: $cmd"
        else
            warn "Failed: $cmd (mungkin gak masalah)"
        fi
    done
}

################################################################################
# MAIN ROLLBACK
################################################################################

perform_rollback() {
    header "PERFORMING ROLLBACK"
    
    # File yang perlu di-restore
    local files=(
        "${PTERODACTYL_PATH}/app/Services/Servers/ServerCreationService.php|ServerCreationService.php"
        "${PTERODACTYL_PATH}/app/Services/Servers/BuildModificationService.php|BuildModificationService.php"
        "${PTERODACTYL_PATH}/app/Http/Controllers/Admin/Servers/ServerController.php|Admin ServerController.php"
    )
    
    for file_entry in "${files[@]}"; do
        IFS='|' read -r file_path description <<< "$file_entry"
        restore_file "$file_path" "$description"
    done
    
    echo ""
    if [[ $FAILED -eq 0 ]]; then
        success "Semua file berhasil di-restore!"
    else
        warn "Beberapa file gagal di-restore ($FAILED file)"
        warn "Cek alternatif restore manual di bawah"
    fi
}

################################################################################
# SUMMARY
################################################################################

show_summary() {
    header "ROLLBACK SUMMARY"
    
    echo ""
    info "HASIL ROLLBACK:"
    echo "  ✓ Files restored: $RESTORED"
    echo "  ✗ Files failed: $FAILED"
    echo ""
    
    if [[ $RESTORED -gt 0 ]]; then
        success "Resource limiter berhasil dihapus!"
        echo ""
        info "STATUS SEKARANG:"
        echo "  - Semua admin bisa bikin server unlimited lagi"
        echo "  - Validasi resource sudah di-disable"
        echo "  - Panel kembali ke kondisi default Pterodactyl"
        echo ""
    fi
    
    if [[ $FAILED -gt 0 ]]; then
        warn "PERHATIAN:"
        echo "  Beberapa file gagal di-restore!"
        echo "  Silakan cek log: $LOG_FILE"
        echo ""
        restore_original_files_manual
    fi
    
    info "BACKUP FILES:"
    echo "  File sebelum rollback tersimpan dengan suffix: .before_rollback_${TIMESTAMP}"
    echo "  Lokasi: $PTERODACTYL_PATH/app/Services/Servers/"
    echo ""
    
    info "NEXT STEPS:"
    echo "  1. Test bikin server dengan RAM/CPU/Disk = 0"
    echo "  2. Pastikan gak ada error"
    echo "  3. Kalo masih error, coba restart queue worker:"
    echo "     systemctl restart pteroq"
    echo ""
    
    if [[ $FAILED -eq 0 ]]; then
        success "Rollback selesai! Panel udah balik normal! 🎉"
    else
        warn "Rollback selesai dengan beberapa error. Cek manual ya!"
    fi
    
    echo ""
}

################################################################################
# SHOW BACKUP LIST
################################################################################

show_backup_list() {
    header "DAFTAR BACKUP YANG TERSEDIA"
    
    info "Scanning backup files..."
    echo ""
    
    local backup_found=false
    
    # Cari semua backup
    while IFS= read -r backup_file; do
        if [[ -f "$backup_file" ]]; then
            backup_found=true
            local size=$(du -h "$backup_file" | cut -f1)
            local date=$(stat -c %y "$backup_file" | cut -d' ' -f1,2 | cut -d'.' -f1)
            echo "  📄 $(basename "$backup_file")"
            echo "     Size: $size | Date: $date"
            echo ""
        fi
    done < <(find "$PTERODACTYL_PATH" -name "*.backup_*" -type f 2>/dev/null)
    
    if [[ "$backup_found" == false ]]; then
        warn "Tidak ada backup file ditemukan!"
        echo ""
        info "Rollback akan download file original dari GitHub"
    fi
    
    echo ""
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    header "PTERODACTYL RESOURCE LIMITER ROLLBACK"
    
    info "Starting rollback at: $(date)"
    info "Log file: $LOG_FILE"
    echo ""
    
    check_requirements
    show_backup_list
    confirm_rollback
    perform_rollback
    clear_cache
    show_summary
    
    if [[ $FAILED -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Jalankan rollback
main "$@"
