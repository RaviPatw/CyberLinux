#!/usr/bin/env bash
# ============================
# cp_harden_master.sh
# CyberPatriot full system hardening orchestrator
# ============================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LOGFILE="/var/log/cp_harden_master_$(date +%Y%m%d-%H%M%S).log"

log() {
    local ts; ts="$(date --iso-8601=seconds 2>/dev/null || date)"
    echo "[$ts] $*" | tee -a "$LOGFILE"
}

ensure_root() {
    [[ "${EUID:-0}" -eq 0 ]] || { echo "[-] Must run as root"; exit 1; }
}

ensure_root
log "[+] Starting full CyberPatriot hardening..."

# Users & Accounts
if [[ -f "$SCRIPT_DIR/users_harden.sh" ]]; then
    log "[*] Running users_harden.sh"
    bash "$SCRIPT_DIR/users_harden.sh"
else
    log "[-] users_harden.sh not found!"
fi

# Services
if [[ -f "$SCRIPT_DIR/services_harden.sh" ]]; then
    log "[*] Running services_harden.sh"
    bash "$SCRIPT_DIR/services_harden.sh"
else
    log "[-] services_harden.sh not found!"
fi

# Network / Firewall
if [[ -f "$SCRIPT_DIR/cp_harden_network_services_purge.sh" ]]; then
    log "[*] Running cp_harden_network_services_purge.sh"
    bash "$SCRIPT_DIR/cp_harden_network_services_purge.sh"
else
    log "[-] cp_harden_network_services_purge.sh not found!"
fi

# System Hardening
if [[ -f "$SCRIPT_DIR/system_harden.sh" ]]; then
    log "[*] Running system_harden.sh"
    bash "$SCRIPT_DIR/system_harden.sh"
else
    log "[-] system_harden.sh not found!"
fi

# Kernel / Filesystem Hardening
if [[ -f "$SCRIPT_DIR/filesystem_kernel_harden.sh" ]]; then
    log "[*] Running filesystem_kernel_harden.sh"
    bash "$SCRIPT_DIR/filesystem_kernel_harden.sh"
else
    log "[-] filesystem_kernel_harden.sh not found!"
fi

# Packages & Security Services
if [[ -f "$SCRIPT_DIR/packages_services_harden.sh" ]]; then
    log "[*] Running packages_services_harden.sh"
    bash "$SCRIPT_DIR/packages_services_harden.sh"
else
    log "[-] packages_services_harden.sh not found!"
fi

# Logging & Monitoring
if [[ -f "$SCRIPT_DIR/logging_harden.sh" ]]; then
    log "[*] Running logging_harden.sh"
    bash "$SCRIPT_DIR/logging_harden.sh"
else
    log "[-] logging_harden.sh not found!"
fi

log "[+] All hardening modules complete."
log "[+] Check individual module logs in /var/log/ for details."
exit 0
