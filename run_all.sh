#!/bin/bash
set -e  # Stop on error so nothing continues in a broken state

SCRIPT_DIR="$(dirname "$0")"

echo "[+] Starting full CyberPatriot hardening..."

bash "$SCRIPT_DIR/users_harden.sh"
bash "$SCRIPT_DIR/services_harden.sh"
bash "$SCRIPT_DIR/network_service.sh"
bash "$SCRIPT_DIR/system_harden.sh"
bash "$SCRIPT_DIR/kernel_harden.sh"
bash "$SCRIPT_DIR/packages_services.sh"
bash "$SCRIPT_DIR/logging_harden.sh"

echo "[+] All hardening modules complete."
exit 0
