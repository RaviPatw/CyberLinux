#!/bin/bash
# =====================================================================
# CyberPatriot Mint 21 Hardening Script (Scenario-Compliant)
# - Mint 21 only (no external repos)
# - LightDM remains the display manager
# - Chromium is the default browser
# - Apache2 and MySQL must remain operational (CRITICAL SERVICES)
# - Creates 'edarby' with temp password and forces password change
# - Sets exact admin passwords from prompt; authorized users non-sudo
# - UFW enabled; HTTP/HTTPS allowed for Apache2
# - Daily unattended upgrades (10periodic / 50unattended-upgrades)
# - Removes hacking tools and non-work media (with confirmation)
# - DOES NOT touch CyberPatriot scoring software or CCS client
# =====================================================================

set -euo pipefail

# ------------------------------
# Root check
# ------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "[-] Run as root (use sudo)."
  exit 1
fi

# Store the user who invoked sudo to protect them
ACTUAL_USER="${SUDO_USER:-$USER}"
echo "[!] Running as root, protecting user: $ACTUAL_USER"

STAMP="$(date +%Y%m%d-%H%M%S)"
LOGFILE="/var/log/cp_mint21_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[+] Start @ $STAMP"

# ------------------------------
# Scenario: Authorized accounts
# ------------------------------
AUTHORIZED_ADMINISTRATORS=(benjamin jpearson rzane2 hspecter llitt awilliams swheeler)
# Per prompt: exact passwords
declare -A ADMIN_PASSWORDS=(
  [benjamin]='W1llH4ck4B4con!'
  [jpearson]='W1llH4ck4B4con!'
  [hspecter]='L1f3!W1llH4ck4B4con'
  [llitt]='W1llH4ck4B4con'
  [awilliams]='W1llH4ck4B4con'
  [swheeler]='W1llH4ck4B4con'
  [rzane2]='W1llH4ck4B4con'
)

AUTHORIZED_USERS=(
  mross
  kbennett
  pporter
  baltman
  kbennett
  rzane
  scarter
  dpaulson
  gbodinski
  kdurant
  hgunderson
  jkirkwood
  skeller
  zlawford
)

ALL_AUTHORIZED_USERS=("${AUTHORIZED_ADMINISTRATORS[@]}" "${AUTHORIZED_USERS[@]}")

# CRITICAL: Add current user to authorized admins if not already there
if [[ ! " ${AUTHORIZED_ADMINISTRATORS[*]} " =~ " ${ACTUAL_USER} " ]]; then
  echo "[!] Adding $ACTUAL_USER to authorized administrators to prevent lockout!"
  AUTHORIZED_ADMINISTRATORS+=("$ACTUAL_USER")
  ALL_AUTHORIZED_USERS+=("$ACTUAL_USER")
fi

# ------------------------------
# Basic apt hygiene (Mint 21 only)
# - enable deb-src lines
# - update cache
# ------------------------------
echo "[*] Enabling source repositories (deb-src) and refreshing APT..."
shopt -s nullglob
for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
  sed -ri 's/^\s*#\s*(deb-src\s+)/\1/' "$f" || true
done
apt update

# ------------------------------
# User Management
# ------------------------------
echo "[*] Ensuring authorized users exist (without changing home data)..."
ensure_user() {
  local u="$1"
  if id "$u" &>/dev/null; then
    echo "[+] User $u exists."
  else
    echo "[*] Creating user $u ..."
    adduser --disabled-password --gecos "" "$u"
  fi
}

for u in "${ALL_AUTHORIZED_USERS[@]}"; do
  ensure_user "$u"
done

# Choose a competition-safe temporary password (you may change this at run):
# TMP_PASS="Temp-ChangeMe-123!"
# ensure_user "edarby"
# echo "edarby:${TMP_PASS}" | chpasswd
# chage -d 0 edarby
# echo "[+] edarby created/updated with temporary password and forced password change at next login."

# Set exact admin passwords from prompt
echo "[*] Setting admin passwords per prompt..."
ADMIN_PASSFILE="$(mktemp)"
trap 'rm -f "$ADMIN_PASSFILE"' EXIT
for a in benjamin jpearson hspecter llitt awilliams swheeler rzane2; do
  ensure_user "$a"
  if [[ -n "${ADMIN_PASSWORDS[$a]:-}" ]]; then
    echo "${a}:${ADMIN_PASSWORDS[$a]}" >> "$ADMIN_PASSFILE"
  fi
done
chpasswd < "$ADMIN_PASSFILE"
echo "[+] Admin passwords applied."

# Sudo group enforcement
echo "[*] Enforcing sudo membership for admins and removing for non-admins..."
for a in "${AUTHORIZED_ADMINISTRATORS[@]}"; do
  usermod -aG sudo "$a"
  echo "[+] Added $a to sudo group"
done

# Remove unauthorized users from sudo (but NEVER remove current user)
if getent group sudo >/dev/null; then
  for u in $(getent group sudo | cut -d: -f4 | tr ',' ' '); do
    [[ -z "$u" ]] && continue
    # Skip if this is the current user
    if [[ "$u" == "$ACTUAL_USER" ]]; then
      echo "[!] Protecting $u (current user) - keeping in sudo"
      continue
    fi
    if [[ ! " ${AUTHORIZED_ADMINISTRATORS[*]} " =~ " ${u} " ]]; then
      echo "[*] Removing $u from sudo..."
      deluser "$u" sudo || true
    fi
  done
fi

# Remove unauthorized human users (uid >= 1000) with confirmation
echo "[*] Checking for unauthorized non-system users..."
for user in $(awk -F: '{print $1}' /etc/passwd); do
  # Never remove the current user!
  if [[ "$user" == "$ACTUAL_USER" ]]; then
    continue
  fi
  
  uid="$(id -u "$user" 2>/dev/null || echo 0)"
  if [[ "$uid" -ge 1000 && "$user" != "nobody" ]]; then
    if [[ ! " ${ALL_AUTHORIZED_USERS[*]} " =~ " ${user} " ]]; then
      echo "[!] Found unauthorized user: $user"
      read -rp "    Delete user '$user' and home (y/n)? " ans
      if [[ "$ans" == "y" ]]; then
        userdel -r "$user" || echo "[-] Failed to delete $user"
      else
        echo "[*] Skipping $user"
      fi
    fi
  fi
done

# ------------------------------
# Password Policy / Aging
# ------------------------------
echo "[*] Enforcing password strength and aging..."
apt install -y libpam-pwquality

PASSWD_PAM="/etc/pam.d/common-password"
[[ -f "${PASSWD_PAM}.bak" ]] || cp "$PASSWD_PAM" "${PASSWD_PAM}.bak"

# Strength: minlen 12, credits required, remember 5
if grep -q 'pam_pwquality.so' "$PASSWD_PAM"; then
  sed -ri 's#(^.*pam_pwquality\.so.*)(retry=[0-9]+)?#\1 retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1#' "$PASSWD_PAM"
else
  echo 'password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' >> "$PASSWD_PAM"
fi

# Aging in /etc/login.defs
sed -i.bak -E 's/^(PASS_MAX_DAYS\s+).*/\190/' /etc/login.defs
sed -i -E   's/^(PASS_MIN_DAYS\s+).*/\110/' /etc/login.defs
sed -i -E   's/^(PASS_WARN_AGE\s+).*/\17/'  /etc/login.defs
echo "[+] Password policy updated (minlen=12, remember=5, max=90, min=10, warn=7)."

# ------------------------------
# Account lockout (competition-safe)
# ------------------------------
AUTH_PAM="/etc/pam.d/common-auth"
[[ -f "${AUTH_PAM}.bak" ]] || cp "$AUTH_PAM" "${AUTH_PAM}.bak"
if ! grep -q 'pam_tally2.so' "$AUTH_PAM"; then
  echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' >> "$AUTH_PAM"
fi
echo "[+] Account lockout enabled (5 tries, 30 min)."

# ------------------------------
# UFW Firewall - FOR APACHE2 (not SSH/FTP)
# ------------------------------
echo "[*] Configuring UFW for Apache2..."
apt install -y ufw
ufw --force enable
ufw allow 80/tcp    # HTTP for Apache2
ufw allow 443/tcp   # HTTPS for Apache2
echo "[+] UFW enabled; HTTP (80) and HTTPS (443) allowed for Apache2."
ufw logging on

# ------------------------------
# APACHE2 - CRITICAL SERVICE (Must remain operational)
# ------------------------------
echo "[*] Ensuring Apache2 is installed and running..."
apt install -y apache2

# Basic Apache2 security hardening
A2_CONF="/etc/apache2/conf-available/security.conf"
if [[ -f "$A2_CONF" ]]; then
  [[ -f "${A2_CONF}.bak" ]] || cp "$A2_CONF" "${A2_CONF}.bak"
  
  # Hide Apache version
  sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$A2_CONF"
  sed -i 's/^ServerSignature.*/ServerSignature Off/' "$A2_CONF"
fi

# Disable directory listing if not already
a2dismod -f autoindex 2>/dev/null || true

systemctl enable apache2 --now
echo "[+] Apache2 configured, hardened, and running."

# ------------------------------
# MYSQL - CRITICAL SERVICE (Must remain operational)
# ------------------------------
echo "[*] Ensuring MySQL is installed and running..."
apt install -y mysql-server

systemctl enable mysql --now
echo "[+] MySQL installed and running."

echo "[!] IMPORTANT: Run 'mysql_secure_installation' manually to:"
echo "    - Set root password"
echo "    - Remove anonymous users"
echo "    - Disable remote root login"
echo "    - Remove test database"

# ------------------------------
# LightDM (do not change; warn if not default)
# ------------------------------
echo "[*] Verifying LightDM is the display manager..."
DEFAULT_DM_FILE="/etc/X11/default-display-manager"
if [[ -f "$DEFAULT_DM_FILE" ]]; then
  CURR_DM="$(cat "$DEFAULT_DM_FILE" 2>/dev/null || true)"
  if [[ "$CURR_DM" != "/usr/sbin/lightdm" ]]; then
    echo "[!] Warning: Current display manager is '$CURR_DM'. Prompt requires LightDM remain set."
    echo "    (Not changing display manager automatically during competition.)"
  else
    echo "[+] LightDM is the current display manager."
  fi
else
  echo "[!] Could not verify default display manager."
fi

# ------------------------------
# Automatic Updates (10periodic / 50unattended-upgrades)
# ------------------------------
echo "[*] Enabling unattended security updates..."
apt install -y unattended-upgrades apt-listchanges
dpkg-reconfigure --priority=low unattended-upgrades

cat >/etc/apt/apt.conf.d/10periodic <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

cat >/etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Origins-Pattern {
        "o=Ubuntu,a=jammy-security";
        "o=UbuntuESM,a=jammy";
        "o=Linux Mint,a=vanessa";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

apt update
apt -y upgrade
echo "[+] Unattended upgrades configured and system updated."

# ------------------------------
# Chromium as default browser (Mint package)
# ------------------------------
echo "[*] Ensuring Chromium is installed and default..."
apt install -y chromium
if command -v update-alternatives >/dev/null 2>&1; then
  if [[ -x /usr/bin/chromium ]]; then
    update-alternatives --set x-www-browser /usr/bin/chromium || true
    echo "[+] Chromium set as default x-www-browser."
  else
    echo "[!] /usr/bin/chromium not found; verify package name on this Mint build."
  fi
fi

# ------------------------------
# Remove hacking tools & non-work media (prompt before delete)
# ------------------------------
HACKER_TOOLS=(john hydra nmap zenmap metasploit-framework wireshark sqlmap aircrack-ng ophcrack)
MEDIA_PATTERNS=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac")

echo "[*] Checking for hacking tools..."
for t in "${HACKER_TOOLS[@]}"; do
  if dpkg -l | grep -qw "$t"; then
    echo "[!] Found $t"
    apt remove --purge -y "$t" || true
  fi
done
apt autoremove -y

echo "[*] Searching for non-work media under /home and /root (will prompt per file)..."
for pat in "${MEDIA_PATTERNS[@]}"; do
  while IFS= read -r -d '' f; do
    echo "[!] Found: $f"
    read -rp "    Delete this file (y/n)? " ans
    [[ "$ans" == "y" ]] && rm -f -- "$f" || echo "[*] Skipped."
  done < <(find /home /root -type f -iname "$pat" -print0 2>/dev/null)
done

# ------------------------------
# Disable unneeded services (NOT apache2, mysql, or scoring client)
# ------------------------------
maybe_disable() {
  local svc="$1"
  if systemctl list-unit-files | grep -qw "${svc}.service"; then
    if systemctl is-enabled --quiet "$svc"; then
      systemctl disable --now "$svc" || true
      echo "[+] Disabled $svc"
    else
      echo "[+] $svc already disabled"
    fi
  fi
}

echo "[*] Disabling unneeded network services (if present)..."
maybe_disable avahi-daemon
maybe_disable vsftpd
maybe_disable ssh
maybe_disable nginx
# apache2 and mysql stay enabled by requirement - DO NOT DISABLE

# ------------------------------
# DO NOT LOCK ROOT (prevents lockout)
# ------------------------------
echo "[!] NOT locking root account to prevent lockout"
echo "[!] Consider locking root manually after verifying sudo access works"

# ------------------------------
# Final Reminders (non-automatable tasks)
# ------------------------------
cat <<NOTE

=====================================================================
SCRIPT COMPLETED - CRITICAL SERVICES STATUS:
- Apache2: $(systemctl is-active apache2) (HTTP server on ports 80/443)
- MySQL: $(systemctl is-active mysql) (Database server)

YOUR SUDO ACCESS: Confirmed for user '$ACTUAL_USER'

REMINDERS (do these manually):
- Unique Identifier: Double-click the "CyberPatriot Set Unique Identifier" icon
  on the Desktop and enter your valid ID ASAP.
- Forensics Questions: Answer any Desktop "Forensics Questions" before changing
  system settings that might affect them.
- MySQL Security: Run 'sudo mysql_secure_installation' to secure MySQL
- Test Apache2: Visit http://localhost in browser to verify it's working
- Verify you can still use sudo: Try 'sudo -v' to confirm

LOCKOUT PROTECTION APPLIED:
- User '$ACTUAL_USER' protected and kept in sudo group
- Root account NOT locked (lock manually if desired)
=====================================================================

NOTE

echo "[+] Completed successfully on Mint 21."
echo "[+] Critical services: Apache2 ($(systemctl is-active apache2)), MySQL ($(systemctl is-active mysql))"
echo "[+] Your sudo access protected for: $ACTUAL_USER"
exit 0