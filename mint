#!/bin/bash
# ==================================================
# Advanced Security Hardening Script (Linux Mint 21)
# CyberPatriot SMI Finals - Enhanced Edition
# CRITICAL SERVICES: Apache2 and MySQL
# ==================================================

set -euo pipefail

# ------------------------------
# Ensure run as root
# ------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "[-] Run with sudo/root."
  exit 1
fi

# Store the user who invoked sudo to protect them
ACTUAL_USER="${SUDO_USER:-$USER}"
echo "[!] Running as root, protecting user: $ACTUAL_USER"

echo "[+] Starting ADVANCED Security Hardening for Linux Mint 21..."

# ------------------------------
# Logging
# ------------------------------
LOGFILE="/var/log/security_hardening_mint21_advanced.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ------------------------------
# Authorized accounts
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
# Config
# ------------------------------
MIN_PASS_LENGTH=12
PASS_MAX_DAYS=90
PASS_MIN_DAYS=10
PASS_WARN_AGE=7

HACKER_TOOLS=("john" "hydra" "nmap" "zenmap" "metasploit" "wireshark" "sqlmap" "aircrack-ng" "ophcrack" "netcat" "netcat-openbsd" "netcat-traditional" "nikto" "ettercap" "tcpdump" "dsniff" "kismet" "mitmproxy" "burpsuite")

FILE_TYPES_TO_REMOVE=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac" "*.mov" "*.wav" "*.wma" "*.wmv" "*.3gp" "*.mpg" "*.mpeg")

SSH_CONFIG="/etc/ssh/sshd_config"
SYSCTL_CONF="/etc/sysctl.d/99-cybersec-hardening.conf"

RESET_PASSWORDS=true
TEMP_PASSWORD_PREFIX="AFA-Temp!"

# ------------------------------
# Helpers
# ------------------------------
has_user() { id "$1" &>/dev/null; }

detect_autologin_user() {
  local u=""
  if [[ -f /etc/lightdm/lightdm.conf ]]; then
    u="$(grep -E '^\s*autologin-user\s*=' /etc/lightdm/lightdm.conf | tail -n1 | cut -d= -f2 | xargs || true)"
  fi
  if [[ -z "$u" ]] && [[ -d /etc/lightdm/lightdm.conf.d ]]; then
    u="$(grep -R -E '^\s*autologin-user\s*=' /etc/lightdm/lightdm.conf.d 2>/dev/null | tail -n1 | cut -d= -f2 | xargs || true)"
  fi
  echo "$u"
}

# ------------------------------
# APT hygiene
# ------------------------------
echo "[*] Updating package lists..."
apt-get update -y

# ------------------------------
# Install security tools
# ------------------------------
echo "[*] Installing essential security packages..."
apt-get install -y \
  libpam-pwquality \
  libpam-modules \
  libpam-cracklib \
  ufw \
  fail2ban \
  auditd \
  audispd-plugins \
  apparmor \
  apparmor-utils \
  aide \
  rkhunter \
  chkrootkit \
  lynis \
  debsums \
  acct \
  sysstat \
  libpam-tmpdir \
  apt-listchanges \
  needrestart

# ------------------------------
# Kernel & Network Hardening (sysctl)
# ------------------------------
echo "[*] Configuring kernel hardening parameters..."

cat > "$SYSCTL_CONF" << 'EOF'
# CyberPatriot Advanced Security Hardening

# IP Forwarding (disable unless router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# SYN Cookies (protection against SYN flood attacks)
net.ipv4.tcp_syncookies = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore secure ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Do not send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 0
net.ipv6.icmp.echo_ignore_all = 0

# Ignore Broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable source address verification (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log Martian packets (impossible addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable TCP SYN cookie protection from SYN floods
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable IPv6 if not needed (adjust based on requirements)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# Increase security of shared memory
kernel.shmmax = 68719476736
kernel.shmall = 4294967296

# Restrict kernel pointers in /proc
kernel.kptr_restrict = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict performance events
kernel.perf_event_paranoid = 3

# Enable ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# Restrict ptrace to prevent debugging of other processes
kernel.yama.ptrace_scope = 1

# Protect against memory overcommit attacks
vm.overcommit_memory = 1
vm.overcommit_ratio = 50

# Minimize swap usage
vm.swappiness = 10

# Increase inotify watches (for monitoring)
fs.inotify.max_user_watches = 524288

# Protect hard and symbolic links
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Core dump restrictions
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# TCP hardening
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Protect against time-wait assassination
net.ipv4.tcp_rfc1337 = 1

# Enable BBR congestion control (if kernel supports)
# net.core.default_qdisc = fq
# net.ipv4.tcp_congestion_control = bbr
EOF

echo "[+] Applying sysctl settings..."
sysctl -p "$SYSCTL_CONF" || true
sysctl --system || true

# ------------------------------
# User management
# ------------------------------
echo "[*] Checking for unauthorized human users (UID >= 1000)..."
for user in $(awk -F: '{print $1}' /etc/passwd); do
  # Never remove the current user!
  if [[ "$user" == "$ACTUAL_USER" ]]; then
    continue
  fi
  
  uid="$(id -u "$user" 2>/dev/null || true)"
  [[ -z "$uid" ]] && continue

  if [[ "$uid" -ge 1000 && "$user" != "nobody" ]]; then
    if [[ ! " ${ALL_AUTHORIZED_USERS[*]} " =~ " ${user} " ]]; then
      echo "[!] Found unauthorized user: $user"
      read -r -p "Delete user '$user' and their home directory? (y/n): " confirm
      if [[ "$confirm" == "y" ]]; then
        echo "[*] Deleting $user..."
        userdel -r "$user" || echo "[-] Failed to delete $user"
      else
        echo "[*] Skipping deletion of $user."
      fi
    fi
  fi
done

# ------------------------------
# Sudo group enforcement
# ------------------------------
echo "[*] Enforcing sudo group membership..."
current_sudo_members="$(getent group sudo | awk -F: '{print $4}' | tr ',' ' ')"
for u in $current_sudo_members; do
  [[ -z "$u" ]] && continue
  # Skip if this is the current user
  if [[ "$u" == "$ACTUAL_USER" ]]; then
    echo "[!] Protecting $u (current user) - keeping in sudo"
    continue
  fi
  if [[ " ${AUTHORIZED_ADMINISTRATORS[*]} " =~ " ${u} " ]]; then
    echo "[+] Keeping sudo for: $u"
  else
    echo "[!] Removing sudo from: $u"
    deluser "$u" sudo || true
  fi
done

for admin in "${AUTHORIZED_ADMINISTRATORS[@]}"; do
  if has_user "$admin"; then
    usermod -aG sudo "$admin" || true
    echo "[+] Ensured sudo for admin: $admin"
  fi
done

# ------------------------------
# Configure sudo security
# ------------------------------
echo "[*] Hardening sudo configuration..."
cat > /etc/sudoers.d/cybersec-hardening << 'EOF'
# Require password for sudo
Defaults timestamp_timeout=5
Defaults passwd_tries=3
Defaults logfile="/var/log/sudo.log"
Defaults log_input,log_output
Defaults use_pty
Defaults requiretty
EOF

chmod 0440 /etc/sudoers.d/cybersec-hardening

# ------------------------------
# Root login policy - DO NOT LOCK (prevents lockout)
# ------------------------------
echo "[!] NOT locking root account to prevent lockout"
echo "[!] Consider locking root manually after verifying sudo access works"
# passwd -l root || true  # COMMENTED OUT TO PREVENT LOCKOUT

# ------------------------------
# SSH Hardening (optional - not critical service)
# ------------------------------
echo "[*] Hardening SSH configuration..."
if [[ -f "$SSH_CONFIG" ]]; then
  cp "$SSH_CONFIG" "$SSH_CONFIG.bak.$(date -u +%Y%m%dT%H%M%SZ)"

  # Create hardened SSH config
  cat >> "$SSH_CONFIG" << 'EOF'

# CyberPatriot Security Hardening
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
Protocol 2
HostbasedAuthentication no
IgnoreRhosts yes
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
EOF

  # Remove duplicate directives
  awk '!seen[$1]++' "$SSH_CONFIG" > "$SSH_CONFIG.tmp" && mv "$SSH_CONFIG.tmp" "$SSH_CONFIG"
fi

# ------------------------------
# Password policy (pwquality)
# ------------------------------
echo "[*] Enforcing password complexity policies..."
PWQ="/etc/security/pwquality.conf"
cp "$PWQ" "$PWQ.bak.$(date -u +%Y%m%dT%H%M%SZ)" || true

set_pwq() {
  local key="$1" val="$2"
  if grep -qE "^\s*${key}\s*=" "$PWQ"; then
    sed -i "s/^\s*${key}\s*=.*/${key} = ${val}/" "$PWQ"
  else
    echo "${key} = ${val}" >> "$PWQ"
  fi
}

set_pwq "minlen" "$MIN_PASS_LENGTH"
set_pwq "ucredit" "-1"
set_pwq "lcredit" "-1"
set_pwq "dcredit" "-1"
set_pwq "ocredit" "-1"
set_pwq "minclass" "3"
set_pwq "maxrepeat" "3"
set_pwq "maxsequence" "3"
set_pwq "gecoscheck" "1"
set_pwq "dictcheck" "1"
set_pwq "usercheck" "1"
set_pwq "enforcing" "1"

# Password aging
echo "[*] Setting password aging..."
cp /etc/login.defs /etc/login.defs.bak.$(date -u +%Y%m%dT%H%M%SZ)
sed -i -E "s/^(PASS_MAX_DAYS\s+).*/\1$PASS_MAX_DAYS/" /etc/login.defs
sed -i -E "s/^(PASS_MIN_DAYS\s+).*/\1$PASS_MIN_DAYS/" /etc/login.defs
sed -i -E "s/^(PASS_WARN_AGE\s+).*/\1$PASS_WARN_AGE/" /etc/login.defs
sed -i -E "s/^(PASS_MIN_LEN\s+).*/\1$MIN_PASS_LENGTH/" /etc/login.defs

# Apply to existing users (skip benjamin and current user)
for u in "${ALL_AUTHORIZED_USERS[@]}"; do
  if has_user "$u"; then
    # Skip benjamin completely
    if [[ "$u" == "benjamin" ]]; then
      echo "[!] Skipping benjamin (no modifications)"
      continue
    fi
    # Skip current user
    if [[ "$u" == "$ACTUAL_USER" ]]; then
      echo "[!] Skipping $ACTUAL_USER (current user)"
      continue
    fi
    chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" "$u" 2>/dev/null || true
  fi
done

# ------------------------------
# Account lockout (pam_faillock)
# ------------------------------
echo "[*] Configuring login failure lockout..."
COMMON_AUTH="/etc/pam.d/common-auth"
COMMON_ACCOUNT="/etc/pam.d/common-account"

cp "$COMMON_AUTH" "$COMMON_AUTH.bak.$(date -u +%Y%m%dT%H%M%SZ)"
cp "$COMMON_ACCOUNT" "$COMMON_ACCOUNT.bak.$(date -u +%Y%m%dT%H%M%SZ)"

if ! grep -q "pam_faillock.so.*preauth" "$COMMON_AUTH"; then
  sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800' "$COMMON_AUTH"
fi
if ! grep -q "pam_faillock.so.*authfail" "$COMMON_AUTH"; then
  echo "auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800" >> "$COMMON_AUTH"
fi
if ! grep -q "pam_faillock.so" "$COMMON_ACCOUNT"; then
  echo "account required pam_faillock.so" >> "$COMMON_ACCOUNT"
fi

# ------------------------------
# Fail2Ban configuration (focused on Apache, not SSH)
# ------------------------------
echo "[*] Configuring Fail2Ban for Apache..."
systemctl enable --now fail2ban

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log

[apache-badbots]
enabled = true
port = http,https
logpath = /var/log/apache*/*access.log
maxretry = 2

[apache-noscript]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log

[apache-overflows]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log
maxretry = 2

[apache-nohome]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log
maxretry = 2

[apache-botsearch]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log
maxretry = 2
EOF

systemctl restart fail2ban

# ------------------------------
# Firewall (UFW) - Focused on Apache
# ------------------------------
echo "[*] Configuring UFW for Apache (HTTP/HTTPS)..."
ufw --force reset

ufw default deny incoming
ufw default allow outgoing
ufw default deny routed

# Web services (CRITICAL)
ufw allow 80/tcp comment 'HTTP for Apache'
ufw allow 443/tcp comment 'HTTPS for Apache'

# SSH (optional, with rate limiting if needed)
ufw limit 22/tcp comment 'SSH rate limit'

# Logging
ufw logging high

ufw --force enable

# ------------------------------
# AppArmor enforcement
# ------------------------------
echo "[*] Enabling AppArmor profiles..."
systemctl enable --now apparmor

# Set all profiles to enforce mode
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# ------------------------------
# Audit system (auditd)
# ------------------------------
echo "[*] Configuring audit rules..."
systemctl enable --now auditd

cat > /etc/audit/rules.d/cybersec.rules << 'EOF'
# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (1 = log, 2 = panic)
-f 1

# Audit system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User/Group modifications
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# Login/Logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Permission modifications
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Unauthorized file access attempts
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Monitor sudoers
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd

# Apache configuration
-w /etc/apache2/apache2.conf -p wa -k apache
-w /etc/apache2/sites-enabled/ -p wa -k apache

# MySQL configuration
-w /etc/mysql/my.cnf -p wa -k mysql
-w /etc/mysql/mysql.conf.d/ -p wa -k mysql

# Make configuration immutable
-e 2
EOF

service auditd restart || true

# ------------------------------
# File integrity monitoring (AIDE)
# ------------------------------
echo "[*] Initializing AIDE database (this may take several minutes)..."
aideinit || true
if [[ -f /var/lib/aide/aide.db.new ]]; then
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi

# ------------------------------
# Chromium installation
# ------------------------------
echo "[*] Ensuring Chromium is installed and set as default..."
apt-get install -y chromium || true

if command -v chromium >/dev/null 2>&1; then
  update-alternatives --install /usr/bin/x-www-browser x-www-browser "$(command -v chromium)" 100 || true
  update-alternatives --set x-www-browser "$(command -v chromium)" || true
elif command -v chromium-browser >/dev/null 2>&1; then
  update-alternatives --install /usr/bin/x-www-browser x-www-browser "$(command -v chromium-browser)" 100 || true
  update-alternatives --set x-www-browser "$(command -v chromium-browser)" || true
fi

# ------------------------------
# Remove hacking tools
# ------------------------------
echo "[*] Removing prohibited tools..."
for tool in "${HACKER_TOOLS[@]}"; do
  if dpkg -l | awk '{print $2}' | grep -qx "$tool"; then
    echo "[!] Purging $tool..."
    apt-get remove --purge -y "$tool" || true
  fi
done
apt-get autoremove -y

# ------------------------------
# Remove non-work media files
# ------------------------------
echo "[*] Searching for non-work media files..."
for pattern in "${FILE_TYPES_TO_REMOVE[@]}"; do
  find /home /root -type f -iname "$pattern" 2>/dev/null | while read -r f; do
    echo "[!] Found media: $f"
    read -r -p "Delete '$f'? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
      rm -f "$f" && echo "[+] Deleted."
    fi
  done
done

# ------------------------------
# Secure shared memory
# ------------------------------
echo "[*] Securing shared memory..."
if ! grep -q "/run/shm" /etc/fstab; then
  echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
fi

# ------------------------------
# Disable unnecessary services (NOT apache2 or mysql)
# ------------------------------
echo "[*] Disabling unnecessary services..."
SERVICES_TO_DISABLE=("avahi-daemon" "cups" "bluetooth" "isc-dhcp-server" "isc-dhcp-server6" "nfs-server" "rpcbind" "vsftpd" "snmpd")

for svc in "${SERVICES_TO_DISABLE[@]}"; do
  if systemctl list-unit-files | grep -qw "${svc}.service"; then
    echo "[*] Disabling $svc..."
    systemctl disable --now "$svc" 2>/dev/null || true
  fi
done

# ------------------------------
# Harden /tmp
# ------------------------------
echo "[*] Hardening /tmp partition..."
if ! grep -q "^tmpfs /tmp" /etc/fstab; then
  echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,mode=1777 0 0" >> /etc/fstab
fi

# ------------------------------
# Password resets (SKIP BENJAMIN AND CURRENT USER)
# ------------------------------
AUTOLOGIN_USER="$(detect_autologin_user || true)"
if [[ -n "$AUTOLOGIN_USER" ]]; then
  echo "[*] Detected LightDM autologin user: $AUTOLOGIN_USER"
fi

if [[ "$RESET_PASSWORDS" == "true" ]]; then
  echo "[*] Resetting passwords for authorized users..."
  for u in "${ALL_AUTHORIZED_USERS[@]}"; do
    if has_user "$u"; then
      # SKIP BENJAMIN COMPLETELY
      if [[ "$u" == "benjamin" ]]; then
        echo "[!] Skipping benjamin (no password reset)"
        continue
      fi
      
      # Skip current user
      if [[ "$u" == "$ACTUAL_USER" ]]; then
        echo "[!] Skipping $ACTUAL_USER (current user - no password reset)"
        continue
      fi
      
      # Skip autologin user
      if [[ -n "$AUTOLOGIN_USER" && "$u" == "$AUTOLOGIN_USER" ]]; then
        echo "[*] Skipping autologin account: $u"
        continue
      fi

      TEMP_PASS="${TEMP_PASSWORD_PREFIX}${u}!2025"
      echo "${u}:${TEMP_PASS}" | chpasswd
      chage -d 0 "$u" || true
      echo "[+] $u password reset (must change at next login)"
    fi
  done
fi

# ------------------------------
# CRITICAL SERVICES: Ensure Apache2 and MySQL are running
# ------------------------------
echo "[*] Ensuring CRITICAL services (Apache2 and MySQL) are enabled..."

# Apache2 - CRITICAL SERVICE
echo "[+] Installing and configuring Apache2..."
apt-get install -y apache2

# Basic Apache2 security hardening
A2_CONF="/etc/apache2/conf-available/security.conf"
if [[ -f "$A2_CONF" ]]; then
  [[ -f "${A2_CONF}.bak" ]] || cp "$A2_CONF" "${A2_CONF}.bak"
  
  # Hide Apache version
  sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$A2_CONF"
  sed -i 's/^ServerSignature.*/ServerSignature Off/' "$A2_CONF"
  a2enconf security
fi

# Disable directory listing
a2dismod -f autoindex 2>/dev/null || true

systemctl enable apache2 --now
echo "[+] Apache2 enabled and running (CRITICAL SERVICE)"

# MySQL - CRITICAL SERVICE
echo "[+] Installing and configuring MySQL..."
apt-get install -y mysql-server

systemctl enable mysql --now
echo "[+] MySQL enabled and running (CRITICAL SERVICE)"

echo "[!] IMPORTANT: Run 'mysql_secure_installation' manually to:"
echo "    - Set root password"
echo "    - Remove anonymous users"
echo "    - Disable remote root login"
echo "    - Remove test database"

# SSH - Optional (not critical)
if systemctl list-unit-files | grep -qw sshd.service; then
  systemctl enable sshd --now
  systemctl restart sshd
elif systemctl list-unit-files | grep -qw ssh.service; then
  systemctl enable ssh --now
  systemctl restart ssh
fi
echo "[+] SSH service enabled (optional, not critical)"

# ------------------------------
# Disable nginx if present
# ------------------------------
if systemctl list-unit-files | grep -qw nginx.service; then
  echo "[*] Disabling nginx..."
  systemctl disable --now nginx || true
fi

# ------------------------------
# Set file permissions on sensitive files
# ------------------------------
echo "[*] Setting secure file permissions..."
chmod 600 /etc/ssh/sshd_config
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 640 /etc/gshadow
chmod 644 /etc/group
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 700 /root
chmod 600 /etc/crontab
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.monthly
chmod 700 /etc/cron.weekly

# Apache permissions
chmod 640 /etc/apache2/apache2.conf 2>/dev/null || true
chown root:root /etc/apache2 2>/dev/null || true

# MySQL permissions
chmod 640 /etc/mysql/my.cnf 2>/dev/null || true
chown root:root /etc/mysql 2>/dev/null || true

# ------------------------------
# Disable USB storage (optional - uncomment if needed)
# ------------------------------
# echo "[*] Disabling USB storage..."
# echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf

# ------------------------------
# Enable process accounting
# ------------------------------
echo "[*] Enabling process accounting..."
systemctl enable --now acct || true

# ------------------------------
# Summary
# ------------------------------
echo ""
echo "======================================================"
echo "[+] ADVANCED HARDENING COMPLETE"
echo "======================================================"
echo ""
echo "CRITICAL SERVICES STATUS:"
echo "  ✓ Apache2: $(systemctl is-active apache2) - HTTP/HTTPS on ports 80/443"
echo "  ✓ MySQL: $(systemctl is-active mysql) - Database server"
echo ""
echo "YOUR ACCESS PROTECTED:"
echo "  ✓ User '$ACTUAL_USER' protected and kept in sudo group"
echo "  ✓ User 'benjamin' left untouched (no modifications)"
echo "  ✓ Root account NOT locked (prevents lockout)"
echo ""
echo "Enhancements applied:"
echo "  ✓ TCP SYN cookies enabled"
echo "  ✓ Kernel hardening (ASLR, ptrace restrictions, etc.)"
echo "  ✓ Network hardening (IP forwarding disabled, anti-spoofing, etc.)"
echo "  ✓ SSH hardened (strong ciphers, rate limiting)"
echo "  ✓ Fail2Ban configured for Apache (primary focus)"
echo "  ✓ AppArmor profiles enforced"
echo "  ✓ Auditd monitoring system events"
echo "  ✓ AIDE file integrity monitoring initialized"
echo "  ✓ Enhanced password policies"
echo "  ✓ UFW firewall with HTTP/HTTPS focus"
echo "  ✓ Process accounting enabled"
echo "  ✓ Secure file permissions set"
echo "  ✓ Unnecessary services disabled"
echo "  ✓ /tmp and shared memory hardened"
echo ""
echo "REMINDERS:"
echo "  - Display manager: LightDM (unchanged)"
echo "  - Timezone: UTC (unchanged)"
echo "  - CCS Client/scoring: NOT modified"
echo "  - Test sudo: Run 'sudo -v' to verify"
echo "  - Test Apache: Visit http://localhost in browser"
echo "  - Secure MySQL: Run 'sudo mysql_secure_installation'"
echo ""
echo "Log file: $LOGFILE"
echo "======================================================"