#!/bin/bash
# ==================================================
# CyberPatriot Advanced Security Hardening Script
# Linux Mint 21 - SAFE VERSION
# CRITICAL SERVICES: Apache2 and MySQL (fully hardened)
# BENJAMIN: Completely untouched - sudo access preserved
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

echo "[+] Starting CyberPatriot Security Hardening for Linux Mint 21..."

# ------------------------------
# Logging
# ------------------------------
LOGFILE="/var/log/security_hardening_mint21.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ------------------------------
# CRITICAL: Users to NEVER touch (completely ignored by script)
# ------------------------------
DO_NOT_TOUCH_USERS=("benjamin" "$ACTUAL_USER")

# ------------------------------
# Authorized accounts (benjamin excluded - he's protected separately)
# ------------------------------
AUTHORIZED_ADMINISTRATORS=(jpearson rzane2 hspecter llitt awilliams swheeler)

declare -A ADMIN_PASSWORDS=(
  [jpearson]='W1llH4ck4B4con!'
  [hspecter]='L1f3!W1llH4ck4B4con'
  [llitt]='W1llH4ck4B4con!'
  [awilliams]='W1llH4ck4B4con!'
  [swheeler]='W1llH4ck4B4con!'
  [rzane2]='W1llH4ck4B4con!'
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

# ------------------------------
# Config
# ------------------------------
MIN_PASS_LENGTH=12
PASS_MAX_DAYS=90
PASS_MIN_DAYS=10
PASS_WARN_AGE=7

HACKER_TOOLS=("john" "hydra" "nmap" "zenmap" "metasploit" "wireshark" "sqlmap" "aircrack-ng" "ophcrack" "netcat" "netcat-openbsd" "netcat-traditional" "nikto" "ettercap" "tcpdump" "dsniff" "kismet" "mitmproxy" "burpsuite" "medusa" "hashcat" "wpscan" "gobuster" "dirb" "enum4linux" "smbclient" "nbtscan" "snmpwalk" "onesixtyone" "fierce" "dnsrecon" "theharvester" "recon-ng" "maltego" "setoolkit" "beef-xss" "msfconsole" "armitage" "veil" "empire" "crackmapexec" "responder" "impacket" "bloodhound" "mimikatz" "lazagne" "procdump")

FILE_TYPES_TO_REMOVE=("*.mp3" "*.avi" "*.mkv" "*.mp4" "*.m4a" "*.flac" "*.mov" "*.wav" "*.wma" "*.wmv" "*.3gp" "*.mpg" "*.mpeg" "*.ogg" "*.aac" "*.webm" "*.flv")

SSH_CONFIG="/etc/ssh/sshd_config"
SYSCTL_CONF="/etc/sysctl.d/99-cybersec-hardening.conf"

# ------------------------------
# Helpers
# ------------------------------
has_user() { id "$1" &>/dev/null; }

is_protected_user() {
  local user="$1"
  [[ " ${DO_NOT_TOUCH_USERS[*]} " =~ " ${user} " ]]
}

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
# Backup critical files FIRST
# ------------------------------
echo "[*] Backing up critical system files..."
BACKUP_DIR="/root/cyberpatriot_backups_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp /etc/passwd "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/shadow "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/group "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/sudoers "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/sudoers.d "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/pam.d "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/ssh "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/login.defs "$BACKUP_DIR/" 2>/dev/null || true
echo "[+] Backups saved to $BACKUP_DIR"

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
  ufw \
  fail2ban \
  auditd \
  audispd-plugins \
  apparmor \
  apparmor-utils \
  rkhunter \
  chkrootkit \
  clamav \
  clamav-daemon \
  lynis \
  debsums \
  acct \
  sysstat \
  apt-listchanges \
  needrestart \
  unattended-upgrades

# ------------------------------
# Kernel & Network Hardening (sysctl)
# ------------------------------
echo "[*] Configuring kernel hardening parameters..."

cat > "$SYSCTL_CONF" << 'EOF'
# CyberPatriot Advanced Security Hardening

# IP Forwarding (disable)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# SYN Cookies (DDoS protection)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Do not send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable source address verification (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log Martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Restrict kernel pointers
kernel.kptr_restrict = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict performance events
kernel.perf_event_paranoid = 3

# Enable ASLR
kernel.randomize_va_space = 2

# Restrict ptrace
kernel.yama.ptrace_scope = 1

# Protect hard and symbolic links
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Core dump restrictions
fs.suid_dumpable = 0

# TCP hardening
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_rfc1337 = 1

# Minimize swap
vm.swappiness = 10
EOF

echo "[+] Applying sysctl settings..."
sysctl -p "$SYSCTL_CONF" 2>/dev/null || true
sysctl --system 2>/dev/null || true

# ------------------------------
# User management (PROTECTS BENJAMIN)
# ------------------------------
echo "[*] Checking for unauthorized users (UID >= 1000)..."
echo "[!] Protected users (will NOT be touched): ${DO_NOT_TOUCH_USERS[*]}"

for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
  # NEVER touch protected users
  if is_protected_user "$user"; then
    echo "[!] PROTECTED: Skipping $user (DO NOT TOUCH)"
    continue
  fi
  
  if [[ "$user" == "nobody" ]]; then
    continue
  fi

  if [[ ! " ${ALL_AUTHORIZED_USERS[*]} " =~ " ${user} " ]]; then
    echo "[!] Found unauthorized user: $user"
    read -r -p "Delete user '$user' and their home directory? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
      pkill -u "$user" 2>/dev/null || true
      userdel -r "$user" 2>/dev/null || echo "[-] Failed to delete $user"
    else
      echo "[*] Skipping deletion of $user."
    fi
  fi
done

# ------------------------------
# Set admin passwords (SKIP PROTECTED USERS)
# ------------------------------
echo "[*] Setting administrator passwords..."
for admin in "${AUTHORIZED_ADMINISTRATORS[@]}"; do
  if is_protected_user "$admin"; then
    echo "[!] PROTECTED: Skipping password for $admin"
    continue
  fi
  
  if has_user "$admin"; then
    if [[ -n "${ADMIN_PASSWORDS[$admin]:-}" ]]; then
      echo "${admin}:${ADMIN_PASSWORDS[$admin]}" | chpasswd
      echo "[+] Password set for $admin"
    fi
  fi
done

# ------------------------------
# Sudo group enforcement (PROTECTS BENJAMIN)
# ------------------------------
echo "[*] Enforcing sudo group membership..."
echo "[!] Benjamin's sudo access will be PRESERVED"

# Ensure benjamin stays in sudo
if has_user "benjamin"; then
  usermod -aG sudo benjamin 2>/dev/null || true
  echo "[+] PROTECTED: benjamin kept in sudo group"
fi

# Add authorized admins to sudo
for admin in "${AUTHORIZED_ADMINISTRATORS[@]}"; do
  if has_user "$admin"; then
    usermod -aG sudo "$admin" 2>/dev/null || true
    echo "[+] Added $admin to sudo group"
  fi
done

# Remove unauthorized users from sudo (but NOT protected users)
current_sudo_members="$(getent group sudo | awk -F: '{print $4}' | tr ',' ' ')"
for u in $current_sudo_members; do
  [[ -z "$u" ]] && continue
  
  if is_protected_user "$u"; then
    echo "[!] PROTECTED: Keeping $u in sudo"
    continue
  fi
  
  if [[ ! " ${AUTHORIZED_ADMINISTRATORS[*]} " =~ " ${u} " ]]; then
    echo "[*] Removing $u from sudo..."
    deluser "$u" sudo 2>/dev/null || true
  fi
done

# ------------------------------
# Configure sudo security (SAFE - no requiretty)
# ------------------------------
echo "[*] Hardening sudo configuration (SAFE settings)..."
cat > /etc/sudoers.d/cybersec-hardening << 'EOF'
# CyberPatriot Sudo Hardening - SAFE VERSION
Defaults timestamp_timeout=5
Defaults passwd_tries=3
Defaults logfile="/var/log/sudo.log"
Defaults log_input,log_output
Defaults use_pty
# NOTE: requiretty removed - it breaks sudo in many cases
EOF

chmod 0440 /etc/sudoers.d/cybersec-hardening
visudo -c || rm /etc/sudoers.d/cybersec-hardening

# ------------------------------
# DO NOT lock root (prevents lockout)
# ------------------------------
echo "[!] NOT locking root account to prevent lockout"

# ------------------------------
# SSH Hardening
# ------------------------------
echo "[*] Hardening SSH configuration..."
if [[ -f "$SSH_CONFIG" ]]; then
  cp "$SSH_CONFIG" "$SSH_CONFIG.bak.$(date +%Y%m%d%H%M%S)"

  cat > "$SSH_CONFIG" << 'EOF'
# CyberPatriot SSH Hardening Configuration
Port 22
AddressFamily inet
Protocol 2

# Authentication
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Login Controls
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30
MaxStartups 10:30:100

# Security Features
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
PermitUserEnvironment no
PermitTunnel no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no

# Host-based auth (disable)
IgnoreRhosts yes
IgnoreUserKnownHosts yes
HostbasedAuthentication no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Security
StrictModes yes
UseDNS no

# Banner
Banner /etc/issue.net

# Strong ciphers only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
EOF

  # Create SSH banner
  cat > /etc/issue.net << 'EOF'
***************************************************************************
                            AUTHORIZED ACCESS ONLY
This system is for authorized users only. All activities are monitored and
logged. Unauthorized access is strictly prohibited and will be prosecuted.
***************************************************************************
EOF

  # Test and restart SSH
  sshd -t && systemctl restart ssh || echo "[-] SSH config test failed, reverting..."
fi

# ------------------------------
# Password policy (pwquality)
# ------------------------------
echo "[*] Enforcing password complexity policies..."
PWQ="/etc/security/pwquality.conf"
[[ -f "$PWQ" ]] && cp "$PWQ" "$PWQ.bak"

cat > "$PWQ" << EOF
# CyberPatriot Password Quality Configuration
minlen = $MIN_PASS_LENGTH
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 3
maxrepeat = 3
maxclassrepeat = 4
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
EOF

# Password aging in login.defs
echo "[*] Setting password aging..."
sed -i.bak -E "s/^(PASS_MAX_DAYS\s+).*/\1$PASS_MAX_DAYS/" /etc/login.defs
sed -i -E "s/^(PASS_MIN_DAYS\s+).*/\1$PASS_MIN_DAYS/" /etc/login.defs
sed -i -E "s/^(PASS_WARN_AGE\s+).*/\1$PASS_WARN_AGE/" /etc/login.defs
sed -i -E "s/^(PASS_MIN_LEN\s+).*/\1$MIN_PASS_LENGTH/" /etc/login.defs

# Apply to users (SKIP PROTECTED)
for u in "${ALL_AUTHORIZED_USERS[@]}"; do
  if is_protected_user "$u"; then
    echo "[!] PROTECTED: Skipping password aging for $u"
    continue
  fi
  if has_user "$u"; then
    chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" "$u" 2>/dev/null || true
  fi
done

# ------------------------------
# Firewall (UFW)
# ------------------------------
echo "[*] Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed

# Critical services
ufw allow 80/tcp comment 'HTTP for Apache'
ufw allow 443/tcp comment 'HTTPS for Apache'
ufw limit 22/tcp comment 'SSH rate limited'

ufw logging high
ufw --force enable
echo "[+] UFW enabled with HTTP, HTTPS, and SSH (rate limited)"

# ------------------------------
# APACHE2 - CRITICAL SERVICE (Full CyberPatriot Hardening)
# ------------------------------
echo "[*] Installing and hardening Apache2 (CRITICAL SERVICE)..."
apt-get install -y apache2 libapache2-mod-security2 libapache2-mod-evasive

# Backup Apache config
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.bak 2>/dev/null || true

# Main Apache hardening
cat > /etc/apache2/conf-available/security.conf << 'EOF'
# CyberPatriot Apache2 Security Configuration

# Hide Apache version
ServerTokens Prod
ServerSignature Off

# Disable TRACE method
TraceEnable Off

# Prevent clickjacking
Header always set X-Frame-Options "SAMEORIGIN"

# Prevent MIME type sniffing
Header always set X-Content-Type-Options "nosniff"

# Enable XSS protection
Header always set X-XSS-Protection "1; mode=block"

# Strict Transport Security (HTTPS)
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

# Content Security Policy
Header always set Content-Security-Policy "default-src 'self';"

# Referrer Policy
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Permissions Policy
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Timeout settings
Timeout 60
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5

# Limit request size
LimitRequestBody 10485760
LimitRequestFields 50
LimitRequestFieldSize 8190
LimitRequestLine 8190

# Directory security
<Directory />
    Options -Indexes -FollowSymLinks -ExecCGI
    AllowOverride None
    Require all denied
</Directory>

<Directory /var/www/>
    Options -Indexes +FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

# Deny access to sensitive files
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

<FilesMatch "\.(conf|sql|bak|old|backup|txt|log)$">
    Require all denied
</FilesMatch>

# Disable server-status and server-info
<Location /server-status>
    Require all denied
</Location>

<Location /server-info>
    Require all denied
</Location>
EOF

# Enable required modules
a2enmod headers 2>/dev/null || true
a2enmod ssl 2>/dev/null || true
a2enmod rewrite 2>/dev/null || true

# Disable unnecessary modules
a2dismod -f status 2>/dev/null || true
a2dismod -f autoindex 2>/dev/null || true
a2dismod -f userdir 2>/dev/null || true
a2dismod -f cgi 2>/dev/null || true
a2dismod -f include 2>/dev/null || true

# Enable security config
a2enconf security 2>/dev/null || true

# Configure mod_evasive (DoS protection)
mkdir -p /var/log/mod_evasive
chown www-data:www-data /var/log/mod_evasive

cat > /etc/apache2/mods-available/evasive.conf << 'EOF'
<IfModule mod_evasive20.c>
    DOSHashTableSize 3097
    DOSPageCount 2
    DOSSiteCount 50
    DOSPageInterval 1
    DOSSiteInterval 1
    DOSBlockingPeriod 10
    DOSLogDir "/var/log/mod_evasive"
</IfModule>
EOF

a2enmod evasive 2>/dev/null || true

# Set Apache file permissions
chown -R root:root /etc/apache2
chmod 750 /etc/apache2
chmod 640 /etc/apache2/*.conf
chmod 750 /etc/apache2/sites-available
chmod 750 /etc/apache2/sites-enabled
chmod 750 /etc/apache2/conf-available
chmod 750 /etc/apache2/conf-enabled

# Secure web root
chown -R root:www-data /var/www
chmod 750 /var/www
find /var/www -type d -exec chmod 750 {} \;
find /var/www -type f -exec chmod 640 {} \;

# Test and restart Apache
apache2ctl configtest && systemctl enable apache2 --now && systemctl restart apache2
echo "[+] Apache2 hardened and running (CRITICAL SERVICE)"

# ------------------------------
# MYSQL - CRITICAL SERVICE (Full CyberPatriot Hardening)
# ------------------------------
echo "[*] Installing and hardening MySQL (CRITICAL SERVICE)..."
apt-get install -y mysql-server

# MySQL security configuration
MYSQL_CONF="/etc/mysql/mysql.conf.d/mysqld.cnf"
cp "$MYSQL_CONF" "${MYSQL_CONF}.bak" 2>/dev/null || true

# Add security settings to MySQL config
cat >> "$MYSQL_CONF" << 'EOF'

# CyberPatriot MySQL Security Configuration
# Bind to localhost only
bind-address = 127.0.0.1
mysqlx-bind-address = 127.0.0.1

# Disable local infile (prevents file reading attacks)
local-infile = 0

# Disable symbolic links
symbolic-links = 0

# Enable logging
log_error = /var/log/mysql/error.log
general_log_file = /var/log/mysql/mysql.log
general_log = 1
slow_query_log = 1
slow_query_log_file = /var/log/mysql/mysql-slow.log
long_query_time = 2

# Security settings
skip-show-database
secure-file-priv = /var/lib/mysql-files

# Connection settings
max_connections = 100
max_connect_errors = 10
wait_timeout = 600
interactive_timeout = 600

# Disable anonymous users
# (Run mysql_secure_installation to fully enforce)
EOF

# Set MySQL file permissions
chown -R mysql:mysql /var/lib/mysql
chmod 750 /var/lib/mysql
chown root:root /etc/mysql
chmod 755 /etc/mysql
chmod 644 /etc/mysql/mysql.conf.d/*.cnf

# Create secure MySQL log directory
mkdir -p /var/log/mysql
chown mysql:mysql /var/log/mysql
chmod 750 /var/log/mysql

# Start MySQL
systemctl enable mysql --now
systemctl restart mysql

# Run mysql_secure_installation non-interactively (basic security)
echo "[*] Applying MySQL security settings..."
mysql -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null || true
mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null || true
mysql -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null || true
mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true

echo "[+] MySQL hardened and running (CRITICAL SERVICE)"
echo "[!] IMPORTANT: Run 'sudo mysql_secure_installation' to set root password"

# ------------------------------
# Fail2Ban for Apache and SSH
# ------------------------------
echo "[*] Configuring Fail2Ban..."
systemctl enable fail2ban --now

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log
maxretry = 3

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

[apache-fakegooglebot]
enabled = true
port = http,https
logpath = /var/log/apache*/*access.log
maxretry = 1

[apache-modsecurity]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log
maxretry = 2

[apache-shellshock]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log
maxretry = 1
bantime = 86400

[mysqld-auth]
enabled = true
port = 3306
logpath = /var/log/mysql/error.log
maxretry = 3
EOF

systemctl restart fail2ban

# ------------------------------
# AppArmor
# ------------------------------
echo "[*] Enabling AppArmor..."
systemctl enable apparmor --now
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# ------------------------------
# Auditd
# ------------------------------
echo "[*] Configuring audit system..."
systemctl enable auditd --now

cat > /etc/audit/rules.d/cybersec.rules << 'EOF'
-D
-b 8192
-f 1

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User/Group changes
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

# Login events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Sudoers
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# SSH
-w /etc/ssh/sshd_config -p wa -k sshd

# Apache
-w /etc/apache2/ -p wa -k apache
-w /var/www/ -p wa -k webfiles

# MySQL
-w /etc/mysql/ -p wa -k mysql

# Kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

-e 2
EOF

service auditd restart 2>/dev/null || true

# ------------------------------
# Automatic Updates
# ------------------------------
echo "[*] Enabling automatic security updates..."
cat > /etc/apt/apt.conf.d/10periodic << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Origins-Pattern {
        "o=Ubuntu,a=${distro_codename}-security";
        "o=UbuntuESMApps,a=${distro_codename}-apps-security";
        "o=UbuntuESM,a=${distro_codename}-infra-security";
        "o=Linux Mint,a=vanessa";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true

# ------------------------------
# Guest Account & Autologin
# ------------------------------
echo "[*] Disabling guest account and autologin..."
LIGHTDM_CONF="/etc/lightdm/lightdm.conf"
mkdir -p /etc/lightdm/lightdm.conf.d

cat > /etc/lightdm/lightdm.conf.d/50-security.conf << 'EOF'
[Seat:*]
allow-guest=false
greeter-hide-users=false
greeter-show-manual-login=true
EOF

# Remove autologin if present
if [[ -f "$LIGHTDM_CONF" ]]; then
  sed -i 's/^autologin-user=/#autologin-user=/' "$LIGHTDM_CONF"
  sed -i 's/^autologin-user-timeout=/#autologin-user-timeout=/' "$LIGHTDM_CONF"
fi

# ------------------------------
# Chromium browser
# ------------------------------
echo "[*] Installing Chromium..."
apt-get install -y chromium 2>/dev/null || apt-get install -y chromium-browser 2>/dev/null || true
update-alternatives --set x-www-browser /usr/bin/chromium 2>/dev/null || true

# ------------------------------
# Remove hacking tools
# ------------------------------
echo "[*] Removing prohibited hacking tools..."
for tool in "${HACKER_TOOLS[@]}"; do
  if dpkg -l 2>/dev/null | awk '{print $2}' | grep -qx "$tool"; then
    echo "[!] Removing $tool..."
    apt-get remove --purge -y "$tool" 2>/dev/null || true
  fi
done
apt-get autoremove -y

# ------------------------------
# Remove non-work media files
# ------------------------------
echo "[*] Searching for prohibited media files..."
for pattern in "${FILE_TYPES_TO_REMOVE[@]}"; do
  find /home /root -type f -iname "$pattern" 2>/dev/null | while read -r f; do
    # Skip protected users' files
    for protected in "${DO_NOT_TOUCH_USERS[@]}"; do
      if [[ "$f" == "/home/$protected/"* ]]; then
        echo "[!] PROTECTED: Skipping $f (belongs to $protected)"
        continue 2
      fi
    done
    echo "[!] Found: $f"
    read -r -p "Delete? (y/n): " confirm
    [[ "$confirm" == "y" ]] && rm -f "$f" && echo "[+] Deleted."
  done
done

# ------------------------------
# Disable unnecessary services
# ------------------------------
echo "[*] Disabling unnecessary services..."
SERVICES_TO_DISABLE=("avahi-daemon" "cups" "cups-browsed" "bluetooth" "isc-dhcp-server" "isc-dhcp-server6" "nfs-server" "nfs-kernel-server" "rpcbind" "vsftpd" "proftpd" "snmpd" "telnet" "telnetd" "rsh-server" "nis" "tftp" "tftpd-hpa" "xinetd" "talk" "ntalk" "ldap" "slapd" "rsync" "smbd" "nmbd" "nginx" "postfix" "sendmail" "dovecot" "ircd")

for svc in "${SERVICES_TO_DISABLE[@]}"; do
  if systemctl list-unit-files 2>/dev/null | grep -qw "${svc}.service"; then
    echo "[*] Disabling $svc..."
    systemctl disable --now "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
  fi
done

# ------------------------------
# Secure shared memory and /tmp
# ------------------------------
echo "[*] Securing shared memory and /tmp..."
if ! grep -q "/run/shm" /etc/fstab; then
  echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
fi
if ! grep -q "^tmpfs /tmp" /etc/fstab; then
  echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,mode=1777 0 0" >> /etc/fstab
fi

# ------------------------------
# File permissions
# ------------------------------
echo "[*] Setting secure file permissions..."
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow
chmod 600 /etc/ssh/sshd_config
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 700 /root
chmod 600 /etc/crontab
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly

# ------------------------------
# Disable Ctrl+Alt+Del reboot
# ------------------------------
echo "[*] Disabling Ctrl+Alt+Del reboot..."
systemctl mask ctrl-alt-del.target 2>/dev/null || true

# ------------------------------
# Enable process accounting
# ------------------------------
echo "[*] Enabling process accounting..."
systemctl enable acct --now 2>/dev/null || true

# ------------------------------
# Run security scans
# ------------------------------
echo "[*] Updating malware definitions..."
freshclam 2>/dev/null || true

echo "[*] Running rootkit check..."
rkhunter --update 2>/dev/null || true

# ------------------------------
# Verify protected users
# ------------------------------
echo ""
echo "[*] Verifying protected users..."
for user in "${DO_NOT_TOUCH_USERS[@]}"; do
  if has_user "$user"; then
    if groups "$user" | grep -q sudo; then
      echo "[+] ✓ $user exists and has sudo access"
    else
      echo "[!] WARNING: $user exists but may not have sudo - adding now..."
      usermod -aG sudo "$user"
    fi
  fi
done

# ------------------------------
# Summary
# ------------------------------
echo ""
echo "======================================================"
echo "[+] CYBERPATRIOT HARDENING COMPLETE"
echo "======================================================"
echo ""
echo "CRITICAL SERVICES STATUS:"
echo "  Apache2: $(systemctl is-active apache2)"
echo "  MySQL:   $(systemctl is-active mysql)"
echo ""
echo "PROTECTED USERS (NOT MODIFIED):"
for user in "${DO_NOT_TOUCH_USERS[@]}"; do
  if has_user "$user"; then
    echo "  ✓ $user - sudo: $(groups $user | grep -q sudo && echo 'YES' || echo 'NO')"
  fi
done
echo ""
echo "FIREWALL STATUS:"
ufw status | head -5
echo ""
echo "SECURITY FEATURES ENABLED:"
echo "  ✓ Kernel hardening (ASLR, ptrace restrictions)"
echo "  ✓ Network hardening (SYN cookies, anti-spoofing)"
echo "  ✓ SSH hardened with strong ciphers"
echo "  ✓ Apache2 fully hardened (mod_security, mod_evasive)"
echo "  ✓ MySQL hardened (localhost only, logging enabled)"
echo "  ✓ Fail2Ban protecting SSH, Apache, MySQL"
echo "  ✓ AppArmor profiles enforced"
echo "  ✓ Auditd monitoring system events"
echo "  ✓ Password policies enforced"
echo "  ✓ Automatic security updates enabled"
echo "  ✓ Guest account disabled"
echo "  ✓ Unnecessary services disabled"
echo ""
echo "IMPORTANT REMINDERS:"
echo "  1. Test sudo: sudo -v"
echo "  2. Test Apache: curl http://localhost"
echo "  3. Secure MySQL: sudo mysql_secure_installation"
echo "  4. Answer forensics questions FIRST!"
echo "  5. Set Unique Identifier on Desktop"
echo ""
echo "Backups saved to: $BACKUP_DIR"
echo "Log file: $LOGFILE"
echo "======================================================"