#!/bin/bash
# Ubuntu Proot Honeypot Setup Script - Ultimate Edition
# Creates a highly realistic Ubuntu environment with comprehensive monitoring and deception
# Author: Security Research Team
# Version: 3.0

# ========================
# 🔧 Configuration
# ========================
UBUNTU_VERSION="22.04"
PROOT_ROOT="$HOME/ubuntu_honeypot_ultimate"
LOG_DIR="$PROOT_ROOT/logs"
TRAP_DIR="$PROOT_ROOT/trap"
SERVICE_DIR="$PROOT_ROOT/etc/systemd/system"
VULN_SERVICES=("nginx" "mysql-server" "redis-server" "openssh-server" "postgresql" "vsftpd" "telnetd" "snmpd" "apache2" "tomcat9" "proftpd")
MONITORING_TOOLS=("auditd" "tcpdump" "sysstat" "fail2ban" "psad" "osquery" "tripwire" "aide")
FAKE_CREDS_FILE="$TRAP_DIR/fake_creds.txt"
FAKE_DOCUMENTS_DIR="$PROOT_ROOT/var/www/html/documents"
PROOT_DISTRO_URL="https://raw.githubusercontent.com/termux/proot-distro/master/proot-distro.sh"
NETWORK_CONFIG=("192.168.1.100/24" "10.0.0.100/24")
DECEPTION_USERS=("admin" "developer" "test" "backup" "dbadmin" "webmaster" "git" "jenkins" "ansible")
DECEPTION_PORTS=(8080 8443 3306 5432 6379 11211 27017 9200 5601)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Banner
echo -e "${BLUE}"
cat << "EOF"
  _   _ ____  _   _ _   _  ____ _____ ____  
 | | | | __ )| | | | \ | |/ ___|_   _/ ___| 
 | | | |  _ \| | | |  \| | |     | | \___ \ 
 | |_| | |_) | |_| | |\  | |___  | |  ___) |
  \___/|____/ \___/|_| \_|\____| |_| |____/ 
EOF
echo -e "${NC}"
echo -e "${GREEN}🔍 Ubuntu Proot Honeypot Setup - Ultimate Edition${NC}"
echo -e "${YELLOW}⚠️ Creating highly deceptive environment with comprehensive monitoring${NC}\n"

# ========================
# 🔍 Pre-Flight Checks
# ========================
echo -e "${GREEN}[+] Verifying system requirements...${NC}"

# Check if running as root
if [ "$(id -u)" -eq 0 ]; then
  echo -e "${RED}❌ Error: This script should not be run as root${NC}"
  exit 1
fi

# Check dependencies
declare -A REQUIRED_DEPS=(
  [wget]="wget"
  [curl]="curl"
  [git]="git"
  [python3]="python3"
  [pip3]="python3-pip"
  [iptables]="iptables"
  [proot]="proot"
  [tcpdump]="tcpdump"
  [auditctl]="auditd"
  [fail2ban-client]="fail2ban"
  [jq]="jq"
)

MISSING_DEPS=0
for cmd in "${!REQUIRED_DEPS[@]}"; do
  if ! command -v "$cmd" &> /dev/null; then
    echo -e "${YELLOW}⚠️ Missing $cmd (package: ${REQUIRED_DEPS[$cmd]})${NC}"
    MISSING_DEPS=1
  fi
done

if [ "$MISSING_DEPS" -eq 1 ]; then
  echo -e "\n${GREEN}[+] Installing missing dependencies...${NC}"
  sudo apt-get update
  sudo apt-get install -y "${REQUIRED_DEPS[@]}" "${MONITORING_TOOLS[@]}"
  sudo pip3 install --upgrade pip
  sudo pip3 install requests geoip2 python-whois
fi

# ========================
# 📁 Filesystem Setup
# ========================
echo -e "\n${GREEN}[+] Creating directory structure...${NC}"
mkdir -p "$PROOT_ROOT" "$LOG_DIR" "$TRAP_DIR" "$PROOT_ROOT/var/www/html" \
         "$PROOT_ROOT/etc/nginx" "$PROOT_ROOT/var/lib/mysql" \
         "$PROOT_ROOT/etc/redis" "$PROOT_ROOT/var/lib/redis" \
         "$PROOT_ROOT/etc/audit" "$PROOT_ROOT/var/log/audit" \
         "$PROOT_ROOT/var/spool/mail" "$PROOT_ROOT/var/log/apache2" \
         "$FAKE_DOCUMENTS_DIR" "$PROOT_ROOT/var/lib/postgresql" \
         "$PROOT_ROOT/opt" "$PROOT_ROOT/tmp/.hidden"

# ========================
# 🖼️ Ubuntu RootFS Setup
# ========================
echo -e "\n${GREEN}[+] Setting up Ubuntu rootfs with proot-distro...${NC}"

if ! command -v proot-distro &> /dev/null; then
  echo -e "${YELLOW}⏳ Installing proot-distro...${NC}"
  wget -q "$PROOT_DISTRO_URL" -O /tmp/proot-distro.sh
  chmod +x /tmp/proot-distro.sh
  sudo mv /tmp/proot-distro.sh /usr/local/bin/proot-distro
fi

if [ ! -d "$PROOT_ROOT/etc" ]; then
  echo -e "${YELLOW}⏳ Installing Ubuntu $UBUNTU_VERSION...${NC}"
  proot-distro install ubuntu-$UBUNTU_VERSION --path "$PROOT_ROOT"
fi

# ========================
# 🌐 Network Configuration
# ========================
echo -e "\n${GREEN}[+] Configuring network settings...${NC}"

# Enhanced network interfaces configuration
cat > "$PROOT_ROOT/etc/network/interfaces" << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet static
    address ${NETWORK_CONFIG[0]%/*}
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4
    dns-search example.com

# Secondary network interface
auto eth1
iface eth1 inet static
    address ${NETWORK_CONFIG[1]%/*}
    netmask 255.255.255.0
    mtu 9000

# VLAN interface
auto eth0.100
iface eth0.100 inet static
    address 192.168.100.100
    netmask 255.255.255.0
    vlan-raw-device eth0
EOF

# Enhanced hosts file with more entries
cat > "$PROOT_ROOT/etc/hosts" << EOF
127.0.0.1       localhost
${NETWORK_CONFIG[0]%/*}   ubuntu-server production-server
${NETWORK_CONFIG[1]%/*}   ubuntu-server-backup

# Development servers
192.168.1.101   dev-server-1
192.168.1.102   dev-server-2
192.168.1.103   staging-server
192.168.1.104   ci-server

# Database servers
10.0.0.101      db-master
10.0.0.102      db-replica-1
10.0.0.103      db-replica-2

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

# Configure hostname
echo "production-server" > "$PROOT_ROOT/etc/hostname"

# Create fake ARP entries
echo -e "${YELLOW}⏳ Creating fake ARP entries...${NC}"
cat > "$PROOT_ROOT/etc/ethers" << EOF
# Fake MAC addresses for deception
00:16:3e:01:23:45 192.168.1.101
00:16:3e:67:89:ab 192.168.1.102
00:16:3e:cd:ef:01 192.168.1.103
EOF

# ========================
# 🛡️ Security Monitoring Setup
# ========================
echo -e "\n${GREEN}[+] Configuring security monitoring...${NC}"

# Enhanced auditd configuration
cat > "$PROOT_ROOT/etc/audit/audit.rules" << EOF
# Log all system calls
-a always,exit -F arch=b64 -S all -F path=/bin -F perm=x -k binaries
-a always,exit -F arch=b32 -S all -F path=/bin -F perm=x -k binaries

# Monitor file changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor system files
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/nginx/nginx.conf -p wa -k nginx_config
-w /etc/mysql/my.cnf -p wa -k mysql_config
-w /etc/redis/redis.conf -p wa -k redis_config
-w /etc/postgresql/ -p wa -k postgres_config

# Monitor log files
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/syslog -p wa -k syslog
-w /var/log/nginx/access.log -p wa -k nginx_log
-w /var/log/mysql/error.log -p wa -k mysql_log

# Monitor processes
-w /bin/kill -p x -k process_control
-w /bin/killall -p x -k process_control
-w /bin/nc -p x -k netcat
-w /bin/netcat -p x -k netcat

# Monitor network configuration changes
-w /etc/network/interfaces -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/hosts -p wa -k network_config

# Monitor cron jobs
-w /etc/crontab -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
EOF

# Enhanced fail2ban configuration
mkdir -p "$PROOT_ROOT/etc/fail2ban"
cat > "$PROOT_ROOT/etc/fail2ban/jail.local" << EOF
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

[nginx-botsearch]
enabled = true
port = 80,443
filter = nginx-botsearch
logpath = /var/log/nginx/access.log
maxretry = 5
bantime = 86400

[nginx-http-auth]
enabled = true
port = 80,443
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

[mysql-auth]
enabled = true
port = 3306
filter = mysql-auth
logpath = /var/log/mysql/error.log
maxretry = 3
bantime = 86400

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 604800
findtime = 86400
maxretry = 3
EOF

# Install monitoring tools in Proot environment
echo -e "${YELLOW}⏳ Installing monitoring tools in Proot environment...${NC}"
proot -S "$PROOT_ROOT" apt update
proot -S "$PROOT_ROOT" apt install -y "${MONITORING_TOOLS[@]}"
proot -S "$PROOT_ROOT" systemctl enable auditd
proot -S "$PROOT_ROOT" systemctl enable fail2ban
proot -S "$PROOT_ROOT" systemctl enable tripwire
proot -S "$PROOT_ROOT" systemctl enable aide

# ========================
# 🎭 Enhanced Deceptive Environment
# ========================
echo -e "\n${GREEN}[+] Configuring enhanced deceptive environment...${NC}"

# Generate comprehensive fake credentials
echo -e "${YELLOW}⏳ Generating fake credentials...${NC}"
cat > "$FAKE_CREDS_FILE" << EOF
# Fake Credentials - DO NOT USE IN PRODUCTION

# System Accounts
- root:ubuntu123
- admin:admin@123
- backup:backup$((RANDOM%1000))
- mysql:mysql_$(openssl rand -hex 6)
- postgres:postgres_$(date +%s)

# Database Credentials
MySQL:
- root:mysql_root_$(openssl rand -hex 8)
- wp_user:wp_$(openssl rand -hex 10)
- dbadmin:admin_$(date +%Y%m%d)

PostgreSQL:
- postgres:postgres_$(openssl rand -hex 6)
- db_user:user_$(date +%s)
- replica_user:replica_$(openssl rand -hex 8)

MongoDB:
- admin:admin_$(openssl rand -hex 6)
- user:user_$(date +%m%d)

Redis:
- default:redis_$(openssl rand -hex 8)

# Web Apps:
- WordPress Admin: wpadmin / Wp@$(date +%Y)!
- phpMyAdmin: pma / $(openssl rand -base64 12)
- Joomla Admin: joomla / Joomla$(date +%m)!
- Drupal Admin: drupal / Drupal$(date +%d)!
- Jenkins: jenkins / Jenkins$(date +%m%d)!
- GitLab: root / $(openssl rand -base64 16)

# FTP Accounts:
- ftpuser:ftp_$(openssl rand -hex 6)
- upload:upload_$(date +%s)
- deploy:deploy_$(openssl rand -hex 8)

# SSH Keys:
- Deployment Key: $(openssl rand -hex 32)
- Backup Key: $(openssl rand -hex 32)

# API Keys:
- AWS Access Key: AKIA$(openssl rand -hex 20 | head -c 20)
- AWS Secret Key: $(openssl rand -base64 40 | head -c 40)
- Stripe API Key: sk_live_$(openssl rand -hex 12)
- Slack Token: xoxb-$(openssl rand -hex 20)
EOF

# Create fake documents
echo -e "${YELLOW}⏳ Generating fake documents...${NC}"
mkdir -p "$FAKE_DOCUMENTS_DIR"
cat > "$FAKE_DOCUMENTS_DIR/employee_salaries.xlsx.txt" << EOF
Employee ID,Name,Position,Salary,Bonus
1001,John Doe,CEO,250000,50000
1002,Jane Smith,CTO,220000,45000
1003,Bob Johnson,CFO,210000,40000
1004,Alice Brown,Director,180000,30000
EOF

cat > "$FAKE_DOCUMENTS_DIR/backup_passwords.txt" << EOF
# Emergency Backup Passwords (Do Not Share!)

Database Master Password: DB_$(openssl rand -hex 12)
SSH Root Password: Root_$(openssl rand -hex 8)
VPN Credentials: vpn_$(openssl rand -hex 10)
EOF

cat > "$FAKE_DOCUMENTS_DIR/network_diagram.pdf.txt" << EOF
NETWORK DIAGRAM - CONFIDENTIAL

Internal Network:
- 192.168.1.0/24: Production Servers
- 10.0.0.0/16: Database Cluster
- 172.16.0.0/24: Development Environment

Firewall Rules:
- Allow SSH from 203.0.113.0/24
- Allow RDP from 198.51.100.0/24
EOF

# Enhanced /etc/passwd with more realistic users
echo -e "${YELLOW}⏳ Configuring system users...${NC}"
{
echo "root:x:0:0:root:/root:/bin/bash"
echo "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
echo "bin:x:2:2:bin:/bin:/usr/sbin/nologin"
echo "sys:x:3:3:sys:/dev:/usr/sbin/nologin"
echo "sync:x:4:65534:sync:/bin:/bin/sync"
echo "games:x:5:60:games:/usr/games:/usr/sbin/nologin"
echo "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin"
echo "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin"
echo "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin"
echo "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin"
echo "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin"
echo "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin"
echo "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
echo "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin"
echo "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin"
echo "irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin"
echo "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin"
echo "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"
echo "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin"
echo "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin"
echo "systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin"
echo "messagebus:x:103:106::/nonexistent:/usr/sbin/nologin"
echo "syslog:x:104:110::/home/syslog:/usr/sbin/nologin"
echo "_apt:x:105:65534::/nonexistent:/usr/sbin/nologin"
echo "tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false"
echo "uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin"
echo "tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin"
echo "landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin"
echo "pollinate:x:110:1::/var/cache/pollinate:/bin/false"
echo "sshd:x:111:65534::/run/sshd:/usr/sbin/nologin"
echo "systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin"

# Add deception users
for i in "${!DECEPTION_USERS[@]}"; do
  uid=$((1000 + i))
  echo "${DECEPTION_USERS[$i]}:x:$uid:$uid:${DECEPTION_USERS[$i]} User,,,:/home/${DECEPTION_USERS[$i]}:/bin/bash"
done

# Add service accounts
echo "mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false"
echo "redis:x:113:119::/var/lib/redis:/usr/sbin/nologin"
echo "postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash"
echo "ftp:x:115:121:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin"
echo "tomcat:x:116:122:Apache Tomcat,,,:/usr/share/tomcat9:/bin/false"
echo "jenkins:x:117:123:Jenkins CI,,,:/var/lib/jenkins:/bin/bash"
} > "$PROOT_ROOT/etc/passwd"

# Realistic /etc/shadow with hashed passwords
echo -e "${YELLOW}⏳ Configuring password hashes...${NC}"
{
echo "root:\$6\$rounds=50000\$J5J9VbNTrkSoH9N2\$XjWj8JbZ/6LJf7h5YQ7WY1X5Z8X9Qe8WY1X5Z8X9Qe8WY1X5Z8X9Qe:19185:0:99999:7:::"
echo "daemon:*:19185:0:99999:7:::"
echo "bin:*:19185:0:99999:7:::"
echo "sys:*:19185:0:99999:7:::"
echo "sync:*:19185:0:99999:7:::"
echo "games:*:19185:0:99999:7:::"
echo "man:*:19185:0:99999:7:::"
echo "lp:*:19185:0:99999:7:::"
echo "mail:*:19185:0:99999:7:::"
echo "news:*:19185:0:99999:7:::"
echo "uucp:*:19185:0:99999:7:::"
echo "proxy:*:19185:0:99999:7:::"
echo "www-data:*:19185:0:99999:7:::"
echo "backup:*:19185:0:99999:7:::"
echo "list:*:19185:0:99999:7:::"
echo "irc:*:19185:0:99999:7:::"
echo "gnats:*:19185:0:99999:7:::"
echo "nobody:*:19185:0:99999:7:::"
echo "systemd-network:*:19185:0:99999:7:::"
echo "systemd-resolve:*:19185:0:99999:7:::"
echo "systemd-timesync:*:19185:0:99999:7:::"
echo "messagebus:*:19185:0:99999:7:::"
echo "syslog:*:19185:0:99999:7:::"
echo "_apt:*:19185:0:99999:7:::"
echo "tss:*:19185:0:99999:7:::"
echo "uuidd:*:19185:0:99999:7:::"
echo "tcpdump:*:19185:0:99999:7:::"
echo "landscape:*:19185:0:99999:7:::"
echo "pollinate:*:19185:0:99999:7:::"
echo "sshd:*:19185:0:99999:7:::"
echo "systemd-coredump:!!:19185::::::"

# Add deception users with weak hashes
for user in "${DECEPTION_USERS[@]}"; do
  echo "$user:\$6\$rounds=50000\$J5J9VbNTrkSoH9N2\$XjWj8JbZ/6LJf7h5YQ7WY1X5Z8X9Qe8WY1X5Z8X9Qe8WY1X5Z8X9Qe:19185:0:99999:7:::"
done

# Add service accounts
echo "mysql:!:19185:0:99999:7:::"
echo "redis:*:19185:0:99999:7:::"
echo "postgres:\$6\$rounds=50000\$J5J9VbNTrkSoH9N2\$XjWj8JbZ/6LJf7h5YQ7WY1X5Z8X9Qe8WY1X5Z8X9Qe8WY1X5Z8X9Qe:19185:0:99999:7:::"
echo "ftp:*:19185:0:99999:7:::"
echo "tomcat:!:19185:0:99999:7:::"
echo "jenkins:\$6\$rounds=50000\$J5J9VbNTrkSoH9N2\$XjWj8JbZ/6LJf7h5YQ7WY1X5Z8X9Qe8WY1X5Z8X9Qe8WY1X5Z8X9Qe:19185:0:99999:7:::"
} > "$PROOT_ROOT/etc/shadow"

# Create home directories and realistic contents
echo -e "${YELLOW}⏳ Setting up home directories...${NC}"
for user in "${DECEPTION_USERS[@]}"; do
  mkdir -p "$PROOT_ROOT/home/$user"
  chown -R $((1000 + ${#DECEPTION_USERS[@]})):$((1000 + ${#DECEPTION_USERS[@]})) "$PROOT_ROOT/home/$user"
  
  # Create realistic files in each home directory
  cat > "$PROOT_ROOT/home/$user/.bashrc" << EOF
# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case \$- in
    *i*) ;;
      *) return;;
esac

# History settings
HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=2000

# Aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias alert='notify-send --urgency=low -i "\$([ \$? = 0 ] && echo terminal || echo error)" "\$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert\$//'\'')"'

# Environment variables
export EDITOR=vim
export PATH="\$PATH:\$HOME/bin"
EOF

  # Create fake SSH keys
  mkdir -p "$PROOT_ROOT/home/$user/.ssh"
  ssh-keygen -t rsa -b 2048 -f "$PROOT_ROOT/home/$user/.ssh/id_rsa" -N "" -q
  cat "$PROOT_ROOT/home/$user/.ssh/id_rsa.pub" > "$PROOT_ROOT/home/$user/.ssh/authorized_keys"
  chmod 700 "$PROOT_ROOT/home/$user/.ssh"
  chmod 600 "$PROOT_ROOT/home/$user/.ssh/id_rsa"
  chmod 644 "$PROOT_ROOT/home/$user/.ssh/id_rsa.pub"
  chmod 644 "$PROOT_ROOT/home/$user/.ssh/authorized_keys"
  chown -R $((1000 + ${#DECEPTION_USERS[@]})):$((1000 + ${#DECEPTION_USERS[@]})) "$PROOT_ROOT/home/$user/.ssh"
done

# Create service account home directories
mkdir -p "$PROOT_ROOT/root" "$PROOT_ROOT/var/lib/postgresql" \
         "$PROOT_ROOT/srv/ftp" "$PROOT_ROOT/var/lib/jenkins" \
         "$PROOT_ROOT/usr/share/tomcat9"

chown -R 0:0 "$PROOT_ROOT/root"
chown -R 114:120 "$PROOT_ROOT/var/lib/postgresql"
chown -R 115:121 "$PROOT_ROOT/srv/ftp"
chown -R 117:123 "$PROOT_ROOT/var/lib/jenkins"
chown -R 116:122 "$PROOT_ROOT/usr/share/tomcat9"

# Create realistic mail spool
echo -e "${YELLOW}⏳ Setting up mail spool...${NC}"
for user in root "${DECEPTION_USERS[@]}"; do
  touch "$PROOT_ROOT/var/spool/mail/$user"
  chown "$user":mail "$PROOT_ROOT/var/spool/mail/$user"
done

# Create fake crontabs
echo -e "${YELLOW}⏳ Setting up fake cron jobs...${NC}"
for user in root "${DECEPTION_USERS[@]}"; do
  mkdir -p "$PROOT_ROOT/var/spool/cron/crontabs"
  
  cat > "$PROOT_ROOT/var/spool/cron/crontabs/$user" << EOF
# m h  dom mon dow   command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

# Backup jobs
0 2 * * * /usr/local/bin/backup_db.sh > /var/log/backup.log 2>&1
30 3 * * * /usr/local/bin/cleanup_tmp.sh

# Monitoring jobs
*/5 * * * * /usr/local/bin/check_disk_space.sh
EOF

  chown "$user":crontab "$PROOT_ROOT/var/spool/cron/crontabs/$user"
  chmod 600 "$PROOT_ROOT/var/spool/cron/crontabs/$user"
done

# Create fake backup scripts
mkdir -p "$PROOT_ROOT/usr/local/bin"
cat > "$PROOT_ROOT/usr/local/bin/backup_db.sh" << EOF
#!/bin/bash
# Database backup script

TIMESTAMP=\$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/mysql"
MYSQL_USER="backup_user"
MYSQL_PASS="backup_\$(date +%m%d)"

mkdir -p "\$BACKUP_DIR"
mysqldump -u\$MYSQL_USER -p\$MYSQL_PASS --all-databases | gzip > "\$BACKUP_DIR/full_backup_\$TIMESTAMP.sql.gz"

# Keep only last 7 backups
find "\$BACKUP_DIR" -name "full_backup_*.sql.gz" -type f -mtime +7 -delete
EOF

cat > "$PROOT_ROOT/usr/local/bin/cleanup_tmp.sh" << EOF
#!/bin/bash
# Temporary files cleanup script

find /tmp -type f -mtime +2 -delete
find /var/tmp -type f -mtime +7 -delete
EOF

chmod +x "$PROOT_ROOT/usr/local/bin/backup_db.sh"
chmod +x "$PROOT_ROOT/usr/local/bin/cleanup_tmp.sh"

# ========================
# 🛠️ Enhanced Vulnerable Services
# ========================
echo -e "\n${GREEN}[+] Configuring enhanced vulnerable services...${NC}"

# Install Ubuntu packages in Proot environment
echo -e "${YELLOW}⏳ Installing vulnerable services...${NC}"
proot -S "$PROOT_ROOT" apt update
proot -S "$PROOT_ROOT" apt install -y "${VULN_SERVICES[@]}"
proot -S "$PROOT_ROOT" apt install -y php-fpm php-mysql php-curl php-gd php-mbstring php-xml php-xmlrpc

# Configure vulnerable SSH with weak ciphers
echo -e "${YELLOW}⏳ Configuring vulnerable SSH...${NC}"
cat > "$PROOT_ROOT/etc/ssh/sshd_config" << EOF
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding no
PrintMotd yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Vulnerable configurations
KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1
Ciphers aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc
MACs hmac-sha1,hmac-sha1-96
EOF

# Generate weak SSH host keys
echo -e "${YELLOW}⏳ Generating weak SSH host keys...${NC}"
proot -S "$PROOT_ROOT" ssh-keygen -t rsa -b 1024 -f "/etc/ssh/ssh_host_rsa_key" -N "" -q
proot -S "$PROOT_ROOT" ssh-keygen -t ecdsa -b 256 -f "/etc/ssh/ssh_host_ecdsa_key" -N "" -q
proot -S "$PROOT_ROOT" ssh-keygen -t ed25519 -f "/etc/ssh/ssh_host_ed25519_key" -N "" -q

# Enhanced realistic bash history
echo -e "${YELLOW}⏳ Generating realistic command history...${NC}"
cat > "$PROOT_ROOT/root/.bash_history" << EOF
apt update
apt upgrade -y
apt install nginx mysql-server redis-server postgresql vsftpd
systemctl start nginx
systemctl start mysql
mysql_secure_installation
nano /etc/nginx/nginx.conf
systemctl restart nginx
cd /var/www/html
wget https://wordpress.org/latest.tar.gz
tar xzvf latest.tar.gz
mv wordpress/* .
rm -rf wordpress latest.tar.gz
chown -R www-data:www-data /var/www/html
mysql -u root -p
CREATE DATABASE wordpress;
CREATE USER 'wp_user'@'localhost' IDENTIFIED BY 'password123';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wp_user'@'localhost';
FLUSH PRIVILEGES;
exit
vim /var/www/html/wp-config.php
exit
EOF

cat > "$PROOT_ROOT/home/admin/.bash_history" << EOF
ls -la
cd /var/www/html
sudo apt install git
git clone https://github.com/example/project.git
cd project
npm install
vim config.js
sudo systemctl status nginx
sudo tail -f /var/log/nginx/error.log
exit
EOF

cat > "$PROOT_ROOT/home/developer/.bash_history" << EOF
cd /var/www/html
vim index.php
php -S localhost:8000
git pull origin master
composer install
exit
EOF

# Configure vulnerable nginx with multiple sites
echo -e "${YELLOW}⏳ Setting up vulnerable web server...${NC}"
mkdir -p "$PROOT_ROOT/etc/nginx/sites-available" "$PROOT_ROOT/etc/nginx/sites-enabled"

# Main nginx config
cat > "$PROOT_ROOT/etc/nginx/nginx.conf" << EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    gzip on;
    gzip_disable "msie6";
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Default site
cat > "$PROOT_ROOT/etc/nginx/sites-available/default" << EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    root /var/www/html;
    index index.php index.html index.htm;
    
    server_name _;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Vulnerable configs
    autoindex on;
    disable_symlinks off;
    client_max_body_size 100M;
    location ~* \.(env|ini|conf|sql|log)$ {
        deny all;
    }
}
EOF

# Admin portal site
cat > "$PROOT_ROOT/etc/nginx/sites-available/admin" << EOF
server {
    listen 8080;
    server_name admin.internal;
    
    root /var/www/admin;
    index index.php;
    
    auth_basic "Admin Portal";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Vulnerable config
    location /backups {
        alias /var/backups;
        autoindex on;
    }
}
EOF

ln -s "$PROOT_ROOT/etc/nginx/sites-available/default" "$PROOT_ROOT/etc/nginx/sites-enabled/default"
ln -s "$PROOT_ROOT/etc/nginx/sites-available/admin" "$PROOT_ROOT/etc/nginx/sites-enabled/admin"

# Create fake admin portal
mkdir -p "$PROOT_ROOT/var/www/admin"
cat > "$PROOT_ROOT/var/www/admin/index.php" << EOF
<?php
// Fake admin portal with vulnerabilities
if (!isset(\$_SERVER['PHP_AUTH_USER'])) {
    header('WWW-Authenticate: Basic realm="Admin Portal"');
    header('HTTP/1.0 401 Unauthorized');
    echo 'Authentication Required';
    exit;
}

\$valid_users = ['admin' => 'admin123', 'superuser' => 'super123'];

if (!isset(\$valid_users[\$_SERVER['PHP_AUTH_USER']]) || 
    \$valid_users[\$_SERVER['PHP_AUTH_USER']] != \$_SERVER['PHP_AUTH_PW']) {
    header('HTTP/1.0 403 Forbidden');
    echo 'Access Denied';
    exit;
}

// Command injection vulnerability
if (isset(\$_GET['cmd'])) {
    echo "<pre>" . shell_exec(\$_GET['cmd']) . "</pre>";
}

// File inclusion vulnerability
if (isset(\$_GET['file'])) {
    include(\$_GET['file']);
}

echo "<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
    <style>body { font-family: Arial; }</style>
</head>
<body>
    <h1>Welcome to Admin Portal</h1>
    <p>Server Status: <strong>Online</strong></p>
    
    <h2>System Information</h2>
    <pre>" . shell_exec('uname -a') . "</pre>
    
    <h2>Disk Usage</h2>
    <pre>" . shell_exec('df -h') . "</pre>
    
    <h2>Recent Logs</h2>
    <pre>" . shell_exec('tail -n 20 /var/log/nginx/access.log') . "</pre>
</body>
</html>";
EOF

# Create fake .htpasswd file
echo 'admin:$apr1$9Cv7OMGs$X7J4Vz8zUZvQ4ZQz9XQwH/' > "$PROOT_ROOT/etc/nginx/.htpasswd"

# Create fake WordPress site with more vulnerabilities
echo -e "${YELLOW}⏳ Creating fake web content...${NC}"
mkdir -p "$PROOT_ROOT/var/www/html/wp-admin" "$PROOT_ROOT/var/www/html/wp-content/uploads" \
         "$PROOT_ROOT/var/www/html/wp-includes" "$PROOT_ROOT/var/www/html/vendor"

# Main index.php with multiple vulnerabilities
cat > "$PROOT_ROOT/var/www/html/index.php" << EOF
<?php
// Fake WordPress with vulnerable components
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', true);

// Insecure credentials
\$db_config = [
    'name' => 'wordpress_db',
    'user' => 'wp_user',
    'password' => 'wp_password_123',
    'host' => 'localhost',
    'charset' => 'utf8'
];

// Vulnerable function (SQLi example)
function vulnerable_search(\$query) {
    global \$wpdb;
    return \$wpdb->get_results("SELECT * FROM posts WHERE post_content LIKE '%\$query%'");
}

// XSS example
function display_search_results(\$results) {
    foreach (\$results as \$result) {
        echo "<div class='result'>" . \$result->post_content . "</div>";
    }
}

// Command injection vulnerability
function ping_host(\$host) {
    system("ping -c 4 " . \$host);
}

// File inclusion vulnerability
function load_template(\$template) {
    include(\$template);
}

// Fake admin login
if (isset(\$_POST['login'])) {
    \$username = \$_POST['username'];
    \$password = \$_POST['password'];
    
    if (\$username === 'admin' && \$password === 'admin123') {
        // Successful login (but insecure)
        header('Location: /wp-admin/admin.php');
    }
}

// Check for command injection
if (isset(\$_GET['cmd'])) {
    echo "<pre>" . shell_exec(\$_GET['cmd']) . "</pre>";
}

// Check for file inclusion
if (isset(\$_GET['file'])) {
    load_template(\$_GET['file']);
}

echo "<!DOCTYPE html>
<html>
<head>
    <title>WordPress Site</title>
    <style>body { font-family: Arial; }</style>
</head>
<body>
    <h1>Welcome to WordPress</h1>
    <form method='POST'>
        <input name='username' placeholder='Username'>
        <input name='password' type='password' placeholder='Password'>
        <button name='login'>Log In</button>
    </form>
    <!-- Vulnerable search form -->
    <form method='GET'>
        <input name='s' placeholder='Search...'>
        <button>Search</button>
    </form>
</body>
</html>";

// Process search
if (isset(\$_GET['s'])) {
    \$results = vulnerable_search(\$_GET['s']);
    display_search_results(\$results);
}

// Process ping
if (isset(\$_GET['ping'])) {
    ping_host(\$_GET['ping']);
}
EOF

# Create additional vulnerable files
cat > "$PROOT_ROOT/var/www/html/wp-config.php" << EOF
<?php
define('DB_NAME', 'wordpress_db');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'wp_password_123');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');

define('AUTH_KEY',         '$(openssl rand -base64 32)');
define('SECURE_AUTH_KEY',  '$(openssl rand -base64 32)');
define('LOGGED_IN_KEY',    '$(openssl rand -base64 32)');
define('NONCE_KEY',        '$(openssl rand -base64 32)');
define('AUTH_SALT',        '$(openssl rand -base64 32)');
define('SECURE_AUTH_SALT', '$(openssl rand -base64 32)');
define('LOGGED_IN_SALT',   '$(openssl rand -base64 32)');
define('NONCE_SALT',       '$(openssl rand -base64 32)');

\$table_prefix = 'wp_';
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', true);

if (!defined('ABSPATH'))
    define('ABSPATH', dirname(__FILE__) . '/');

require_once(ABSPATH . 'wp-settings.php');
EOF

# Create fake wp-admin directory
cat > "$PROOT_ROOT/var/www/html/wp-admin/index.php" << EOF
<?php
require_once('../../wp-config.php');
echo "<h1>WordPress Admin</h1>";
echo "<p>Welcome to the WordPress admin panel</p>";

if (isset(\$_POST['action'])) {
    switch (\$_POST['action']) {
        case 'update':
            echo "<pre>" . shell_exec('git pull origin master') . "</pre>";
            break;
        case 'clear_cache':
            echo "<pre>" . shell_exec('rm -rf /var/cache/*') . "</pre>";
            break;
    }
}

echo "<form method='POST'>
    <select name='action'>
        <option value='update'>Update System</option>
        <option value='clear_cache'>Clear Cache</option>
    </select>
    <button>Execute</button>
</form>";
EOF

# Configure vulnerable MySQL with weak settings
echo -e "${YELLOW}⏳ Setting up vulnerable database...${NC}"
cat > "$PROOT_ROOT/etc/mysql/mysql.conf.d/mysqld.cnf" << EOF
[mysqld]
user = mysql
pid-file = /var/run/mysqld/mysqld.pid
socket = /var/run/mysqld/mysqld.sock
port = 3306
basedir = /usr
datadir = /var/lib/mysql
tmpdir = /tmp
lc-messages-dir = /usr/share/mysql
skip-external-locking
bind-address = 0.0.0.0
key_buffer_size = 16M
max_allowed_packet = 16M
thread_stack = 192K
thread_cache_size = 8
myisam-recover-options = BACKUP
query_cache_limit = 1M
query_cache_size = 16M
log_error = /var/log/mysql/error.log
expire_logs_days = 10
max_binlog_size = 100M

# Vulnerable configurations
secure-file-priv = ""
local-infile = 1
skip-name-resolve
skip-grant-tables
log-raw = 1
general_log = 1
general_log_file = /var/log/mysql/mysql.log
EOF

# Initialize MySQL with fake data
echo -e "${YELLOW}⏳ Initializing MySQL with fake data...${NC}"
proot -S "$PROOT_ROOT" service mysql start

# Create databases and users
proot -S "$PROOT_ROOT" mysql -e "CREATE DATABASE wordpress;"
proot -S "$PROOT_ROOT" mysql -e "CREATE USER 'wp_user'@'localhost' IDENTIFIED BY 'wp_password_123';"
proot -S "$PROOT_ROOT" mysql -e "GRANT ALL PRIVILEGES ON wordpress.* TO 'wp_user'@'localhost';"
proot -S "$PROOT_ROOT" mysql -e "FLUSH PRIVILEGES;"

# Create tables and insert fake data
proot -S "$PROOT_ROOT" mysql wordpress << EOF
CREATE TABLE wp_users (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    user_login VARCHAR(60) NOT NULL,
    user_pass VARCHAR(255) NOT NULL,
    user_nicename VARCHAR(50) NOT NULL,
    user_email VARCHAR(100) NOT NULL,
    user_registered DATETIME NOT NULL,
    user_status INT NOT NULL,
    display_name VARCHAR(250) NOT NULL
);

CREATE TABLE wp_posts (
    ID BIGINT AUTO_INCREMENT PRIMARY KEY,
    post_author BIGINT NOT NULL,
    post_date DATETIME NOT NULL,
    post_content LONGTEXT NOT NULL,
    post_title TEXT NOT NULL,
    post_excerpt TEXT NOT NULL,
    post_status VARCHAR(20) NOT NULL,
    comment_status VARCHAR(20) NOT NULL,
    ping_status VARCHAR(20) NOT NULL,
    post_name VARCHAR(200) NOT NULL,
    post_modified DATETIME NOT NULL,
    post_type VARCHAR(20) NOT NULL
);

INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_registered, user_status, display_name) VALUES
('admin', '\$P\$B4r3lYbLbLbLbLbLbLbLbLbLbLbL', 'admin', 'admin@example.com', NOW(), 0, 'Administrator'),
('editor', '\$P\$B4r3lYbLbLbLbLbLbLbLbLbLbL', 'editor', 'editor@example.com', NOW(), 0, 'Editor'),
('author', '\$P\$B4r3lYbLbLbLbLbLbLbLbLbLbL', 'author', 'author@example.com', NOW(), 0, 'Author');

INSERT INTO wp_posts (post_author, post_date, post_content, post_title, post_excerpt, post_status, comment_status, ping_status, post_name, post_modified, post_type) VALUES
(1, NOW(), 'Welcome to WordPress. This is your first post. Edit or delete it, then start writing!', 'Hello world!', '', 'publish', 'open', 'open', 'hello-world', NOW(), 'post'),
(1, NOW(), 'This is an example page. It's different from a blog post because it will stay in one place and will show up in your site navigation (in most themes).', 'Sample Page', '', 'publish', 'closed', 'closed', 'sample-page', NOW(), 'page');
EOF

proot -S "$PROOT_ROOT" service mysql stop

# Configure vulnerable Redis with weak settings
echo -e "${YELLOW}⏳ Setting up vulnerable cache server...${NC}"
cat > "$PROOT_ROOT/etc/redis/redis.conf" << EOF
bind 0.0.0.0
protected-mode no
port 6379
tcp-backlog 511
timeout 0
tcp-keepalive 300
daemonize yes
supervised no
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error no
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis
requirepass redis123

# Vulnerable configurations
rename-command FLUSHALL ""
rename-command CONFIG ""
rename-command SHUTDOWN ""
rename-command BGSAVE ""
rename-command SAVE ""
EOF

# Configure vulnerable FTP server
echo -e "${YELLOW}⏳ Setting up vulnerable FTP server...${NC}"
cat > "$PROOT_ROOT/etc/vsftpd.conf" << EOF
listen=YES
anonymous_enable=YES
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO

# Vulnerable configurations
anon_root=/srv/ftp
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
no_anon_password=YES
EOF

# Configure vulnerable Apache
echo -e "${YELLOW}⏳ Setting up vulnerable Apache...${NC}"
cat > "$PROOT_ROOT/etc/apache2/sites-available/000-default.conf" << EOF
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html

    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined

    # Vulnerable configurations
    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    # Server-status exposed
    <Location /server-status>
        SetHandler server-status
        Require all granted
    </Location>
</VirtualHost>
EOF

# Configure vulnerable Tomcat
echo -e "${YELLOW}⏳ Setting up vulnerable Tomcat...${NC}"
cat > "$PROOT_ROOT/etc/tomcat9/server.xml" << EOF
<?xml version='1.0' encoding='utf-8'?>
<Server port="8005" shutdown="SHUTDOWN">
  <Listener className="org.apache.catalina.startup.VersionLoggerListener" />
  <Listener className="org.apache.catalina.core.AprLifecycleListener" SSLEngine="on" />
  <Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener" />
  <Listener className="org.apache.catalina.mbeans.GlobalResourcesLifecycleListener" />
  <Listener className="org.apache.catalina.core.ThreadLocalLeakPreventionListener" />

  <GlobalNamingResources>
    <Resource name="UserDatabase" auth="Container"
              type="org.apache.catalina.UserDatabase"
              description="User database that can be updated and saved"
              factory="org.apache.catalina.users.MemoryUserDatabaseFactory"
              pathname="conf/tomcat-users.xml" />
  </GlobalNamingResources>

  <Service name="Catalina">
    <Connector port="8080" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443" />
               
    <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" />

    <Engine name="Catalina" defaultHost="localhost">
      <Realm className="org.apache.catalina.realm.LockOutRealm">
        <Realm className="org.apache.catalina.realm.UserDatabaseRealm"
               resourceName="UserDatabase"/>
      </Realm>

      <Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="true">
        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %u %t &quot;%r&quot; %s %b" />
      </Host>
    </Engine>
  </Service>
</Server>
EOF

# Create vulnerable Tomcat users
cat > "$PROOT_ROOT/etc/tomcat9/tomcat-users.xml" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <role rolename="manager-jmx"/>
  <role rolename="manager-status"/>
  <role rolename="admin-gui"/>
  <role rolename="admin-script"/>
  <user username="tomcat" password="tomcat" roles="manager-gui,manager-script,manager-jmx,manager-status,admin-gui,admin-script"/>
</tomcat-users>
EOF

# Create FTP content
echo "This is a fake FTP server with vulnerable configuration" > "$PROOT_ROOT/srv/ftp/README.txt"
echo "Flag: CTF{FTP_ANON_ACCESS_GRANTED}" > "$PROOT_ROOT/srv/ftp/flag.txt"
echo "Backup file: backup_$(date +%Y%m%d).tar.gz" > "$PROOT_ROOT/srv/ftp/backup_list.txt"

# Create fake backups
mkdir -p "$PROOT_ROOT/var/backups"
echo "Fake database backup" | gzip > "$PROOT_ROOT/var/backups/db_backup_$(date +%Y%m%d).sql.gz"
echo "Fake website backup" | gzip > "$PROOT_ROOT/var/backups/web_backup_$(date +%Y%m%d).tar.gz"

# ========================
# 🚀 Final Setup
# ========================
echo -e "\n${GREEN}[+] Finalizing setup...${NC}"

# Create startup script
cat > "$PROOT_ROOT/start_honeypot.sh" << EOF
#!/bin/bash
# Start all vulnerable services
service mysql start
service redis-server start
service nginx start
service apache2 start
service vsftpd start
service tomcat9 start

# Start monitoring
service auditd start
service fail2ban start
service tripwire start
service aide start

# Create fake network connections
nc -l -p 4444 > /dev/null &
nc -l -p 5555 > /dev/null &

# Keep container running
tail -f /dev/null
EOF

chmod +x "$PROOT_ROOT/start_honeypot.sh"

# Create monitoring script
cat > "$TRAP_DIR/trap.py" << EOF
#!/usr/bin/env python3
"""
CANARYTRAP Ultimate Pro - Advanced Honeypot Monitoring System
Author: Security Research Team
Version: 3.0
"""
import os
import sys
import json
import time
import subprocess
from datetime import datetime

# Configuration
PROOT_ROOT = "$PROOT_ROOT"
LOG_DIR = "$LOG_DIR"
MONITOR_INTERVAL = 30

def monitor_services():
    services = ["nginx", "mysql", "redis", "apache2", "vsftpd", "tomcat9"]
    status = {}
    
    for service in services:
        try:
            result = subprocess.run(["proot", "-S", PROOT_ROOT, "service", service, "status"], 
                                  capture_output=True, text=True)
            status[service] = "running" if "active (running)" in result.stdout else "stopped"
        except:
            status[service] = "error"
    
    return status

def check_intrusions():
    # Check for common intrusion signs
    signs = {
        "modified_passwd": os.path.getmtime(f"{PROOT_ROOT}/etc/passwd"),
        "modified_shadow": os.path.getmtime(f"{PROOT_ROOT}/etc/shadow"),
        "ssh_login_attempts": 0,
        "web_shells": 0
    }
    
    # Count SSH login attempts
    try:
        with open(f"{PROOT_ROOT}/var/log/auth.log") as f:
            signs["ssh_login_attempts"] = sum(1 for line in f if "Failed password" in line)
    except:
        pass
    
    # Check for web shells
    web_dirs = ["/var/www/html", "/var/www/admin"]
    for web_dir in web_dirs:
        full_path = f"{PROOT_ROOT}{web_dir}"
        if os.path.exists(full_path):
            for root, _, files in os.walk(full_path):
                for file in files:
                    if file.endswith((".php", ".jsp")):
                        try:
                            with open(os.path.join(root, file)) as f:
                                content = f.read()
                                if any(cmd in content for cmd in ["system(", "exec(", "shell_exec("]):
                                    signs["web_shells"] += 1
                        except:
                            pass
    
    return signs

def log_event(event_type, details):
    timestamp = datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "event_type": event_type,
        "details": details
    }
    
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(f"{LOG_DIR}/honeypot_events.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    print(f"[{timestamp}] {event_type}: {json.dumps(details)}")

def main():
    print("CANARYTRAP Ultimate Pro - Monitoring Started")
    print(f"Monitoring Proot environment at: {PROOT_ROOT}")
    
    while True:
        # Monitor services
        service_status = monitor_services()
        log_event("service_status", service_status)
        
        # Check for intrusions
        intrusion_signs = check_intrusions()
        if any(value > 0 for key, value in intrusion_signs.items() if key in ["ssh_login_attempts", "web_shells"]):
            log_event("intrusion_signs", intrusion_signs)
        
        time.sleep(MONITOR_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nMonitoring stopped")
        sys.exit(0)
EOF

chmod +x "$TRAP_DIR/trap.py"

# Create readme file
cat > "$PROOT_ROOT/README.txt" << EOF
Ubuntu Proot Honeypot - Ultimate Edition
=======================================

This is a highly realistic Ubuntu honeypot environment designed to:
- Attract and detect attackers
- Monitor malicious activities
- Collect threat intelligence

Configuration:
- Ubuntu $UBUNTU_VERSION
- Proot environment at: $PROOT_ROOT
- Logs directory: $LOG_DIR
- Trap directory: $TRAP_DIR

Vulnerable Services:
- SSH (port 22)
- HTTP (ports 80, 8080)
- HTTPS (port 443)
- MySQL (port 3306)
- Redis (port 6379)
- FTP (port 21)
- Apache Tomcat (port 8080)

Monitoring Tools:
- Auditd
- Fail2Ban
- Tripwire
- AIDE
- Custom Python monitoring

Start the honeypot:
./start_honeypot.sh

Start monitoring:
python3 $TRAP_DIR/trap.py

Warning:
This environment contains intentionally vulnerable configurations.
Do not use in production or on internet-accessible hosts.
EOF

echo -e "\n${GREEN}[✓] Honeypot setup complete!${NC}"
echo -e "${YELLOW}To start the honeypot, run: proot -S $PROOT_ROOT /start_honeypot.sh${NC}"
echo -e "${YELLOW}For monitoring, run: python3 $TRAP_DIR/trap.py${NC}"
echo -e "${YELLOW}Access web interfaces at: http://localhost:8080 (admin) and http://localhost:80 (WordPress)${NC}"
