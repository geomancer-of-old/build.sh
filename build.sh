#!/usr/bin/env bash
#
# Script for the "Daily Lighthouse" target
#
#
# Usage:
#   sudo ./build.sh
#
#   This box is INTENTIONALLY VULNERABLE. Never attach it to a security group
#   that allows 0.0.0.0/0. 
#
set -euo pipefail

APP_REPO="${APP_REPO:-https://github.com/geomancer-of-old/daily-lighthouse.git}"
APP_REF="${APP_REF:-main}"                 # branch/tag/commit to pin the AMI to
APP_DIR="/opt/daily-lighthouse"
APP_ENTRY="${APP_ENTRY:-app.py}"           # Flask entrypoint inside the repo
APP_PORT="${APP_PORT:-80}"                 # port the web app listens on
APP_USER="lighthouse"                      # service account for the Flask app

# Deliberately weak lab credentials
LAB_USER="${LAB_USER:-}"
LAB_PASS="${LAB_PASS:-}"
ENABLE_FTP="${ENABLE_FTP:-1}"              # vsftpd w/ anonymous + weak user on 21
ENABLE_SMTP="${ENABLE_SMTP:-1}"            # postfix open-ish relay on 25
ENABLE_WEAK_SSH="${ENABLE_WEAK_SSH:-1}"   # password auth + weak lab user on 22
ENABLE_DB="${ENABLE_DB:-1}"               # MariaDB w/ synthetic corp data on 3306
DB_NAME="${DB_NAME:-lighthouse_corp}"
DB_USER="${DB_USER:-}"                    # prompted below unless preset
DB_PASS="${DB_PASS:-}"                    # prompted below unless preset
DB_NETWORK="${DB_NETWORK:-1}"             # 1 = listen on the subnet (the vuln), 0 = localhost only
ENABLE_PHPMYADMIN="${ENABLE_PHPMYADMIN:-1}"  # phpMyAdmin for managing the corp DB
PMA_PORT="${PMA_PORT:-8080}"              # own port so it doesn't clash with Flask on 80
### ──────────────────────────────────────────────────────────────────────────

log() { printf '\n\033[1;36m[zaio.vuln.vm]\033[0m %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then echo "Run with sudo." >&2; exit 1; fi
export DEBIAN_FRONTEND=noninteractive

# Prompts unless the value is already set in the environment.
prompt_cred() {
  # $1 = var name, $2 = prompt label, $3 = secret? (1=hidden)
  local __var="$1" __label="$2" __secret="${3:-0}" __val __confirm
  if [[ -n "${!__var:-}" ]]; then return; fi   # already provided via env
  while :; do
    if [[ "$__secret" == "1" ]]; then
      read -rs -p "${__label}: " __val < /dev/tty; echo
      read -rs -p "${__label} (confirm): " __confirm < /dev/tty; echo
      if [[ "$__val" != "$__confirm" ]]; then echo "  ✗ Didn't match, try again."; continue; fi
    else
      read -r -p "${__label}: " __val < /dev/tty
    fi
    if [[ -z "$__val" ]]; then echo "  ✗ Cannot be empty."; continue; fi
    printf -v "$__var" '%s' "$__val"; break
  done
}

log "Set the lab credential (used for both SSH and FTP)"
prompt_cred LAB_USER "Lab username" 0
prompt_cred LAB_PASS "Lab password" 1

if [[ "$ENABLE_DB" == "1" ]]; then
  log "Set the database credential (MariaDB app/login user)"
  prompt_cred DB_USER "Database username" 0
  prompt_cred DB_PASS "Database password" 1
fi

log "Installing base packages"
apt-get update -y
apt-get install -y --no-install-recommends \
  git python3 python3-venv python3-pip sqlite3 ca-certificates curl ufw


log "Deploying Daily Lighthouse from ${APP_REPO}@${APP_REF}"
id -u "$APP_USER" &>/dev/null || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"

if [[ -d "$APP_DIR/.git" ]]; then
  git -C "$APP_DIR" fetch --all --quiet && git -C "$APP_DIR" checkout --quiet "$APP_REF" && git -C "$APP_DIR" pull --quiet || true
else
  git clone --quiet "$APP_REPO" "$APP_DIR"
  git -C "$APP_DIR" checkout --quiet "$APP_REF"
fi

python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
if [[ -f "$APP_DIR/requirements.txt" ]]; then
  "$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
else
  "$APP_DIR/.venv/bin/pip" install --quiet flask
fi
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

log "Installing systemd unit for the web app"
cat >/etc/systemd/system/daily-lighthouse.service <<EOF
[Unit]
Description=The Daily Lighthouse (PM-02 vulnerable target)
After=network-online.target
Wants=network-online.target

[Service]
User=${APP_USER}
WorkingDirectory=${APP_DIR}
Environment=FLASK_APP=${APP_ENTRY}
# AmbientCapabilities lets an unprivileged user bind port 80.
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=${APP_DIR}/.venv/bin/python ${APP_ENTRY} --host 0.0.0.0 --port ${APP_PORT}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable daily-lighthouse.service

###  Weak lab user (used by SSH and FTP) 
log "Creating lab user ${LAB_USER}"
id -u "$LAB_USER" &>/dev/null || useradd -m -s /bin/bash "$LAB_USER"
echo "${LAB_USER}:${LAB_PASS}" | chpasswd

###  Corporate database (3306) MariaDB with SYNTHETIC data 
if [[ "$ENABLE_DB" == "1" ]]; then
  log "Installing MariaDB and seeding synthetic corp data into ${DB_NAME}"
  apt-get install -y --no-install-recommends mariadb-server
  systemctl enable mariadb
  systemctl start mariadb

  if [[ "$DB_NETWORK" == "1" ]]; then
    # Deliberate weakness: reachable over the (isolated) subnet, not just localhost.
    sed -ri 's/^#?bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf
    systemctl restart mariadb
  fi

  # All names, ID numbers and account numbers below are FICTIONAL training data.
  mariadb <<SQL
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
USE ${DB_NAME};

CREATE TABLE IF NOT EXISTS employees (
  id INT PRIMARY KEY AUTO_INCREMENT,
  first_name VARCHAR(50), last_name VARCHAR(50),
  national_id VARCHAR(20), email VARCHAR(120),
  department VARCHAR(50), title VARCHAR(60), start_date DATE
);
CREATE TABLE IF NOT EXISTS payroll (
  id INT PRIMARY KEY AUTO_INCREMENT,
  employee_id INT, salary_zar INT,
  bank_name VARCHAR(40), account_number VARCHAR(20), tax_number VARCHAR(20),
  FOREIGN KEY (employee_id) REFERENCES employees(id)
);
-- App/login users with intentionally weak, crackable MD5 hashes.
CREATE TABLE IF NOT EXISTS app_users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(40), password_md5 CHAR(32), role VARCHAR(20)
);

INSERT INTO employees (first_name,last_name,national_id,email,department,title,start_date) VALUES
 ('Thandi','Mokoena','0000010000080','thandi.mokoena@lighthouse.lab','Finance','CFO','2019-03-01'),
 ('Sipho','Dlamini','0000020000081','sipho.dlamini@lighthouse.lab','IT','Sysadmin','2021-07-15'),
 ('Lerato','Khumalo','0000030000082','lerato.khumalo@lighthouse.lab','HR','HR Manager','2020-01-20'),
 ('Johan','Venter','0000040000083','johan.venter@lighthouse.lab','Sales','Sales Lead','2018-11-05'),
 ('Aisha','Patel','0000050000084','aisha.patel@lighthouse.lab','Engineering','Developer','2022-02-28'),
 ('Bongani','Nkosi','0000060000085','bongani.nkosi@lighthouse.lab','Engineering','Developer','2023-06-12'),
 ('Marike','Botha','0000070000086','marike.botha@lighthouse.lab','Finance','Payroll Clerk','2021-09-01'),
 ('David','Naidoo','0000080000087','david.naidoo@lighthouse.lab','IT','Help Desk','2024-01-08');

INSERT INTO payroll (employee_id,salary_zar,bank_name,account_number,tax_number) VALUES
 (1,1850000,'FNB','00010001234','9990010001'),
 (2, 720000,'Capitec','00010002345','9990010002'),
 (3, 680000,'Standard Bank','00010003456','9990010003'),
 (4, 910000,'Absa','00010004567','9990010004'),
 (5, 640000,'Nedbank','00010005678','9990010005'),
 (6, 540000,'Capitec','00010006789','9990010006'),
 (7, 360000,'FNB','00010007890','9990010007'),
 (8, 300000,'TymeBank','00010008901','9990010008');

-- Passwords here are 'password', 'admin', 'letmein', 'sunshine' (MD5) — meant to be cracked.
INSERT INTO app_users (username,password_md5,role) VALUES
 ('admin','21232f297a57a5a743894a0e4a801fc3','admin'),
 ('tmokoena','5f4dcc3b5aa765d61d8327deb882cf99','finance'),
 ('snkosi','0d107d09f5bbe40cade3de5c71e9e9b7','user'),
 ('backup_svc','0571749e2ac330a7455809c6b0e7af90','service');

CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'%'        IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'%';
FLUSH PRIVILEGES;
SQL
  log "Seeded ${DB_NAME}: employees, payroll, app_users (all fictional)"

  ###  phpMyAdmin (on its own port) 
  if [[ "$ENABLE_PHPMYADMIN" == "1" ]]; then
    log "Installing phpMyAdmin on port ${PMA_PORT}"
    # Skip the interactive debconf prompts; no dbconfig control DB needed for a lab.
    debconf-set-selections <<< "phpmyadmin phpmyadmin/dbconfig-install boolean false"
    debconf-set-selections <<< "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2"
    apt-get install -y --no-install-recommends \
      apache2 php libapache2-mod-php php-mysql phpmyadmin

    # Move Apache off 80 (Flask owns it) onto PMA_PORT.
    sed -ri "s/^Listen 80$/Listen ${PMA_PORT}/" /etc/apache2/ports.conf
    sed -ri "s/<VirtualHost \*:80>/<VirtualHost *:${PMA_PORT}>/" /etc/apache2/sites-available/000-default.conf

    a2enconf phpmyadmin >/dev/null 2>&1 || true
    a2enmod php* >/dev/null 2>&1 || true
    systemctl enable apache2
    systemctl restart apache2
    log "phpMyAdmin reachable at http://<box>:${PMA_PORT}/phpmyadmin (log in with ${DB_USER})"
  fi
fi

###  Vulnerable SSH (22) 
if [[ "$ENABLE_WEAK_SSH" == "1" ]]; then
  log "Enabling password SSH auth"
  apt-get install -y --no-install-recommends openssh-server
  sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  mkdir -p /etc/ssh/sshd_config.d
  echo "PasswordAuthentication yes" >/etc/ssh/sshd_config.d/99-pm02.conf
  systemctl enable ssh
fi

###  Vulnerable FTP (21) 
if [[ "$ENABLE_FTP" == "1" ]]; then
  log "Configuring vsftpd (anonymous + local user)"
  apt-get install -y --no-install-recommends vsftpd
  cat >/etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_root=/srv/ftp
no_anon_password=YES
pasv_min_port=40000
pasv_max_port=40100
EOF
  mkdir -p /srv/ftp/pub
  echo "Welcome to the Daily Lighthouse FTP drop." >/srv/ftp/pub/README.txt
  chown -R ftp:ftp /srv/ftp
  systemctl enable vsftpd
fi

### Vulnerable SMTP (25) 
if [[ "$ENABLE_SMTP" == "1" ]]; then
  log "Configuring postfix (local delivery, open on the lab subnet)"
  debconf-set-selections <<< "postfix postfix/mailname string lighthouse.lab"
  debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
  apt-get install -y --no-install-recommends postfix
  postconf -e "inet_interfaces = all"
  postconf -e "mynetworks = 0.0.0.0/0"   # open within the isolated subnet only
  postconf -e "smtpd_banner = lighthouse.lab ESMTP"
  systemctl enable postfix
fi

###  Host firewall (defence-in-depth; SG is the real boundary) 
log "Setting host firewall to expose only lab ports"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "${APP_PORT}/tcp"
[[ "$ENABLE_WEAK_SSH" == "1" ]] && ufw allow 22/tcp
[[ "$ENABLE_FTP" == "1" ]] && { ufw allow 21/tcp; ufw allow 40000:40100/tcp; }
[[ "$ENABLE_SMTP" == "1" ]] && ufw allow 25/tcp
[[ "$ENABLE_DB" == "1" && "$DB_NETWORK" == "1" ]] && ufw allow 3306/tcp
[[ "$ENABLE_DB" == "1" && "$ENABLE_PHPMYADMIN" == "1" ]] && ufw allow "${PMA_PORT}/tcp"
ufw --force enable

### re-seed host identity on each clone 
log "Installing first-boot identity reset (so clones aren't fingerprint-twins)"
cat >/usr/local/sbin/pm02-firstboot.sh <<'EOF'
#!/usr/bin/env bash
set -e
# Regenerate SSH host keys and machine-id once per cloned instance.
rm -f /etc/ssh/ssh_host_*
ssh-keygen -A
rm -f /etc/machine-id /var/lib/dbus/machine-id
systemd-machine-id-setup
ln -sf /etc/machine-id /var/lib/dbus/machine-id
systemctl disable pm02-firstboot.service
EOF
chmod +x /usr/local/sbin/pm02-firstboot.sh
cat >/etc/systemd/system/pm02-firstboot.service <<'EOF'
[Unit]
Description=PM-02 per-clone identity reset
Before=ssh.service
ConditionFirstBoot=no

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/pm02-firstboot.sh

[Install]
WantedBy=multi-user.target
EOF
systemctl enable pm02-firstboot.service

###  Pre-snapshot cleanup 
log "Cleaning logs and caches before you snapshot"
apt-get clean
journalctl --rotate || true
journalctl --vacuum-time=1s || true
find /var/log -type f -exec truncate -s 0 {} \; || true
rm -f /root/.bash_history "/home/${LAB_USER}/.bash_history" || true

cat <<EOF

╭──────────────────────────────────────────────────────────────╮
│  PM-02 Daily Lighthouse target baked.                         │
│                                                              │
│  Verify, then snapshot:                                       │
│    systemctl start daily-lighthouse && curl -sI localhost:${APP_PORT}
│    systemctl status daily-lighthouse vsftpd postfix ssh mariadb
│                                                              │
│  Lab creds:  ${LAB_USER} / ${LAB_PASS}                        │
│  DB login :  ${DB_USER} @ ${DB_NAME} (port 3306)             │
│  phpMyAdmin: http://<box>:${PMA_PORT}/phpmyadmin              │
│                                                              │
│  Then: EC2 → Actions → Image → Create image.                  │
│  Point usurper at the resulting AMI id.                       │
╰──────────────────────────────────────────────────────────────╯
EOF