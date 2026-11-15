#!/usr/bin/env bash
#
# Build script for the "Daily Lighthouse" PM-02 vulnerable target.
#
# Usage:
#   sudo ./build.sh
#
#   This box is INTENTIONALLY VULNERABLE. Never attach it to a security group
#   that allows 0.0.0.0/0. It is meant to run only inside an isolated lab
#   subnet reached through the WireGuard gateway (see the AWS setup guide).
#
#   Base image should be an Ubuntu LTS (22.04 or 24.04). PS04's OpenSCAP CIS
#   content file must match the OS version: ssg-ubuntu2204 for 22.04, or
#   ssg-ubuntu2404 for 24.04. The script warns if it's neither.
#
set -euo pipefail

APP_REPO="${APP_REPO:-https://github.com/geomancer-of-old/daily-lighthouse.git}"
APP_REF="${APP_REF:-main}"                 # branch/tag/commit to pin the AMI to
APP_DIR="/opt/daily-lighthouse"
APP_ENTRY="${APP_ENTRY:-app.py}"           # Flask entrypoint inside the repo
APP_PORT="${APP_PORT:-80}"                 # port the web app listens on
APP_USER="lighthouse"                      # service account for the Flask app

# Deliberately weak lab credential (shared by SSH + FTP), prompted below.
LAB_USER="${LAB_USER:-}"
LAB_PASS="${LAB_PASS:-}"

# PS04 backup admin: the authorised sudo account students use to run the host
# audits if their PS02 attack did not land. Matches the PS04 brief.
ADMIN_USER="${ADMIN_USER:-danny.kent}"
ADMIN_PASS="${ADMIN_PASS:-iL0v3Th3BluRR}"

ENABLE_FTP="${ENABLE_FTP:-1}"              # vsftpd w/ anonymous + weak user on 21
ENABLE_SMTP="${ENABLE_SMTP:-1}"           # postfix open-ish relay on 25
ENABLE_WEAK_SSH="${ENABLE_WEAK_SSH:-1}"   # password auth + weak lab user on 22
ENABLE_DB="${ENABLE_DB:-1}"               # MariaDB w/ synthetic newsroom data on 3306
DB_NAME="${DB_NAME:-lighthouse_news}"
DB_USER="${DB_USER:-}"                    # prompted below unless preset
DB_PASS="${DB_PASS:-}"                    # prompted below unless preset
DB_NETWORK="${DB_NETWORK:-1}"             # 1 = listen on the subnet (the vuln), 0 = localhost only
SUB_COUNT="${SUB_COUNT:-500}"             # synthetic subscriber rows to generate
ENABLE_PHPMYADMIN="${ENABLE_PHPMYADMIN:-1}"  # phpMyAdmin for managing the corp DB
PMA_PORT="${PMA_PORT:-8080}"             # own port so it doesn't clash with Flask on 80
### ──────────────────────────────────────────────────────────────────────────

log() { printf '\n\033[1;36m[zaio.vuln.vm]\033[0m %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then echo "Run with sudo." >&2; exit 1; fi
export DEBIAN_FRONTEND=noninteractive

# Warn (don't block) if the base OS isn't an Ubuntu LTS PS04 has content for.
if ! grep -qE 'VERSION_ID="(22.04|24.04)"' /etc/os-release 2>/dev/null; then
  log "WARNING: base image is not Ubuntu 22.04 or 24.04. PS04's OpenSCAP CIS"
  log "         content (ssg-ubuntu2204 / ssg-ubuntu2404) must match the OS."
  log "         Continue only if you know the matching SCAP content exists."
fi

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

log "Set the weak lab credential (used for both SSH and FTP)"
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
  git python3 python3-venv python3-pip sqlite3 ca-certificates curl wget unzip ufw sudo

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

# The repo hardcodes app.run(port=5000); serve the lab web app on APP_PORT (80).
log "Pinning the web app to port ${APP_PORT}"
sed -ri "s/port=[0-9]+/port=${APP_PORT}/" "$APP_DIR/$APP_ENTRY" || true

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
# DB connection details for the Flask app (read with os.getenv in the app).
Environment=DB_HOST=127.0.0.1
Environment=DB_NAME=${DB_NAME}
Environment=DB_USER=${DB_USER}
Environment=DB_PASSWORD=${DB_PASS}
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

###  Weak lab user (used by SSH and FTP) — the student's hardening target
log "Creating weak lab user ${LAB_USER}"
id -u "$LAB_USER" &>/dev/null || useradd -m -s /bin/bash "$LAB_USER"
echo "${LAB_USER}:${LAB_PASS}" | chpasswd

###  PS04 backup admin (authorised sudo account)
log "Creating backup admin ${ADMIN_USER} (sudo)"
id -u "$ADMIN_USER" &>/dev/null || useradd -m -s /bin/bash "$ADMIN_USER"
echo "${ADMIN_USER}:${ADMIN_PASS}" | chpasswd
usermod -aG sudo "$ADMIN_USER"

###  Newsroom database (3306) MariaDB with SYNTHETIC data
if [[ "$ENABLE_DB" == "1" ]]; then
  log "Installing MariaDB and seeding synthetic newsroom data into ${DB_NAME}"
  apt-get install -y --no-install-recommends mariadb-server
  systemctl enable mariadb
  systemctl start mariadb

  if [[ "$DB_NETWORK" == "1" ]]; then
    # Deliberate weakness: reachable over the (isolated) subnet, not just localhost.
    sed -ri 's/^#?bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf
    systemctl restart mariadb
  fi

  # All names, emails and numbers below are FICTIONAL training data.
  mariadb <<SQL
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
USE ${DB_NAME};

-- The subscriber list (the newsroom's crown-jewel PII).
CREATE TABLE IF NOT EXISTS subscribers (
  id INT PRIMARY KEY AUTO_INCREMENT,
  full_name VARCHAR(80), email VARCHAR(120),
  plan VARCHAR(20), card_last4 CHAR(4), joined DATE
);

-- Unpublished / embargoed stories.
CREATE TABLE IF NOT EXISTS stories (
  id INT PRIMARY KEY AUTO_INCREMENT,
  headline VARCHAR(160), author VARCHAR(60),
  status VARCHAR(20), body TEXT, embargo_until DATE
);

-- Whistleblower correspondence (source-protected).
CREATE TABLE IF NOT EXISTS whistleblower_emails (
  id INT PRIMARY KEY AUTO_INCREMENT,
  from_alias VARCHAR(60), subject VARCHAR(160), received DATETIME, body TEXT
);

-- CMS login users with intentionally weak, crackable MD5 hashes.
CREATE TABLE IF NOT EXISTS app_users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(40), password_md5 CHAR(32), role VARCHAR(20)
);

-- Generate a realistic subscriber list (SUB_COUNT rows).
DROP PROCEDURE IF EXISTS seed_subscribers;
DELIMITER //
CREATE PROCEDURE seed_subscribers(IN n INT)
BEGIN
  DECLARE i INT DEFAULT 0;
  WHILE i < n DO
    INSERT INTO subscribers (full_name, email, plan, card_last4, joined)
    VALUES (
      CONCAT('Reader ', LPAD(i,5,'0')),
      CONCAT('reader', i, '@readers.lighthouse.lab'),
      ELT(1 + FLOOR(RAND()*3), 'digital', 'print', 'premium'),
      LPAD(FLOOR(RAND()*10000), 4, '0'),
      DATE_SUB(CURDATE(), INTERVAL FLOOR(RAND()*2000) DAY)
    );
    SET i = i + 1;
  END WHILE;
END //
DELIMITER ;
CALL seed_subscribers(${SUB_COUNT});
DROP PROCEDURE seed_subscribers;

INSERT INTO stories (headline, author, status, body, embargo_until) VALUES
 ('City tender irregularities exposed','Thandi Mokoena','embargoed','DRAFT: documents show three contracts awarded without tender...','2027-01-15'),
 ('Hospital backlog: the leaked memo','Sipho Dlamini','unpublished','DRAFT: internal memo confirms waiting lists understated by...','2027-02-01'),
 ('Who funds the mayor?','Lerato Khumalo','review','DRAFT: donation records trace back to a shell company...','2027-01-30');

INSERT INTO whistleblower_emails (from_alias, subject, received, body) VALUES
 ('deepsource','Re: the tender documents','2026-10-02 21:14:00','I can get you the signed originals. Do not use my name.'),
 ('clerk_41','Payroll discrepancy','2026-10-11 08:02:00','The numbers in the public report do not match what I process.');

-- Passwords: 'admin', 'password', 'letmein', 'sunshine' (MD5) — meant to be cracked.
INSERT INTO app_users (username, password_md5, role) VALUES
 ('editor','21232f297a57a5a743894a0e4a801fc3','admin'),
 ('tmokoena','5f4dcc3b5aa765d61d8327deb882cf99','journalist'),
 ('snkosi','0d107d09f5bbe40cade3de5c71e9e9b7','journalist'),
 ('backup_svc','0571749e2ac330a7455809c6b0e7af90','service');

CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'%'        IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'%';
FLUSH PRIVILEGES;
SQL
  log "Seeded ${DB_NAME}: subscribers (${SUB_COUNT}), stories, whistleblower_emails, app_users (all fictional)"

  ###  phpMyAdmin (on its own port)
  if [[ "$ENABLE_PHPMYADMIN" == "1" ]]; then
    log "Installing phpMyAdmin on port ${PMA_PORT}"
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
#   NOTE: root login is disabled on purpose (good practice, and it keeps the
#   box safe). The student's PS02 hardening target is the WEAK LAB USER:
#   Hydra cracks ${LAB_USER} -> they add fail2ban / disable password auth ->
#   the attack then fails. PS02 step 10 and the PS04 before/after use that.
if [[ "$ENABLE_WEAK_SSH" == "1" ]]; then
  log "Enabling password SSH auth (root login stays disabled)"
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
  # Loot: an unpublished story left readable over anonymous FTP (a real finding).
  cat >/srv/ftp/pub/EMBARGOED-city-tender.txt <<'EOF'
EMBARGOED — NOT FOR PUBLICATION until 2027-01-15
Headline: City tender irregularities exposed
Byline: Thandi Mokoena
Source documents indicate three municipal contracts were awarded without
an open tender process. Do not distribute. Source is protected.
EOF
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

###  PS04 host-audit tooling (Lynis + OpenSCAP with matching CIS content)
#   The Ubuntu-packaged SCAP content lags behind the OS, so the distro package
#   often lacks this release's datastream. Fetch a ComplianceAsCode build that
#   has it and bake the matching ssg-ubuntu<ver>-ds.xml into the image.
log "Installing Lynis + OpenSCAP and baking CIS content for this OS"
apt-get install -y --no-install-recommends lynis openscap-scanner
SSG_VER="${SSG_VER:-0.1.79}"
UBU_VER="$(. /etc/os-release; echo "${VERSION_ID//./}")"   # e.g. 2204 or 2404
SSG_DS="ssg-ubuntu${UBU_VER}-ds.xml"
SSG_DEST="/usr/share/xml/scap/ssg/content"
mkdir -p "$SSG_DEST"
if [[ ! -f "$SSG_DEST/$SSG_DS" ]]; then
  tmpd="$(mktemp -d)"
  if wget -q -O "$tmpd/ssg.zip" \
       "https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VER}/scap-security-guide-${SSG_VER}.zip"; then
    unzip -q -o "$tmpd/ssg.zip" -d "$tmpd"
    if [[ -f "$tmpd/scap-security-guide-${SSG_VER}/$SSG_DS" ]]; then
      cp "$tmpd/scap-security-guide-${SSG_VER}/$SSG_DS" "$SSG_DEST/"
      log "Baked $SSG_DS (SSG ${SSG_VER}) for PS04"
    else
      log "WARNING: $SSG_DS not found in SSG ${SSG_VER}. Set SSG_VER to a release that ships it."
    fi
  else
    log "WARNING: could not download SSG ${SSG_VER}; OpenSCAP content not baked."
  fi
  rm -rf "$tmpd"
fi

###  Host firewall (defence-in-depth; the SG is the real boundary)
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
rm -f /root/.bash_history "/home/${LAB_USER}/.bash_history" "/home/${ADMIN_USER}/.bash_history" || true

cat <<EOF

╭──────────────────────────────────────────────────────────────╮
│  PM-02 Daily Lighthouse target baked.                         │
│                                                              │
│  Verify, then snapshot:                                       │
│    systemctl start daily-lighthouse && curl -sI localhost:${APP_PORT}
│    systemctl status daily-lighthouse vsftpd postfix ssh mariadb
│                                                              │
│  Weak lab creds : ${LAB_USER} / ${LAB_PASS}                   │
│  Backup admin   : ${ADMIN_USER} / ${ADMIN_PASS} (sudo, PS04)  │
│  DB login       : ${DB_USER} @ ${DB_NAME} (port 3306)         │
│  phpMyAdmin     : http://<box>:${PMA_PORT}/phpmyadmin         │
│                                                              │
│  Then: EC2 → Actions → Image → Create image.                  │
│  Point usurper at the resulting AMI id.                       │
╰──────────────────────────────────────────────────────────────╯
EOF