#!/usr/bin/env bash
# Instalador premium Odoo (16.0-19.0) - Producción segura
# Creada por Samuel Sarante
# Fecha: 2025-10-02
set -euo pipefail
IFS=$'\n\t'

# ------------------ root check ------------------
if [ "$EUID" -ne 0 ]; then
  echo "Este script debe ejecutarse como root (sudo)."
  exit 1
fi

# ------------------ funciones ------------------
read_default() {
  local prompt="$1"; local default="$2"
  read -p "$prompt [$default]: " input
  echo "${input:-$default}"
}

read_yes_no() {
  local prompt="$1"; local default="$2"
  while true; do
    read -p "$prompt [$default]: " yn
    yn=${yn:-$default}
    case "${yn,,}" in
      y|yes ) echo "True"; return ;;
      n|no ) echo "False"; return ;;
      * ) echo "Por favor responde yes/no (y/n)";;
    esac
  done
}

# ------------------ preguntas ------------------
echo "=== INSTALADOR PREMIUM SEGURO DE ODOO ==="

OE_VERSION=$(read_default "Versión Odoo (16.0-19.0)" "19.0")
DEFAULT_USER="odoo${OE_VERSION%%.*}"
OE_USER=$(read_default "Usuario sistema para Odoo" "$DEFAULT_USER")
OE_HOME=$(read_default "Directorio base" "/home/$OE_USER")
OE_HOME_EXT="/opt/${OE_USER}-server"
OE_PORT=$(read_default "Puerto HTTP interno de Odoo" "8069")
LONGPOLL_PORT=$(read_default "Puerto longpolling" "8072")

GENERATE_RANDOM_PASS=$(read_yes_no "¿Generar contraseña superadmin aleatoria?" "yes")
if [ "$GENERATE_RANDOM_PASS" = "True" ]; then
  OE_SUPERADMIN=$(tr -dc 'A-Za-z0-9!@#$%^-_' </dev/urandom | head -c 20)
else
  OE_SUPERADMIN=$(read_default "Contraseña superadmin" "admin")
fi

INSTALL_NGINX=$(read_yes_no "¿Instalar Nginx + Certbot SSL?" "yes")
BACKUP_DIR=$(read_default "Directorio de backups" "/opt/backups_odoo")
RETENTION_DAYS=$(read_default "Retención backups (días)" "30")
INSTALL_CLAMAV=$(read_yes_no "¿Instalar ClamAV y escaneos cada 5 horas?" "yes")

# ------------------ rama git ------------------
case "$OE_VERSION" in
  19|19.0) OE_GIT_BRANCH="19.0" ;;
  18|18.0) OE_GIT_BRANCH="18.0" ;;
  17|17.0) OE_GIT_BRANCH="17.0" ;;
  16|16.0) OE_GIT_BRANCH="16.0" ;;
  *) OE_GIT_BRANCH="$OE_VERSION" ;;
esac

# ------------------ resumen inicial ------------------
echo
echo "Resumen:"
echo "  Odoo version: $OE_VERSION (branch Git: $OE_GIT_BRANCH)"
echo "  Usuario: $OE_USER"
echo "  Home: $OE_HOME"
echo "  Servidor: $OE_HOME_EXT"
echo "  Puerto interno: $OE_PORT  Longpoll: $LONGPOLL_PORT"
echo "  Backups: $BACKUP_DIR (retención $RETENTION_DAYS días)"
echo "  ClamAV: $INSTALL_CLAMAV"
echo "  Nginx/SSL: $INSTALL_NGINX"
echo
read -p "Continuar? (Enter para continuar, Ctrl+C para cancelar) " _

# ---------- actualizar e instalar dependencias desde install.txt ----------
echo -e "\n==> Actualizando sistema..."
apt update && apt upgrade -y

if [ -f "./install.txt" ]; then
  echo "==> Instalando paquetes desde install.txt..."
  xargs -a ./install.txt apt install -y
else
  echo "ERROR: install.txt no encontrado. Abortando."
  exit 1
fi


npm config set strict-ssl false
npm install -g less

# ------------------ seguridad ------------------
echo -e "\n==> Configurando UFW y Fail2Ban..."
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80
ufw allow 443
ufw --force enable
systemctl enable --now fail2ban

# ------------------ usuario ------------------
echo -e "\n==> Crear usuario $OE_USER..."
if ! id "$OE_USER" >/dev/null 2>&1; then
  useradd --system --create-home --shell /bin/bash --home-dir "$OE_HOME" "$OE_USER"
fi

# ------------------ PostgreSQL ------------------
echo -e "\n==> Configurando PostgreSQL..."
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$OE_USER'" | grep -q 1; then
  sudo -u postgres psql -c "CREATE ROLE \"$OE_USER\" WITH LOGIN CREATEDB PASSWORD '${OE_SUPERADMIN}';"
fi

# ------------------ Clon Odoo ------------------
echo -e "\n==> Clonando Odoo..."
# Limpiar carpeta
rm -rf "$OE_HOME_EXT"

# Crear carpeta y asignar permisos al usuario
mkdir -p "$OE_HOME_EXT"
chown -R "$OE_USER":"$OE_USER" "$OE_HOME_EXT"

# Clonar con el usuario correcto
sudo -u "$OE_USER" git clone --depth 1 --branch "$OE_GIT_BRANCH" https://github.com/odoo/odoo.git "$OE_HOME_EXT"

# ------------------ virtualenv ------------------
echo -e "\n==> Configurando virtualenv..."
sudo -u "$OE_USER" python3 -m venv "$OE_HOME_EXT/venv"
sudo -u "$OE_USER" "$OE_HOME_EXT/venv/bin/pip" install --upgrade pip setuptools wheel
sudo -u "$OE_USER" "$OE_HOME_EXT/venv/bin/pip" install rlpycairo phonenumbers google_auth pypdf pdf2image pytesseract numpy opencv-python Crypto pycryptodome woocommerce
sudo -u "$OE_USER" "$OE_HOME_EXT/venv/bin/pip" install --force-reinstall reportlab
sudo -u "$OE_USER" "$OE_HOME_EXT/venv/bin/pip" install -r "$OE_HOME_EXT/requirements.txt"

# ------------------ custom addons ------------------
CUSTOM_ADDONS_DIR="$OE_HOME/custom/addons"
mkdir -p "$CUSTOM_ADDONS_DIR"
mkdir -p "$OE_HOME_EXT/enterprise"
chown -R "$OE_USER":"$OE_USER" "$CUSTOM_ADDONS_DIR"
chown -R "$OE_USER":"$OE_USER" "$OE_HOME_EXT/enterprise"

# ---------- Instalando libssl----------
echo -e "\n==> Instalando libssl..."
libssl_URL="http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb"
wget -O /tmp/libssl.deb "$libssl_URL"
apt install -y /tmp/libssl.deb
rm /tmp/libssl.deb

# ------------------ wkhtmltopdf ------------------
echo -e "\n==> Instalando wkhtmltopdf compatible Ubuntu 24.04..."
WKHTML_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/wkhtmltox_0.12.6-1.focal_amd64.deb"
wget -O /tmp/wkhtmltopdf.deb "$WKHTML_URL"
apt install -y /tmp/wkhtmltopdf.deb
rm /tmp/wkhtmltopdf.deb

# ------------------ GeoLite2 ------------------
echo -e "\n==> Descargando GeoLite2..."
mkdir -p /usr/share/GeoIP
wget -O /usr/share/GeoIP/GeoLite2-ASN.mmdb "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb"
wget -O /usr/share/GeoIP/GeoLite2-City.mmdb "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb"
wget -O /usr/share/GeoIP/GeoLite2-Country.mmdb "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb"

# ------------------ backups ------------------
echo -e "\n==> Configurando backups diarios comprimidos..."
mkdir -p "$BACKUP_DIR"
echo "0 2 * * * root pg_dumpall | gzip > $BACKUP_DIR/pg_dump_\$(date +\%F).sql.gz && find $BACKUP_DIR -type f -mtime +$RETENTION_DAYS -delete" > /etc/cron.d/odoo_backup

# ------------------ ClamAV ------------------
if [ "$INSTALL_CLAMAV" = "True" ]; then
  echo -e "\n==> Instalando ClamAV..."
  apt install -y clamav clamav-daemon
  systemctl enable --now clamav-freshclam
  echo "0 */5 * * * root clamscan -ri /opt /home --exclude-dir=/proc --exclude-dir=/sys --exclude-dir=/dev" > /etc/cron.d/odoo_clamav
fi

# ------------------ systemd ------------------
echo -e "\n==> Configurando systemd..."
echo " Calculando parámetros óptimos de rendimiento..."

# Detectar núcleos de CPU
NUM_CPUS=$(nproc)
# Detectar memoria total en GB (entero)
TOTAL_RAM=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)

echo "Detectado: $NUM_CPUS núcleos de CPU y $TOTAL_RAM GB de RAM."

# Calcular los parámetros recomendados
WORKERS=$((NUM_CPUS * 2 + 1))
LIMIT_MEMORY_HARD=$(($TOTAL_RAM * 1024 * 1024 * 1024 * 3 / 4))  # 75% de RAM
LIMIT_MEMORY_SOFT=$(($LIMIT_MEMORY_HARD * 4 / 5))               # 80% del límite duro
MAX_CRON_THREADS=1
DB_MAXCONN=$WORKERS

cat > "$OE_HOME_EXT/odoo.conf" <<EOF
[options]
admin_passwd = $OE_SUPERADMIN
db_host = False
db_port = False
db_user = $OE_USER
db_password = False
xmlrpc_port = $OE_PORT
longpolling_port = $LONGPOLL_PORT
addons_path = $OE_HOME_EXT/addons,$CUSTOM_ADDONS_DIR,$OE_HOME_EXT/enterprise
default_productivity_apps = True
proxy_mode = True
logfile = $OE_HOME_EXT/odoo.log
limit_time_cpu = 60
limit_time_real = 120
workers = $WORKERS
max_cron_threads = 1
EOF

cat > /etc/systemd/system/${OE_USER}.service <<EOF
[Unit]
Description=Odoo ${OE_VERSION} server
After=network.target postgresql.service

[Service]
Type=simple
User=${OE_USER}
Group=${OE_USER}
LimitNOFILE=65535
ExecStart=${OE_HOME_EXT}/venv/bin/python3 ${OE_HOME_EXT}/odoo-bin -c ${OE_HOME_EXT}/odoo.conf
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${OE_USER}.service

# ------------------ Nginx + SSL ------------------
if [ "$INSTALL_NGINX" = "True" ]; then
  echo -e "\n==> Configurando Nginx y SSL..."
  read -p "Dominio para Odoo (ej: odoo.midominio.com): " DOMAIN

  # Detectar si es dominio local
  if [[ "$DOMAIN" == *.local ]] || [[ "$DOMAIN" == "localhost" ]]; then
    echo "Dominio local detectado, se generará certificado autofirmado..."
    SSL_DIR="/etc/ssl/odoo"
    mkdir -p "$SSL_DIR"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$SSL_DIR/odoo.key" \
      -out "$SSL_DIR/odoo.crt" \
      -subj "/C=DO/ST=RepD/L=SantoDomingo/O=MiEmpresa/OU=IT/CN=$DOMAIN"
    SSL_CERT="$SSL_DIR/odoo.crt"
    SSL_KEY="$SSL_DIR/odoo.key"
    USE_LETSENCRYPT="False"
  else
    # Dominio público → usar Let's Encrypt
    SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    USE_LETSENCRYPT="True"
  fi

  cat > /etc/nginx/sites-available/odoo.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    server_name $DOMAIN;

    ssl_certificate $SSL_CERT;
    ssl_certificate_key $SSL_KEY;

    location / {
        proxy_pass http://127.0.0.1:$OE_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

  ln -sf /etc/nginx/sites-available/odoo.conf /etc/nginx/sites-enabled/odoo.conf
  nginx -t && systemctl reload nginx

  # Certbot solo si es dominio público
  if [ "$USE_LETSENCRYPT" = "True" ]; then
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m admin@$DOMAIN
  fi
fi

# Obtener IP privada
IP_PRIV=$(hostname -I | awk '{print $1}')
# Obtener IP pública (opcional)
IP_PUB=$(curl -s https://ipinfo.io/ip || echo "No disponible")


# ------------------ resumen final ------------------
echo
echo "========================================"
echo " INSTALACIÓN FINALIZADA - PRODUCCIÓN"
echo " Dirección IP privada: $IP_PRIV"
echo " Dirección IP pública : $IP_PUB"
echo " Accede a Odoo: http://$IP_PRIV:$OE_PORT o https://$DOMAIN"
echo " Odoo versión: $OE_VERSION"
echo " Usuario sistema: $OE_USER"
echo " Home: $OE_HOME"
echo " Código: $OE_HOME_EXT"
echo " Custom addons: $CUSTOM_ADDONS_DIR"
echo " Puerto interno HTTP: $OE_PORT  Longpoll: $LONGPOLL_PORT"
echo " Workers: $WORKERS"
echo " Backups: $BACKUP_DIR (retención $RETENTION_DAYS días)"
if [ "$GENERATE_RANDOM_PASS" = "True" ]; then
  echo
  echo " -> Superadmin (aleatorio): $OE_SUPERADMIN"
  echo "   GUARDA ESTA CONTRASEÑA EN LUGAR SEGURO."
fi
echo "========================================"

