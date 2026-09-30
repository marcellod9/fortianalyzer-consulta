#!/usr/bin/env bash
# Instala a aplicação numa VM Ubuntu (22.04/24.04). Rode como root a partir da pasta do projeto:
#   sudo ./deploy/install.sh
set -euo pipefail

APP_DIR=/opt/fortianalyzer-consulta
ENV_DIR=/etc/fortianalyzer-consulta
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

apt-get update
apt-get install -y python3 python3-venv nginx ssl-cert rsync

id fazconsulta >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin fazconsulta

mkdir -p "$APP_DIR"
rsync -a --delete --exclude .git --exclude .venv --exclude .env "$SRC_DIR"/ "$APP_DIR"/
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
chown -R root:root "$APP_DIR"

mkdir -p "$ENV_DIR"
if [ ! -f "$ENV_DIR/env" ]; then
  cp "$APP_DIR/.env.example" "$ENV_DIR/env"
  echo ">> Edite $ENV_DIR/env com FAZ_URL e FAZ_API_TOKEN antes de usar."
fi
chown root:fazconsulta "$ENV_DIR/env"
chmod 640 "$ENV_DIR/env"

cp "$APP_DIR/deploy/fortianalyzer-consulta.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now fortianalyzer-consulta
systemctl restart fortianalyzer-consulta

cp "$APP_DIR/deploy/nginx.conf" /etc/nginx/sites-available/fortianalyzer-consulta
ln -sf /etc/nginx/sites-available/fortianalyzer-consulta /etc/nginx/sites-enabled/fortianalyzer-consulta
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo ">> Pronto. Acesse https://<ip-da-vm>/"
