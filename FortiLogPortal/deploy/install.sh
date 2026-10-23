#!/usr/bin/env bash
# Radar Marista - instalação (e atualização) em Ubuntu 24.04 LTS, em /opt/radar-marista.
#
# Rode como root a partir da pasta FortiLogPortal extraída do GitHub:
#   sudo bash deploy/install.sh
#
# Pode rodar de novo quando quiser: o código é substituído e ficam preservados
#   config/.env, database/, logs/, exports/ e cache/
# Para atualizar baixando do GitHub, use: sudo /opt/radar-marista/deploy/update.sh
set -euo pipefail

APP_DIR=/opt/radar-marista
APP_USER=radar
SERVICE=radar-marista
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIRS=(database logs exports cache)

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Rode como root: sudo bash $0"; exit 1; }
[ -f "$SRC_DIR/backend/app/main.py" ] || { echo "Não achei o código em $SRC_DIR (rode a partir da pasta FortiLogPortal)."; exit 1; }
if ! grep -q 'VERSION_ID="24.04"' /etc/os-release 2>/dev/null; then
  warn "Este script foi feito para Ubuntu 24.04 LTS; seguindo mesmo assim."
fi

say "1/7 Pacotes do sistema"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv python3-pip nginx ssl-cert rsync curl unzip ca-certificates

say "2/7 Usuário de serviço ($APP_USER)"
id "$APP_USER" >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --no-create-home --shell /usr/sbin/nologin "$APP_USER"

say "3/7 Código em $APP_DIR"
mkdir -p "$APP_DIR"
if [ "$SRC_DIR" != "$APP_DIR" ]; then
  # --delete apaga só o que saiu do código; os itens excluídos abaixo (seus dados) nunca são tocados
  rsync -a --delete \
    --exclude '/config/.env' --exclude '/database/' --exclude '/logs/' --exclude '/exports/' --exclude '/cache/' \
    --exclude '/.venv/' --exclude '/.versao-instalada' --exclude '.git/' --exclude '__pycache__/' --exclude '.pytest_cache/' \
    "$SRC_DIR"/ "$APP_DIR"/
fi
[ -n "${RADAR_VERSION:-}" ] && echo "$RADAR_VERSION" > "$APP_DIR/.versao-instalada"
chown -R root:root "$APP_DIR"
chmod 755 "$APP_DIR"
for d in "${DATA_DIRS[@]}"; do
  mkdir -p "$APP_DIR/$d"
  chown -R "$APP_USER:$APP_USER" "$APP_DIR/$d"
  chmod 750 "$APP_DIR/$d"
done
chmod +x "$APP_DIR"/deploy/*.sh

say "4/7 Configuração (config/.env)"
ENV_FILE="$APP_DIR/config/.env"
FIRST_INSTALL=0
if [ ! -f "$ENV_FILE" ]; then
  cp "$APP_DIR/config/.env.example" "$ENV_FILE"
  FIRST_INSTALL=1
  echo "Criado $ENV_FILE a partir do .env.example."
fi
# o portal escuta só em 127.0.0.1; o nginx publica em HTTPS
if grep -qE '^\s*PORTAL_HOST\s*=' "$ENV_FILE"; then
  sed -i -E 's|^\s*PORTAL_HOST\s*=.*|PORTAL_HOST=127.0.0.1|' "$ENV_FILE"
fi
sed -i 's/\r$//' "$ENV_FILE"   # .env copiado do Windows (CRLF)
chown root:"$APP_USER" "$ENV_FILE"
chmod 640 "$ENV_FILE"

say "5/7 Ambiente Python (.venv)"
if [ ! -x "$APP_DIR/.venv/bin/python" ] || ! "$APP_DIR/.venv/bin/python" -c 'import sys' 2>/dev/null; then
  rm -rf "$APP_DIR/.venv"
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
"$APP_DIR/.venv/bin/python" -m compileall -q "$APP_DIR/backend" >/dev/null || true

say "6/7 Serviço systemd ($SERVICE)"
install -m 644 "$APP_DIR/deploy/radar-marista.service" "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
systemctl restart "$SERVICE"

say "7/7 nginx (HTTPS)"
SITE=/etc/nginx/sites-available/$SERVICE
if [ ! -f "$SITE" ]; then
  install -m 644 "$APP_DIR/deploy/nginx-radar-marista.conf" "$SITE"
else
  echo "Mantido $SITE (já existia; o certificado e o nome configurados por você não são trocados)."
fi
ln -sf "$SITE" "/etc/nginx/sites-enabled/$SERVICE"
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx >/dev/null
systemctl reload nginx || systemctl restart nginx
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 'Nginx Full' >/dev/null && echo "Liberado HTTP/HTTPS no ufw."
fi

say "Verificando o portal"
ok=0
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
if [ "$ok" = 1 ]; then
  echo "Portal respondendo em http://127.0.0.1:8000 (publicado pelo nginx em https://$(hostname -f 2>/dev/null || hostname)/)."
else
  warn "O portal não respondeu. Veja: journalctl -u $SERVICE -n 50 --no-pager"
  exit 1
fi

if [ "$FIRST_INSTALL" = 1 ]; then
  cat <<MSG

Próximos passos:
  1. Edite $ENV_FILE (FAZ_URL, FAZ_API_TOKEN, V1_API_TOKEN, FGT_*, AUTH_MODE=entra, ENTRA_*).
     Com login Microsoft: ENTRA_REDIRECT_URI=https://<nome-do-servidor>/auth/callback,
     e cadastre esse mesmo endereço no aplicativo do Entra ID.
  2. sudo systemctl restart $SERVICE
  3. Troque o certificado de teste do nginx pelo da instituição (docs/INSTALACAO_UBUNTU.md).
MSG
fi
