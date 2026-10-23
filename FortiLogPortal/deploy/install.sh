#!/usr/bin/env bash
# Radar Marista - instalação (e atualização) em Ubuntu 24.04 LTS, em /opt/radar-marista.
#
# Rode como root a partir da pasta FortiLogPortal extraída do GitHub:
#   sudo bash deploy/install.sh
#
# Pode rodar de novo quando quiser: o código é substituído e ficam preservados
#   config/.env, database/, logs/, exports/ e cache/
# Para atualizar baixando do GitHub, use: sudo /opt/radar-marista/deploy/update.sh
#
# Servidor que já tem outros sistemas:
#   - porta interna do portal: PORTAL_PORT no config/.env (padrão 8000); o script recusa uma porta já usada.
#     Na primeira instalação (ainda sem .env) informe na linha de comando: sudo RADAR_PORT=8010 bash deploy/install.sh
#   - nginx já publicando outro site: informe o nome do portal, ex.
#       sudo RADAR_SERVER_NAME=radar.marista.edu.br bash deploy/install.sh
#   - outro servidor web (Apache etc.) em 80/443: RADAR_NGINX=0 pula o nginx (publique pelo servidor existente)
set -euo pipefail

APP_DIR=/opt/radar-marista
APP_USER=radar
SERVICE=radar-marista
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIRS=(database logs exports cache pedidos)

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Rode como root: sudo bash $0"; exit 1; }
[ -f "$SRC_DIR/backend/app/main.py" ] || { echo "Não achei o código em $SRC_DIR (rode a partir da pasta FortiLogPortal)."; exit 1; }
if ! grep -q 'VERSION_ID="24.04"' /etc/os-release 2>/dev/null; then
  warn "Este script foi feito para Ubuntu 24.04 LTS; seguindo mesmo assim."
fi

RADAR_NGINX="${RADAR_NGINX:-1}"
RADAR_SERVER_NAME="${RADAR_SERVER_NAME:-}"
env_port() {
  local f="$APP_DIR/config/.env" v=""
  [ -f "$f" ] && v="$(sed -n -E 's/^\s*PORTAL_PORT\s*=\s*"?([0-9]+)"?\s*\r?$/\1/p' "$f" | tail -1)"
  echo "${v:-8000}"
}
# fuso horário do portal: o FortiAnalyzer recebe as datas no horário local,
# então o serviço precisa estar no mesmo fuso que ele (a VM pode estar em UTC)
env_tz() {
  local f="$APP_DIR/config/.env" v=""
  [ -f "$f" ] && v="$(sed -n -E 's/^\s*PORTAL_TZ\s*=\s*"?([A-Za-z0-9_+/-]+)"?\s*\r?$/\1/p' "$f" | tail -1)"
  echo "${v:-America/Sao_Paulo}"
}
# quem escuta na porta TCP $1: "nome[pid]" de cada processo, vazio se livre
port_owners() {
  ss -ltnpH "sport = :$1" 2>/dev/null | grep -oE '\("[^"]+",pid=[0-9]+' | sed -E 's/\("([^"]+)",pid=([0-9]+)/\1[\2]/' | sort -u | tr '\n' ' ' || true
}
ours() {  # o processo é o próprio Radar Marista?
  local pid
  for pid in $(echo "$1" | grep -oE '\[[0-9]+\]' | tr -d '[]'); do
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "$APP_DIR/" || return 1
  done
  return 0
}

say "0/7 Conferindo portas"
PORT="${RADAR_PORT:-$(env_port)}"
case "$PORT" in ''|*[!0-9]*) echo "Porta inválida: $PORT"; exit 1 ;; esac
owners="$(port_owners "$PORT")"
if [ -n "$owners" ] && ! ours "$owners"; then
  echo "A porta $PORT já está em uso por: $owners"
  echo "Escolha outra porta livre no config/.env, ex.: PORTAL_PORT=8010 (em $APP_DIR/config/.env), e rode de novo."
  exit 1
fi
echo "Porta interna do portal: 127.0.0.1:$PORT (livre ou já do Radar Marista)."
if [ "$RADAR_NGINX" = 1 ]; then
  for p in 80 443; do
    owners="$(port_owners "$p")"
    if [ -n "$owners" ] && ! echo "$owners" | grep -qE '^(nginx\[[0-9]+\] ?)+$'; then
      echo "A porta $p já é usada por outro servidor web: $owners"
      echo "O portal pode ser publicado por ele (proxy para http://127.0.0.1:$PORT) e o nginx fica de fora:"
      echo "  sudo RADAR_NGINX=0 bash $0"
      exit 1
    fi
  done
  OTHER_SITES="$(find /etc/nginx/sites-enabled /etc/nginx/conf.d -maxdepth 1 \( -type f -o -type l \) 2>/dev/null \
                 | grep -vE "/($SERVICE|default)$" || true)"
  if [ -n "$OTHER_SITES" ] && [ -z "$RADAR_SERVER_NAME" ] && [ ! -f "/etc/nginx/sites-available/$SERVICE" ]; then
    echo "O nginx já publica outros sites:"; echo "$OTHER_SITES" | sed 's/^/  /'
    echo "Para não misturar com eles, informe o nome (DNS) do portal, ex.:"
    echo "  sudo RADAR_SERVER_NAME=radar.marista.edu.br bash $0"
    exit 1
  fi
fi

say "1/7 Pacotes do sistema"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
PKGS=(python3 python3-venv python3-pip rsync curl unzip ca-certificates iproute2 tzdata)
[ "$RADAR_NGINX" = 1 ] && PKGS+=(nginx ssl-cert)
apt-get install -y -q "${PKGS[@]}"

say "2/7 Usuário de serviço ($APP_USER)"
id "$APP_USER" >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --no-create-home --shell /usr/sbin/nologin "$APP_USER"

say "3/7 Código em $APP_DIR"
mkdir -p "$APP_DIR"
if [ "$SRC_DIR" != "$APP_DIR" ]; then
  # --delete apaga só o que saiu do código; os itens excluídos abaixo (seus dados) nunca são tocados
  rsync -a --delete \
    --exclude '/config/.env' --exclude '/database/' --exclude '/logs/' --exclude '/exports/' --exclude '/cache/' --exclude '/pedidos/' \
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
# a porta escolhida fica no .env (o serviço e o nginx usam a mesma)
if grep -qE '^\s*PORTAL_PORT\s*=' "$ENV_FILE"; then
  sed -i -E "s|^\s*PORTAL_PORT\s*=.*|PORTAL_PORT=$PORT|" "$ENV_FILE"
else
  printf '\n# porta interna do portal (só 127.0.0.1; o nginx publica em HTTPS)\nPORTAL_PORT=%s\n' "$PORT" >> "$ENV_FILE"
fi
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
TZ_PORTAL="${RADAR_TZ:-$(env_tz)}"
if [ ! -f "/usr/share/zoneinfo/$TZ_PORTAL" ]; then
  warn "Fuso horário desconhecido: $TZ_PORTAL. Usando America/Sao_Paulo."
  TZ_PORTAL=America/Sao_Paulo
fi
echo "Fuso horário do portal: $TZ_PORTAL (o do sistema não muda: $(date +%Z))"
sed -e "s/--port 8000/--port $PORT/" -e "s|^Environment=TZ=.*|Environment=TZ=$TZ_PORTAL|" \
  "$APP_DIR/deploy/radar-marista.service" > "/etc/systemd/system/$SERVICE.service"
chmod 644 "/etc/systemd/system/$SERVICE.service"
# botões "Atualizar" e "Reiniciar" da tela de Configuração: o portal cria um pedido em pedidos/ e esta
# unidade (root) executa deploy/acao_admin.sh; o portal continua sem sudo nem root
install -d -m 2750 -o root -g "$APP_USER" /var/log/radar-marista   # saída dos botões (o portal só lê)
install -m 644 "$APP_DIR/deploy/$SERVICE-acao.service" "/etc/systemd/system/$SERVICE-acao.service"
install -m 644 "$APP_DIR/deploy/$SERVICE-acao.path" "/etc/systemd/system/$SERVICE-acao.path"
chmod 755 "$APP_DIR/deploy/acao_admin.sh" "$APP_DIR/deploy/update.sh"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
systemctl enable "$SERVICE-acao.path" >/dev/null
systemctl start "$SERVICE-acao.path" || true
systemctl restart "$SERVICE"

say "7/7 nginx (HTTPS)"
SITE=/etc/nginx/sites-available/$SERVICE
if [ "$RADAR_NGINX" != 1 ]; then
  echo "nginx não configurado (RADAR_NGINX=0). Publique http://127.0.0.1:$PORT pelo seu servidor web, repassando"
  echo "os cabeçalhos Host, X-Forwarded-For e X-Forwarded-Proto (exemplo em deploy/nginx-radar-marista.conf)."
else
  if [ ! -f "$SITE" ]; then
    sed "s|proxy_pass http://127.0.0.1:8000;|proxy_pass http://127.0.0.1:$PORT;|" "$APP_DIR/deploy/nginx-radar-marista.conf" > "$SITE"
    if [ -n "$RADAR_SERVER_NAME" ]; then
      sed -i "s|server_name _;|server_name $RADAR_SERVER_NAME;|" "$SITE"
    fi
    chmod 644 "$SITE"
  else
    # mantém o certificado e o nome configurados; só acompanha a porta do PORTAL_PORT
    sed -i -E "s|proxy_pass http://127\.0\.0\.1:[0-9]+;|proxy_pass http://127.0.0.1:$PORT;|" "$SITE"
    sed -i -E "s|^(\s*proxy_read_timeout)\s+300s;.*|\1 900s;   # Ameaças lê 7 fontes do FAZ, uma por vez|" "$SITE"
    # RADAR_SERVER_NAME informado de novo: troca o nome (ex.: o domínio do portal mudou)
    if [ -n "$RADAR_SERVER_NAME" ]; then
      sed -i -E "s|^(\s*server_name)\s+[^;]*;|\1 $RADAR_SERVER_NAME;|" "$SITE"
    fi
    echo "Mantido $SITE (o certificado configurado por você não é trocado)."
  fi
  ln -sf "$SITE" "/etc/nginx/sites-enabled/$SERVICE"
  # o site padrão do Ubuntu só sai quando não há outros sistemas no nginx
  if [ -z "${OTHER_SITES:-}" ] && [ -L /etc/nginx/sites-enabled/default ] && grep -q "root /var/www/html" /etc/nginx/sites-available/default 2>/dev/null; then
    rm -f /etc/nginx/sites-enabled/default
  fi
  nginx -t
  systemctl enable nginx >/dev/null
  systemctl reload nginx || systemctl restart nginx
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 'Nginx Full' >/dev/null && echo "Liberado HTTP/HTTPS no ufw."
  fi
fi

say "Verificando o portal"
ok=0
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
if [ "$ok" = 1 ]; then
  echo "Portal respondendo em http://127.0.0.1:$PORT${RADAR_SERVER_NAME:+ (publicado em https://$RADAR_SERVER_NAME/)}."
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
