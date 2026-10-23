#!/usr/bin/env bash
# Radar Marista - atualização a partir do GitHub (Ubuntu).
#
#   sudo /opt/radar-marista/deploy/update.sh            baixa a versão mais recente e reinstala
#   sudo /opt/radar-marista/deploy/update.sh --force    reinstala mesmo se já estiver na mais recente
#   sudo /opt/radar-marista/deploy/update.sh --zip arquivo.zip   usa um .zip já baixado (servidor sem internet)
#   sudo /opt/radar-marista/deploy/update.sh --branch main
#
# Repositório e branch também podem vir do config/.env: UPDATE_REPO e UPDATE_BRANCH.
# Ficam preservados config/.env, database/, logs/, exports/ e cache/.
set -euo pipefail

APP_DIR=/opt/radar-marista
ENV_FILE="$APP_DIR/config/.env"
REPO="" BRANCH="" FORCE=0 ZIP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1 ;;
    --branch) BRANCH="$2"; shift ;;
    --repo) REPO="$2"; shift ;;
    --zip) ZIP="$2"; shift ;;
    *) echo "Opção desconhecida: $1"; exit 1 ;;
  esac
  shift
done
[ "$(id -u)" -eq 0 ] || { echo "Rode como root: sudo $0"; exit 1; }

env_value() { [ -f "$ENV_FILE" ] && sed -n -E "s/^\s*$1\s*=\s*\"?([^\"]*)\"?\s*$/\1/p" "$ENV_FILE" | tail -1 | tr -d '\r'; }
[ -n "$REPO" ] || REPO="$(env_value UPDATE_REPO || true)"
[ -n "$REPO" ] || REPO="marcellod9/fortianalyzer-consulta"
[ -n "$BRANCH" ] || BRANCH="$(env_value UPDATE_BRANCH || true)"
[ -n "$BRANCH" ] || BRANCH="claude/fortilogportal-poc-vf3roq"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
LATEST=""
if [ -z "$ZIP" ]; then
  echo "== Radar Marista: atualização a partir de github.com/$REPO ($BRANCH)"
  LATEST="$(curl -fsS -H 'User-Agent: RadarMarista-update' "https://api.github.com/repos/$REPO/commits/$BRANCH" \
            | python3 -c 'import json, sys; print(json.load(sys.stdin)["sha"])' 2>/dev/null || true)"
  INSTALLED="$(cat "$APP_DIR/.versao-instalada" 2>/dev/null || true)"
  if [ -n "$LATEST" ] && [ "$LATEST" = "$INSTALLED" ] && [ "$FORCE" = 0 ]; then
    echo "Já está na versão mais recente (${LATEST:0:7}). Use --force para reinstalar."
    exit 0
  fi
  ZIP="$WORK/radar.zip"
  curl -fSL -o "$ZIP" "https://codeload.github.com/$REPO/zip/refs/heads/$BRANCH"
fi
mkdir "$WORK/src"
unzip -q "$ZIP" -d "$WORK/src"
SRC="$(find "$WORK/src" -maxdepth 5 -type f -path '*/FortiLogPortal/deploy/install.sh' | head -1)"
[ -n "$SRC" ] || { echo "O .zip não tem a pasta FortiLogPortal/deploy/install.sh."; exit 1; }
RADAR_VERSION="$LATEST" bash "$SRC"
