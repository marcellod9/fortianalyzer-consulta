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
REPO="" BRANCH="" FORCE=0 ZIP="" INSTALLED=""
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
  echo "Baixando ${LATEST:0:7}..."
  curl -fsSL -o "$ZIP" "https://codeload.github.com/$REPO/zip/refs/heads/$BRANCH"
fi
mkdir "$WORK/src"
unzip -q "$ZIP" -d "$WORK/src"
SRC="$(find "$WORK/src" -maxdepth 5 -type f -path '*/FortiLogPortal/deploy/install.sh' | head -1)"
[ -n "$SRC" ] || { echo "O .zip não tem a pasta FortiLogPortal/deploy/install.sh."; exit 1; }
RADAR_VERSION="$LATEST" bash "$SRC"

# ---- o que mudou -------------------------------------------------------------------------------
if [ -n "$LATEST" ]; then
  echo
  REPO="$REPO" OLD="${INSTALLED:-}" NEW="$LATEST" python3 - <<'PY' || echo "(não foi possível listar as novidades)"
import json, os, urllib.request

repo, old, new = os.environ["REPO"], os.environ["OLD"], os.environ["NEW"]

def get(path):
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/{path}", headers={"User-Agent": "RadarMarista-update"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)

if old and old != new:
    commits = get(f"compare/{old}...{new}").get("commits", [])
    title = f"Novidades desta atualização ({old[:7]} -> {new[:7]}):"
else:
    commits = list(reversed(get(f"commits?sha={new}&per_page=10")))
    title = "Últimas mudanças desta versão:" if not old else "Versão reinstalada; últimas mudanças:"
lines = []
for c in reversed(commits):  # mais recente primeiro
    msg = c["commit"]["message"].splitlines()[0].strip()
    if msg.lower().startswith("merge "):
        continue
    lines.append(f"  {c['commit']['author']['date'][:10]}  {msg}")
print(f"\033[1;36m{title}\033[0m")
print("\n".join(lines[:40]) or "  (nenhuma mudança listada)")
if len(lines) > 40:
    print(f"  ... e mais {len(lines) - 40}")
PY
fi
# opções novas no modelo de configuração, que ainda não estão no seu .env
if [ -f "$ENV_FILE" ]; then
  NEW_OPTS="$(grep -E '^\s*#?\s*[A-Z0-9_]+\s*=' "$APP_DIR/config/.env.example" | sed -E 's/^\s*#?\s*//' | while IFS= read -r line; do
      k="${line%%=*}"; grep -qE "^\s*#?\s*$k\s*=" "$ENV_FILE" || echo "  $line"; done)"
  if [ -n "$NEW_OPTS" ]; then
    echo
    echo "Opções novas em config/.env.example (copie para $ENV_FILE se quiser mudar o padrão):"
    echo "$NEW_OPTS"
  fi
fi
