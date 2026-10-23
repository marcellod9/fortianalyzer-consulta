#!/usr/bin/env bash
# Radar Marista - executa o pedido feito na tela de Configuração (chamado por radar-marista-acao.path).
# O portal não tem root: ele só cria pedidos/atualizar ou pedidos/reiniciar. Este script não lê o
# conteúdo desses arquivos (quem pediu fica na auditoria do portal) e grava a saída em /var/log/radar-marista,
# pasta do root que o portal só lê: nada que o usuário radar controla é escrito como root.
set -uo pipefail
APP_DIR=/opt/radar-marista
REQ="$APP_DIR/pedidos"
OUTDIR=/var/log/radar-marista
install -d -m 2750 -o root -g radar "$OUTDIR"
LOG="$OUTDIR/acao-admin.log"
OUT="$OUTDIR/atualizacao.log"

note() { echo "$(date '+%Y-%m-%dT%H:%M:%S%z') $*" >> "$LOG"; }

if [ -e "$REQ/atualizar" ] || [ -L "$REQ/atualizar" ]; then
  rm -f "$REQ/atualizar" "$REQ/reiniciar"   # a atualização já reinicia o portal
  note "atualizar inicio"
  "$APP_DIR/deploy/update.sh" > "$OUT" 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then note "atualizar ok"; else note "atualizar falhou (código $rc)"; fi
elif [ -e "$REQ/reiniciar" ] || [ -L "$REQ/reiniciar" ]; then
  rm -f "$REQ/reiniciar"
  note "reiniciar inicio"
  if systemctl restart radar-marista; then note "reiniciar ok"; else note "reiniciar falhou"; fi
fi
exit 0
