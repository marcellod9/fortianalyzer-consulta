"""Botões "Atualizar" e "Reiniciar" da tela de Configuração (servidor Ubuntu).

O portal roda sem root. O botão só cria um arquivo de pedido em pedidos/; a unidade systemd
radar-marista-acao.path (root) vê o arquivo e executa deploy/acao_admin.sh, que roda deploy/update.sh
ou reinicia o serviço. A saída fica em /var/log/radar-marista, que o portal só lê.
"""
import os
import re
from datetime import datetime
from pathlib import Path

from ..config import BASE_DIR

REQUESTS = BASE_DIR / "pedidos"
OUT_DIR = Path(os.getenv("PORTAL_ACTION_LOG_DIR", "/var/log/radar-marista"))
ACTIONS = ("atualizar", "reiniciar")
TAIL = 80
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def available() -> bool:
    """Só no servidor instalado pelo deploy/install.sh (no Windows não há pasta pedidos/)."""
    return REQUESTS.is_dir() and os.access(REQUESTS, os.W_OK)


def _tail(path: Path, n: int) -> list[str]:
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 64 * 1024))
            return ANSI.sub("", f.read().decode("utf-8", "replace")).splitlines()[-n:]
    except OSError:
        return []


def _version() -> str:
    try:
        return (BASE_DIR / ".versao-instalada").read_text().strip()[:40]
    except OSError:
        return ""


def _entry(line: str) -> dict:
    """Linha do acao-admin.log ("2026-10-23T16:30:00-0300 atualizar ok") no horário do portal."""
    stamp, _, text = line.partition(" ")
    try:
        when = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S%z").astimezone().replace(tzinfo=None)
    except ValueError:
        return {"quando": "", "texto": line, "_dt": None}
    return {"quando": when.strftime("%Y-%m-%d %H:%M:%S"), "texto": text, "_dt": when}


def status() -> dict:
    history = [_entry(x) for x in _tail(OUT_DIR / "acao-admin.log", 20) if x.strip()]
    last = history[-1] if history else None
    pending = [a for a in ACTIONS if (REQUESTS / a).exists()]
    # um "inicio" sem fim há mais de 40 min (servidor desligado no meio) não trava os botões
    running = bool(last and last["texto"].endswith("inicio") and last["_dt"]
                   and (datetime.now() - last["_dt"]).total_seconds() < 40 * 60)
    for h in history:
        h.pop("_dt")
    return {"disponivel": available(), "versao": _version(), "pendente": pending,
            "em_andamento": running and not pending, "ultimo": last, "historico": history[::-1],
            "saida_atualizacao": _tail(OUT_DIR / "atualizacao.log", TAIL)}


def request(action: str, by: str) -> None:
    if action not in ACTIONS:
        raise ValueError("ação desconhecida")
    if not available():
        raise RuntimeError("Disponível só no servidor Ubuntu instalado pelo deploy/install.sh.")
    st = status()
    if st["pendente"] or st["em_andamento"]:
        raise RuntimeError("Já há uma atualização ou reinício em andamento. Aguarde terminar.")
    tmp = REQUESTS / f".{action}.tmp"
    tmp.write_text(f"{datetime.now():%Y-%m-%d %H:%M:%S} {by}\n")
    tmp.replace(REQUESTS / action)  # aparece de uma vez para o radar-marista-acao.path
