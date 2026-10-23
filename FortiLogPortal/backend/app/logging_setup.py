"""Logs da aplicação em logs/ (arquivos rotativos).

- logs/app.log         erros e eventos gerais
- logs/auditoria.log   quem consultou o quê (LGPD: os logs contêm dados pessoais)
- logs/integracoes.log chamadas às APIs, falhas e tempo de resposta
"""
import logging
from logging.handlers import RotatingFileHandler

from .config import settings

FMT = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")


def _file(name: str) -> RotatingFileHandler:
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    h = RotatingFileHandler(settings.log_dir / name, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    h.setFormatter(FMT)
    return h


def setup_logging() -> None:
    root = logging.getLogger()
    if getattr(root, "_portal_configured", False):
        return
    root.setLevel(settings.log_level)
    console = logging.StreamHandler()
    console.setFormatter(FMT)
    root.addHandler(console)
    root.addHandler(_file("app.log"))

    for name, filename in (("auditoria", "auditoria.log"), ("integracao", "integracoes.log")):
        lg = logging.getLogger(name)
        lg.addHandler(_file(filename))
    root._portal_configured = True  # type: ignore[attr-defined]
