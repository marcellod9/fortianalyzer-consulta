"""Registro de tempo de resposta e falhas das integrações."""
import logging
import time
from contextlib import contextmanager

from .. import database

log = logging.getLogger("integracao")


@contextmanager
def timed(source: str, operation: str):
    """Mede uma chamada externa e grava em logs/integracoes.log e na tabela app_log."""
    t0 = time.perf_counter()
    try:
        yield
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        log.error("%s %s FALHA em %dms: %s", source, operation, ms, e)
        database.add_app_log("ERROR", source, f"{operation}: {e}", ms)
        raise
    ms = int((time.perf_counter() - t0) * 1000)
    log.info("%s %s ok em %dms", source, operation, ms)
    database.add_app_log("INFO", source, operation, ms)
