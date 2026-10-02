import getpass
import logging
import re
import time
from contextlib import contextmanager

from fastapi import HTTPException, Request

from .. import database
from ..services.fortianalyzer import FazError
from ..services.reputation import IndicatorError
from ..services.visionone import V1Error

audit = logging.getLogger("auditoria")
SAFE_USER = re.compile(r"^[\w.\-@\\ ]{1,64}$")

try:
    OS_USER = getpass.getuser()
except Exception:  # pragma: no cover
    OS_USER = "local"


def who(request: Request) -> str:
    """Usuário da consulta: o e-mail do login Microsoft (AUTH_MODE=entra). Sem login, o nome informado
    na interface (header X-Portal-User) ou o usuário do Windows que iniciou o portal."""
    user = getattr(request.state, "user", None)
    if user:
        return user.upn
    u = (request.headers.get("x-portal-user") or "").strip()
    return u if u and SAFE_USER.match(u) else OS_USER


@contextmanager
def tracked(request: Request, query_type: str, term: str, params: dict | None = None):
    """Mede, audita e grava no histórico. O bloco preenche info['count'], info['blocked'], info['summary']."""
    user = who(request)
    info = {"count": 0, "blocked": 0, "summary": ""}
    t0 = time.perf_counter()
    audit.info("usuario=%s tipo=%s termo=%r", user, query_type, term)
    try:
        yield info
    except (FazError, V1Error) as e:
        ms = int((time.perf_counter() - t0) * 1000)
        database.add_history(user, query_type, term, "erro", params=params, summary=str(e), duration_ms=ms)
        raise HTTPException(502, str(e))
    except (IndicatorError, ValueError) as e:
        ms = int((time.perf_counter() - t0) * 1000)
        database.add_history(user, query_type, term, "invalida", params=params, summary=str(e), duration_ms=ms)
        raise HTTPException(400, str(e))
    ms = int((time.perf_counter() - t0) * 1000)
    database.add_history(user, query_type, term, "ok", params=params, result_count=info["count"],
                         blocked_count=info["blocked"], summary=info["summary"], duration_ms=ms)
