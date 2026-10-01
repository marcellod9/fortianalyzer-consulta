"""FortiLogPortal - aplicação FastAPI.

Executar:  python backend\\run.py   (ou scripts\\start.bat)
"""
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, database
from .config import BASE_DIR, settings
from .logging_setup import setup_logging
from .routers import api, pages
from .services import fortianalyzer, visionone

setup_logging()
log = logging.getLogger("portal")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _startup()
    yield
    fortianalyzer.reset_client()
    visionone.reset_client()


def _startup():
    database.init_db()
    database.cache_purge()
    log.info("FortiLogPortal %s iniciado (demo=%s, FAZ=%s, Vision One=%s)", __version__, settings.demo,
             settings.faz_url or "não configurado", settings.v1_base_url if settings.v1_token else "não configurado")
    if settings.demo:
        log.warning("MODO DEMONSTRAÇÃO ATIVO: os dados exibidos são simulados (PORTAL_DEMO=true).")


app = FastAPI(title="FortiLogPortal", version=__version__, lifespan=lifespan,
              description="Portal de consultas de segurança (FortiAnalyzer + Trend Vision One) - POC Marista Brasil")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend" / "static")), name="static")
app.include_router(api.router)
app.include_router(pages.router)


@app.middleware("http")
async def _timing(request: Request, call_next):
    t0 = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        log.exception("erro não tratado em %s %s", request.method, request.url.path)
        database.add_app_log("ERROR", "portal", f"{request.method} {request.url.path}: erro não tratado")
        return JSONResponse({"detail": "Erro interno. Consulte logs\\app.log."}, status_code=500)
    ms = int((time.perf_counter() - t0) * 1000)
    if request.url.path.startswith("/api/"):
        log.info("%s %s -> %s em %dms", request.method, request.url.path, response.status_code, ms)
    response.headers["X-Response-Time-ms"] = str(ms)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.exception_handler(RequestValidationError)
async def _validation(request: Request, exc: RequestValidationError):
    msgs = []
    for e in exc.errors():
        field = ".".join(str(x) for x in e.get("loc", []) if x not in ("body", "query", "path"))
        msg = str(e.get("msg", "")).replace("Value error, ", "")
        msgs.append(f"{field}: {msg}" if field else msg)
    return JSONResponse({"detail": "; ".join(msgs) or "Dados inválidos"}, status_code=422)
