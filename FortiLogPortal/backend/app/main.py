"""FortiLogPortal - aplicação FastAPI.

Executar:  python backend\\run.py   (ou scripts\\start.bat)
"""
import logging
import time
from contextlib import asynccontextmanager
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, database
from .config import BASE_DIR, settings
from .logging_setup import setup_logging
from .routers import api, auth as auth_router, pages
from .services import auth, fortianalyzer, visionone

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
    if settings.auth_enabled:
        log.info("Login Microsoft Entra ID ativo (redirect %s, MFA pelo Acesso Condicional%s)", settings.redirect_uri,
                 f" + contexto {settings.entra_auth_context}" if settings.entra_auth_context else "")
        for p in auth.config_problems():
            log.warning("Login: %s", p)
    else:
        log.warning("Login desativado (AUTH_MODE=off): qualquer pessoa com acesso a este computador usa o portal.")
    if settings.demo:
        log.warning("MODO DEMONSTRAÇÃO ATIVO: os dados exibidos são simulados (PORTAL_DEMO=true).")


app = FastAPI(title="FortiLogPortal", version=__version__, lifespan=lifespan,
              description="Portal de consultas de segurança (FortiAnalyzer + Trend Vision One) - POC Marista Brasil")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend" / "static")), name="static")
app.include_router(auth_router.router)
app.include_router(api.router)
app.include_router(pages.router)


PUBLIC_PREFIXES = ("/static/", "/auth/")
PUBLIC_PATHS = {"/api/health", "/favicon.ico"}
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def _login(request: Request, call_next):
    """Com AUTH_MODE=entra, tudo exige sessão (exceto login e arquivos estáticos)."""
    request.state.user = None
    if not settings.auth_enabled:
        return await call_next(request)
    path = request.url.path
    if path.startswith(PUBLIC_PREFIXES) or path in PUBLIC_PATHS:
        return await call_next(request)
    user = auth.session_user(request.cookies.get(auth.SESSION_COOKIE))
    if path.startswith("/api/") or path.startswith("/docs") or path.startswith("/openapi"):
        if not user:
            return JSONResponse({"detail": "Sessão expirada. Entre de novo."}, status_code=401)
        # cookie SameSite=Lax + cabeçalho próprio: um site de fora não consegue disparar ações em nome do usuário
        if request.method in UNSAFE and request.headers.get("x-flp-request") != "1":
            return JSONResponse({"detail": "Requisição recusada (origem não confirmada)."}, status_code=403)
    elif not user:
        nxt = path + (f"?{request.url.query}" if request.url.query else "")
        origin = auth.redirect_origin()
        if f"{request.url.scheme}://{request.url.netloc}" != origin:
            return RedirectResponse(origin + nxt, status_code=303)
        return RedirectResponse("/auth/login?" + urlencode({"next": nxt}), status_code=303)
    request.state.user = user
    return await call_next(request)


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
