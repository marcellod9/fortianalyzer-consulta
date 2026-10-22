"""Login Microsoft Entra ID (/auth/*) e administração de acessos (/api/acessos)."""
import hashlib
import logging
import time
from datetime import datetime
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from .. import database
from ..config import settings
from ..services import auth
from .pages import templates

router = APIRouter()
log = logging.getLogger("portal.auth")


def _message(request: Request, title: str, text: str, status: int = 200, login: bool = True):
    return templates.TemplateResponse(request, "auth_msg.html",
                                      {"title": title, "text": text, "login": login}, status_code=status)


def _cookie_opts(max_age: int) -> dict:
    return {"httponly": True, "samesite": "lax", "secure": auth._secure_cookie(), "max_age": max_age, "path": "/"}


@router.get("/auth/login", include_in_schema=False)
def login(request: Request, next: str = "/"):
    if not settings.auth_enabled:
        return RedirectResponse("/", status_code=303)
    nxt = auth.safe_next(next)
    origin = auth.redirect_origin()
    if f"{request.url.scheme}://{request.url.netloc}" != origin:
        # o cookie do login vale só para o endereço da URI de redirecionamento cadastrada no Entra
        return RedirectResponse(f"{origin}/auth/login?{urlencode({'next': nxt})}", status_code=303)
    if auth.session_user(request.cookies.get(auth.SESSION_COOKIE)):
        return RedirectResponse(nxt, status_code=303)
    problems = auth.config_problems()
    if any(not p.startswith("PORTAL_ADMINS") for p in problems):
        return _message(request, "Login não configurado", "Corrija em config\\.env: " + "; ".join(problems), 500, False)
    try:
        url, flow_id = auth.start_login(nxt)
    except auth.AuthError as e:
        return _message(request, "Não foi possível entrar", str(e), 502)
    except Exception:
        log.exception("falha ao iniciar o login")
        database.add_app_log("ERROR", "entra", "falha ao iniciar o login (rede ou configuração)")
        return _message(request, "Não foi possível entrar",
                        "O portal não conseguiu falar com login.microsoftonline.com. Veja logs\\app.log.", 502)
    resp = RedirectResponse(url, status_code=303)
    resp.set_cookie(auth.FLOW_COOKIE, flow_id, **_cookie_opts(auth.FLOW_TTL))
    return resp


@router.get("/auth/callback", include_in_schema=False)
def callback(request: Request):
    if not settings.auth_enabled:
        return RedirectResponse("/", status_code=303)
    params = dict(request.query_params)
    ip = request.client.host if request.client else ""
    try:
        claims, nxt = auth.finish_login(request.cookies.get(auth.FLOW_COOKIE), params)
    except auth.AuthError as e:
        log.warning("login recusado ip=%s: %s", ip, e)
        database.add_app_log("WARNING", "entra", f"login recusado: {e}")
        database.add_history("(login)", "login", ip, "erro", summary=str(e))
        return _message(request, "Login não concluído", str(e), 403)
    except Exception:
        log.exception("falha no retorno do login")
        database.add_app_log("ERROR", "entra", "falha ao concluir o login")
        return _message(request, "Login não concluído", "Erro ao validar o login. Veja logs\\app.log.", 502)
    token = auth.create_session(claims, ip)
    resp = RedirectResponse(nxt, status_code=303)
    resp.delete_cookie(auth.FLOW_COOKIE, path="/")
    resp.set_cookie(auth.SESSION_COOKIE, token, **_cookie_opts(settings.session_hours * 3600))
    return resp


@router.get("/auth/logout", include_in_schema=False)
def logout(request: Request):
    auth.end_session(request.cookies.get(auth.SESSION_COOKIE))
    resp = RedirectResponse(auth.logout_url() if settings.auth_enabled else "/", status_code=303)
    resp.delete_cookie(auth.SESSION_COOKIE, path="/")
    return resp


@router.get("/auth/saiu", include_in_schema=False)
def signed_out(request: Request):
    return _message(request, "Você saiu do portal", "A sessão foi encerrada no portal e na conta Microsoft.")


# ---- usuário atual e administração de acessos --------------------------------------------------
@router.get("/api/me")
def me(request: Request):
    u = auth.current(request)
    if not settings.auth_enabled:
        return {"login": False, "admin": True, "relatorios": True}
    return {"login": True, **u.public()}


class Grant(BaseModel):
    email: str = Field(..., max_length=254)
    relatorios: bool = True


def _row(r: dict) -> dict:
    return {**r, "admin": r["upn"] in settings.portal_admins}


@router.get("/api/acessos")
def list_access(request: Request):
    auth.require_admin(request)
    return {"usuarios": [_row(r) for r in database.user_list()], "login": settings.auth_enabled,
            "funcao_relatorios": settings.role_reports, "funcao_admin": settings.role_admin,
            "admins": list(settings.portal_admins)}


def _audit(request: Request, upn: str, what: str) -> None:
    by = auth.current(request).upn if auth.current(request) else "local"
    auth.audit.info("permissao usuario=%s alvo=%s %s", by, upn, what)
    database.add_history(by, "permissao", upn, "ok", summary=what)


@router.post("/api/acessos")
def grant(g: Grant, request: Request):
    auth.require_admin(request)
    email = g.email.strip().lower()
    if not auth.UPN.match(email):
        raise HTTPException(400, "Informe o e-mail corporativo (UPN), ex.: maria.souza@marista.org.br")
    by = auth.current(request).upn if auth.current(request) else "local"
    r = database.user_set_reports(email, g.relatorios, by)
    _audit(request, email, "relatórios concedido" if g.relatorios else "relatórios retirado")
    return _row(r)


@router.put("/api/acessos/{uid}")
def set_access(uid: int, g: Grant, request: Request):
    auth.require_admin(request)
    r = database.user_get(uid)
    if not r:
        raise HTTPException(404, "Usuário não encontrado")
    by = auth.current(request).upn if auth.current(request) else "local"
    r = database.user_set_reports(r["upn"], g.relatorios, by, uid=uid)
    _audit(request, r["upn"], "relatórios concedido" if g.relatorios else "relatórios retirado")
    return _row(r)


@router.delete("/api/acessos/{uid}")
def remove_access(uid: int, request: Request):
    auth.require_admin(request)
    r = database.user_get(uid)
    if not r:
        raise HTTPException(404, "Usuário não encontrado")
    database.user_delete(uid)
    _audit(request, r["upn"], "removido do portal (sessões encerradas)")
    return {"ok": True}


# ---- quem está logado ----------------------------------------------------------------------------
ACTIVE_SECONDS = 300   # usou o portal nos últimos 5 min (a última atividade é gravada no máximo a cada 1 min)


def _session_id(token_hash: str) -> str:
    """Identificador para a tela: derivado do hash do cookie, nunca o próprio hash."""
    return hashlib.sha256(("sid:" + token_hash).encode()).hexdigest()[:20]


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


@router.get("/api/acessos/sessoes")
def list_sessions(request: Request):
    auth.require_admin(request)
    if not settings.auth_enabled:
        return {"login": False, "sessoes": []}
    token = request.cookies.get(auth.SESSION_COOKIE) or ""
    mine = auth._hash(token) if token else ""
    now = time.time()
    out = []
    for s in database.session_list(settings.session_idle_min * 60):
        idle = max(0, now - s["last_seen"])
        out.append({"id": _session_id(s["token_hash"]), "upn": s["upn"], "nome": s["name"] or s["upn"], "ip": s["ip"] or "",
                    "entrou": _when(s["created_at"]), "ultima_atividade": _when(s["last_seen"]),
                    "ocioso_min": int(idle // 60), "ativo": idle <= ACTIVE_SECONDS,
                    "expira": _when(min(s["expires_at"], s["last_seen"] + settings.session_idle_min * 60)),
                    "voce": s["token_hash"] == mine, "admin": s["upn"] in settings.portal_admins})
    return {"login": True, "sessoes": out, "usuarios": len({s["upn"] for s in out}),
            "inatividade_min": settings.session_idle_min}


@router.delete("/api/acessos/sessoes/{sid}")
def end_session(sid: str, request: Request):
    auth.require_admin(request)
    for s in database.session_list(settings.session_idle_min * 60):
        if _session_id(s["token_hash"]) == sid:
            database.session_delete(s["token_hash"])
            _audit(request, s["upn"], "sessão encerrada pelo administrador")
            return {"ok": True}
    raise HTTPException(404, "Sessão não encontrada (talvez já tenha expirado)")
