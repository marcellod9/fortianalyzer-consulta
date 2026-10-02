"""Login SSO com Microsoft Entra ID (OpenID Connect, fluxo authorization code + PKCE via MSAL).

- O MFA é exigido pelo Acesso Condicional do Entra (política aplicada ao aplicativo do portal);
  opcionalmente o portal também exige o contexto de autenticação (claim acrs) definido em ENTRA_AUTH_CONTEXT.
- O usuário é identificado pelo oid (imutável), nunca só pelo e-mail.
- Sessão no servidor: o navegador recebe um cookie aleatório HttpOnly; no banco fica só o hash dele.
- Quem pode emitir relatórios: função de aplicativo do Entra (ENTRA_ROLE_RELATORIOS), administradores,
  ou usuários incluídos pelo administrador na aba Acessos.
"""
import hashlib
import json
import logging
import re
import secrets
import time
import warnings
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from fastapi import HTTPException, Request

from .. import database
from ..config import settings

log = logging.getLogger("portal.auth")
audit = logging.getLogger("auditoria")

SESSION_COOKIE = "flp_session"
FLOW_COOKIE = "flp_login"
FLOW_TTL = 600
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
UPN = re.compile(r"^[A-Za-z0-9._%+'\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")


class AuthError(Exception):
    """Falha de login com mensagem para o usuário."""


@dataclass
class User:
    oid: str
    upn: str
    name: str
    roles: tuple
    admin: bool
    reports: bool

    def public(self) -> dict:
        return {"nome": self.name, "email": self.upn, "admin": self.admin, "relatorios": self.reports,
                "funcoes": list(self.roles)}


LOCAL_USER = None  # sem login (AUTH_MODE=off): tudo liberado, como na POC local


# ---- configuração --------------------------------------------------------------------------------
def config_problems() -> list[str]:
    s = settings
    p = []
    if s.auth_mode not in ("off", "entra"):
        p.append("AUTH_MODE deve ser off ou entra")
    if not s.auth_enabled:
        return p
    if not GUID.match(s.entra_tenant_id):
        p.append("ENTRA_TENANT_ID deve ser o ID do locatário (GUID) mostrado na Visão geral do Entra ID")
    if not GUID.match(s.entra_client_id):
        p.append("ENTRA_CLIENT_ID deve ser o ID do aplicativo (cliente), um GUID")
    if not (s.entra_client_secret or (s.entra_cert_path and s.entra_cert_thumbprint)):
        p.append("defina ENTRA_CLIENT_SECRET ou ENTRA_CERT_PATH + ENTRA_CERT_THUMBPRINT")
    u = urlsplit(s.redirect_uri)
    if not (u.scheme == "https" or (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1"))) \
            or u.path != "/auth/callback":
        p.append("ENTRA_REDIRECT_URI deve terminar em /auth/callback e usar https (http só em localhost)")
    if not s.portal_admins:
        p.append("PORTAL_ADMINS vazio: ninguém administra os acessos (use a função de aplicativo ou preencha)")
    return p


def redirect_origin() -> str:
    u = urlsplit(settings.redirect_uri)
    return f"{u.scheme}://{u.netloc}"


def _secure_cookie() -> bool:
    return settings.redirect_uri.startswith("https://")


_msal_app = None


def _app():
    """ConfidentialClientApplication do MSAL (biblioteca oficial da Microsoft)."""
    global _msal_app
    if _msal_app is None:
        import msal
        if settings.entra_cert_path:
            with open(settings.entra_cert_path, encoding="utf-8") as f:
                cred = {"private_key": f.read(), "thumbprint": settings.entra_cert_thumbprint}
        else:
            cred = settings.entra_client_secret
        try:
            _msal_app = msal.ConfidentialClientApplication(
                settings.entra_client_id, client_credential=cred,
                authority=f"https://login.microsoftonline.com/{settings.entra_tenant_id}")
        except ValueError as e:
            log.warning("Entra ID: %s", e)
            raise AuthError("A Microsoft não reconheceu o locatário. Confira ENTRA_TENANT_ID em config\\.env "
                            "(ID do diretório na Visão geral do Entra ID).")
    return _msal_app


def reset() -> None:
    global _msal_app
    _msal_app = None


def _claims_challenge() -> str | None:
    if not settings.entra_auth_context:
        return None
    want = {"acrs": {"essential": True, "value": settings.entra_auth_context}}
    return json.dumps({"id_token": want, "access_token": want})


# ---- fluxo de login ------------------------------------------------------------------------------
def safe_next(nxt: str | None) -> str:
    """Só caminhos locais (evita redirecionamento aberto)."""
    if not nxt or not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt or nxt.startswith("/auth/"):
        return "/"
    return nxt[:500]


def start_login(nxt: str) -> tuple[str, str]:
    """Devolve (URL da Microsoft, id do fluxo para o cookie). state, nonce e PKCE ficam no servidor."""
    # response_mode=query: com form_post o retorno é um POST vindo da Microsoft, e o cookie SameSite=Lax do
    # fluxo não chega. O código é de uso único e protegido por PKCE, state e nonce.
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="response_mode=")
        flow = _app().initiate_auth_code_flow(
            scopes=[], redirect_uri=settings.redirect_uri, max_age=settings.entra_max_age_min * 60,
            claims_challenge=_claims_challenge(), response_mode="query")
    if "auth_uri" not in flow:
        raise AuthError(flow.get("error_description") or "Não foi possível iniciar o login")
    flow_id = secrets.token_urlsafe(24)
    database.temp_set(f"authflow:{flow_id}", {"flow": flow, "next": safe_next(nxt)}, ttl=FLOW_TTL)
    return flow["auth_uri"], flow_id


def finish_login(flow_id: str | None, params: dict) -> tuple[dict, str]:
    """Troca o código pelo token, valida e devolve (claims, próximo caminho)."""
    if params.get("error"):
        desc = params.get("error_description") or params["error"]
        raise AuthError(f"A Microsoft recusou o login: {desc}")
    data = database.temp_get(f"authflow:{flow_id}") if flow_id else None
    if not data:
        raise AuthError("O login expirou ou foi aberto em outra janela. Tente de novo.")
    database.temp_set(f"authflow:{flow_id}", None, ttl=1)  # uso único
    try:
        result = _app().acquire_token_by_auth_code_flow(data["flow"], params)
    except ValueError as e:  # state diferente do esperado (CSRF) ou fluxo inválido
        raise AuthError(f"Resposta de login inválida: {e}")
    except RuntimeError as e:  # nonce diferente (replay) ou login antigo demais (max_age)
        log.warning("login recusado: %s", str(e).split("The ID token")[0])
        raise AuthError("A resposta de login não passou na validação (nonce ou tempo de autenticação). Tente de novo.")
    if "error" in result:
        raise AuthError(f"Login não concluído: {result.get('error_description') or result['error']}")
    claims = result.get("id_token_claims") or {}
    for acc in _app().get_accounts():  # o portal não usa os tokens; não ficam em memória
        _app().remove_account(acc)
    check_claims(claims)
    return claims, data["next"]


def check_claims(claims: dict, now: float | None = None) -> None:
    """Valida o ID token. Ele vem direto do endpoint de token da Microsoft por TLS (OIDC Core 3.1.3.7);
    o MSAL confere state, PKCE, nonce e auth_time. Aqui: emissor, público, validade, locatário e MFA."""
    now = now or time.time()
    tid = settings.entra_tenant_id.lower()
    if claims.get("iss", "").lower() != f"https://login.microsoftonline.com/{tid}/v2.0":
        raise AuthError("Emissor do token inesperado.")
    aud = claims.get("aud")
    if (aud if isinstance(aud, str) else "") != settings.entra_client_id:
        raise AuthError("O token não foi emitido para este aplicativo.")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] + 120 < now:
        raise AuthError("Token expirado. Tente de novo.")
    if claims.get("nbf") and claims["nbf"] - 120 > now:
        raise AuthError("Token ainda não é válido; confira o relógio do computador.")
    if claims.get("tid", "").lower() != tid:
        raise AuthError("Conta de outro locatário (tenant). Use sua conta corporativa.")
    if not claims.get("oid"):
        raise AuthError("O token não trouxe o identificador do usuário (oid).")
    ctx = settings.entra_auth_context
    if ctx and ctx not in (claims.get("acrs") or []):
        raise AuthError(f"O login não cumpriu o contexto de autenticação {ctx} (MFA). "
                        "Confira a política de Acesso Condicional ou deixe ENTRA_AUTH_CONTEXT vazio.")


def user_name(claims: dict) -> tuple[str, str]:
    upn = (claims.get("preferred_username") or claims.get("email") or claims.get("upn") or "").lower()
    return upn, claims.get("name") or upn


def create_session(claims: dict, ip: str) -> str:
    upn, name = user_name(claims)
    roles = [r for r in claims.get("roles") or [] if isinstance(r, str)]
    database.user_login(claims["oid"], upn, name)
    token = secrets.token_urlsafe(32)
    database.session_add(_hash(token), claims["oid"], upn, name, roles, ip, settings.session_hours)
    audit.info("login usuario=%s oid=%s ip=%s funcoes=%s", upn, claims["oid"], ip, ",".join(roles))
    database.add_history(upn, "login", upn, "ok", summary=f"Login Microsoft ({', '.join(roles) or 'sem funções'})")
    return token


def end_session(token: str | None) -> None:
    if token:
        s = database.session_get(_hash(token))
        database.session_delete(_hash(token))
        if s:
            audit.info("logout usuario=%s", s["upn"])
            database.add_history(s["upn"], "login", s["upn"], "ok", summary="Saiu do portal")


def logout_url() -> str:
    q = urlencode({"post_logout_redirect_uri": redirect_origin() + "/auth/saiu"})
    return f"https://login.microsoftonline.com/{settings.entra_tenant_id}/oauth2/v2.0/logout?{q}"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---- sessão e permissões --------------------------------------------------------------------------
def build_user(oid: str, upn: str, name: str, roles) -> User:
    roles = tuple(roles)
    admin = settings.role_admin in roles or upn.lower() in settings.portal_admins
    row = database.user_by_oid(oid)
    reports = admin or settings.role_reports in roles or bool(row and row["can_reports"])
    return User(oid, upn, name, roles, admin, reports)


def session_user(token: str | None) -> User | None:
    if not token or len(token) > 100:
        return None
    h = _hash(token)
    s = database.session_get(h)
    now = time.time()
    if not s:
        return None
    if s["expires_at"] < now or s["last_seen"] + settings.session_idle_min * 60 < now:
        database.session_delete(h)
        return None
    if now - s["last_seen"] > 60:
        database.session_touch(h)
    return build_user(s["oid"], s["upn"], s["name"] or s["upn"], s["roles"])


def current(request: Request) -> User | None:
    return getattr(request.state, "user", None)


def can_reports(request: Request) -> bool:
    u = current(request)
    return not settings.auth_enabled or bool(u and u.reports)


def is_admin(request: Request) -> bool:
    u = current(request)
    return not settings.auth_enabled or bool(u and u.admin)


def require_reports(request: Request) -> None:
    if not can_reports(request):
        raise HTTPException(403, "Você não tem permissão para emitir relatórios. Peça ao administrador do portal.")


def require_admin(request: Request) -> None:
    if not is_admin(request):
        raise HTTPException(403, "Somente administradores do portal.")
