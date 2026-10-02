"""Login Microsoft Entra ID e permissão de relatórios (MSAL simulado; nunca acessa a Microsoft)."""
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from app import database
from app.config import settings
from app.main import app
from app.services import auth

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
BASE = "http://localhost:8000"
CSRF = {"X-FLP-Request": "1"}
PERIOD = {"start": "2026-10-01T08:00", "end": "2026-10-01T12:00"}


def claims(oid, upn, name, roles=(), **extra):
    now = int(time.time())
    return {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "aud": CLIENT, "tid": TENANT, "oid": oid,
            "preferred_username": upn, "name": name, "exp": now + 3600, "nbf": now - 10, "roles": list(roles), **extra}


class FakeMsal:
    """Imita o ConfidentialClientApplication: guarda o state e devolve os claims combinados."""
    def __init__(self):
        self.next_claims = None
        self.kwargs = None

    def initiate_auth_code_flow(self, **kw):
        self.kwargs = kw
        return {"auth_uri": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize?state=abc", "state": "abc"}

    def acquire_token_by_auth_code_flow(self, flow, params):
        if params.get("state") != flow["state"]:
            raise ValueError("state mismatch")
        return {"id_token_claims": self.next_claims}

    def get_accounts(self):
        return []

    def remove_account(self, acc):
        pass


@pytest.fixture()
def entra(monkeypatch):
    for k, v in {"auth_mode": "entra", "entra_tenant_id": TENANT, "entra_client_id": CLIENT,
                 "entra_client_secret": "segredo-de-teste", "entra_redirect_uri": f"{BASE}/auth/callback",
                 "entra_auth_context": "", "portal_admins": ("admin@marista.org.br",)}.items():
        monkeypatch.setattr(settings, k, v)
    fake = FakeMsal()
    monkeypatch.setattr(auth, "_app", lambda: fake)
    with database.connect() as c:
        c.execute("DELETE FROM portal_user")
        c.execute("DELETE FROM auth_session")
    return fake


def login(fake, oid, upn, name="Usuário", roles=()):
    c = TestClient(app, base_url=BASE)
    r = c.get("/auth/login?next=/relatorios", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("https://login.microsoftonline.com/")
    fake.next_claims = claims(oid, upn, name, roles)
    r = c.get("/auth/callback?code=x&state=abc", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/relatorios", r.text
    return c


def test_without_session_pages_go_to_login_and_api_is_401(entra):
    c = TestClient(app, base_url=BASE)
    r = c.get("/logs?x=1", follow_redirects=False)
    assert r.status_code == 303 and parse_qs(urlsplit(r.headers["location"]).query)["next"] == ["/logs?x=1"]
    assert c.get("/api/me").status_code == 401
    assert c.get("/api/health").status_code == 200
    assert c.get("/static/js/app.js").status_code == 200


def test_other_host_is_sent_to_the_registered_address(entra):
    c = TestClient(app, base_url="http://127.0.0.1:8000")
    r = c.get("/relatorios", follow_redirects=False)
    assert r.headers["location"] == f"{BASE}/relatorios"
    r = c.get("/auth/login?next=/logs", follow_redirects=False)
    assert r.headers["location"] == f"{BASE}/auth/login?next=%2Flogs"


def test_login_requests_max_age_and_mfa_context(entra, monkeypatch):
    monkeypatch.setattr(settings, "entra_auth_context", "c1")
    TestClient(app, base_url=BASE).get("/auth/login", follow_redirects=False)
    assert entra.kwargs["max_age"] == settings.entra_max_age_min * 60
    assert '"acrs": {"essential": true, "value": "c1"}' in entra.kwargs["claims_challenge"]


def test_user_without_permission_cannot_issue_reports(entra):
    c = login(entra, "oid-n1", "n1@marista.org.br", "Analista N1")
    me = c.get("/api/me").json()
    assert me["email"] == "n1@marista.org.br" and not me["relatorios"] and not me["admin"]
    assert c.get("/relatorios").status_code == 403
    assert "Relatórios" not in c.get("/logs").text.split("<main")[0]
    assert c.post("/api/reports", json={**PERIOD, "tipo": "geral"}, headers=CSRF).status_code == 403
    assert c.get("/api/acessos").status_code == 403
    assert c.get("/configuracao").status_code == 403
    assert c.post("/api/faz/logs", json={**PERIOD, "logtype": "webfilter", "limit": 5}, headers=CSRF).status_code == 200


def test_admin_grants_by_email_before_first_login(entra):
    adm = login(entra, "oid-adm", "admin@marista.org.br", "Admin")
    r = adm.post("/api/acessos", json={"email": "Maria.Souza@marista.org.br"}, headers=CSRF)
    assert r.status_code == 200 and r.json()["oid"] is None
    assert adm.post("/api/acessos", json={"email": "nao-e-email"}, headers=CSRF).status_code == 400

    maria = login(entra, "oid-maria", "maria.souza@marista.org.br", "Maria")
    assert maria.get("/api/me").json()["relatorios"] is True
    assert maria.get("/relatorios").status_code == 200
    r = maria.post("/api/reports", json={**PERIOD, "tipo": "geral"}, headers=CSRF)
    assert r.status_code == 200
    assert database.list_history(5, "relatorio")[0]["username"] == "maria.souza@marista.org.br"

    uid = next(u["id"] for u in adm.get("/api/acessos").json()["usuarios"] if u["oid"] == "oid-maria")
    assert adm.put(f"/api/acessos/{uid}", json={"email": "x@y.zz", "relatorios": False}, headers=CSRF).status_code == 200
    assert maria.get("/relatorios").status_code == 403  # vale na hora, sem novo login
    hist = database.list_history(5, "permissao")
    assert hist[0]["username"] == "admin@marista.org.br" and "retirado" in hist[0]["summary"]

    assert adm.delete(f"/api/acessos/{uid}", headers=CSRF).status_code == 200
    assert maria.get("/api/me").status_code == 401  # removido: sessões encerradas


def test_permission_follows_oid_not_a_reused_email(entra):
    adm = login(entra, "oid-adm", "admin@marista.org.br", "Admin")
    adm.post("/api/acessos", json={"email": "joao@marista.org.br"}, headers=CSRF)
    login(entra, "oid-joao-1", "joao@marista.org.br", "João")
    novo = login(entra, "oid-joao-2", "joao@marista.org.br", "Outro João")
    assert novo.get("/api/me").json()["relatorios"] is False


def test_entra_app_role_gives_reports(entra):
    c = login(entra, "oid-r", "r@marista.org.br", "Com função", roles=[settings.role_reports])
    assert c.get("/api/me").json()["relatorios"] is True


def test_unsafe_api_call_needs_portal_header(entra):
    c = login(entra, "oid-adm", "admin@marista.org.br")
    assert c.post("/api/acessos", json={"email": "a@marista.org.br"}).status_code == 403
    assert c.delete("/api/cache").status_code == 403
    assert c.delete("/api/cache", headers=CSRF).status_code == 200


def test_logout_clears_session_and_signs_out_of_microsoft(entra):
    c = login(entra, "oid-n1", "n1@marista.org.br")
    r = c.get("/auth/logout", follow_redirects=False)
    assert r.headers["location"].startswith(f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/logout?")
    assert c.get("/api/me").status_code == 401


def test_idle_session_expires(entra, monkeypatch):
    c = login(entra, "oid-n1", "n1@marista.org.br")
    with database.connect() as db:
        db.execute("UPDATE auth_session SET last_seen = ?", (time.time() - settings.session_idle_min * 60 - 5,))
    assert c.get("/api/me").status_code == 401


def test_callback_rejects_wrong_state_and_reused_flow(entra):
    c = TestClient(app, base_url=BASE)
    c.get("/auth/login", follow_redirects=False)
    entra.next_claims = claims("o", "a@marista.org.br", "A")
    assert c.get("/auth/callback?code=x&state=outro", follow_redirects=False).status_code == 403
    assert c.get("/auth/callback?code=x&state=abc", follow_redirects=False).status_code == 403  # fluxo já usado
    assert c.get("/auth/callback?error=access_denied&error_description=MFA+recusado").status_code == 403


@pytest.mark.parametrize("change", [{"tid": "99999999-2222-3333-4444-555555555555"}, {"aud": "outro-app"},
                                    {"iss": "https://sts.windows.net/x/"}, {"exp": 1000}, {"oid": ""}])
def test_invalid_tokens_are_refused(entra, change):
    with pytest.raises(auth.AuthError):
        auth.check_claims({**claims("o", "a@b.cc", "A"), **change})


def test_mfa_context_is_required_when_configured(entra, monkeypatch):
    monkeypatch.setattr(settings, "entra_auth_context", "c1")
    with pytest.raises(auth.AuthError):
        auth.check_claims(claims("o", "a@b.cc", "A"))
    auth.check_claims(claims("o", "a@b.cc", "A", acrs=["c1"]))


@pytest.mark.parametrize("nxt,expected", [("/logs?a=1", "/logs?a=1"), ("//evil.com", "/"), ("https://evil.com", "/"),
                                          ("/\\evil.com", "/"), ("/auth/logout", "/"), (None, "/")])
def test_safe_next(nxt, expected):
    assert auth.safe_next(nxt) == expected


def test_config_problems(entra, monkeypatch):
    assert auth.config_problems() == []
    monkeypatch.setattr(settings, "entra_redirect_uri", "http://portal.marista.local/auth/callback")
    monkeypatch.setattr(settings, "entra_client_secret", "")
    assert len(auth.config_problems()) == 2
