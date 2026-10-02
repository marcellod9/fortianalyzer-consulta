"""Configuração lida de variáveis de ambiente / config/.env.

Credenciais nunca ficam no código: só em config/.env (fora do git) ou em
variáveis de ambiente do Windows.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[2]  # .../FortiLogPortal
ENV_FILE = Path(os.getenv("PORTAL_ENV_FILE", BASE_DIR / "config" / ".env"))
load_dotenv(ENV_FILE, override=False)


def _bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("true", "1", "yes", "sim")


def _verify(name: str):
    """true/false ou caminho para um bundle de CA."""
    v = os.getenv(name, "true").strip()
    if v.lower() in ("true", "1", "yes", "sim"):
        return True
    if v.lower() in ("false", "0", "no", "nao", "não"):
        return False
    return v


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass
class Settings:
    host: str = field(default_factory=lambda: os.getenv("PORTAL_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _int("PORTAL_PORT", 8000))
    log_level: str = field(default_factory=lambda: os.getenv("PORTAL_LOG_LEVEL", "INFO").upper())
    demo: bool = field(default_factory=lambda: _bool("PORTAL_DEMO"))
    cache_ttl: int = field(default_factory=lambda: _int("PORTAL_CACHE_TTL", 600))

    faz_url: str = field(default_factory=lambda: os.getenv("FAZ_URL", "").rstrip("/"))
    faz_token: str = field(default_factory=lambda: os.getenv("FAZ_API_TOKEN", ""))
    faz_verify: object = field(default_factory=lambda: _verify("FAZ_VERIFY_TLS"))
    faz_default_adom: str = field(default_factory=lambda: os.getenv("FAZ_DEFAULT_ADOM", "root"))
    faz_max_results: int = field(default_factory=lambda: _int("FAZ_MAX_RESULTS", 1000))
    faz_search_timeout: int = field(default_factory=lambda: _int("FAZ_SEARCH_TIMEOUT", 120))
    faz_parallel_searches: int = field(default_factory=lambda: _int("FAZ_PARALLEL_SEARCHES", 1))
    # Relatórios: eventos lidos por tipo de log para montar os gráficos (os mais recentes do período)
    report_max_rows: int = field(default_factory=lambda: max(100, min(_int("REPORT_MAX_ROWS", 5000), 50000)))
    # relatório filtrado (usuário, IP, site, aplicação): lê mais, para a lista de usuários/destinos sair completa
    report_max_rows_filtered: int = field(default_factory=lambda: max(100, min(_int("REPORT_MAX_ROWS_FILTRADO", 20000), 100000)))

    v1_base_url: str = field(default_factory=lambda: os.getenv("V1_BASE_URL", "https://api.xdr.trendmicro.com").rstrip("/"))
    v1_token: str = field(default_factory=lambda: os.getenv("V1_API_TOKEN", ""))
    v1_verify: object = field(default_factory=lambda: _verify("V1_VERIFY_TLS"))
    v1_lookback_days: int = field(default_factory=lambda: _int("V1_LOOKBACK_DAYS", 30))
    v1_sandbox_enabled: bool = field(default_factory=lambda: _bool("V1_SANDBOX_ENABLED"))
    # Consultas (sintaxe TMV1-Query, campo:"valor") usadas para achar detecções de um indicador.
    # {v} é substituído pelo indicador validado. Ajuste os campos se o seu tenant usar outros.
    v1_query_url: str = field(default_factory=lambda: os.getenv("V1_DETECTION_QUERY_URL", 'request:"{v}"'))
    v1_query_domain: str = field(default_factory=lambda: os.getenv("V1_DETECTION_QUERY_DOMAIN", 'request:"*{v}*"'))
    v1_query_ip: str = field(default_factory=lambda: os.getenv("V1_DETECTION_QUERY_IP", 'dst:"{v}" or src:"{v}"'))

    # ---- Login (SSO Microsoft Entra ID) ----
    # off = sem login (POC local, um usuário); entra = exige login Microsoft com MFA (Acesso Condicional)
    auth_mode: str = field(default_factory=lambda: os.getenv("AUTH_MODE", "off").strip().lower())
    entra_tenant_id: str = field(default_factory=lambda: os.getenv("ENTRA_TENANT_ID", "").strip())
    entra_client_id: str = field(default_factory=lambda: os.getenv("ENTRA_CLIENT_ID", "").strip())
    entra_client_secret: str = field(default_factory=lambda: os.getenv("ENTRA_CLIENT_SECRET", ""))
    # alternativa ao segredo (recomendada pela Microsoft): certificado .pem com a chave privada + thumbprint
    entra_cert_path: str = field(default_factory=lambda: os.getenv("ENTRA_CERT_PATH", "").strip())
    entra_cert_thumbprint: str = field(default_factory=lambda: os.getenv("ENTRA_CERT_THUMBPRINT", "").strip())
    entra_redirect_uri: str = field(default_factory=lambda: os.getenv("ENTRA_REDIRECT_URI", "").strip())
    # opcional: contexto de autenticação (ex.: c1) que o Acesso Condicional liga ao MFA; o portal exige o claim acrs
    entra_auth_context: str = field(default_factory=lambda: os.getenv("ENTRA_AUTH_CONTEXT", "").strip())
    # login mais antigo que isso (minutos) pede autenticação de novo na Microsoft
    entra_max_age_min: int = field(default_factory=lambda: max(5, _int("ENTRA_MAX_AGE_MIN", 480)))
    # e-mails (UPN) dos administradores do portal, separados por vírgula
    portal_admins: tuple = field(default_factory=lambda: tuple(
        x.strip().lower() for x in os.getenv("PORTAL_ADMINS", "").split(",") if x.strip()))
    # funções de aplicativo (App roles) do Entra que dão acesso, sem cadastro no portal
    role_admin: str = field(default_factory=lambda: os.getenv("ENTRA_ROLE_ADMIN", "Portal.Admin").strip())
    role_reports: str = field(default_factory=lambda: os.getenv("ENTRA_ROLE_RELATORIOS", "Relatorios.Emitir").strip())
    session_hours: int = field(default_factory=lambda: max(1, min(_int("PORTAL_SESSION_HOURS", 8), 24)))
    session_idle_min: int = field(default_factory=lambda: max(5, min(_int("PORTAL_SESSION_IDLE_MIN", 60), 480)))

    db_path: Path = field(default_factory=lambda: Path(os.getenv("PORTAL_DB", BASE_DIR / "database" / "fortilogportal.db")))
    log_dir: Path = BASE_DIR / "logs"
    export_dir: Path = BASE_DIR / "exports"
    cache_dir: Path = BASE_DIR / "cache"

    @property
    def faz_configured(self) -> bool:
        return bool(self.faz_url and self.faz_token)

    @property
    def auth_enabled(self) -> bool:
        return self.auth_mode == "entra"

    @property
    def redirect_uri(self) -> str:
        return self.entra_redirect_uri or f"http://localhost:{self.port}/auth/callback"

    @property
    def v1_configured(self) -> bool:
        return bool(self.v1_base_url and self.v1_token)

    def public_summary(self) -> dict:
        """Resumo seguro para a tela de configuração (sem segredos)."""
        return {
            "demo": self.demo,
            "faz_url": self.faz_url,
            "faz_token_definido": bool(self.faz_token),
            "faz_verify_tls": self.faz_verify if isinstance(self.faz_verify, bool) else "CA personalizada",
            "faz_default_adom": self.faz_default_adom,
            "faz_max_results": self.faz_max_results,
            "report_max_rows": self.report_max_rows,
            "report_max_rows_filtered": self.report_max_rows_filtered,
            "v1_base_url": self.v1_base_url,
            "v1_token_definido": bool(self.v1_token),
            "v1_lookback_days": self.v1_lookback_days,
            "v1_sandbox_enabled": self.v1_sandbox_enabled,
            "cache_ttl": self.cache_ttl,
            "auth_mode": self.auth_mode,
            "entra_tenant_id": self.entra_tenant_id,
            "entra_client_id": self.entra_client_id,
            "entra_credencial": "certificado" if self.entra_cert_path else ("segredo" if self.entra_client_secret else "não definida"),
            "entra_redirect_uri": self.redirect_uri,
            "entra_auth_context": self.entra_auth_context,
            "portal_admins": len(self.portal_admins),
            "db_path": str(self.db_path),
            "env_file": str(ENV_FILE),
        }


settings = Settings()
