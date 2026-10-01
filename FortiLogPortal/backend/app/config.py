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

    db_path: Path = field(default_factory=lambda: Path(os.getenv("PORTAL_DB", BASE_DIR / "database" / "fortilogportal.db")))
    log_dir: Path = BASE_DIR / "logs"
    export_dir: Path = BASE_DIR / "exports"
    cache_dir: Path = BASE_DIR / "cache"

    @property
    def faz_configured(self) -> bool:
        return bool(self.faz_url and self.faz_token)

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
            "v1_base_url": self.v1_base_url,
            "v1_token_definido": bool(self.v1_token),
            "v1_lookback_days": self.v1_lookback_days,
            "v1_sandbox_enabled": self.v1_sandbox_enabled,
            "cache_ttl": self.cache_ttl,
            "db_path": str(self.db_path),
            "env_file": str(ENV_FILE),
        }


settings = Settings()
