import os
from dataclasses import dataclass


def _bool_or_path(value: str):
    v = value.strip().lower()
    if v in ("true", "1", "yes", "sim"):
        return True
    if v in ("false", "0", "no", "nao", "não"):
        return False
    return value  # caminho para um bundle de CA


@dataclass(frozen=True)
class Settings:
    faz_url: str = os.getenv("FAZ_URL", "").rstrip("/")
    api_token: str = os.getenv("FAZ_API_TOKEN", "")
    verify_tls: object = _bool_or_path(os.getenv("FAZ_VERIFY_TLS", "true"))
    default_adom: str = os.getenv("FAZ_DEFAULT_ADOM", "root")
    max_results: int = int(os.getenv("FAZ_MAX_RESULTS", "1000"))
    search_timeout: int = int(os.getenv("FAZ_SEARCH_TIMEOUT", "120"))
    mock: bool = os.getenv("FAZ_MOCK", "false").lower() in ("true", "1", "yes", "sim")


settings = Settings()
