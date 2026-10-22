"""Classificação FortiGuard de um site perguntada a um FortiGate (API REST do FortiOS).

API oficial: GET /api/v2/monitor/utm/rating-lookup?url=<site> com o token de um administrador REST API.
O FortiGate consulta o FortiGuard e devolve a categoria mesmo de um site que ninguém acessou, ao contrário
dos logs do FortiAnalyzer, que só têm a categoria dos sites acessados.

Opcional: só é usado com FGT_URL e FGT_API_TOKEN no config/.env (perfil somente leitura).
"""
from typing import Any

import requests

from ..config import settings

TIMEOUT = 15
# campos de texto com o nome da categoria (os nomes variam entre versões do FortiOS)
TEXT_FIELDS = ("category_desc", "catdesc", "category_name", "categoryName", "category")


class FgtError(Exception):
    pass


def configured() -> bool:
    return bool(settings.fgt_url and settings.fgt_token)


def _items(results: Any) -> list[dict]:
    if isinstance(results, dict):
        return [results]
    return [r for r in results or [] if isinstance(r, dict)] if isinstance(results, list) else []


def parse_rating(data: dict) -> dict:
    """Categoria e id da resposta do rating-lookup; tolerante ao formato de cada versão."""
    for item in _items(data.get("results")):
        name = next((str(item[k]).strip() for k in TEXT_FIELDS if isinstance(item.get(k), str) and item[k].strip()), None)
        cid = next((item[k] for k in ("category_id", "category", "catid") if isinstance(item.get(k), int)), None)
        if name or cid is not None:
            return {"categoria": name, "categoria_id": cid}
    return {"categoria": None, "categoria_id": None}


def rating_lookup(host: str, session: requests.Session | None = None) -> dict:
    http = session or requests
    try:
        resp = http.get(f"{settings.fgt_url}/api/v2/monitor/utm/rating-lookup", params={"url": host},
                        headers={"Authorization": f"Bearer {settings.fgt_token}"},
                        verify=settings.fgt_verify, timeout=TIMEOUT)
    except requests.exceptions.SSLError as e:
        raise FgtError("Falha de certificado TLS ao conectar no FortiGate. Ajuste FGT_VERIFY_TLS.") from e
    except requests.exceptions.RequestException as e:
        raise FgtError(f"Não foi possível conectar ao FortiGate: {e}") from e
    if resp.status_code in (401, 403):
        raise FgtError(f"FortiGate recusou o token (HTTP {resp.status_code}). Confira FGT_API_TOKEN, o perfil do "
                       "administrador REST API e os Trusted Hosts.")
    if resp.status_code >= 400:
        raise FgtError(f"FortiGate respondeu HTTP {resp.status_code} na consulta de classificação FortiGuard.")
    try:
        data = resp.json()
    except ValueError as e:
        raise FgtError("Resposta inválida do FortiGate na consulta de classificação FortiGuard.") from e
    out = parse_rating(data)
    if not out["categoria"] and out["categoria_id"] is None:
        raise FgtError("O FortiGate não devolveu a categoria do site.")
    return out
