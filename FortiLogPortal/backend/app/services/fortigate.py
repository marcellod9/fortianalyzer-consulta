"""Classificação FortiGuard de um site perguntada a um FortiGate (API REST do FortiOS).

API oficial: GET /api/v2/monitor/utm/rating-lookup?url=<site>. Dois caminhos:
1. pelo FortiAnalyzer (exec /sys/proxy/json repassa a chamada a um FortiGate gerenciado), com o token do FAZ que o
   portal já usa; o FortiGate é FAZ_RATING_DEVICE ou o primeiro da lista;
2. direto num FortiGate, com FGT_URL e FGT_API_TOKEN no config/.env (quando o caminho 1 não funcionar).
O FortiGate consulta o FortiGuard e devolve a categoria mesmo de um site que ninguém acessou, ao contrário
dos logs do FortiAnalyzer, que só têm a categoria dos sites acessados.

"""
from typing import Any
from urllib.parse import quote

import requests

from .. import database
from ..config import settings
from .telemetry import timed

TIMEOUT = 15
# Campos de texto com o nome da categoria, do mais específico ao mais genérico (variam entre versões do FortiOS).
# Em algumas versões um campo traz o grupo (ex.: "General Interest - Personal") e outro a categoria (ex.: "Education"):
# o grupo nunca é usado como categoria.
CATEGORY_FIELDS = ("subcategory", "sub_category", "subcategory_desc", "category_desc", "catdesc", "category_name",
                   "categoryName", "rating", "category")
GROUP_FIELDS = ("group", "group_desc", "group_name", "groupName", "category_group", "catgroup")
# grupos do FortiGuard Web Filter (nomes oficiais, para reconhecer o grupo quando vier num campo "category")
FORTIGUARD_GROUPS = {"potentially liable", "adult/mature content", "bandwidth consuming", "security risk",
                     "general interest - personal", "general interest - business", "unrated", "custom categories"}


class FgtError(Exception):
    pass


PROXY_OFF_KEY = "fgt:proxy-off"   # o FAZ recusou o proxy: não tenta de novo por 1 h
PROXY_OFF_TTL = 3600


def configured() -> bool:
    return bool(settings.fgt_url and settings.fgt_token)


def proxy_available() -> bool:
    return settings.faz_configured and not settings.demo and database.cache_get(PROXY_OFF_KEY) is None


def rating_via_faz(host: str) -> dict:
    """rating-lookup repassado pelo FortiAnalyzer ao FortiGate gerenciado."""
    from .fortianalyzer import FazError, get_client
    faz, adom = get_client(), settings.faz_default_adom
    try:
        device = settings.faz_rating_device or next((d["name"] for d in faz.list_devices(adom) if d.get("name")), None)
        if not device:
            raise FgtError("nenhum FortiGate na ADOM para repassar a consulta")
        data = faz.proxy_fortigate(adom, device, f"/api/v2/monitor/utm/rating-lookup?url={quote(host, safe='')}")
    except FazError as e:
        database.cache_set(PROXY_OFF_KEY, str(e), ttl=PROXY_OFF_TTL)
        raise FgtError(f"o FortiAnalyzer não repassou a consulta ao FortiGate ({e})") from e
    data = data if isinstance(data, dict) else {"results": data}
    out = parse_rating(data)
    if not out["categoria"] and out["categoria_id"] is None:
        raise FgtError(f"o FortiGate não devolveu a categoria do site pelo FortiAnalyzer (resposta: {str(_brief(data))[:300]})")
    return {**out, "via": f"FortiAnalyzer > {device}", "resposta": _brief(data)}


def _items(results: Any) -> list[dict]:
    if isinstance(results, dict):
        return [results]
    return [r for r in results or [] if isinstance(r, dict)] if isinstance(results, list) else []


def _text(v: Any) -> str | None:
    return v.strip() if isinstance(v, str) and v.strip() else None


def parse_rating(data: dict) -> dict:
    """Categoria, grupo e id da resposta do rating-lookup; tolerante ao formato de cada versão."""
    for item in _items(data.get("results")):
        texts = {k: _text(v) for k, v in item.items() if _text(v)}
        group = next((texts[k] for k in GROUP_FIELDS if k in texts), None)
        names = [texts[k] for k in CATEGORY_FIELDS if k in texts]
        # outros campos de texto com "cat" no nome (ex.: "cat_desc"), depois dos conhecidos
        names += [v for k, v in texts.items() if "cat" in k.lower() and k not in CATEGORY_FIELDS and k not in GROUP_FIELDS]
        cats = [n for n in names if n.lower() not in FORTIGUARD_GROUPS and n != group]
        if not group:
            group = next((n for n in names if n.lower() in FORTIGUARD_GROUPS and n.lower() != "unrated"), None)
        name = cats[0] if cats else next((n for n in names if n.lower() == "unrated"), None)
        cid = next((item[k] for k in ("category_id", "catid", "category", "rating_id") if isinstance(item.get(k), int)), None)
        if name or cid is not None:
            return {"categoria": name, "categoria_id": cid, "grupo": group}
    return {"categoria": None, "categoria_id": None, "grupo": None}


def _brief(data: Any) -> Any:
    """Resposta do FortiGate resumida para os Detalhes técnicos (ajuda a conferir os campos de cada versão)."""
    items = _items(data.get("results")) if isinstance(data, dict) else []
    return items[:1] or str(data)[:500]


def test_lookup(host: str = "www.fortinet.com") -> dict:
    """Teste da tela Configuração: consulta um site conhecido pelo caminho em uso, sem cache."""
    if configured():
        r = rating_lookup(host)
        return {"site": host, "categoria": r["categoria"], "grupo": r.get("grupo"), "categoria_id": r["categoria_id"],
                "via": f"FortiGate direto ({settings.fgt_url})", "resposta": r.get("resposta")}
    if not settings.faz_configured:
        raise FgtError("Nem o FortiAnalyzer nem um FortiGate (FGT_URL e FGT_API_TOKEN) estão configurados.")
    database.cache_delete(PROXY_OFF_KEY)
    r = rating_via_faz(host)
    return {"site": host, "categoria": r["categoria"], "grupo": r.get("grupo"), "categoria_id": r["categoria_id"],
            "via": r["via"], "resposta": r.get("resposta")}


def _snippet(resp) -> str:
    text = " ".join((resp.text or "").split())[:160]
    server = resp.headers.get("Server") or ""
    return " · ".join(v for v in (f"servidor {server}" if server else "", f"resposta: {text}" if text else "") if v)


def rating_lookup(host: str, session: requests.Session | None = None) -> dict:
    """GET com ?url= (FortiOS 7.x); se o FortiGate recusar o método (405), tenta POST com {"url": [site]}."""
    http = session or requests
    url = f"{settings.fgt_url}/api/v2/monitor/utm/rating-lookup"
    headers = {"Authorization": f"Bearer {settings.fgt_token}"}
    tries = []
    try:
        with timed("fortigate", "monitor/utm/rating-lookup"):
            resp = http.get(url, params={"url": host}, headers=headers, verify=settings.fgt_verify, timeout=TIMEOUT)
            tries.append(f"GET {resp.status_code}")
            if resp.status_code == 405:
                resp = http.post(url, json={"url": [host]}, headers=headers, verify=settings.fgt_verify, timeout=TIMEOUT)
                tries.append(f"POST {resp.status_code}")
    except requests.exceptions.SSLError as e:
        raise FgtError("Falha de certificado TLS ao conectar no FortiGate. Ajuste FGT_VERIFY_TLS.") from e
    except requests.exceptions.RequestException as e:
        raise FgtError(f"Não foi possível conectar ao FortiGate: {e}") from e
    if resp.status_code in (401, 403):
        raise FgtError(f"FortiGate recusou o token (HTTP {resp.status_code}). Confira FGT_API_TOKEN, o perfil do "
                       "administrador REST API e os Trusted Hosts.")
    if resp.status_code >= 400:
        detail = _snippet(resp)
        hint = (" Confira se FGT_URL aponta para a porta de administração HTTPS do FortiGate (System > Settings > "
                "HTTPS port), e não para o portal da VPN SSL." if resp.status_code in (404, 405) else "")
        raise FgtError(f"FortiGate respondeu HTTP {resp.status_code} na consulta de classificação FortiGuard "
                       f"({', '.join(tries)}{'; ' + detail if detail else ''}).{hint}")
    try:
        data = resp.json()
    except ValueError as e:
        raise FgtError("Resposta inválida do FortiGate na consulta de classificação FortiGuard.") from e
    out = parse_rating(data)
    if not out["categoria"] and out["categoria_id"] is None:
        raise FgtError(f"O FortiGate não devolveu a categoria do site (resposta: {str(_brief(data))[:300]}).")
    return {**out, "resposta": _brief(data)}
