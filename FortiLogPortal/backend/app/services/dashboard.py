"""Dados do dashboard inicial.

Visão FortiAnalyzer: calculada a partir de buscas reais de bloqueio nas últimas N
horas (filtro web + tráfego negado + aplicações), com cache para não sobrecarregar o FAZ.
Visão Vision One e estatísticas: a partir do histórico local (SQLite).
"""
from collections import Counter
from datetime import datetime, timedelta

from .. import database
from ..config import settings
from .faz_filters import LogQuery
from .logsearch import blocked_search


def faz_overview(hours: int = 24, adom: str | None = None, refresh: bool = False) -> dict:
    hours = max(1, min(hours, 168))
    adom = adom or settings.faz_default_adom
    key = f"dash:faz:{adom}:{hours}"
    if not refresh:
        hit = database.cache_get(key)
        if hit:
            hit["cache"] = True
            return hit
    end = datetime.now().replace(second=0, microsecond=0)
    q = LogQuery(adom=adom, start=end - timedelta(hours=hours), end=end, limit=settings.faz_max_results)
    res = blocked_search(q, logtypes=("webfilter", "traffic", "app-ctrl"))
    rows = res["rows"]
    sites = Counter(r["site"] or r["ip_destino"] for r in rows if r["tipo_log"] in ("webfilter", "app-ctrl", "dns")
                    and (r["site"] or r["ip_destino"]))
    users = Counter(r["usuario"] for r in rows if r["usuario"])
    regras = Counter(r["regra"] for r in rows if r["regra"])
    fws = Counter(r["firewall"] for r in rows if r["firewall"])
    cats = Counter(r["categoria"] for r in rows if r["categoria"])
    out = {
        "periodo_horas": hours,
        "amostra": len(rows),
        "total_bloqueios": res["total"],
        "sites_mais_bloqueados": sites.most_common(10),
        "usuarios_mais_bloqueados": users.most_common(10),
        "regras_mais_acionadas": regras.most_common(10),
        "firewalls_mais_eventos": fws.most_common(10),
        "categorias": cats.most_common(8),
        "erros": res.get("erros", {}),
        "atualizado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cache": False,
    }
    database.cache_set(key, out, ttl=max(settings.cache_ttl, 300))
    return out


def local_overview() -> dict:
    return {"visionone": database.ioc_dashboard(), "estatisticas": database.history_stats(14)}
