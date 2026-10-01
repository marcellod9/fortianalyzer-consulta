"""Pesquisas no FortiAnalyzer já normalizadas para o portal (com cache e histórico)."""
import hashlib
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from .. import database
from . import explain
from .faz_filters import BLOCK_ACTIONS, LogQuery
from .fortianalyzer import get_client


def _cache_key(q: LogQuery) -> str:
    raw = json.dumps(q.model_dump(mode="json"), sort_keys=True)
    return "faz:" + hashlib.sha1(raw.encode()).hexdigest()


def run_query(q: LogQuery, use_cache: bool = True) -> dict:
    key = _cache_key(q)
    if use_cache:
        hit = database.cache_get(key)
        if hit:
            hit["cache"] = True
            return hit
    res = get_client().search_logs(
        adom=q.adom, logtype=q.logtype, start=q.faz_time("start"), end=q.faz_time("end"),
        filter_expr=q.filter_expr(), devices=q.devices, limit=q.limit,
    )
    rows = [explain.normalize(lg, q.logtype) for lg in res["logs"]]
    out = {
        "total": res["total"], "returned": len(rows), "filter": q.filter_expr(), "logtype": q.logtype,
        "bloqueados": sum(1 for r in rows if r["bloqueado"]), "rows": rows, "cache": False,
    }
    database.cache_set(key, out)
    return out


def blocked_search(base: LogQuery, logtypes=("webfilter", "traffic", "app-ctrl", "dns")) -> dict:
    """Procura bloqueios em vários tipos de log em paralelo e junta por data."""
    queries = []
    for lt in logtypes:
        if lt not in BLOCK_ACTIONS:
            continue
        data = base.model_dump()
        data.update({"logtype": lt, "only_blocked": True, "action": None})
        if lt in ("traffic", "dns"):
            data["url"] = None  # campo url só existe nos logs de filtro web / app
        queries.append(LogQuery(**data))

    rows, total, errors, filtros = [], 0, {}, {}
    with ThreadPoolExecutor(max_workers=len(queries) or 1) as ex:
        futures = {ex.submit(run_query, q): q for q in queries}
        for fut, q in futures.items():
            filtros[q.logtype] = q.filter_expr()
            try:
                r = fut.result()
                rows.extend(r["rows"])
                total += r["total"]
            except Exception as e:  # um tipo de log falhar não impede os outros
                errors[q.logtype] = str(e)
    rows.sort(key=lambda r: r["data_hora"], reverse=True)
    rows = rows[: base.limit]
    return {"total": total, "returned": len(rows), "bloqueados": len(rows), "rows": rows,
            "filtros": filtros, "erros": errors}


def store_result(kind: str, title: str, columns: list[tuple[str, str]], rows: list[dict], meta: dict | None = None) -> str:
    """Guarda o resultado como temporário para exportação (CSV/XLSX/PDF)."""
    rid = uuid.uuid4().hex
    database.temp_set(f"result:{rid}", {"kind": kind, "title": title, "columns": columns, "rows": rows,
                                        "meta": meta or {}, "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    return rid
