"""Pesquisas no FortiAnalyzer já normalizadas para o portal (com cache e histórico)."""
import hashlib
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from .. import database
from ..config import settings
from . import explain
from .faz_filters import BLOCK_ACTIONS, SAFE_NAME, LogQuery
from .fortianalyzer import get_client


def _cache_key(q: LogQuery) -> str:
    raw = json.dumps(q.model_dump(mode="json"), sort_keys=True)
    return "faz3:" + hashlib.sha1(raw.encode()).hexdigest()


def run_query(q: LogQuery, use_cache: bool = True, save_cache: bool = True, policy_names: bool = True) -> dict:
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
    if policy_names:
        fill_policy_names(rows, q)
    out = {
        "total": res["total"], "returned": len(rows), "filter": q.filter_expr(), "logtype": q.logtype,
        "mais": bool(res.get("mais")) or res["total"] > len(rows),  # o período tem mais eventos do que os lidos
        "bloqueados": sum(1 for r in rows if r["bloqueado"]), "rows": rows, "cache": False,
    }
    if save_cache:
        database.cache_set(key, out)
    return out


POLICY_LOOKUPS_PER_QUERY = 5


def fill_policy_names(rows: list[dict], q: LogQuery) -> None:
    """Logs de filtro web/DNS/aplicação trazem só o número da regra (policyid), sem o nome.

    O nome vem dos logs de tráfego: cada nome visto fica salvo por firewall/vdom no banco e,
    para regras ainda desconhecidas, faz uma busca curta de tráfego (1 linha) por regra.
    """
    learned = {}
    for r in rows:
        key = explain.policy_key(r)
        name = (r.get("log_original") or {}).get("policyname")
        if key and name:
            learned[key] = name
    database.policy_names_set(learned)
    missing = {k for r in rows if (k := explain.policy_key(r)) and not (r.get("log_original") or {}).get("policyname")}
    if not missing:
        return
    names = database.policy_names_get(missing)
    unknown = sorted(missing - names.keys())[:POLICY_LOOKUPS_PER_QUERY]
    if unknown and q.logtype != "traffic":
        found = {}
        for dev_vd, pid in unknown:
            devname = dev_vd.split("/", 1)[0]
            flt = f"policyid={pid}" + (f' and devname="{devname}"' if SAFE_NAME.match(devname) else "")
            try:
                res = get_client().search_logs(adom=q.adom, logtype="traffic", start=q.faz_time("start"),
                                               end=q.faz_time("end"), filter_expr=flt, devices=q.devices, limit=1)
            except Exception:
                continue  # sem o nome, a coluna mostra só o número
            name = next((lg.get("policyname") for lg in res["logs"] if lg.get("policyname")), None)
            if name:
                found[(dev_vd, pid)] = name
        database.policy_names_set(found)
        names.update(found)
    for r in rows:
        key = explain.policy_key(r)
        if key in names and not (r.get("log_original") or {}).get("policyname"):
            explain.set_policy_name(r, names[key])


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
    # Padrão: uma busca por vez. Buscas simultâneas do mesmo admin REST geram erros
    # intermitentes no FAZ ("sem permissão", "Invalid tid"). Ajustável em FAZ_PARALLEL_SEARCHES.
    workers = max(1, min(settings.faz_parallel_searches, len(queries) or 1))
    with ThreadPoolExecutor(max_workers=workers) as ex:
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
