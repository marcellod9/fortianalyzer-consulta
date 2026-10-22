"""Pesquisas no FortiAnalyzer já normalizadas para o portal (com cache e histórico)."""
import hashlib
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from .. import database
from ..config import settings
from . import explain
from .faz_filters import BLOCK_ACTIONS, SAFE_NAME, LogQuery
from .fortianalyzer import get_client


def _cache_key(q: LogQuery) -> str:
    raw = json.dumps(q.model_dump(mode="json"), sort_keys=True)
    return "faz3:" + hashlib.sha1(raw.encode()).hexdigest()


def run_query(q: LogQuery, use_cache: bool = True, save_cache: bool = True, policy_names: bool = True,
              keep: bool = False, reuse: bool | None = None) -> dict:
    """Pesquisa oficial do LogView, normalizada.

    keep: guarda os eventos lidos (PORTAL_KEEP_DAYS) e, na próxima consulta igual, busca no FAZ só o trecho
    novo; reuse=False ignora o que estava guardado (o padrão segue use_cache).
    """
    key = _cache_key(q)
    if use_cache:
        hit = database.cache_get(key)
        if hit:
            hit["cache"] = True
            return hit

    def fetch(part: LogQuery) -> dict:
        res = get_client().search_logs(
            adom=part.adom, logtype=part.logtype, start=part.faz_time("start"), end=part.faz_time("end"),
            filter_expr=part.filter_expr(), devices=part.devices, limit=part.limit,
        )
        rows = [explain.normalize(lg, part.logtype) for lg in res["logs"]]
        if policy_names:
            fill_policy_names(rows, part)
        return {"total": res["total"], "returned": len(rows), "rows": rows,
                "mais": bool(res.get("mais")) or res["total"] > len(rows)}  # o período tem mais eventos do que os lidos

    res = incremental(q, fetch, tag=f"p{int(policy_names)}", reuse=use_cache if reuse is None else reuse) if keep else fetch(q)
    rows = res["rows"]
    out = {
        "total": res["total"], "returned": len(rows), "filter": q.filter_expr(), "logtype": q.logtype,
        "mais": res["mais"], "guardados": res.get("guardados", 0),
        "bloqueados": sum(1 for r in rows if r["bloqueado"]), "rows": rows, "cache": False,
    }
    if save_cache:
        database.cache_set(key, out)
    return out


# ---- eventos guardados ------------------------------------------------------------------------
# Um log não muda depois de gravado no FAZ: os eventos lidos ficam no banco local e a consulta seguinte com os
# mesmos filtros só busca o trecho que ainda não foi lido. O trecho novo começa um pouco antes do fim guardado,
# pelos logs que chegam atrasados ao FAZ.
KEEP_PREFIX = "rows1:"
LATE_LOGS = timedelta(minutes=15)


def _keep_key(q: LogQuery, tag: str) -> str:
    data = q.model_dump(mode="json")
    for k in ("start", "end", "limit"):
        data.pop(k, None)
    data["devices"] = sorted(data.get("devices") or [])
    return KEEP_PREFIX + hashlib.sha1((json.dumps(data, sort_keys=True) + tag).encode()).hexdigest()


def _row_id(r: dict) -> str:
    return r["data_hora"] + json.dumps(r.get("log_original") or r, sort_keys=True, default=str)


def _merge(new: list[dict], old: list[dict], limit: int) -> list[dict]:
    seen, out = set(), []
    for r in sorted(new + old, key=lambda r: r["data_hora"], reverse=True):
        if (k := _row_id(r)) not in seen:
            seen.add(k)
            out.append(r)
    return out[:limit]


def incremental(q: LogQuery, fetch, tag: str = "", reuse: bool = True) -> dict:
    """fetch(LogQuery) -> {total, returned, rows, mais}; devolve o mesmo formato, mais "guardados"."""
    if settings.keep_days <= 0:
        return {**fetch(q), "guardados": 0}
    key = _keep_key(q, tag)
    start, end = q.faz_time("start"), q.faz_time("end")
    stored = database.cache_get(key) if reuse else None
    if stored and not (stored["inicio"] <= start <= stored["fim"]):
        stored = None  # o período começa antes (ou depois) do que está guardado: busca tudo
    if stored and stored["truncado"] and stored["limite"] < q.limit:
        stored = None  # guardado com menos eventos do que esta consulta pede
    if not stored:
        res = fetch(q)
        _keep(key, {"inicio": start, "fim": _now_str(q), "linhas": res["rows"], "truncado": res["mais"], "limite": q.limit})
        return {**res, "guardados": 0}
    fetch_from = max(q.start, min(q.end, datetime.strptime(stored["fim"], "%Y-%m-%d %H:%M:%S") - LATE_LOGS))
    if fetch_from >= q.end:  # o período inteiro já estava guardado
        res = {"total": 0, "returned": 0, "rows": [], "mais": False}
        old = [r for r in stored["linhas"] if start <= r["data_hora"] <= end]
    else:
        part = q.model_copy(update={"start": fetch_from})
        res = fetch(part)
        cut = part.faz_time("start")
        old = [r for r in stored["linhas"] if start <= r["data_hora"] < cut]
    rows = _merge(res["rows"], old, q.limit)
    kept = _merge(res["rows"], stored["linhas"], max(q.limit, stored["limite"]))
    _keep(key, {"inicio": stored["inicio"], "fim": max(stored["fim"], _now_str(q)), "linhas": kept,
                "truncado": stored["truncado"] or res["mais"] or len(res["rows"]) + len(stored["linhas"]) > len(kept),
                "limite": max(q.limit, stored["limite"])})
    return {"total": max(res["total"], res["returned"]) + len(old), "returned": len(rows), "rows": rows,
            "mais": res["mais"] or stored["truncado"] or len(res["rows"]) + len(old) > q.limit, "guardados": len(old)}


def _now_str(q: LogQuery) -> str:
    return min(q.end, datetime.now()).strftime("%Y-%m-%d %H:%M:%S")


def _keep(key: str, value: dict) -> None:
    database.cache_set(key, value, ttl=settings.keep_days * 86400)
    database.cache_trim(KEEP_PREFIX, settings.keep_max_mb * 1024 * 1024)


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


def blocked_search(base: LogQuery, logtypes=("webfilter", "traffic", "app-ctrl", "dns"), keep: bool = False,
                   reuse: bool = True) -> dict:
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
        futures = {ex.submit(run_query, q, keep=keep, reuse=reuse): q for q in queries}
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
