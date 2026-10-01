"""API REST do portal (consumida pela interface web; também pode ser usada por scripts)."""
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from .. import __version__, database
from ..config import settings
from ..services import correlation, dashboard, diagnosis, explain, export, reputation
from ..services.faz_filters import LOGTYPES, SAFE_NAME, LogQuery
from ..services.fortianalyzer import FazError
from ..services.fortianalyzer import get_client as faz
from ..services.logsearch import run_query, store_result
from ..services.visionone import V1Error, default_window
from ..services.visionone import get_client as v1
from .common import tracked, who

router = APIRouter(prefix="/api")

REP_COLUMNS = [("campo", "Campo"), ("valor", "Valor")]


# ---- status --------------------------------------------------------------------
@router.get("/health")
def health():
    return {"status": "ok", "versao": __version__, "demo": settings.demo}


@router.get("/status")
def status():
    return {"config": settings.public_summary(), "integracoes": database.integration_stats(), "versao": __version__}


@router.post("/status/test/{target}")
def test_integration(target: str):
    try:
        if target == "faz":
            return {"ok": True, "detalhe": faz().status()}
        if target == "v1":
            return {"ok": True, "detalhe": v1().connectivity()}
    except (FazError, V1Error) as e:
        return {"ok": False, "erro": str(e)}
    raise HTTPException(404, "Use faz ou v1")


@router.get("/app-log")
def app_log(limit: int = Query(200, le=1000), level: str | None = None):
    return database.list_app_log(limit, level)


@router.delete("/cache")
def clear_cache():
    return {"removidos": database.cache_purge(all_entries=True)}


# ---- FortiAnalyzer ---------------------------------------------------------------
@router.get("/faz/logtypes")
def logtypes():
    return LOGTYPES


@router.get("/faz/adoms")
def adoms():
    key = "faz:adoms"
    hit = database.cache_get(key)
    if hit is not None:
        return hit
    try:
        data = faz().list_adoms()
    except FazError as e:
        if not _permission_error(e):
            raise HTTPException(502, str(e))
        # Admin REST restrito a ADOMs específicas pode não listar /dvmdb/adom; a busca de logs
        # continua funcionando na ADOM configurada em FAZ_DEFAULT_ADOM.
        return [{"name": settings.faz_default_adom, "desc": "ADOM padrão (sem permissão para listar ADOMs)"}]
    database.cache_set(key, data, ttl=3600)
    return data


def _permission_error(e: FazError) -> bool:
    return "sem permissão" in str(e) or "No permission" in str(e)


@router.get("/faz/adoms/{adom}/devices")
def devices(adom: str):
    if not SAFE_NAME.match(adom):
        raise HTTPException(400, "ADOM inválido")
    key = f"faz:devices:{adom}"
    hit = database.cache_get(key)
    if hit is not None:
        return hit
    try:
        data = faz().list_devices(adom)
    except FazError as e:
        if not _permission_error(e):
            raise HTTPException(502, str(e))
        return []  # sem Device Manager: a busca usa todos os firewalls da ADOM
    database.cache_set(key, data, ttl=3600)
    return data


@router.post("/faz/logs")
def search_logs(q: LogQuery, request: Request, cache: bool = True):
    with tracked(request, "logs", q.describe(), q.model_dump(mode="json")) as info:
        res = run_query(q, use_cache=cache)
        info.update(count=res["returned"], blocked=res["bloqueados"],
                    summary=f"{res['returned']} de {res['total']} eventos ({res['bloqueados']} bloqueados)")
    res["result_id"] = store_result("logs", f"Logs {LOGTYPES[q.logtype]}", explain.COLUMNS, res["rows"],
                                    {"Filtro": res["filter"] or "(nenhum)", "Período": f"{q.start} a {q.end}"})
    return res


@router.post("/faz/diagnose")
def diagnose_access(q: diagnosis.DiagnoseQuery, request: Request):
    """Diagnóstico de acesso: bloqueios do usuário/IP no filtro web, aplicações, DNS e firewall de uma vez."""
    term = f"{q.quem.strip()} -> {(q.destino or '').strip() or '(qualquer destino)'}"
    with tracked(request, "diagnostico", term, q.model_dump(mode="json")) as info:
        res = diagnosis.diagnose(q)
        info.update(count=len(res["rows"]), blocked=sum(c["bloqueios"] for c in res["camadas"]), summary=res["titulo"])
    res["result_id"] = store_result("diagnostico", f"Diagnóstico {term}", explain.COLUMNS, res["rows"],
                                    {"Resultado": res["titulo"], "Resumo": res["resumo"], "O que fazer": res["orientacao"],
                                     "Período": f"{res['periodo']['inicio']} a {res['periodo']['fim']}"})
    return res


@router.post("/faz/logs/live")
def live_logs(q: LogQuery, request: Request, first: bool = False):
    """Tempo real: a tela repete a mesma pesquisa a cada poucos segundos para a janela mais recente.

    Usa a mesma pesquisa oficial do LogView (sem cache). Só a primeira pesquisa de cada sessão
    de tempo real entra na auditoria e no histórico, para não gravar uma linha a cada atualização.
    """
    if first:
        with tracked(request, "logs-tempo-real", q.describe(), q.model_dump(mode="json")) as info:
            res = run_query(q, use_cache=False, save_cache=False)
            info.update(count=res["returned"], blocked=res["bloqueados"],
                        summary=f"Tempo real iniciado: {res['returned']} eventos na primeira janela")
        return res
    try:
        return run_query(q, use_cache=False, save_cache=False)
    except FazError as e:
        raise HTTPException(502, str(e))


class StoredLogs(BaseModel):
    logtype: str = "traffic"
    filter: str = ""
    rows: list[dict] = Field(default=[], max_length=10000)


@router.post("/faz/logs/store")
def store_logs(body: StoredLogs):
    """Guarda as linhas mostradas no tempo real para exportar (CSV/XLSX/PDF)."""
    return {"result_id": store_result("logs", f"Logs {LOGTYPES.get(body.logtype, body.logtype)} (tempo real)",
                                      explain.COLUMNS, body.rows, {"Filtro": body.filter or "(nenhum)"})}


# ---- Vision One -----------------------------------------------------------------------
class RepQuery(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)
    type: str = "auto"
    sandbox: bool = False
    sandbox_task: str | None = Field(default=None, max_length=80)  # tarefa concluída a incluir no veredito
    categoria_fortiguard: str | None = Field(default=None, max_length=128)  # categoria do site vinda do log aberto


def _rep_rows(r: dict) -> list[dict]:
    rows = [{"campo": k, "valor": r.get(f)} for k, f in (
        ("Indicador", "indicador"), ("Tipo", "tipo"), ("Reputação", "reputacao"), ("Risk Score", "risk_score"),
        ("Categoria", "categoria"), ("Severidade", "severidade"), ("Tipo da ameaça", "tipo_ameaca"),
        ("Última análise", "ultima_analise"), ("Nível de confiança", "confianca"), ("Fonte", "fontes"),
        ("Recomendações", "recomendacoes"))]
    for i in r.get("iocs_relacionados", []):
        rows.append({"campo": f"IOC relacionado ({i.get('tipo')})", "valor": f"{i.get('valor')} - {i.get('origem')}"})
    return rows


@router.post("/v1/reputation")
def v1_reputation(q: RepQuery, request: Request):
    with tracked(request, "reputacao", q.indicator, q.model_dump()) as info:
        r = reputation.lookup(q.indicator, q.type, use_sandbox=q.sandbox, username=who(request),
                              sandbox_task=q.sandbox_task, fortiguard_category=q.categoria_fortiguard)
        info.update(count=1, summary=f"{r['reputacao']} (score {r['risk_score']})")
    r["result_id"] = store_result("reputacao", f"Reputação {r['indicador']}", REP_COLUMNS, _rep_rows(r))
    return r


@router.get("/v1/sandbox/{task_id}")
def v1_sandbox(task_id: str):
    try:
        return reputation.sandbox_status(task_id)
    except reputation.IndicatorError as e:
        raise HTTPException(400, str(e))
    except V1Error as e:
        raise HTTPException(502, str(e))


@router.get("/v1/alerts")
def v1_alerts(request: Request, days: int = Query(7, ge=1, le=90), severity: str | None = None,
              status: str | None = None):
    """Alertas do Workbench (Active/Critical/Open). Base para a evolução de alertas e incidentes."""
    end = datetime.now().astimezone()
    with tracked(request, "alertas", f"últimos {days} dias") as info:
        items = v1().workbench_alerts(end - timedelta(days=days), end, max_items=500)
        if severity:
            items = [a for a in items if a.get("severity") == severity]
        if status:
            items = [a for a in items if (a.get("status") or a.get("investigationStatus")) == status]
        info.update(count=len(items), summary=f"{len(items)} alertas")
    return [{"id": a.get("id"), "modelo": a.get("model"), "severidade": a.get("severity"), "score": a.get("score"),
             "status": a.get("status") or a.get("investigationStatus"), "criado": a.get("createdDateTime"),
             "link": a.get("workbenchLink"),
             "indicadores": len(a.get("indicators") or [])} for a in items]


@router.get("/v1/endpoints")
def v1_endpoints(request: Request):
    """Inventário de endpoints (base para a evolução de ativos/agentes)."""
    with tracked(request, "endpoints", "inventário") as info:
        items = v1().endpoints()
        info.update(count=len(items))
    return items


# ---- correlação -------------------------------------------------------------------------
class CorrQuery(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)
    start: datetime | None = None
    end: datetime | None = None
    adom: str | None = None


@router.post("/correlation")
def correlate(q: CorrQuery, request: Request):
    end = q.end or datetime.now().replace(second=0, microsecond=0)
    start = q.start or end - timedelta(days=1)
    if end <= start:
        raise HTTPException(400, "A data final precisa ser maior que a data inicial.")
    if q.adom and not SAFE_NAME.match(q.adom):
        raise HTTPException(400, "ADOM inválido")
    with tracked(request, "correlacao", q.indicator, q.model_dump(mode="json")) as info:
        c = correlation.correlate(q.indicator, start, end, q.adom, username=who(request))
        faz_part = c.get("fortianalyzer") or {}
        info.update(count=len(faz_part.get("eventos", [])), blocked=faz_part.get("bloqueios", 0),
                    summary=" ".join(c["analise"])[:900])
    rows = [{"campo": "Análise", "valor": linha} for linha in c["analise"]]
    if c.get("visionone"):
        rows += _rep_rows(c["visionone"])
    c["result_id"] = store_result("correlacao", f"Correlação {c['indicador']}", REP_COLUMNS, rows)
    c["eventos_result_id"] = store_result("correlacao-eventos", f"Eventos {c['indicador']}", explain.COLUMNS,
                                          faz_part.get("eventos", []))
    return c


# ---- dashboard ---------------------------------------------------------------------------
@router.get("/dashboard/faz")
def dash_faz(hours: int = Query(24, ge=1, le=168), refresh: bool = False, adom: str | None = None):
    if adom and not SAFE_NAME.match(adom):
        raise HTTPException(400, "ADOM inválido")
    try:
        return dashboard.faz_overview(hours, adom, refresh)
    except FazError as e:
        raise HTTPException(502, str(e))


@router.get("/dashboard/local")
def dash_local():
    return dashboard.local_overview()


# ---- histórico ----------------------------------------------------------------------------
HIST_COLUMNS = [("ts", "Data e hora"), ("username", "Usuário"), ("query_type", "Tipo"), ("term", "Termo pesquisado"),
                ("status", "Status"), ("result_count", "Resultados"), ("blocked_count", "Bloqueios"),
                ("summary", "Resultado"), ("duration_ms", "Tempo (ms)")]


@router.get("/history")
def history(limit: int = Query(200, le=5000), type: str | None = None, q: str | None = None):
    return database.list_history(limit, type, q)


# ---- exportação ------------------------------------------------------------------------------
def _download(content: bytes, filename: str, fmt: str) -> Response:
    return Response(content, media_type=export.FORMATS[fmt],
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/export/history.{fmt}")
def export_history(fmt: str, request: Request, type: str | None = None, q: str | None = None):
    if fmt not in export.FORMATS:
        raise HTTPException(400, "Formato deve ser csv, xlsx ou pdf")
    rows = database.list_history(5000, type, q)
    content, filename = export.build(fmt, "Histórico de consultas", HIST_COLUMNS, rows, {"Registros": len(rows)})
    return _download(content, filename, fmt)


@router.get("/export/{result_id}.{fmt}")
def export_result(result_id: str, fmt: str, request: Request):
    if fmt not in export.FORMATS:
        raise HTTPException(400, "Formato deve ser csv, xlsx ou pdf")
    if not result_id.isalnum():
        raise HTTPException(400, "Identificador inválido")
    data = database.temp_get(f"result:{result_id}")
    if not data:
        raise HTTPException(404, "Resultado expirou; refaça a consulta para exportar.")
    content, filename = export.build(fmt, data["title"], data["columns"], data["rows"], data.get("meta"))
    database.add_history(who(request), "exportacao", f"{data['title']} ({fmt})", "ok", result_count=len(data["rows"]),
                         summary=filename)
    return _download(content, filename, fmt)
