"""Consulta de reputação consolidada (Vision One).

A API pública v3.0 do Vision One não tem um endpoint único de "reputação global"
para IP/domínio/URL avulso. A reputação é montada com as fontes oficiais:

  1. Suspicious Objects     IOC que a organização (ou integrações) marcaram como suspeitos
  2. Exceções               objetos marcados como confiáveis
  3. Detecções (Search)     o indicador apareceu em detecções do ambiente
  4. Workbench              alertas que citam o indicador
  5. Sandbox (opcional)     análise dinâmica de URL, quando V1_SANDBOX_ENABLED=true

Cada fonte é consultada de forma independente: se uma falhar (ex.: falta de
permissão na chave), as demais continuam e o erro é mostrado na tela.
"""
import hashlib
import ipaddress
import re
from datetime import datetime
from urllib.parse import urlsplit

from .. import database
from ..config import settings
from . import visionone
from .visionone import V1Error, host_of, object_value

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)
URL_RE = re.compile(r"^[^\s\"'\\<>]{1,2048}$")

RISK_SCORE = {"high": 90, "medium": 65, "low": 35, "noRisk": 5}
SEVERITY_SCORE = {"critical": 95, "high": 80, "medium": 55, "low": 30}
SEVERITY_PT = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa", "noRisk": "Nenhuma"}


class IndicatorError(ValueError):
    pass


def parse_indicator(raw: str, forced_type: str | None = None) -> tuple[str, str]:
    """Identifica e normaliza o indicador: ('ip'|'domain'|'url', valor)."""
    v = (raw or "").strip()
    if not v:
        raise IndicatorError("Informe um IP, domínio ou URL.")
    if forced_type in (None, "", "auto"):
        try:
            return "ip", str(ipaddress.ip_address(v))
        except ValueError:
            pass
        if "://" in v or "/" in v:
            forced_type = "url"
        else:
            forced_type = "domain"
    if forced_type == "ip":
        try:
            return "ip", str(ipaddress.ip_address(v))
        except ValueError:
            raise IndicatorError("IP inválido.")
    if forced_type == "domain":
        d = v.lower().rstrip(".")
        if "://" in d:
            d = host_of(d)
        if not DOMAIN_RE.match(d):
            raise IndicatorError("Domínio inválido.")
        return "domain", d
    if forced_type == "url":
        if not URL_RE.match(v):
            raise IndicatorError("URL contém caracteres não permitidos.")
        u = v if "://" in v else f"http://{v}"
        parts = urlsplit(u)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise IndicatorError("URL inválida (use http:// ou https://).")
        return "url", u
    raise IndicatorError("Tipo de indicador inválido.")


def _norm_url(u: str) -> str:
    return u.lower().rstrip("/")


def _match_objects(objs: list[dict], ioc_type: str, value: str) -> list[dict]:
    host = host_of(value) if ioc_type == "url" else value
    out = []
    for o in objs:
        t, ov = o.get("type"), object_value(o).lower()
        if not ov:
            continue
        if ioc_type == "ip" and t == "ip" and ov == value:
            out.append(o)
        elif ioc_type == "domain" and ((t == "domain" and (value == ov or value.endswith("." + ov)))
                                       or (t == "url" and host_of(ov) == value)):
            out.append(o)
        elif ioc_type == "url" and ((t == "url" and _norm_url(ov) in (_norm_url(value), _norm_url(value.split("://", 1)[-1])))
                                    or (t == "domain" and (host == ov or host.endswith("." + ov)))):
            out.append(o)
    return out


def _cached_objects(client, kind: str) -> list[dict]:
    key = f"v1:{kind}"
    data = database.cache_get(key)
    if data is None:
        data = client.suspicious_objects() if kind == "so" else client.suspicious_exceptions()
        database.cache_set(key, data)
    return data


def _query_for(ioc_type: str, value: str) -> str:
    tpl = {"url": settings.v1_query_url, "domain": settings.v1_query_domain, "ip": settings.v1_query_ip}[ioc_type]
    return tpl.replace("{v}", value.replace('"', ""))


def _alert_matches(alert: dict, ioc_type: str, value: str) -> list[dict]:
    needle = host_of(value) if ioc_type == "url" else value
    hits = []
    for ind in alert.get("indicators") or []:
        iv = ind.get("value")
        iv = iv.get("name", "") if isinstance(iv, dict) else str(iv or "")
        if needle and needle.lower() in iv.lower():
            hits.append(ind)
    return hits


def lookup(raw: str, forced_type: str | None = None, *, use_sandbox: bool = False, username: str = "") -> dict:
    ioc_type, value = parse_indicator(raw, forced_type)
    cache_key = "rep:" + hashlib.sha1(f"{ioc_type}:{value}:{use_sandbox}".encode()).hexdigest()
    cached = database.cache_get(cache_key)
    if cached:
        cached["cache"] = True
        return cached

    client = visionone.get_client()
    start, end = visionone.default_window()
    sources: dict[str, dict] = {}
    errors: dict[str, str] = {}

    def run(name, fn):
        try:
            sources[name] = fn()
        except V1Error as e:
            errors[name] = str(e)

    run("suspicious_objects", lambda: {"items": _match_objects(_cached_objects(client, "so"), ioc_type, value)})
    run("exceptions", lambda: {"items": _match_objects(_cached_objects(client, "exc"), ioc_type, value)})
    run("detections", lambda: {"query": _query_for(ioc_type, value),
                               "items": client.search_detections(_query_for(ioc_type, value), start, end, top=50)})

    def alerts():
        matched = []
        for a in client.workbench_alerts(start, end, max_items=500):
            hits = _alert_matches(a, ioc_type, value)
            if hits:
                matched.append({"alert": a, "hits": hits})
        return {"items": matched}
    run("workbench", alerts)

    if use_sandbox and ioc_type == "url":
        if not settings.v1_sandbox_enabled:
            errors["sandbox"] = "Envio ao Sandbox desabilitado (V1_SANDBOX_ENABLED=false)."
        else:
            run("sandbox", lambda: client.sandbox_submit_url(value))

    result = consolidate(ioc_type, value, sources, errors)
    result["periodo"] = {"inicio": start.strftime("%Y-%m-%d %H:%M"), "fim": end.strftime("%Y-%m-%d %H:%M")}
    result["cache"] = False
    if not errors:
        database.cache_set(cache_key, result)
    database.add_ioc_lookup(value, ioc_type, result["reputacao"], result["risk_score"], ", ".join(result["fontes"]))
    return result


def sandbox_status(task_id: str) -> dict:
    """Acompanha uma análise de URL enviada ao Sandbox e devolve o resultado quando pronto."""
    if not re.fullmatch(r"[\w\-]{1,80}", task_id or ""):
        raise IndicatorError("Identificador de tarefa inválido.")
    client = visionone.get_client()
    task = client.sandbox_task(task_id)
    status = task.get("status")
    out = {"task_id": task_id, "status": status}
    if status == "succeeded":
        rid = (task.get("resourceLocation") or "").rstrip("/").split("/")[-1] or task.get("id") or task_id
        res = client.sandbox_result(rid)
        out["resultado"] = {
            "risco": res.get("riskLevel"),
            "severidade": SEVERITY_PT.get(res.get("riskLevel"), res.get("riskLevel")),
            "risk_score": RISK_SCORE.get(res.get("riskLevel")),
            "tipos_ameaca": res.get("threatTypes") or [],
            "deteccoes": res.get("detectionNames") or [],
            "concluido_em": res.get("analysisCompletionDateTime"),
        }
        try:
            out["resultado"]["iocs"] = [{"tipo": o.get("type"), "valor": object_value(o), "risco": o.get("riskLevel")}
                                        for o in client.sandbox_result_iocs(rid)]
        except V1Error:
            out["resultado"]["iocs"] = []
    elif status in ("failed", "rejected", "canceled"):
        out["erro"] = (task.get("error") or {}).get("message", "Análise não concluída no Sandbox.")
    return out


def _latest(*dates: str | None) -> str | None:
    ds = [d for d in dates if d]
    return max(ds) if ds else None


def consolidate(ioc_type: str, value: str, sources: dict, errors: dict) -> dict:
    so = (sources.get("suspicious_objects") or {}).get("items") or []
    exc = (sources.get("exceptions") or {}).get("items") or []
    det = (sources.get("detections") or {}).get("items") or []
    wb = (sources.get("workbench") or {}).get("items") or []
    sb = sources.get("sandbox")

    scores, categorias, tipos, iocs, datas, fontes = [], set(), set(), [], [], []
    severidade_key = None

    if so:
        fontes.append("Suspicious Objects")
        for o in so:
            scores.append(RISK_SCORE.get(o.get("riskLevel"), 50))
            if o.get("description"):
                categorias.add(o["description"])
            tipos.add("IOC na lista de objetos suspeitos" + (" (bloqueio)" if o.get("scanAction") == "block" else " (registro)"))
            datas.append(o.get("lastModifiedDateTime"))
        severidade_key = max((o.get("riskLevel") for o in so), key=lambda r: RISK_SCORE.get(r, 0))

    if det:
        fontes.append("Detecções (Search)")
        scores.append(55 + min(len(det), 10) * 3)
        for d in det:
            for k in ("malName", "ruleName", "detectionName", "eventName"):
                if d.get(k):
                    tipos.add(str(d[k]))
            datas.append(d.get("eventTimeDT") or d.get("detectedDateTime"))

    if wb:
        fontes.append("Workbench")
        for item in wb:
            a = item["alert"]
            scores.append(int(a.get("score") or SEVERITY_SCORE.get(a.get("severity"), 50)))
            if a.get("model"):
                tipos.add(a["model"])
            datas.append(a.get("createdDateTime"))
            for ind in a.get("indicators") or []:
                iv = ind.get("value")
                iv = iv.get("name", "") if isinstance(iv, dict) else str(iv or "")
                if iv and iv.lower() != value.lower() and len(iocs) < 20:
                    iocs.append({"tipo": ind.get("type"), "valor": iv, "origem": f"Alerta {a.get('id')}"})
        sev = max((i["alert"].get("severity") for i in wb), key=lambda s: SEVERITY_SCORE.get(s, 0))
        if SEVERITY_SCORE.get(sev, 0) > RISK_SCORE.get(severidade_key or "", 0):
            severidade_key = sev

    risk = max(scores) if scores else 0
    core = ("suspicious_objects", "exceptions", "detections", "workbench")
    failed = [k for k in core if k in errors]
    if exc and not so:
        reputacao, risk = "Confiável (exceção)", min(risk, 10)
        fontes.append("Lista de exceções")
    elif risk >= 80:
        reputacao = "Malicioso"
    elif risk >= 50:
        reputacao = "Suspeito"
    elif risk > 0:
        reputacao = "Baixo risco"
    elif len(failed) == len(core):
        reputacao = "Não foi possível consultar"   # nenhuma fonte respondeu: não é "sem registro"
    elif failed:
        reputacao = "Inconclusivo"
    else:
        reputacao = "Sem registro no Vision One"

    if so or sb:
        confianca = "Alta"
    elif wb or det:
        confianca = "Média"
    else:
        confianca = "Baixa"

    recomendacoes = {
        "Malicioso": ["Não acessar o recurso e manter o bloqueio no firewall.",
                      "Acionar a equipe de Segurança se houver acesso confirmado por algum usuário.",
                      "Verificar no FortiAnalyzer quais usuários/IPs acessaram o indicador."],
        "Suspeito": ["Manter o bloqueio até análise da equipe de Segurança.",
                     "Não solicitar liberação sem justificativa de negócio aprovada."],
        "Baixo risco": ["Indicador com registro de baixo risco; avaliar a necessidade de negócio antes de liberar."],
        "Confiável (exceção)": ["Indicador marcado como confiável pela organização no Vision One."],
        "Não foi possível consultar": [
            "O Vision One recusou todas as consultas. Veja em \"Fontes que falharam\" o motivo (geralmente permissão "
            "da função da chave de API) e repita depois de corrigir.",
            "Enquanto isso, não trate o indicador como seguro."],
        "Inconclusivo": [
            "Algumas fontes do Vision One não responderam (veja \"Fontes que falharam\"); as que responderam não "
            "têm registro do indicador. O resultado pode estar incompleto."],
        "Sem registro no Vision One": [
            "Nenhum registro no Vision One no período consultado. Isso não garante que o recurso seja seguro.",
            "Se precisar de mais certeza para uma URL, use a análise no Sandbox (quando habilitada)."],
    }[reputacao]

    return {
        "indicador": value,
        "tipo": ioc_type,
        "reputacao": reputacao,
        "risk_score": risk,
        "categoria": ", ".join(sorted(categorias)) or "-",
        "severidade": SEVERITY_PT.get(severidade_key, "Nenhuma") if severidade_key else "Nenhuma",
        "tipo_ameaca": sorted(tipos)[:10],
        "iocs_relacionados": iocs,
        "ultima_analise": _latest(*datas) or "-",
        "confianca": confianca,
        "fontes": fontes or (["Nenhuma fonte respondeu"] if len(failed) == len(core) else ["Vision One (sem ocorrências)"]),
        "recomendacoes": recomendacoes,
        "detalhes": {
            "suspicious_objects": [{"tipo": o.get("type"), "valor": object_value(o), "risco": o.get("riskLevel"),
                                    "acao": o.get("scanAction"), "descricao": o.get("description"),
                                    "expira": o.get("expiredDateTime")} for o in so],
            "excecoes": [{"tipo": o.get("type"), "valor": object_value(o), "descricao": o.get("description")} for o in exc],
            "deteccoes": det[:50],
            "deteccoes_query": (sources.get("detections") or {}).get("query"),
            "alertas": [{"id": i["alert"].get("id"), "modelo": i["alert"].get("model"),
                         "severidade": i["alert"].get("severity"), "score": i["alert"].get("score"),
                         "status": i["alert"].get("status") or i["alert"].get("investigationStatus"),
                         "criado": i["alert"].get("createdDateTime"), "link": i["alert"].get("workbenchLink")}
                        for i in wb],
            "sandbox": sb,
        },
        "erros": errors,
        "consultado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
