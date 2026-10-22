"""Reputação de sites (URL ou domínio).

Desde 2026-10-22 a aba consulta só sites e não cruza mais o indicador com os IOC do Vision One
(Suspicious Objects, exceções, detecções e Workbench). O veredito vem de:

  1. FortiGuard             categoria do site, perguntada a um FortiGate (pelo FortiAnalyzer ou direto)
                            ou lida dos logs do filtro web/DNS do FortiAnalyzer
  2. Sandbox (opcional)     análise dinâmica da URL no Vision One, quando V1_SANDBOX_ENABLED=true

Cada fonte é consultada de forma independente: se uma falhar, a outra continua e o erro é mostrado na tela.
"""
import hashlib
import ipaddress
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

from .. import database
from ..config import settings
from . import visionone
from .visionone import V1Error, host_of, object_value

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)
URL_RE = re.compile(r"^[^\s\"'\\<>]{1,2048}$")

RISK_SCORE = {"high": 90, "medium": 65, "low": 35, "noRisk": 5}
SEVERITY_SCORE = {"critical": 95, "high": 80, "medium": 55, "low": 30}
SEVERITY_PT = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa", "noRisk": "Nenhuma"}

# Categorias do grupo "Security Risk" do FortiGuard, como aparecem no campo catdesc dos logs: score e explicação
FORTIGUARD_RISK = {
    "malicious websites": (90, "site malicioso"),
    "phishing": (90, "phishing (roubo de senha ou dados)"),
    "spam urls": (70, "endereço usado em spam"),
    "newly registered domain": (60, "domínio registrado há pouco tempo"),
    "newly observed domain": (55, "domínio visto pela primeira vez há pouco tempo"),
    "dynamic dns": (55, "DNS dinâmico, muito usado em ataques"),
}
FORTIGUARD_UNRATED = {"unrated", "not rated", "unknown"}
FORTIGUARD_LOOKBACK = timedelta(hours=24)
FORTIGUARD_RATING_TTL = 24 * 3600   # a classificação de um site muda pouco: 1 dia em cache
SAFE_CATEGORY = re.compile(r"^[^\x00-\x1f\"\\<>]{1,128}$")


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


def fortiguard_from_logs(host: str) -> dict:
    """Categoria do FortiGuard do site no log mais recente do filtro web (ou DNS) das últimas 24 h."""
    from .faz_filters import LogQuery  # import local: evita ciclo reputação <-> pesquisa de logs
    from .fortianalyzer import FazError
    from .logsearch import run_query

    key = f"fg:{host}"
    hit = database.cache_get(key)
    if hit is not None:
        return hit
    end = datetime.now().replace(microsecond=0)
    out = {"categoria": None, "origem": "logs", "visto_em": None, "erro": None}
    try:
        for lt in ("webfilter", "dns"):
            res = run_query(LogQuery(logtype=lt, hostname=host, start=end - FORTIGUARD_LOOKBACK, end=end, limit=20),
                            save_cache=False, policy_names=False)
            row = next((r for r in res["rows"] if (r.get("log_original") or {}).get("catdesc")), None)
            if row:
                out.update(categoria=row["log_original"]["catdesc"], visto_em=row["data_hora"],
                           tipo_log=lt, firewall=row.get("firewall"))
                break
    except (FazError, ValueError) as e:  # sem FortiAnalyzer a reputação continua só com o Vision One
        out["erro"] = str(e)
        return out
    database.cache_set(key, out)
    return out


def fortiguard_from_fortigate(host: str) -> dict:
    """Classificação do FortiGuard perguntada a um FortiGate (FGT_URL): vale para qualquer site, mesmo não acessado."""
    from . import fortigate

    key = f"fgt-rating:{host}"
    hit = database.cache_get(key)
    if hit is not None:
        return hit
    r = fortigate.rating_lookup(host) if fortigate.configured() else fortigate.rating_via_faz(host)
    out = {"categoria": r["categoria"] or f"Categoria {r['categoria_id']}", "categoria_id": r["categoria_id"],
           "origem": "fortiguard", "via": r.get("via", "FortiGate"), "visto_em": None, "erro": None}
    database.cache_set(key, out, ttl=FORTIGUARD_RATING_TTL)
    return out


def _fortiguard(ioc_type: str, value: str, category: str | None, from_faz: bool) -> dict | None:
    if ioc_type == "ip":
        return None
    if category:
        return {"categoria": category, "origem": "evento", "visto_em": None, "erro": None}
    host = host_of(value) if ioc_type == "url" else value
    from . import fortigate
    fgt_err = None
    if fortigate.configured() or fortigate.proxy_available():
        try:
            return fortiguard_from_fortigate(host)
        except fortigate.FgtError as e:  # sem o FortiGate, a categoria ainda pode vir dos logs
            fgt_err = str(e)
    if not from_faz:
        return {"categoria": None, "origem": "fortiguard", "visto_em": None, "erro": fgt_err} if fgt_err else None
    out = fortiguard_from_logs(host)
    if fgt_err:
        out = {**out, "aviso": f"Consulta ao FortiGuard pelo FortiGate falhou ({fgt_err}); categoria procurada nos logs."}
    return out


# O que marcar na função (role) da chave de API quando o Vision One responde 403, com os nomes do console em inglês.
_ROLE = "Na função (role) da chave de API no Vision One (Administration > User Roles), "
PERMISSION_HINT = {
    "sandbox": _ROLE + "habilite Threat Intelligence > Sandbox Analysis com View, filter, and search e Submit object.",
    "sandbox_result": _ROLE + "habilite Threat Intelligence > Sandbox Analysis com View, filter, and search.",
}


def lookup(raw: str, forced_type: str | None = None, *, use_sandbox: bool = False, username: str = "",
           sandbox_task: str | None = None, fortiguard_category: str | None = None,
           fortiguard_from_faz: bool = True, sandbox_force: bool = False) -> dict:
    """Reputação consolidada. sandbox_task: tarefa do Sandbox já concluída, para entrar no veredito.

    use_sandbox reaproveita a análise da mesma URL das últimas 24 h; sandbox_force envia de novo.

    fortiguard_category: categoria do site já conhecida (ex.: do log aberto na tela). Sem ela, e com
    fortiguard_from_faz, o portal procura a categoria nos logs do FortiAnalyzer das últimas 24 h.
    """
    ioc_type, value = parse_indicator(raw, forced_type)
    if ioc_type == "ip":  # a aba consulta só sites (2026-10-22): IP não tem categoria FortiGuard nem recategorização
        raise IndicatorError("A Reputação consulta só sites: informe uma URL ou um domínio, não um IP.")
    if fortiguard_category is not None:
        fortiguard_category = fortiguard_category.strip() or None
        if fortiguard_category and not SAFE_CATEGORY.match(fortiguard_category):
            raise IndicatorError("Categoria do FortiGuard inválida.")
    cache_key = "rep:" + hashlib.sha1(f"{ioc_type}:{value}:{use_sandbox}:{sandbox_task}:"
                                      f"{fortiguard_category}:{fortiguard_from_faz}".encode()).hexdigest()
    cached = None if use_sandbox else database.cache_get(cache_key)
    if cached:
        cached["cache"] = True
        return cached

    # a categoria do FortiGuard vem do FortiGate/FortiAnalyzer: busca em paralelo com o Sandbox
    pool = ThreadPoolExecutor(max_workers=1)
    fg_future = pool.submit(_fortiguard, ioc_type, value, fortiguard_category, fortiguard_from_faz)
    pool.shutdown(wait=False)

    sources: dict[str, dict] = {}
    errors: dict[str, str] = {}

    def run(name, fn):
        try:
            sources[name] = fn()
        except V1Error as e:
            hint = PERMISSION_HINT.get(name) if e.status == 403 else None
            errors[name] = f"{e}. {hint}" if hint else str(e)

    if use_sandbox and ioc_type in ("url", "domain"):
        # domínio vai ao Sandbox como a página inicial do site (http://dominio/)
        sandbox_url = value if ioc_type == "url" else f"http://{value}/"
        if not settings.v1_sandbox_enabled:
            errors["sandbox"] = "Envio ao Sandbox desabilitado (V1_SANDBOX_ENABLED=false)."
        else:
            run("sandbox", lambda: sandbox_submit(sandbox_url, username, force=sandbox_force))

    if sandbox_task:
        def finished():
            st = sandbox_status(sandbox_task)
            if st.get("status") != "succeeded":
                raise V1Error(st.get("erro") or f"Análise do Sandbox ainda não concluída ({st.get('status')}).")
            return st["resultado"]
        run("sandbox_result", finished)

    try:
        fortiguard = fg_future.result()
    except Exception as e:  # pragma: no cover - a categoria é complemento, nunca derruba a consulta
        fortiguard = {"categoria": None, "origem": "logs", "visto_em": None, "erro": str(e)}
    result = consolidate(ioc_type, value, sources, errors, fortiguard)
    result["cache"] = False
    if not errors and not use_sandbox:
        database.cache_set(cache_key, result)
    database.add_ioc_lookup(value, ioc_type, result["reputacao"], result["risk_score"], ", ".join(result["fontes"]))
    return result


def sandbox_status(task_id: str) -> dict:
    """Acompanha uma análise de URL enviada ao Sandbox e devolve o resultado quando pronto."""
    if not re.fullmatch(r"[\w\-]{1,80}", task_id or ""):
        raise IndicatorError("Identificador de tarefa inválido.")
    run = database.sandbox_run_get(task_id)
    if run and run["status"] == "succeeded" and run["result"]:
        return {"task_id": task_id, "status": "succeeded", "resultado": run["result"]}  # o resultado não muda
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
        if run:
            database.sandbox_run_finish(task_id, "succeeded", out["resultado"])
    elif status in ("failed", "rejected", "canceled"):
        out["erro"] = (task.get("error") or {}).get("message", "Análise não concluída no Sandbox.")
        if run:
            database.sandbox_run_finish(task_id, "failed", error=out["erro"])
    return out


# ---- economia do Sandbox: a mesma URL não é enviada de novo em 24 h ------------------------
SANDBOX_REUSE_HOURS = 24
QUOTA_KEY = "v1:sandbox-quota"
QUOTA_TTL = 300


def sandbox_key(url: str) -> str:
    """A mesma URL para o Sandbox: esquema e site em minúsculas, sem #fragmento e com "/" quando não há caminho."""
    p = urlsplit(url)
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


def reusable_sandbox(url: str) -> dict | None:
    """Análise da mesma URL nas últimas 24 h que ainda vale: concluída ou em andamento (consultar não gasta cota)."""
    for run in database.sandbox_runs_for(sandbox_key(url), time.time() - SANDBOX_REUSE_HOURS * 3600):
        if run["status"] == "running":
            try:
                st = sandbox_status(run["task_id"])
            except (V1Error, IndicatorError):
                continue
            if st.get("erro"):
                continue
            run["status"] = st.get("status") or "running"
        if run["status"] != "failed":
            return run
    return None


def sandbox_quota(refresh: bool = False) -> dict:
    """Cota diária do Sandbox: envios que ainda restam hoje (e o total, quando o Vision One informa)."""
    if not refresh:
        hit = database.cache_get(QUOTA_KEY)
        if hit is not None:
            return hit
    try:
        u = visionone.get_client().sandbox_usage()
        out = {"restantes": u.get("submissionRemainingCount"), "total": u.get("submissionReserveCount"), "erro": None}
    except V1Error as e:
        out = {"restantes": None, "total": None, "erro": str(e)}
    database.cache_set(QUOTA_KEY, out, ttl=QUOTA_TTL)
    return out


def sandbox_submit(url: str, username: str = "", force: bool = False) -> dict:
    """Envia a URL ao Sandbox ou, sem force, reaproveita a análise da mesma URL das últimas 24 h."""
    if not force:
        run = reusable_sandbox(url)
        if run:
            return {"task_id": run["task_id"], "url": url, "reaproveitado": True, "status": run["status"],
                    "enviado_em": datetime.fromtimestamp(run["submitted_at"]).strftime("%Y-%m-%d %H:%M"),
                    "enviado_por": run.get("username") or None}
    quota = sandbox_quota(refresh=True)  # sem permissão para ver a cota, o envio segue normalmente
    if quota["restantes"] is not None and quota["restantes"] <= 0:
        raise V1Error("A cota diária do Sandbox acabou: não há envios restantes hoje. "
                      "Use um resultado anterior ou tente de novo amanhã.")
    sub = visionone.get_client().sandbox_submit_url(url)
    if sub.get("task_id"):
        database.sandbox_run_add(sub["task_id"], sandbox_key(url), username)
    database.cache_delete(QUOTA_KEY)
    return {**sub, "reaproveitado": False}


def _latest(*dates: str | None) -> str | None:
    ds = [d for d in dates if d]
    return max(ds) if ds else None


def consolidate(ioc_type: str, value: str, sources: dict, errors: dict, fortiguard: dict | None = None) -> dict:
    sb = sources.get("sandbox")
    sbr = sources.get("sandbox_result")  # resultado do Sandbox já concluído

    scores, categorias, tipos, iocs, datas, fontes = [], set(), set(), [], [], []
    severidade_key = None

    if sbr:
        fontes.append("Sandbox Analysis")
        risco = sbr.get("risco")
        scores.append(RISK_SCORE.get(risco, 0))
        tipos.update(str(t) for t in (sbr.get("tipos_ameaca") or []))
        tipos.update(str(d) for d in (sbr.get("deteccoes") or []))
        datas.append(sbr.get("concluido_em"))
        for o in (sbr.get("iocs") or [])[:20]:
            if o.get("valor") and str(o["valor"]).lower() != value.lower():
                iocs.append({"tipo": o.get("tipo"), "valor": o.get("valor"), "origem": "Sandbox"})
        if RISK_SCORE.get(risco, 0) > 0:
            severidade_key = risco

    fg_cat = (fortiguard or {}).get("categoria")
    fg_risk = FORTIGUARD_RISK.get((fg_cat or "").strip().lower())
    fg_unrated = (fg_cat or "").strip().lower() in FORTIGUARD_UNRATED
    if fg_cat:
        fontes.append("FortiGuard (categoria do site)")
        categorias.add(f"{fg_cat} (FortiGuard)")
        if fg_risk:
            scores.append(fg_risk[0])
            tipos.add(f"FortiGuard: {fg_cat} ({fg_risk[1]})")
            if fg_risk[0] > RISK_SCORE.get(severidade_key or "", 0):
                severidade_key = "high" if fg_risk[0] >= 80 else "medium"

    risk = max(scores) if scores else 0
    if risk >= 80:
        reputacao = "Malicioso"
    elif risk >= 50:
        reputacao = "Suspeito"
    elif sbr and sbr.get("risco") == "noRisk" and risk <= RISK_SCORE["noRisk"]:
        reputacao = "Sem risco detectado (Sandbox)"
    elif risk > 0:
        reputacao = "Baixo risco"
    elif fg_unrated:
        reputacao = "Não classificado (FortiGuard)"
    elif fg_cat:
        reputacao = "Sem risco conhecido"
    else:
        reputacao = "Sem categoria encontrada"

    if sbr or (fg_risk and fg_risk[0] >= 80):
        confianca = "Alta"
    elif fg_cat and not fg_unrated:
        confianca = "Média"
    else:
        confianca = "Baixa"

    recomendacoes = list({
        "Malicioso": ["Não acessar o site e manter o bloqueio no firewall.",
                      "Acionar a equipe de Segurança se houver acesso confirmado por algum usuário.",
                      "Verificar no FortiAnalyzer quais usuários/IPs acessaram o site."],
        "Suspeito": ["Manter o bloqueio até análise da equipe de Segurança.",
                     "Não solicitar liberação sem justificativa de negócio aprovada."],
        "Baixo risco": ["Site com indício de baixo risco; avaliar a necessidade de negócio antes de liberar."],
        "Sem risco detectado (Sandbox)": [
            "O Sandbox do Vision One analisou a URL e não encontrou comportamento malicioso.",
            "Se for liberar, confirme também a necessidade de negócio."],
        "Sem risco conhecido": [
            f"O FortiGuard classifica o site como \"{fg_cat}\", uma categoria sem risco de segurança.",
            "Se o acesso foi bloqueado, o motivo é a política de navegação para essa categoria: siga o processo de "
            "liberação com a justificativa do usuário."],
        "Não classificado (FortiGuard)": [
            "O FortiGuard ainda não classificou este site (Unrated). Se o site for seguro, solicite a classificação "
            "no FortiGuard: veja o passo a passo abaixo.",
            "Se precisar de mais certeza antes, use a análise no Sandbox (quando habilitada)."],
        "Sem categoria encontrada": [
            "Não foi possível obter a categoria do FortiGuard para este site (veja o motivo na linha FortiGuard).",
            "Se precisar de mais certeza, use a análise no Sandbox (quando habilitada)."],
    }[reputacao])
    if fg_risk and reputacao in ("Malicioso", "Suspeito"):
        recomendacoes.insert(0, f"O FortiGuard classifica o site como \"{fg_cat}\" ({fg_risk[1]}).")

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
        "fontes": fontes or ["FortiGuard (sem categoria)"],
        "recomendacoes": recomendacoes,
        "fortiguard": ({**fortiguard, "risco": ("alto" if fg_risk[0] >= 80 else "medio") if fg_risk else None,
                        "nao_classificado": fg_unrated} if fortiguard else None),
        "detalhes": {
            "sandbox": sb,
            "sandbox_resultado": sbr,
        },
        "erros": errors,
        "consultado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
