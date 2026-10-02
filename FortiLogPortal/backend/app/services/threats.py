"""Ameaças: máquinas comprometidas (IOC) e ranking de ameaças do FortiAnalyzer.

Duas fontes oficiais da API JSON-RPC:
- Máquinas comprometidas: alertas do Event Monitor (get /eventmgmt/adom/{adom}/alerts). As detecções de
  IOC e de botnet do FortiAnalyzer viram alertas dos handlers padrão (ex.: Compromised Host Detection
  IOC By Threat, Botnet Communication Detection); a API de IOC (/ioc/...) não lista essa tabela.
  O administrador REST precisa de "Event Management" somente leitura no perfil.
- Ranking de ameaças: a mesma busca de logs da aba Logs (logview/logsearch) em IPS, antivírus,
  sites maliciosos e phishing do filtro web, botnet do controle de aplicações e domínios maliciosos do DNS.
"""
import hashlib
import json
import re
from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

from .. import database
from ..config import settings
from .faz_filters import SAFE_NAME, LogQuery
from .fortianalyzer import FazError, get_client
from .logsearch import run_query

CACHE_TTL = 300
ROWS_PER_SOURCE = 2000   # eventos lidos por fonte (os mais recentes do período)
ALERTS_MAX = 4000        # alertas do Event Monitor lidos no período
TOP = 10

# id: (nome, tipo de log, categoria (catdesc/appcat contém), severidade padrão)
SOURCES = {
    "ips": ("Intrusão (IPS)", "ips", None, None),
    "virus": ("Vírus / malware", "virus", None, "high"),
    "malicioso": ("Site malicioso", "webfilter", "Malicious", "high"),
    "phishing": ("Phishing", "webfilter", "Phishing", "high"),
    "botnet": ("Botnet (aplicação)", "app-ctrl", "Botnet", "critical"),
    "dns": ("Domínio malicioso (DNS)", "dns", "Malicious", "high"),
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "information": 4, "": 5}
SEVERITY_NAMES = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa", "info": "Informativa",
                  "information": "Informativa", "": "Não informada"}

# Handlers do Event Monitor que indicam máquina comprometida (comparação sem maiúsculas)
COMPROMISED_MARKERS = ("compromised", "ioc", "botnet", "c&c", "command-and-control", "command and control")
ALERT_TEXT_KEYS = ("triggername", "alerttype", "eventtype", "name", "logdesc", "subject")


class ThreatQuery(BaseModel):
    adom: str = Field(default_factory=lambda: settings.faz_default_adom)
    devices: list[str] = []
    devname: str | None = None
    start: datetime
    end: datetime
    top: int = Field(default=TOP, ge=3, le=30)

    @model_validator(mode="after")
    def _check(self):
        if not SAFE_NAME.match(self.adom):
            raise ValueError("ADOM inválido")
        self.log_query("ips")  # valida período, firewall e nome do equipamento
        return self

    def log_query(self, logtype: str, category: str | None = None) -> LogQuery:
        # categoria do site (catdesc); a de aplicação (appcat) entra no filtro em run()
        return LogQuery(adom=self.adom, devices=self.devices, devname=self.devname, start=self.start, end=self.end,
                        logtype=logtype, category=category if logtype != "app-ctrl" else None)

    def faz_time(self, which: str) -> str:
        return getattr(self, which).strftime("%Y-%m-%d %H:%M:%S")


# ---- ranking pelos logs ----------------------------------------------------------------------------
def _severity(log: dict, default: str | None) -> str:
    s = str(log.get("severity") or log.get("crlevel") or default or "").lower()
    return s if s in SEVERITY_ORDER else ""


def threat_row(row: dict, source: str) -> dict:
    """Linha normalizada do portal (explain.normalize) -> linha de ameaça."""
    log = row.get("log_original") or {}
    nome, _lt, _cat, default_sev = SOURCES[source]
    if source == "ips":
        ameaca = log.get("attack") or log.get("msg") or "Assinatura de IPS"
    elif source == "virus":
        ameaca = log.get("virus") or log.get("msg") or "Malware"
    elif source == "botnet":
        ameaca = log.get("app") or "Botnet"
    else:
        ameaca = row.get("site") or row.get("ip_destino") or "-"
    # no IPS o ataque pode vir de fora (origem externa, destino interno): a máquina afetada é o destino
    inbound = source == "ips" and str(log.get("direction") or "").lower() == "incoming"
    return {
        "data_hora": row["data_hora"], "fonte": source, "tipo": nome, "ameaca": str(ameaca)[:200],
        "severidade": _severity(log, default_sev),
        "bloqueado": row["bloqueado"], "acao": row.get("acao_original") or "",
        "usuario": row.get("usuario") or "", "ip_origem": row.get("ip_origem") or "",
        "ip_destino": row.get("ip_destino") or "", "maquina": row.get("maquina") or "",
        "afetado_ip": (row.get("ip_destino") if inbound else row.get("ip_origem")) or "",
        "destino": row.get("destino") or "", "firewall": row.get("firewall") or "",
        "arquivo": str(log.get("filename") or "")[:200], "url": row.get("url") or "",
        "referencia": str(log.get("ref") or "")[:300],
    }


def _ranking(rows: list[dict], top: int) -> dict:
    by_threat: dict[tuple, dict] = {}
    for r in rows:
        key = (r["fonte"], r["ameaca"])
        t = by_threat.setdefault(key, {"ameaca": r["ameaca"], "tipo": r["tipo"], "fonte": r["fonte"], "severidade": r["severidade"],
                                       "eventos": 0, "bloqueados": 0, "maquinas": set(), "usuarios": set(), "ultimo": ""})
        t["eventos"] += 1
        t["bloqueados"] += r["bloqueado"]
        t["maquinas"].add(r["afetado_ip"] or r["maquina"])
        if r["usuario"]:
            t["usuarios"].add(r["usuario"])
        t["ultimo"] = max(t["ultimo"], r["data_hora"])
        if SEVERITY_ORDER.get(r["severidade"], 5) < SEVERITY_ORDER.get(t["severidade"], 5):
            t["severidade"] = r["severidade"]
    threats = sorted(by_threat.values(), key=lambda t: (t["eventos"] - t["bloqueados"] == 0,
                                                        SEVERITY_ORDER.get(t["severidade"], 5), -t["eventos"]))
    for t in threats:
        t["permitidos"] = t["eventos"] - t["bloqueados"]
        t["maquinas"] = len(t["maquinas"] - {""})
        t["usuarios"] = len(t["usuarios"])
    return {"linhas": threats[:500], "total": len(threats)}


def _hosts(rows: list[dict]) -> list[dict]:
    """Máquinas afetadas: quem teve ameaça que passou (não bloqueada) aparece primeiro."""
    hosts: dict[str, dict] = {}
    for r in rows:
        ip = r["afetado_ip"]
        if not ip:
            continue
        h = hosts.setdefault(ip, {"ip": ip, "maquina": "", "usuarios": set(), "ameacas": Counter(), "eventos": 0,
                                  "bloqueados": 0, "pior": "", "ultimo": "", "firewall": r["firewall"]})
        h["eventos"] += 1
        h["bloqueados"] += r["bloqueado"]
        h["ameacas"][r["ameaca"]] += 1
        if r["usuario"]:
            h["usuarios"].add(r["usuario"])
        if r["maquina"] and ip == r["ip_origem"]:
            h["maquina"] = h["maquina"] or r["maquina"]
        if not h["pior"] or SEVERITY_ORDER.get(r["severidade"], 5) < SEVERITY_ORDER.get(h["pior"], 5):
            h["pior"] = r["severidade"]
        h["ultimo"] = max(h["ultimo"], r["data_hora"])
    out = []
    for h in hosts.values():
        h["permitidos"] = h["eventos"] - h["bloqueados"]
        h["usuarios"] = sorted(h["usuarios"])
        h["principais"] = [a for a, _ in h["ameacas"].most_common(3)]
        h["qtd_ameacas"] = len(h["ameacas"])
        del h["ameacas"]
        out.append(h)
    out.sort(key=lambda h: (h["permitidos"] == 0, SEVERITY_ORDER.get(h["pior"], 5), -h["eventos"]))
    return out[:500]


def _charts(rows: list[dict], top: int) -> list[dict]:
    """Mesmo formato dos gráficos da aba Relatórios (o desenho é reaproveitado)."""
    base = len(rows)

    def chart(cid, title, kind, counter, label, n=None):
        items = [[k, c] for k, c in counter.most_common(n)]
        return {"id": cid, "titulo": title, "tipo": kind, "coluna": label, "base": base, "fonte": "eventos de ameaça",
                "distintos": len(counter), "itens": items}
    acao = Counter("Bloqueadas" if r["bloqueado"] else "Não bloqueadas" for r in rows)
    sev = Counter()
    for r in sorted(rows, key=lambda r: SEVERITY_ORDER.get(r["severidade"], 5)):
        sev[SEVERITY_NAMES.get(r["severidade"], r["severidade"])] += 1
    out = [
        {**chart("acao", "Bloqueadas x não bloqueadas", "pie", acao, "Situação"),
         "itens": [[k, acao[k]] for k in ("Bloqueadas", "Não bloqueadas") if acao[k]]},
        chart("tipos", "Ameaças por tipo", "pie", Counter(r["tipo"] for r in rows), "Tipo"),
        {**chart("severidade", "Por severidade", "pie", sev, "Severidade"), "itens": [[k, n] for k, n in sev.items()]},
        chart("ameacas", "Ameaças mais vistas", "bar", Counter(r["ameaca"] for r in rows), "Ameaça", top),
        chart("maquinas", "Máquinas mais afetadas", "bar",
              Counter(r["maquina"] or r["afetado_ip"] for r in rows if r["afetado_ip"]), "Máquina / IP", top),
        chart("usuarios", "Usuários mais afetados", "bar", Counter(r["usuario"] for r in rows if r["usuario"]), "Usuário", top),
    ]
    return [c for c in out if c["itens"]]


# ---- máquinas comprometidas (Event Monitor) -------------------------------------------------------------
def is_compromise_alert(alert: dict) -> bool:
    text = " ".join(str(alert.get(k) or "") for k in ALERT_TEXT_KEYS).lower()
    return any(m in text for m in COMPROMISED_MARKERS)


GROUPBY = re.compile(r"^\s*([\w\-]+)\s*:\s*(.+)$")


def _alert_time(a: dict) -> str:
    for k in ("lastlogtime", "alerttime", "timestamp", "createtime"):
        v = a.get(k)
        if v in (None, ""):
            continue
        try:
            n = int(v)
            if n > 10**12:
                n //= 1000
            return datetime.fromtimestamp(n).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError, OSError):
            return str(v)[:19]
    return ""


def _alert_fields(a: dict) -> dict:
    """Usuário, ameaça e domínio a partir de groupby ("user:maria"), target[] e event_details."""
    got: dict[str, str] = {}
    for k in ("groupby1", "groupby2"):
        m = GROUPBY.match(str(a.get(k) or ""))
        if m:
            got.setdefault(m.group(1).lower(), m.group(2).strip())
    for t in a.get("target") or []:
        if isinstance(t, dict) and t.get("name") and t.get("value"):
            got.setdefault(str(t["name"]).lower(), str(t["value"]))
    det = a.get("event_details") if isinstance(a.get("event_details"), dict) else {}
    user = got.get("user") or got.get("euname") or got.get("unauthuser") or str(det.get("user") or det.get("user_name") or "")
    threat = got.get("threat") or got.get("virus") or got.get("attack") or got.get("app") or ""
    domain = got.get("domain") or got.get("qname") or got.get("host_name") or got.get("hostname") or str(det.get("host_name") or "")
    return {"usuario": user, "ameaca": threat, "dominio": domain}


def compromised_hosts(q: ThreatQuery) -> dict:
    """Alertas de IOC/botnet do Event Monitor agrupados por máquina."""
    alerts = get_client().list_alerts(q.adom, q.faz_time("start"), q.faz_time("end"), limit=ALERTS_MAX)
    lidos = len(alerts["alerts"])
    found = [a for a in alerts["alerts"] if is_compromise_alert(a)]
    if q.devname:
        found = [a for a in found if q.devname.lower() in str(a.get("devname") or "").lower()]
    if q.devices:
        found = [a for a in found if not a.get("devid") or a.get("devid") in q.devices]
    hosts: dict[str, dict] = {}
    for a in found:
        f = _alert_fields(a)
        key = str(a.get("epip") or a.get("epname") or a.get("epid") or "?")
        h = hosts.setdefault(key, {"ip": a.get("epip") or "", "maquina": a.get("epname") or "", "usuarios": set(),
                                   "ameacas": Counter(), "dominios": set(), "alertas": 0, "pior": "", "ultimo": "",
                                   "regras": set(), "firewall": a.get("devname") or "", "reconhecido": True,
                                   "assunto": ""})
        h["alertas"] += 1
        if f["usuario"]:
            h["usuarios"].add(f["usuario"])
        if f["ameaca"]:
            h["ameacas"][f["ameaca"]] += 1
        if f["dominio"]:
            h["dominios"].add(f["dominio"])
        h["regras"].add(str(a.get("triggername") or a.get("name") or ""))
        sev = str(a.get("severity") or "").lower()
        if sev in SEVERITY_ORDER and (not h["pior"] or SEVERITY_ORDER[sev] < SEVERITY_ORDER.get(h["pior"], 5)):
            h["pior"] = sev
        when = _alert_time(a)
        if when >= h["ultimo"]:
            h["ultimo"], h["assunto"] = when, str(a.get("subject") or "")[:300]
        ack = str(a.get("ackflag", a.get("acknowledged", "")) or "").lower()
        h["reconhecido"] = h["reconhecido"] and ack in ("yes", "1", "true", "ack")
    out = []
    for h in hosts.values():
        h["usuarios"] = sorted(h["usuarios"])
        h["ameacas"] = [t for t, _ in h["ameacas"].most_common(5)]
        h["dominios"] = sorted(h["dominios"])[:10]
        h["regras"] = sorted(r for r in h["regras"] if r)
        out.append(h)
    # não reconhecidas (sem ACK) primeiro, depois a pior severidade e o alerta mais recente
    out.sort(key=lambda h: h["ultimo"], reverse=True)
    out.sort(key=lambda h: (h["reconhecido"], SEVERITY_ORDER.get(h["pior"], 5)))
    return {"maquinas": out, "alertas": len(found), "alertas_lidos": lidos, "mais": alerts["mais"]}


# ---- consulta completa ------------------------------------------------------------------------------
def _cache_key(q: ThreatQuery) -> str:
    return "threats:" + hashlib.sha1(json.dumps(q.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()


def run(q: ThreatQuery, use_cache: bool = True) -> dict:
    key = _cache_key(q)
    if use_cache and (hit := database.cache_get(key)):
        hit["cache"] = True
        return hit
    rows: list[dict] = []
    fontes: dict[str, dict[str, Any]] = {}
    for sid, (nome, lt, cat, _sev) in SOURCES.items():
        lq = q.log_query(lt, cat)
        lq.limit = ROWS_PER_SOURCE
        expr = lq.filter_expr()
        if sid == "botnet":
            expr = " and ".join(p for p in (expr, 'appcat~"Botnet"') if p)
        fontes[sid] = {"nome": nome, "filtro": expr, "total": 0, "lidos": 0}
        try:
            res = _search(lq, expr) if sid == "botnet" else run_query(lq, use_cache=False, save_cache=False, policy_names=False)
        except FazError as e:
            fontes[sid]["erro"] = str(e)
            continue
        fontes[sid].update(total=max(res["total"], res["returned"]), lidos=res["returned"], mais=res["mais"])
        rows.extend(threat_row(r, sid) for r in res["rows"])
    erros = {k: f["erro"] for k, f in fontes.items() if f.get("erro")}
    try:
        comprometidas = compromised_hosts(q)
    except FazError as e:
        msg = str(e)
        if "sem permissão" in msg:
            msg = ("O administrador REST não tem acesso ao Event Monitor. No FortiAnalyzer, no perfil do admin REST, "
                   "deixe Event Management como Read-Only.")
        comprometidas = {"maquinas": [], "alertas": 0, "erro": msg}
    if len(erros) == len(SOURCES) and comprometidas.get("erro"):
        raise FazError("Não foi possível consultar o FortiAnalyzer: " + next(iter(erros.values())))
    rows.sort(key=lambda r: r["data_hora"], reverse=True)
    bloqueados = sum(r["bloqueado"] for r in rows)
    out = {
        "periodo": {"inicio": q.start.strftime("%Y-%m-%d %H:%M"), "fim": q.end.strftime("%Y-%m-%d %H:%M")},
        "fontes": fontes, "erros": erros, "amostra": any(f.get("mais") for f in fontes.values()),
        "limite_amostra": ROWS_PER_SOURCE,
        "resumo": {"eventos": len(rows), "bloqueados": bloqueados, "nao_bloqueados": len(rows) - bloqueados,
                   "maquinas": len({r["afetado_ip"] for r in rows if r["afetado_ip"]}),
                   "usuarios": len({r["usuario"] for r in rows if r["usuario"]}),
                   "comprometidas": len(comprometidas["maquinas"])},
        "comprometidas": comprometidas,
        "ameacas": _ranking(rows, q.top),
        "maquinas": _hosts(rows),
        "graficos": _charts(rows, q.top),
        "eventos": rows[:3000],
        "gerado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cache": False,
    }
    if not erros and not comprometidas.get("erro"):
        database.cache_set(key, out, ttl=CACHE_TTL)
    return out


def _search(lq: LogQuery, expr: str) -> dict:
    """Busca com filtro extra que o LogQuery não monta (categoria de aplicação)."""
    from . import explain
    res = get_client().search_logs(adom=lq.adom, logtype=lq.logtype, start=lq.faz_time("start"), end=lq.faz_time("end"),
                                   filter_expr=expr, devices=lq.devices, limit=lq.limit)
    rows = [explain.normalize(lg, lq.logtype) for lg in res["logs"]]
    return {"total": res["total"], "returned": len(rows), "rows": rows, "mais": bool(res.get("mais"))}


EVENT_COLUMNS = [("data_hora", "Data/hora"), ("tipo", "Tipo"), ("ameaca", "Ameaça"), ("severidade", "Severidade"),
                 ("acao", "Ação"), ("usuario", "Usuário"), ("ip_origem", "IP de origem"), ("maquina", "Máquina"),
                 ("ip_destino", "IP de destino"), ("destino", "Destino"), ("arquivo", "Arquivo"), ("firewall", "Firewall")]
