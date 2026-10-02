"""Ameaças > Trend inativo: máquinas vistas no firewall da unidade cujo agente Trend não está protegendo.

1. Máquinas da unidade: origens internas vistas nos logs do firewall escolhido no FortiAnalyzer, com o nome,
   MAC, usuário e sistema que o FortiGate identificou. Primeiro o FortiView Top Sources (o FAZ já agrega o
   período inteiro); se a versão não tiver essa visão, os logs de tráfego mais recentes do período.
2. Inventário do Vision One: GET /v3.0/endpointSecurity/endpoints (mesma lista do SDK oficial pytmv1,
   campos endpointName, lastUsedIp, ipAddresses, eppAgent.status/lastConnectedDateTime, edrSensor.connectivity).
3. Cruzamento pelo nome da máquina e, sem nome, pelo IP. Situação do agente: a mesma regra da busca de máquina
   (desligado, sem comunicação há 7 dias ou mais, sensor desconectado) e "sem Trend" quando a máquina não está
   no inventário.

A chave de API do Vision One precisa visualizar o Endpoint Inventory; o FAZ, Log View (e FortiView, opcional).
"""
import ipaddress
import logging
from collections import Counter
from datetime import datetime, timezone

from .. import database
from ..config import settings
from . import explain, visionone
from .fortianalyzer import FazError
from .fortianalyzer import get_client as faz_client
from .machine import NAME_RE, _agent, _parse_ts, _value, build_query, norm_host, norm_user
from .threats import ThreatQuery
from .visionone import V1Error

log = logging.getLogger("portal.trend")

SOURCES_TOP = 3000        # linhas do FortiView Top Sources
LOG_ROWS = 5000           # logs de tráfego lidos quando não há FortiView
INVENTORY_TTL = 1800      # inventário do Vision One em cache (30 min)
SHOW_MAX = 3000
LOOKUP_MAX = 300          # máquinas fora da lista procuradas uma a uma no inventário (Endpoint Inventory)
LOOKUP_BATCH = 10         # máquinas por consulta TMV1-Query
# o que o FortiGate identifica como celular, TV, impressora etc.: não leva agente Trend
NOT_COMPUTER = ("android", "ios", "iphone", "ipad", "phone", "tablet", "printer", "impressora", "camera", "tv",
                "playstation", "xbox", "nintendo", "chromecast", "roku", "router", "switch", "access point", "voip")
STATE = {
    "desligado": ("Trend desligado ou offline", 0), "sem_contato": ("Trend sem comunicação", 1),
    "sem_trend": ("Sem Trend (fora do inventário)", 2), "desconhecido": ("Situação não informada", 3),
    "ativo": ("Trend ativo", 9),
}
COLUMNS = [("situacao", "Situação do Trend"), ("maquina", "Máquina"), ("ip", "IP"), ("mac", "MAC"),
           ("usuario", "Usuário (firewall)"), ("usuario_trend", "Último usuário (Trend)"), ("sistema", "Sistema"),
           ("rede", "Rede (interface)"), ("ultimo_contato", "Último contato do Trend"), ("visto", "Visto no firewall"),
           ("firewall", "Firewall"), ("grupo", "Grupo/política no Trend"), ("achado_por", "Encontrado por")]


class CoverageQuery(ThreatQuery):
    so_computadores: bool = True     # deixa de fora celulares, TVs e impressoras identificados pelo FortiGate
    incluir_ativos: bool = False


# ---- máquinas vistas no firewall -------------------------------------------------------------
def _private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not a.is_loopback and not a.is_link_local


def _first(d: dict, *keys) -> str:
    for k in keys:
        v = d.get(k)
        if isinstance(v, list):
            v = next((x for x in v if x), "")
        if v not in (None, "", "N/A", "n/a"):
            return str(v)
    return ""


def _add(seen: dict, ip: str, row: dict, when: str = "", sessions: int = 1) -> None:
    m = seen.setdefault(ip, {"ip": ip, "maquina": "", "mac": "", "usuario": "", "sistema": "", "tipo": "", "rede": "",
                             "firewall": Counter(), "visto": "", "sessoes": 0})
    for k, keys in (("maquina", ("srcname", "hostname", "src_name")), ("mac", ("srcmac", "mastersrcmac", "mac")),
                    ("usuario", ("user", "unauthuser", "srcuser")), ("sistema", ("osname", "os")),
                    ("tipo", ("devtype", "srcdevtype")), ("rede", ("srcintf",))):
        if not m[k]:
            m[k] = _first(row, *keys)
    if not m["sistema"] and row.get("osversion"):
        m["sistema"] = str(row["osversion"])
    fw = _first(row, "devname", "dev_name")
    if fw:
        m["firewall"][fw] += 1
    m["visto"] = max(m["visto"], when or "")
    m["sessoes"] += sessions


def machines_from_faz(q: CoverageQuery) -> tuple[list[dict], str, list[str]]:
    """(máquinas, de onde vieram, avisos)."""
    client = faz_client()
    avisos: list[str] = []
    seen: dict[str, dict] = {}
    start, end = q.faz_time("start"), q.faz_time("end")
    try:
        rows = client.fortiview(q.adom, "top-sources", start, end, devices=q.devices or None, limit=SOURCES_TOP)
        for r in rows:
            ip = _first(r, "srcip", "src", "ip")
            if ip and _private(ip):
                if q.devname and q.devname.lower() not in _first(r, "devname").lower() and _first(r, "devname"):
                    continue
                _add(seen, ip, r, when=_first(r, "last_seen", "lastseen"), sessions=int(r.get("sessions") or 1))
    except FazError as e:
        log.info("FortiView top-sources indisponível: %s", e)
    origem = "FortiView Top Sources (período inteiro)"
    if not seen:
        lq = q.log_query("traffic")
        lq.limit = LOG_ROWS
        res = client.search_logs(adom=lq.adom, logtype="traffic", start=start, end=end, filter_expr=lq.filter_expr(),
                                 devices=lq.devices or None, limit=LOG_ROWS)
        for lg in res["logs"]:
            ip = str(lg.get("srcip") or "")
            if ip and _private(ip):
                _add(seen, ip, lg, when=explain.normalize(lg, "traffic")["data_hora"])
        origem = f"logs de tráfego (os {len(res['logs'])} mais recentes do período)"
        if res.get("mais"):
            avisos.append(f"O período tem mais de {LOG_ROWS} logs de tráfego: foram lidos os mais recentes. "
                          "Use um período menor para ver todas as máquinas da unidade.")
    out = []
    for m in seen.values():
        m["firewall"] = m["firewall"].most_common(1)[0][0] if m["firewall"] else ""
        out.append(m)
    return out, origem, avisos


def is_computer(m: dict) -> bool:
    text = f"{m.get('sistema', '')} {m.get('tipo', '')}".lower()
    return not any(k in text for k in NOT_COMPUTER)


# ---- inventário do Vision One ----------------------------------------------------------------
def inventory(refresh: bool = False) -> list[dict]:
    key = "v1:endpoint-inventory"
    if not refresh:
        hit = database.cache_get(key)
        if hit is not None:
            return hit
    client = visionone.get_client()
    items = client.endpoints(max_items=settings.v1_inventory_max)
    slim = [{k: it.get(k) for k in ("agentGuid", "endpointName", "lastUsedIp", "ipAddresses", "osName", "osPlatform",
                                    "lastLoggedOnUser", "eppAgent", "edrSensor", "isolationStatus")} for it in items]
    database.cache_set(key, slim, ttl=INVENTORY_TTL)
    return slim


UNMANAGED = "Sem agente Trend (máquina descoberta, não gerenciada no Vision One)"


def has_agent(ep: dict) -> bool:
    """A lista de endpoints também traz as máquinas só descobertas (Unmanaged endpoints), sem eppAgent nem edrSensor."""
    return bool(ep.get("eppAgent") or ep.get("edrSensor"))


def _name(ep: dict) -> str:
    v = ep.get("endpointName")
    return str(v.get("value") if isinstance(v, dict) else v or "")


def _last_contact(ep: dict) -> datetime:
    dts = [_parse_ts((ep.get(k) or {}).get("lastConnectedDateTime")) for k in ("eppAgent", "edrSensor")]
    return max([d for d in dts if d] or [datetime.min.replace(tzinfo=timezone.utc)])


def index(eps: list[dict]) -> tuple[dict, dict]:
    by_name: dict[str, dict] = {}
    by_ip: dict[str, dict] = {}
    for ep in eps:
        for d, k in ([(by_name, norm_host(_name(ep)))] if _name(ep) else []) + \
                    [(by_ip, ip) for ip in {ep.get("lastUsedIp"), *(ep.get("ipAddresses") or [])} if ip]:
            # nome/IP repetido: vale o registro com agente e, entre eles, o de contato mais recente
            if k not in d or (has_agent(ep), _last_contact(ep)) > (has_agent(d[k]), _last_contact(d[k])):
                d[k] = ep
    return by_name, by_ip


def lookup_missing(client, machines: list[dict]) -> tuple[list[dict], list[str]]:
    """Procura no Endpoint Inventory (GET /eiqs/endpoints, TMV1-Query) as máquinas que não vieram na lista e lê a
    situação do agente de cada uma achada (GET /endpointSecurity/endpoints/{id}), como na busca de máquina."""
    found: dict[str, dict] = {}
    falhas: list[str] = []
    for i in range(0, len(machines), LOOKUP_BATCH):
        batch = machines[i:i + LOOKUP_BATCH]
        query = " or ".join(build_query(m["ip"] if _private(m["ip"]) else None,
                                        m["maquina"] if NAME_RE.fullmatch(m["maquina"] or "") else None) for m in batch)
        try:
            invs = client.search_endpoints(query, max_items=len(batch) * 3)
        except (V1Error, ValueError) as e:
            falhas.append(str(e))
            if getattr(e, "status", None) in (401, 403):
                break
            continue
        for inv in invs:
            guid = inv.get("agentGuid")
            if not guid or guid in found:
                continue
            try:
                det = client.endpoint_details(guid)
            except V1Error as e:
                falhas.append(str(e))
                det = {}
            name = str(_value(inv.get("endpointName")) or det.get("endpointName") or "")
            ips = [str(x) for x in (_value(inv.get("ip")) or [])] + ([det["lastUsedIp"]] if det.get("lastUsedIp") else [])
            found[guid] = {"agentGuid": guid, "endpointName": name, "lastUsedIp": det.get("lastUsedIp"), "ipAddresses": ips,
                           "osName": inv.get("osName"), "lastLoggedOnUser": det.get("lastLoggedOnUser"),
                           "eppAgent": det.get("eppAgent"), "edrSensor": det.get("edrSensor"), "_busca": True}
    return list(found.values()), falhas


# ---- cruzamento ---------------------------------------------------------------------------------
def run(q: CoverageQuery, refresh: bool = False) -> dict:
    machines, origem, avisos = machines_from_faz(q)
    vistos = len(machines)
    if q.so_computadores:
        machines = [m for m in machines if is_computer(m)]
    try:
        client = visionone.get_client()
        if hasattr(client, "inventory_for"):  # demonstração (PORTAL_DEMO=true): inventário só das máquinas vistas
            eps = client.inventory_for([m["ip"] for m in machines])
        else:
            eps = inventory(refresh)
    except V1Error as e:
        msg = str(e)
        if e.status == 403:
            msg += " Na função (role) da chave de API no Vision One, marque a permissão de visualizar o Endpoint Inventory."
        raise V1Error(msg, e.status)
    by_name, by_ip = index(eps)

    def match(m):
        if m["maquina"] and norm_host(m["maquina"]) in by_name:
            return by_name[norm_host(m["maquina"])], "nome"
        if m["ip"] in by_ip:
            return by_ip[m["ip"]], "IP"
        return None, ""

    # a lista pode não trazer todas as máquinas (limite, grupos da chave): as que faltaram são procuradas uma a uma
    # com a lista completa, quem não está nela não está no inventário: a busca individual só roda se ela foi cortada
    truncated = len(eps) >= settings.v1_inventory_max
    missing = [m for m in machines if not match(m)[0]] if truncated else []
    extra, falhas = lookup_missing(client, missing[:LOOKUP_MAX])
    if extra:
        n2, i2 = index(extra)
        for k, v in n2.items():
            by_name.setdefault(k, v)
        for k, v in i2.items():
            by_ip.setdefault(k, v)
    if falhas:
        avisos.append("A busca individual no Endpoint Inventory falhou para parte das máquinas: " + falhas[0])
    if len(missing) > LOOKUP_MAX:
        avisos.append(f"{len(missing) - LOOKUP_MAX} máquina(s) não foram procuradas uma a uma (limite de {LOOKUP_MAX}); "
                      "escolha um firewall ou um período menor.")
    rows, count = [], Counter()
    for m in machines:
        ep, por = match(m)
        if ep and ep.get("_busca"):
            por += " (busca no inventário)"
        if ep and not has_agent(ep):
            # registro de máquina descoberta (Unmanaged endpoints no console): o V1 conhece, mas não há agente
            ag, estado = None, "sem_trend"
        elif ep:
            ag = _agent(ep)
            estado = ag["estado"]
        else:
            ag, estado = None, "sem_trend"
        count[estado] += 1
        if estado == "ativo" and not q.incluir_ativos:
            continue
        epp = (ep or {}).get("eppAgent") or {}
        rows.append({
            "estado": estado, "situacao": ag["texto"] if ag else (UNMANAGED if ep else STATE["sem_trend"][0]),
            "maquina": m["maquina"] or (_name(ep) if ep else ""), "nome_trend": _name(ep) if ep else "",
            "ip": m["ip"], "mac": m["mac"], "usuario": m["usuario"], "usuario_trend": (ep or {}).get("lastLoggedOnUser") or "",
            "sistema": m["sistema"] or (ep or {}).get("osName") or "", "tipo": m["tipo"], "rede": m["rede"],
            "ultimo_contato": ag["ultimo_contato"] if ag else "", "dias_sem_contato": ag["dias_sem_contato"] if ag else None,
            "visto": m["visto"], "firewall": m["firewall"], "sessoes": m["sessoes"],
            "grupo": " · ".join(v for v in (epp.get("endpointGroup"), epp.get("policyName")) if v),
            "achado_por": por, "guid": (ep or {}).get("agentGuid") or "",
            "mesmo_usuario": bool(m["usuario"] and ep and ep.get("lastLoggedOnUser")
                                  and norm_user(m["usuario"]) == norm_user(str(ep["lastLoggedOnUser"]))),
        })
    rows.sort(key=lambda r: r["visto"], reverse=True)  # visto por último primeiro, dentro de cada situação
    rows.sort(key=lambda r: STATE.get(r["estado"], ("", 5))[1])
    inativos = count["desligado"] + count["sem_contato"]
    if eps and not count["ativo"] and not inativos and machines:
        avisos.append("Nenhuma máquina da unidade foi encontrada no inventário do Vision One. Confira se o nome que o "
                      "FortiGate identifica é o mesmo do Trend e se a chave de API vê todos os grupos de endpoints.")
    if len(eps) >= settings.v1_inventory_max:
        avisos.append(f"O inventário do Vision One foi lido até o limite de {settings.v1_inventory_max} endpoints "
                      "(V1_INVENTORY_MAX); máquinas além disso aparecem como sem Trend.")
    return {
        "linhas": rows[:SHOW_MAX], "total_linhas": len(rows),
        "resumo": {"vistas": vistos, "computadores": len(machines), "ativos": count["ativo"], "inativos": inativos,
                   "sem_trend": count["sem_trend"], "desconhecido": count["desconhecido"], "inventario": len(eps)},
        "origem": origem, "avisos": avisos,
        "periodo": {"inicio": q.faz_time("start"), "fim": q.faz_time("end")},
        "gerado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
