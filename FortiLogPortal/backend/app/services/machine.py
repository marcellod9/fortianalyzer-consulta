"""Situação da máquina no Vision One: o agente Trend está ativo? Há alertas abertos no Workbench?

Pelo IP de origem do log (e pelo nome da máquina, quando o firewall identifica o dispositivo) o portal
procura a máquina no inventário de endpoints e mostra o agente: ligado ou não, último contato, sensor XDR
e isolamento. Os alertas do Workbench do período (V1_LOOKBACK_DAYS) são filtrados aqui mesmo pela máquina
(nome, IP ou GUID do agente) e pelo usuário (conta ou e-mail).

APIs oficiais v3.0: GET /eiqs/endpoints (TMV1-Query), GET /endpointSecurity/endpoints/{id} e
GET /workbench/alerts. A função da chave de API precisa visualizar o Endpoint Inventory e o Workbench.
"""
import ipaddress
import re
from datetime import datetime, timezone

from .. import database
from ..config import settings
from . import visionone
from .visionone import V1Error

NAME_RE = re.compile(r"[\w.\- ]{1,64}")  # sem aspas: o valor vai entre '...' na consulta
USER_RE = re.compile(r"[\w.\-@\\ ]{1,128}")
MAX_ENDPOINTS = 5
MAX_DETAILS = 3
MAX_ALERTS = 500
STALE_DAYS = 7  # sem contato há uma semana ou mais: agente "sem comunicação"
ALERTS_TTL = 300
PRODUCTS = {"sao": "Proteção de endpoint (Standard Endpoint Protection / Apex One)",
            "sds": "Server & Workload Protection", "xes": "Sensor XDR (Endpoint Sensor)"}
SEVERITY = {"critical": "crítica", "high": "alta", "medium": "média", "low": "baixa"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ALERT_STATUS = {"Open": "Aberto", "In Progress": "Em andamento", "Closed": "Encerrado", "New": "Novo"}
ISOLATION = {"on": "Isolada da rede", "isolated": "Isolada da rede", "pending": "Isolamento pendente",
             "off": "Não isolada", "normal": "Não isolada"}
COMPONENTS = {"latestVersion": "Atualizados", "outdatedVersion": "Desatualizados"}
PERMISSION_HINT = {
    "inventario": "Na função (role) da chave de API no Vision One, marque a permissão de visualizar o Endpoint Inventory.",
    "alertas": "Na função (role) da chave de API no Vision One, marque a permissão de visualizar o Workbench.",
}


# ---- entrada ------------------------------------------------------------------------
def _clean_ip(ip: str | None) -> str | None:
    v = (ip or "").strip()
    if not v:
        return None
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        raise ValueError("IP de origem inválido.") from None


def norm_user(u: str) -> str:
    """DOMINIO\\usuario, usuario@dominio e USUARIO viram usuario."""
    return (u or "").strip().lower().rsplit("\\", 1)[-1].split("@", 1)[0]


def norm_host(h: str) -> str:
    """NB-01.marista.local e nb-01 viram nb-01 (IP fica como está)."""
    h = (h or "").strip().lower()
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        return h.split(".", 1)[0]


def _name_variants(name: str) -> list[str]:
    short = name.split(".", 1)[0]
    out: list[str] = []
    for v in (name, name.upper(), short, short.upper()):
        if v and v not in out:
            out.append(v)
    return out


def build_query(ip: str | None, name: str | None) -> str:
    """Consulta TMV1-Query do inventário (mesma sintaxe do SDK oficial: campo eq 'valor', unidos por or)."""
    parts = [f"ip eq '{ip}'"] if ip else []
    parts += [f"endpointName eq '{v}'" for v in _name_variants(name)] if name else []
    return " or ".join(parts)


# ---- respostas da API -------------------------------------------------------------------
def _value(x):
    return x.get("value") if isinstance(x, dict) else x


def _as_list(x) -> list[str]:
    v = _value(x)
    if not v:
        return []
    return [str(i) for i in v] if isinstance(v, list) else [str(v)]


def _parse_ts(ts) -> datetime | None:
    if not ts:
        return None
    s = str(ts).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            dt = datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _local(ts) -> str | None:
    dt = _parse_ts(ts)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M") if dt else None


def _error_text(kind: str, e: V1Error) -> str:
    return f"{e} {PERMISSION_HINT[kind]}" if e.status == 403 else str(e)


def _agent(det: dict | None) -> dict:
    """Situação do agente a partir do detalhe do endpoint (endpointSecurity/endpoints/{id})."""
    if not det:
        return {"estado": "desconhecido", "texto": "Situação do agente não disponível", "titulo": None,
                "ultimo_contato": None, "dias_sem_contato": None, "protecao": None, "sensor": None}
    epp, edr = det.get("eppAgent") or {}, det.get("edrSensor") or {}
    seen = [d for d in (_parse_ts(epp.get("lastConnectedDateTime")), _parse_ts(edr.get("lastConnectedDateTime"))) if d]
    last = max(seen) if seen else None
    days = (datetime.now(timezone.utc) - last).days if last else None
    st, conn = (epp.get("status") or "").lower(), (edr.get("connectivity") or "").lower()
    titulo = None  # título da conclusão quando o agente não está se comunicando
    if epp and st == "off":
        estado, texto, titulo = "desligado", "Agente desligado ou offline", "Agente Trend desligado ou offline"
    elif days is not None and days >= STALE_DAYS:
        estado, texto = "sem_contato", f"Sem comunicação há {days} dias"
        titulo = f"Agente Trend sem comunicação há {days} dias"
    elif st == "on" or conn == "connected":
        estado, texto = "ativo", "Agente ativo"
    elif not st and conn == "disconnected":
        estado, texto, titulo = "desligado", "Sensor desconectado", "Sensor XDR do Trend desconectado"
    else:
        estado, texto = "desconhecido", f"Situação do agente: {epp.get('status') or edr.get('connectivity') or 'não informada'}"
    protecao = {"on": "Ligada", "off": "Desligada"}.get(st, epp.get("status")) if epp else None
    sensor = None
    if edr:
        sensor = {"connected": "Conectado", "disconnected": "Desconectado"}.get(conn, edr.get("connectivity") or "")
        if (edr.get("status") or "").lower() == "disabled":
            sensor = (sensor + " · " if sensor else "") + "desativado"
    return {"estado": estado, "texto": texto, "titulo": titulo,
            "ultimo_contato": last.astimezone().strftime("%Y-%m-%d %H:%M") if last else None,
            "dias_sem_contato": days, "protecao": protecao, "sensor": sensor or None}


def _endpoint(inv: dict, det: dict | None, det_err: str | None, ip: str | None, names: set[str]) -> dict:
    det_ = det or {}
    epp = det_.get("eppAgent") or {}
    name = str(_value(inv.get("endpointName")) or det_.get("endpointName") or "")
    ips = _as_list(inv.get("ip"))
    for itf in det_.get("interfaces") or []:
        ips += [str(i) for i in itf.get("ipAddresses") or []]
    if det_.get("lastUsedIp"):
        ips.append(str(det_["lastUsedIp"]))
    macs = _as_list(inv.get("macAddress")) + [str(i["macAddress"]) for i in det_.get("interfaces") or [] if i.get("macAddress")]
    users = _as_list(inv.get("loginAccount"))
    if det_.get("lastLoggedOnUser"):
        users.append(str(det_["lastLoggedOnUser"]))
    os_ = det_.get("os") or {}
    codes = [inv.get("productCode")] + list(inv.get("installedProductCodes") or [])
    iso = (det_.get("isolationStatus") or "").lower()
    comp = epp.get("componentVersion") or inv.get("componentVersion")
    found = [k for k, ok in (("ip", ip and ip in ips), ("nome", norm_host(name) in names)) if ok]
    return {
        "guid": inv.get("agentGuid") or det_.get("agentGuid"), "nome": name,
        "ips": list(dict.fromkeys(ips)), "macs": list(dict.fromkeys(m.lower() for m in macs)),
        "usuarios": list(dict.fromkeys(users)), "ultimo_usuario": det_.get("lastLoggedOnUser"),
        "sistema": inv.get("osDescription") or os_.get("name") or " ".join(
            str(v) for v in (inv.get("osName"), inv.get("osVersion")) if v) or None,
        "produtos": list(dict.fromkeys(PRODUCTS.get(c, c) for c in codes if c)),
        "politica": epp.get("policyName") or inv.get("policyName"),
        "gerenciador": epp.get("protectionManager") or inv.get("protectionManager"),
        "componentes": COMPONENTS.get(comp, comp) if comp else None,
        "agente": _agent(det), "isolada": iso in ("on", "isolated"),
        "isolamento": ISOLATION.get(iso, det_.get("isolationStatus")) if iso else None,
        "encontrado_por": found, "erro": det_err,
    }


# ---- alertas do Workbench -------------------------------------------------------------------
def _slim_alert(a: dict) -> dict:
    """Só o necessário para o cache: identificação e as entidades afetadas (impactScope)."""
    ents = [{"tipo": e.get("entityType"), "valor": e.get("entityValue")}
            for e in (a.get("impactScope") or {}).get("entities") or []]
    ents += [{"tipo": "host", "valor": i["value"]} for i in a.get("indicators") or []
             if isinstance(i.get("value"), dict) and i["value"].get("name")]
    return {"id": a.get("id"), "modelo": a.get("model"), "severidade": a.get("severity"), "score": a.get("score"),
            "status": a.get("status"), "investigacao": a.get("investigationStatus"),
            "criado": a.get("createdDateTime"), "link": a.get("workbenchLink"), "entidades": ents}


def _alerts(client, refresh: bool) -> tuple[list[dict], bool]:
    key = f"v1:wb-maquina:{settings.v1_lookback_days}"
    if not refresh:
        hit = database.cache_get(key)
        if hit is not None:
            return hit, True
    start, end = visionone.default_window()
    items = [_slim_alert(a) for a in client.workbench_alerts(start, end, max_items=MAX_ALERTS)]
    database.cache_set(key, items, ttl=ALERTS_TTL)
    return items, False


def _is_open(a: dict) -> bool:
    if a.get("status"):
        return a["status"] != "Closed"
    return (a.get("investigacao") or "New") in ("New", "In Progress")


def match_alert(a: dict, hosts: set[str], guids: set[str], ip: str | None, user: str | None) -> list[str]:
    """Por que o alerta é desta máquina ou deste usuário (vazio: não é)."""
    why = []
    for e in a.get("entidades") or []:
        t, v = e.get("tipo"), e.get("valor")
        if t == "host":
            hv = v if isinstance(v, dict) else {"name": v}
            hname = str(hv.get("name") or "")
            if (hv.get("guid") and hv["guid"] in guids) or (hname and norm_host(hname) in hosts):
                why.append(f"máquina {hname or hv.get('guid')}")
            elif ip and ip in [str(x) for x in hv.get("ips") or []]:
                why.append(f"IP {ip}")
        elif user and t in ("account", "emailAddress") and isinstance(v, str) and norm_user(v) == user:
            why.append(f"{'usuário' if t == 'account' else 'e-mail'} {v}")
    return list(dict.fromkeys(why))


def _alert_out(a: dict, why: list[str]) -> dict:
    link = a.get("link") if str(a.get("link") or "").startswith("https://") else None
    st = a.get("status") or a.get("investigacao") or "Open"
    sev = a.get("severidade")
    return {"id": a.get("id"), "modelo": a.get("modelo") or "Alerta sem nome", "severidade": sev,
            "severidade_texto": SEVERITY.get(sev, sev) or "não informada", "score": a.get("score"),
            "status": ALERT_STATUS.get(st, st), "criado": _local(a.get("criado")), "_criado": a.get("criado") or "",
            "link": link, "motivos": why}


# ---- consulta ---------------------------------------------------------------------------------
def machine_status(ip: str | None = None, nome: str | None = None, usuario: str | None = None,
                   refresh: bool = False) -> dict:
    ip = _clean_ip(ip)
    nome, user = (nome or "").strip() or None, (usuario or "").strip() or None
    avisos: list[str] = []
    if nome and not NAME_RE.fullmatch(nome):
        if not ip:
            raise ValueError("Nome de máquina inválido.")
        avisos.append(f"O nome {nome} tem caracteres que a consulta do Vision One não aceita; a máquina foi procurada só pelo IP.")
        nome = None
    if user and not USER_RE.fullmatch(user):
        if not (ip or nome):
            raise ValueError("Usuário inválido.")
        avisos.append(f"O usuário {user} tem caracteres não aceitos; os alertas foram procurados só pela máquina.")
        user = None
    if not (ip or nome or user):
        raise ValueError("Informe o IP, o nome da máquina ou o usuário.")

    client = visionone.get_client()
    erros: dict[str, str] = {}
    query = build_query(ip, nome)
    names = {norm_host(v) for v in ([nome] if nome else [])}
    endpoints: list[dict] = []
    if query:
        try:
            inv = client.search_endpoints(query, max_items=MAX_ENDPOINTS)
        except V1Error as e:
            inv = []
            erros["inventario"] = _error_text("inventario", e)
        seen_guids = set()
        for i, item in enumerate(inv):
            guid = item.get("agentGuid")
            if guid in seen_guids:
                continue
            seen_guids.add(guid)
            det, det_err = None, None
            if guid and i < MAX_DETAILS:
                try:
                    det = client.endpoint_details(guid)
                except V1Error as e:
                    det_err = ("O Vision One não devolveu os detalhes deste agente (HTTP 404)." if e.status == 404
                               else _error_text("inventario", e))
            endpoints.append(_endpoint(item, det, det_err, ip, names))
        # a máquina achada pelos dois critérios (IP e nome) vem primeiro; depois o nome (o IP muda com o DHCP)
        endpoints.sort(key=lambda e: (-len(e["encontrado_por"]), "nome" not in e["encontrado_por"]))
    elif user:
        avisos.append("Sem IP ou nome da máquina: mostrando só os alertas do usuário.")

    if ip and nome and endpoints and not any("nome" in e["encontrado_por"] for e in endpoints):
        avisos.append(f"No Vision One o IP {ip} está com {', '.join(e['nome'] for e in endpoints)}, não com {nome}. "
                      "O IP pode ter mudado desde o log (DHCP).")
    elif ip and nome and endpoints and not any("ip" in e["encontrado_por"] for e in endpoints):
        avisos.append(f"No Vision One, {endpoints[0]['nome']} está com o IP {', '.join(endpoints[0]['ips']) or '-'} "
                      f"(no log era {ip}). O IP pode ter mudado desde o log (DHCP).")
    elif ip and nome and len(endpoints) > 1 and {"ip"} == set(endpoints[-1]["encontrado_por"]):
        avisos.append(f"O IP {ip} aparece também em {endpoints[-1]['nome']}: o IP pode ter mudado desde o log (DHCP).")

    hosts = names | {norm_host(e["nome"]) for e in endpoints if e["nome"]}
    guids = {e["guid"] for e in endpoints if e["guid"]}
    abertos, encerrados, alerts_cache = [], [], False
    try:
        alerts, alerts_cache = _alerts(client, refresh)
        for a in alerts:
            why = match_alert(a, hosts, guids, ip, norm_user(user) if user else None)
            if why:
                (abertos if _is_open(a) else encerrados).append(_alert_out(a, why))
        if len(alerts) >= MAX_ALERTS:
            avisos.append(f"Foram verificados os {MAX_ALERTS} alertas mais recentes do Workbench.")
    except V1Error as e:
        erros["alertas"] = _error_text("alertas", e)
    if len(erros) == 2 or (erros.get("alertas") and not query):
        raise V1Error("; ".join(erros.values()))
    abertos.sort(key=lambda a: a["_criado"], reverse=True)
    abertos.sort(key=lambda a: SEVERITY_ORDER.get(a["severidade"], 9))  # mais grave primeiro, depois o mais novo
    encerrados.sort(key=lambda a: a["_criado"], reverse=True)
    for a in abertos + encerrados:
        a.pop("_criado")

    start, end = visionone.default_window()
    out = {
        "consulta": {"ip": ip, "nome": nome, "usuario": user}, "consulta_v1": query or None,
        "endpoints": endpoints, "alertas": abertos, "alertas_encerrados": encerrados[:10],
        "total_encerrados": len(encerrados), "alertas_cache": alerts_cache,
        "periodo_alertas": {"inicio": start.strftime("%Y-%m-%d"), "fim": end.strftime("%Y-%m-%d"),
                            "dias": settings.v1_lookback_days},
        "erros": erros, "avisos": avisos, "consultado_em": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    out.update(conclude(out))
    return out


def conclude(d: dict) -> dict:
    """Conclusão em linguagem simples para o atendente."""
    eps, abertos, q = d["endpoints"], d["alertas"], d["consulta"]
    alvo = q["nome"] or q["ip"] or q["usuario"]
    main = eps[0] if eps else None
    agente = f" Agente Trend: {main['agente']['texto'].lower()} em {main['nome']}." if main else ""
    # isolamento primeiro: é a explicação direta para "a internet não funciona" (os alertas vêm logo abaixo)
    isolada = next((e for e in eps if e["isolada"]), None)
    if isolada:
        ids = ", ".join(a["id"] for a in abertos[:3])
        return {"status": "isolada", "titulo": "Máquina isolada da rede pelo Vision One",
                "resumo": f"{isolada['nome']} está isolada: só se comunica com o Trend Vision One."
                          + (f" Há também {len(abertos)} alerta(s) aberto(s) no Workbench ({ids})." if abertos else ""),
                "orientacao": "Com a máquina isolada a internet e a rede não funcionam, e a causa não é o firewall. "
                              "Não tente liberar acesso: encaminhe à equipe de segurança, que decide quando liberar."
                              + (f" Informe no chamado o número do alerta ({abertos[0]['id']})." if abertos else "")}
    if abertos:
        a = abertos[0]
        return {"status": "alerta", "titulo": f"{len(abertos)} alerta(s) aberto(s) no Workbench",
                "resumo": f"O mais grave: {a['modelo']} (severidade {a['severidade_texto']}, {a['status'].lower()}), "
                          f"criado em {a['criado']}, ligado a {a['motivos'][0]}.{agente}",
                "orientacao": "Esta máquina ou este usuário tem alerta de segurança em aberto. Não libere sites, exceções "
                              "ou acessos antes de falar com a equipe de segurança, e informe no chamado o número do "
                              f"alerta ({a['id']})."}
    if main:
        ag = main["agente"]
        when = f" Último contato: {ag['ultimo_contato']}." if ag["ultimo_contato"] else ""
        if ag["estado"] == "ativo":
            return {"status": "ok", "titulo": "Agente Trend ativo e nenhum alerta aberto",
                    "resumo": f"{main['nome']} tem o agente ativo.{when} Nenhum alerta aberto no Workbench para a "
                              f"máquina ou o usuário nos últimos {d['periodo_alertas']['dias']} dias.",
                    "orientacao": "Pelo Vision One a máquina está protegida. Se o problema é de acesso, siga com o "
                                  "diagnóstico do firewall."}
        if ag["estado"] in ("desligado", "sem_contato"):
            return {"status": "atencao", "titulo": ag["titulo"] or ag["texto"],
                    "resumo": f"{main['nome']}: {ag['texto'].lower()}.{when} Nenhum alerta aberto no Workbench.",
                    "orientacao": "Peça para o usuário reiniciar a máquina conectado à rede da Marista. Se o agente "
                                  "continuar sem comunicação, encaminhe à equipe responsável pelo antivírus."}
        return {"status": "info", "titulo": "Máquina encontrada no Vision One",
                "resumo": f"{main['nome']} está no inventário, mas a situação do agente não veio na consulta. "
                          "Nenhum alerta aberto no Workbench.",
                "orientacao": "Confira a máquina no console do Vision One (Endpoint Inventory) ou encaminhe ao N2."}
    if d["erros"].get("inventario"):
        return {"status": "erro", "titulo": "Não foi possível consultar o inventário de endpoints",
                "resumo": f"Nenhum alerta aberto no Workbench para {alvo}. O agente não pôde ser verificado.",
                "orientacao": d["erros"]["inventario"]}
    if not d["consulta_v1"]:
        return {"status": "ok", "titulo": "Nenhum alerta aberto para o usuário",
                "resumo": f"Nenhum alerta aberto no Workbench para {alvo} nos últimos {d['periodo_alertas']['dias']} dias.",
                "orientacao": "Para ver o agente Trend, consulte também pelo IP ou pelo nome da máquina."}
    return {"status": "sem_agente", "titulo": "Nenhum agente Trend encontrado",
            "resumo": f"O inventário do Vision One não tem máquina com {' ou '.join(v for v in (q['ip'], q['nome']) if v)}. "
                      "Nenhum alerta aberto no Workbench.",
            "orientacao": "Pode ser um aparelho sem o agente (celular, notebook pessoal ou de visitante) ou o IP mudou "
                          "desde o log (DHCP). Confira o nome da máquina com o usuário. Máquina da Marista sem o agente "
                          "deve ser encaminhada à equipe responsável pelo antivírus."}
