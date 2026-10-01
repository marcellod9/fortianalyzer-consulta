"""Normaliza logs do FortiGate e traduz para linguagem simples.

Os nomes de campos seguem a referência de logs do FortiOS 7.x
(date, time, devname, srcip, dstip, srcport, dstport, user, url, hostname,
app, appcat, policyid, policyname, profile, srcintf, dstintf, action,
eventtype, catdesc, msg, attack, virus, qname...).
"""
from datetime import datetime

ALLOW = {"accept", "pass", "passthrough", "allowed", "permit", "monitored", "detected", "close", "timeout",
         "server-rst", "client-rst"}
BLOCK = {"deny", "blocked", "block", "dropped", "reset", "reset-client", "reset-server", "drop", "ip-conn"}

ACTION_LABEL = {
    "accept": "Permitido", "pass": "Permitido", "passthrough": "Permitido (monitorado)", "allowed": "Permitido",
    "monitored": "Permitido (monitorado)", "detected": "Permitido (detectado)", "close": "Permitido (encerrado)",
    "timeout": "Permitido (tempo esgotado)", "server-rst": "Permitido (reset pelo servidor)",
    "client-rst": "Permitido (reset pelo cliente)",
    "deny": "Bloqueado", "blocked": "Bloqueado", "block": "Bloqueado", "dropped": "Bloqueado",
    "drop": "Bloqueado", "reset": "Bloqueado (conexão resetada)", "ip-conn": "Bloqueado (limite de conexões)",
}


# Conexões permitidas pelo firewall que terminaram com problema (não é bloqueio de regra)
CONNECTION_PROBLEM = {
    "timeout": "o destino não respondeu (tempo esgotado)",
    "server-rst": "o servidor de destino recusou ou encerrou a conexão",
}

PORT_NAMES = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 123: "NTP", 135: "RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB - compartilhamento de arquivos", 465: "SMTPS", 514: "Syslog", 587: "SMTP", 636: "LDAPS",
    853: "DNS sobre TLS", 993: "IMAPS", 995: "POP3S", 1433: "SQL Server", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP - área de trabalho remota", 5060: "SIP - telefonia", 5432: "PostgreSQL", 8080: "HTTP alternativo",
    8443: "HTTPS alternativo",
}


def port_label(port) -> str:
    try:
        name = PORT_NAMES.get(int(port))
    except (TypeError, ValueError):
        return str(port or "")
    return f"{port} ({name})" if name else str(port)


def situation(log: dict) -> str:
    """bloqueado | falha (permitido, mas a conexão não funcionou) | permitido."""
    if is_blocked(log):
        return "bloqueado"
    if (log.get("action") or "").lower() in CONNECTION_PROBLEM:
        return "falha"
    return "permitido"


def classify_action(action: str | None) -> str:
    """Allow / Deny / Block, como pedido na especificação."""
    a = (action or "").lower()
    if a == "deny":
        return "Deny"
    if a in BLOCK:
        return "Block"
    if a in ALLOW or not a:
        return "Allow"
    return a.capitalize()


def is_blocked(log: dict) -> bool:
    return (log.get("action") or "").lower() in BLOCK or (log.get("utmaction") or "").lower() in BLOCK


def _when(log: dict) -> str:
    if log.get("date") and log.get("time"):
        return f"{log['date']} {log['time']}"
    for k in ("itime", "eventtime"):
        v = log.get(k)
        if v:
            try:
                v = int(v)
                if v > 10**12:  # eventtime em ns/us
                    v = v // 10**9 if v > 10**15 else v // 10**3
                return datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, OSError):
                return str(v)
    return ""


def reason(log: dict, logtype: str) -> str:
    """Motivo do bloqueio (ou do evento) em linguagem simples."""
    action = (log.get("action") or "").lower()
    blocked = is_blocked(log)
    ev = (log.get("eventtype") or "").lower()
    cat = log.get("catdesc") or log.get("cat")
    policy = log.get("policyname") or log.get("policyid")

    if logtype == "webfilter":
        if not blocked:
            return f"Acesso permitido pela política de navegação{f' (categoria: {cat})' if cat else ''}."
        if ev == "ftgd_blk" or (cat and ev in ("", "ftgd_blk")):
            return f"Categoria \"{cat or 'desconhecida'}\" não permitida pela política de navegação corporativa."
        if ev == "urlfilter":
            return "Endereço bloqueado por um filtro de URL (lista de bloqueio configurada no firewall)."
        if ev in ("content", "keyword"):
            return "Conteúdo da página bloqueado por palavra-chave proibida."
        if ev == "ftgd_err":
            return "Não foi possível classificar o site (FortiGuard indisponível) e a política bloqueia nesse caso."
        if ev in ("activexfilter", "cookiefilter", "scriptfilter"):
            return "Conteúdo ativo da página (script/cookie/ActiveX) bloqueado pela política."
        return log.get("msg") or "Acesso bloqueado pelo filtro web."

    if logtype == "app-ctrl":
        app = log.get("app") or "aplicação"
        if blocked:
            return f"Aplicação \"{app}\" ({log.get('appcat') or 'categoria não informada'}) bloqueada pelo controle de aplicações."
        return f"Aplicação \"{app}\" identificada e permitida."

    if logtype == "dns":
        if blocked:
            return f"Consulta DNS para \"{log.get('qname') or log.get('hostname')}\" bloqueada pelo filtro DNS" \
                   f"{f' (categoria: {cat})' if cat else ''}."
        return "Consulta DNS permitida."

    if logtype == "ips":
        return f"Tentativa de ataque detectada pelo IPS: {log.get('attack') or log.get('msg') or 'assinatura não informada'}" \
               f"{' (tráfego bloqueado)' if blocked else ' (apenas registrado)'}."

    if logtype == "virus":
        return f"Arquivo malicioso detectado: {log.get('virus') or log.get('msg') or 'ameaça não informada'}" \
               f"{' (download bloqueado)' if blocked else ''}."

    if logtype == "ssl":
        return log.get("msg") or ("Conexão bloqueada pela inspeção SSL (certificado inválido ou não confiável)."
                                   if blocked else "Conexão SSL inspecionada.")

    if logtype == "traffic":
        if action == "deny":
            if str(log.get("policyid", "")) == "0":
                return "Nenhuma regra do firewall permite este tráfego (bloqueio implícito, regra 0)."
            if (log.get("utmaction") or "").lower() in BLOCK:
                return f"Tráfego bloqueado por perfil de segurança aplicado na regra \"{policy}\"."
            return f"Tráfego negado pela regra \"{policy}\" do firewall."
        if action == "ip-conn":
            return "Bloqueado por limite de conexões por IP."
        if blocked:
            return log.get("msg") or "Tráfego bloqueado."
        base = f"Tráfego permitido pela regra \"{policy}\"" if policy else "Tráfego permitido"
        problem = CONNECTION_PROBLEM.get(action)
        return f"{base}, mas {problem}." if problem else f"{base}."

    return log.get("msg") or log.get("logdesc") or ""


def guidance(row: dict, log: dict, logtype: str) -> str:
    """O que o atendente N1 deve fazer com este evento."""
    action = (log.get("action") or "").lower()
    ev = (log.get("eventtype") or "").lower()
    cat = log.get("catdesc") or log.get("cat")
    dest = row.get("site") or row.get("ip_destino") or "o destino"
    if logtype == "ips":
        return ("Possível ataque ou atividade suspeita. Não solicite liberação. Encaminhe este evento para a "
                "equipe de Segurança e informe o usuário/equipamento de origem.")
    if logtype == "virus":
        return ("Arquivo malicioso detectado. Não tente contornar o bloqueio. Encaminhe para a equipe de Segurança "
                "e peça uma verificação de antivírus no equipamento do usuário.")
    if row.get("situacao") == "falha":
        return ("O firewall liberou o acesso; o problema está no destino ou no caminho até ele, não em regra de "
                "bloqueio. Confirme se o serviço está no ar e, se o problema continuar, encaminhe ao N2 de Redes.")
    if not row.get("bloqueado"):
        return ("O firewall permitiu este acesso. Se o usuário relata que não funciona, a causa provavelmente não é "
                "bloqueio do firewall: marque \"Somente bloqueios\" para ver se outro acesso dele foi bloqueado, ou "
                "verifique se o site está no ar.")
    if logtype == "traffic" and action == "deny":
        if str(log.get("policyid", "")) == "0":
            return (f"Nenhuma regra libera este acesso. Se ele for necessário para o trabalho, abra chamado para a "
                    f"equipe de Firewall pedindo liberação de {row.get('ip_origem') or 'origem'} para {dest} "
                    f"na porta {row.get('servico') or '-'}, com a justificativa do usuário.")
        return (f"Existe uma regra que bloqueia este acesso de propósito ({row.get('regra')}). Confirme a necessidade "
                f"com o usuário e encaminhe para a equipe de Firewall/Segurança avaliar.")
    if logtype in ("webfilter", "dns") and ev == "ftgd_err":
        return ("Falha temporária na classificação do site. Peça para o usuário tentar de novo em alguns minutos; "
                "se continuar, encaminhe ao N2.")
    if logtype == "webfilter" and ev == "urlfilter":
        return ("O endereço está em uma lista de bloqueio criada pela equipe de Segurança. Se o acesso for necessário, "
                "encaminhe o pedido de liberação com justificativa.")
    if logtype in ("webfilter", "dns") or (logtype == "traffic" and cat):
        return (f"Site bloqueado pela política de navegação{f' (categoria {cat})' if cat else ''}. Consulte a "
                "reputação do site; se for confiável e necessário para o trabalho, encaminhe pedido de liberação "
                "com justificativa.")
    if logtype == "app-ctrl":
        return (f"A aplicação {log.get('app') or ''} é bloqueada pela política. A liberação depende de aprovação "
                "da equipe de Segurança; encaminhe com a justificativa do usuário.").replace("  ", " ")
    if logtype == "ssl":
        return ("O certificado do site não é confiável ou é inválido. Pode ser problema do próprio site; se ele for "
                "necessário, encaminhe ao N2 de Segurança.")
    return "Acesso bloqueado pelo firewall. Encaminhe ao N2 com os dados deste evento."


def rule_label(policy_id, policy_name: str) -> str:
    if policy_id in (None, ""):
        return policy_name or ""
    if str(policy_id) == "0":
        return "0 - bloqueio implícito (nenhuma regra permitiu)"
    return f"{policy_id} - {policy_name}" if policy_name else str(policy_id)


def policy_key(row: dict) -> tuple[str, str] | None:
    """(firewall/vdom, nº da regra) de uma linha normalizada; None se não houver regra numerada."""
    lg = row.get("log_original") or {}
    pid = lg.get("policyid")
    dev = lg.get("devname") or lg.get("devid")
    if pid in (None, "") or str(pid) == "0" or not dev:
        return None
    return (f"{dev}/{lg.get('vd') or ''}", str(pid))


def set_policy_name(row: dict, name: str) -> None:
    """Completa o nome da regra em logs que só trazem o número (filtro web, DNS, aplicações...)."""
    lg = row.get("log_original") or {}
    row["regra"] = rule_label(lg.get("policyid"), name)
    row["regra_nome"] = name
    row["explicacao"] = explain(row)


def normalize(log: dict, logtype: str) -> dict:
    """Converte uma linha do FAZ nas colunas exibidas no portal."""
    user = log.get("user") or log.get("unauthuser") or ""
    site = log.get("hostname") or log.get("qname") or log.get("dstname") or ""
    url = log.get("url") or ""
    if url and site and url.startswith("/"):
        url = f"{site}{url}"
    policy_id = log.get("policyid")
    policy_name = log.get("policyname") or ""
    regra = rule_label(policy_id, policy_name)
    regra_id = "" if policy_id in (None, "") else str(policy_id)
    regra_nome = "bloqueio implícito" if regra_id == "0" else policy_name
    blocked = is_blocked(log)
    row = {
        "data_hora": _when(log),
        "firewall": log.get("devname") or log.get("devid") or "",
        "ip_origem": log.get("srcip") or "",
        "ip_destino": log.get("dstip") or "",
        "porta_origem": log.get("srcport") or "",
        "porta_destino": log.get("dstport") or "",
        "usuario": user,
        "site": site,
        "url": url,
        "aplicacao": log.get("app") or log.get("service") or "",
        "categoria": log.get("appcat") or log.get("catdesc") or "",
        "regra": regra,
        "regra_id": regra_id,
        "regra_nome": regra_nome,
        "politica": log.get("profile") or "",
        "interface_entrada": log.get("srcintf") or "",
        "interface_saida": log.get("dstintf") or "",
        "acao": classify_action(log.get("action")),
        "acao_original": log.get("action") or "",
        "bloqueado": blocked,
        "motivo": reason(log, logtype),
        "tipo_log": logtype,
        "situacao": situation(log),
        "servico": port_label(log.get("dstport")),
    }
    dest = site or row["ip_destino"]
    if not site and row["porta_destino"]:
        dest = f"{dest}:{row['porta_destino']}"
    row["destino"] = dest
    row["orientacao"] = guidance(row, log, logtype)
    row["explicacao"] = explain(row)
    row["log_original"] = log
    return row


def explain(row: dict) -> dict:
    """Bloco de explicação no formato pedido pela Sustentação."""
    acesso = row.get("site") or row.get("url") or row.get("ip_destino") or "-"
    if row.get("porta_destino") and not row.get("site"):
        acesso = f"{acesso}:{row['porta_destino']}"
    resultado = {"bloqueado": "Bloqueado", "falha": "Permitido, mas a conexão falhou"}.get(row.get("situacao"), "Permitido")
    return {
        "Usuário": row.get("usuario") or f"(não autenticado) {row.get('ip_origem') or ''}".strip(),
        "Acesso": acesso,
        "Resultado": resultado,
        "Motivo": row.get("motivo") or "-",
        "Política": row.get("politica") or "-",
        "Regra": row.get("regra") or "-",
        "Firewall": row.get("firewall") or "-",
    }


COLUMNS = [
    ("data_hora", "Data e hora"), ("firewall", "Firewall"), ("ip_origem", "IP origem"),
    ("ip_destino", "IP destino"), ("porta_origem", "Porta origem"), ("porta_destino", "Porta destino"),
    ("usuario", "Usuário"), ("site", "Site"), ("url", "URL"), ("aplicacao", "Aplicação"),
    ("categoria", "Categoria"), ("regra", "Regra"), ("politica", "Política"),
    ("interface_entrada", "Interface entrada"), ("interface_saida", "Interface saída"),
    ("acao", "Ação"), ("motivo", "Motivo"),
]
