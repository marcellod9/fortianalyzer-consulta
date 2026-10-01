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
        return f"Tráfego permitido pela regra \"{policy}\"." if policy else "Tráfego permitido."

    return log.get("msg") or log.get("logdesc") or ""


def normalize(log: dict, logtype: str) -> dict:
    """Converte uma linha do FAZ nas colunas exibidas no portal."""
    user = log.get("user") or log.get("unauthuser") or ""
    site = log.get("hostname") or log.get("qname") or log.get("dstname") or ""
    url = log.get("url") or ""
    if url and site and url.startswith("/"):
        url = f"{site}{url}"
    policy_id = log.get("policyid")
    policy_name = log.get("policyname") or ""
    if policy_id in (None, ""):
        regra = policy_name
    elif str(policy_id) == "0":
        regra = "0 - bloqueio implícito (nenhuma regra permitiu)"
    else:
        regra = f"{policy_id} - {policy_name}" if policy_name else str(policy_id)
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
        "politica": log.get("profile") or "",
        "interface_entrada": log.get("srcintf") or "",
        "interface_saida": log.get("dstintf") or "",
        "acao": classify_action(log.get("action")),
        "acao_original": log.get("action") or "",
        "bloqueado": blocked,
        "motivo": reason(log, logtype),
        "tipo_log": logtype,
    }
    row["explicacao"] = explain(row)
    return row


def explain(row: dict) -> dict:
    """Bloco de explicação no formato pedido pela Sustentação."""
    acesso = row.get("site") or row.get("url") or row.get("ip_destino") or "-"
    if row.get("porta_destino") and not row.get("site"):
        acesso = f"{acesso}:{row['porta_destino']}"
    resultado = "Bloqueado" if row.get("bloqueado") else "Permitido"
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
