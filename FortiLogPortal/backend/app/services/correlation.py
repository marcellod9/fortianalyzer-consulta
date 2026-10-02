"""Correlação FortiAnalyzer x Vision One para um indicador (domínio, URL ou IP).

Exemplo de saída:
  Usuário realizou acesso ao domínio xyz.com.
  FortiAnalyzer: bloqueio registrado pela política WebFilter.
  Vision One: domínio identificado como malicioso.
"""
from collections import Counter
from datetime import datetime

from ..config import settings
from . import reputation
from .faz_filters import LogQuery
from .logsearch import blocked_search, run_query
from .visionone import V1Error, host_of


def correlate(raw: str, start: datetime, end: datetime, adom: str | None = None, username: str = "") -> dict:
    ioc_type, value = reputation.parse_indicator(raw)
    adom = adom or settings.faz_default_adom
    out: dict = {"indicador": value, "tipo": ioc_type, "fortianalyzer": None, "visionone": None, "erros": {}}

    # FortiAnalyzer: eventos (bloqueados e permitidos) envolvendo o indicador
    try:
        base = dict(adom=adom, start=start, end=end, limit=500)
        if ioc_type == "ip":
            bl = blocked_search(LogQuery(dstip=value, **base), logtypes=("traffic", "webfilter"))
            allowed = run_query(LogQuery(logtype="traffic", dstip=value, action="accept", **base))
        else:
            host = host_of(value) if ioc_type == "url" else value
            bl = blocked_search(LogQuery(hostname=host, **base), logtypes=("webfilter", "dns", "app-ctrl"))
            allowed = run_query(LogQuery(logtype="webfilter", hostname=host, action="passthrough", **base))
        rows = bl["rows"]
        out["fortianalyzer"] = {
            "bloqueios": len(rows),
            "permitidos": allowed["returned"],
            "usuarios": Counter(r["usuario"] or r["ip_origem"] for r in rows + allowed["rows"]).most_common(10),
            "politicas": Counter((r["politica"] or r["regra"]) for r in rows if (r["politica"] or r["regra"])).most_common(5),
            "motivos": Counter(r["motivo"] for r in rows).most_common(5),
            "firewalls": Counter(r["firewall"] for r in rows).most_common(5),
            "eventos": (rows + allowed["rows"])[:100],
            "erros": bl.get("erros", {}),
        }
    except Exception as e:
        out["erros"]["fortianalyzer"] = str(e)

    # Vision One: reputação, com a categoria do FortiGuard vista nos eventos acima (sem nova busca no FAZ)
    fg = next((lg["catdesc"] for r in (out["fortianalyzer"] or {}).get("eventos", [])
               if (lg := r.get("log_original") or {}).get("catdesc")), None)
    try:
        out["visionone"] = reputation.lookup(value, ioc_type, username=username, fortiguard_category=fg,
                                             fortiguard_from_faz=False)
    except (V1Error, reputation.IndicatorError) as e:
        out["erros"]["visionone"] = str(e)

    out["analise"] = summary(out)
    return out


def summary(c: dict) -> list[str]:
    nome = {"domain": "o domínio", "url": "a URL", "ip": "o IP"}[c["tipo"]]
    linhas = []
    faz, v1 = c.get("fortianalyzer"), c.get("visionone")
    if faz:
        usuarios = [u for u, _ in faz["usuarios"] if u]
        quem = f"{len(usuarios)} usuários/IPs" if len(usuarios) != 1 else f"O usuário {usuarios[0]}"
        if faz["bloqueios"] or faz["permitidos"]:
            verbo = "tentou" if len(usuarios) == 1 else "tentaram"
            linhas.append(f"{quem} {verbo} acessar {nome} {c['indicador']} "
                          f"({faz['bloqueios']} bloqueio(s), {faz['permitidos']} acesso(s) permitido(s)).")
        else:
            linhas.append(f"Nenhum acesso envolvendo {nome} {c['indicador']} foi registrado no FortiAnalyzer no período.")
        if faz["bloqueios"]:
            pol = faz["politicas"][0][0] if faz["politicas"] else "não identificada"
            motivo = faz["motivos"][0][0] if faz["motivos"] else ""
            linhas.append(f"FortiAnalyzer: bloqueio registrado pela política/regra {pol}. {motivo}")
        if faz["permitidos"] and v1 and v1["reputacao"] in ("Malicioso", "Suspeito"):
            linhas.append("Atenção: houve acessos PERMITIDOS a um indicador classificado como risco. "
                          "Acione a equipe de Segurança.")
    elif "fortianalyzer" in c["erros"]:
        linhas.append(f"FortiAnalyzer indisponível: {c['erros']['fortianalyzer']}")
    if v1:
        txt = {"Malicioso": "identificado como MALICIOSO", "Suspeito": "classificado como SUSPEITO",
               "Baixo risco": "com registro de baixo risco", "Confiável (exceção)": "marcado como confiável",
               }.get(v1["reputacao"], "sem registros de ameaça")
        linhas.append(f"Vision One: indicador {txt} (risk score {v1['risk_score']}, fontes: {', '.join(v1['fontes'])}).")
    elif "visionone" in c["erros"]:
        linhas.append(f"Vision One indisponível: {c['erros']['visionone']}")
    if faz and v1:
        if faz["bloqueios"] and v1["reputacao"] in ("Malicioso", "Suspeito"):
            linhas.append("Resultado: o bloqueio está correto; o recurso representa risco e não deve ser liberado.")
        elif faz["bloqueios"]:
            linhas.append("Resultado: o bloqueio ocorreu por política de navegação/firewall, não por ameaça conhecida. "
                          "Uma liberação depende de aprovação conforme a política corporativa.")
    return linhas
