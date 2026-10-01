"""Diagnóstico de acesso: "por que o usuário não acessa este site?" numa busca só.

O FortiGate pode barrar a navegação em quatro lugares: filtro web, controle de aplicações,
filtro DNS e regras do firewall. O diagnóstico procura bloqueios do usuário (ou IP, MAC ou
máquina) nos quatro tipos de log e, se não houver bloqueio, olha os acessos permitidos para
dizer se o firewall deixou passar ou se a conexão falhou no destino.
"""
from collections import Counter
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, ValidationError, model_validator

from ..config import settings
from .faz_filters import MAC_RE, LogFilter, LogQuery
from .fortianalyzer import FazError
from .logsearch import run_query

LAYERS = {
    "webfilter": ("Filtro web", "pelo filtro web"),
    "app-ctrl": ("Controle de aplicações", "pelo controle de aplicações"),
    "dns": ("Filtro DNS", "pelo filtro DNS"),
    "traffic": ("Regras do firewall", "por uma regra do firewall"),
}
ALLOWED_LIMIT = 100


class DiagnoseQuery(BaseModel):
    adom: str = Field(default_factory=lambda: settings.faz_default_adom)
    devices: list[str] = []
    devname: str | None = None
    start: datetime
    end: datetime
    quem: str = Field(min_length=1, max_length=256)            # usuário, IP/rede, MAC ou nome da máquina
    quem_tipo: Literal["auto", "user", "srcname"] = "auto"
    destino: str | None = Field(default=None, max_length=2048)  # site, URL ou IP (opcional)
    limit: int = 200

    @model_validator(mode="after")
    def _check(self):
        try:  # mesmas validações da pesquisa de logs (ADOM, firewalls, período)
            self.base_query("traffic")
            who_filter(self.quem, self.quem_tipo)
            target_filter(self.destino)
        except ValidationError as e:
            raise ValueError("; ".join(str(err.get("msg", "")).replace("Value error, ", "") for err in e.errors()))
        return self

    def base_query(self, logtype: str, **kw) -> LogQuery:
        return LogQuery(adom=self.adom, devices=self.devices, devname=self.devname, start=self.start, end=self.end,
                        logtype=logtype, **kw)


def who_filter(quem: str, kind: str = "auto") -> LogFilter:
    """Filtro de origem: IP ou rede, MAC, nome da máquina ou usuário (trecho do login)."""
    v = quem.strip()
    if kind == "srcname":
        return LogFilter(field="srcname", op="~", value=v)
    if kind == "auto":
        try:
            return LogFilter(field="srcip", op="=", value=v)
        except ValueError:
            pass
        if MAC_RE.match(v):
            return LogFilter(field="srcmac", op="=", value=v)
    v = v.rsplit("\\", 1)[-1]  # DOMINIO\usuario: o log costuma trazer só o usuário (ou usuario@dominio)
    return LogFilter(field="user", op="~", value=v)


def target_filter(destino: str | None) -> tuple[LogFilter | None, str | None]:
    """Filtro de destino e o tipo ('ip' ou 'site'). Site sem "www." pega também os subdomínios."""
    v = (destino or "").strip()
    if not v:
        return None, None
    try:
        return LogFilter(field="dstip", op="=", value=v), "ip"
    except ValueError:
        pass
    if "://" in v or "/" in v:
        v = urlsplit(v if "://" in v else f"http://{v}").hostname or ""
    v = v.lower().rstrip(".")
    if v.startswith("www."):
        v = v[4:]
    if not v:
        raise ValueError("Site inválido.")
    return LogFilter(field="hostname", op="~", value=v), "site"


def _seen(rows: list[dict], key: str, n: int = 5) -> list[str]:
    return [v for v, _ in Counter(r.get(key) for r in rows if r.get(key)).most_common(n)]


def diagnose(q: DiagnoseQuery) -> dict:
    who = who_filter(q.quem, q.quem_tipo)
    target, target_kind = target_filter(q.destino)
    flts = [who] + ([target] if target else [])

    camadas, blocked, errors = [], [], {}
    for lt, (nome, _) in LAYERS.items():
        layer = {"logtype": lt, "nome": nome, "bloqueios": 0, "aplica": True, "erro": None, "ultimo": None,
                 "motivo": None, "filtro": None}
        camadas.append(layer)
        if lt == "dns" and target_kind == "ip":
            layer.update(aplica=False, nota="O filtro DNS registra nomes de sites; não se aplica a um IP de destino.")
            continue
        lq = q.base_query(lt, only_blocked=True, filters=flts, limit=q.limit)
        layer["filtro"] = lq.filter_expr()
        try:
            # sem cache: o atendente costuma pedir para o usuário tentar de novo e diagnosticar em seguida
            res = run_query(lq, use_cache=False)
        except FazError as e:
            layer["erro"] = errors[lt] = str(e)
            continue
        rows = [r for r in res["rows"] if r["bloqueado"]]
        layer["bloqueios"] = max(res["total"], len(rows)) if rows else 0
        if rows:
            layer.update(ultimo=rows[0]["data_hora"], motivo=rows[0]["motivo"], regra=rows[0]["regra"])
        elif lt == "dns" and who.field == "user":
            layer["nota"] = ("Os logs do filtro DNS podem não trazer o usuário (depende da configuração do firewall). "
                             "Para ter certeza, diagnostique também pelo IP da máquina.")
        blocked.extend(rows)

    applicable = [c for c in camadas if c["aplica"]]
    if len(errors) == len(applicable):
        raise FazError("Nenhum tipo de log pôde ser consultado: " + "; ".join(f"{k}: {v}" for k, v in errors.items()))

    allowed = None
    if blocked:
        rows = blocked
    else:
        rows = []
        for lt in (("traffic", "webfilter") if target_kind == "site" else ("traffic",)):
            try:
                res = run_query(q.base_query(lt, filters=flts, limit=ALLOWED_LIMIT), use_cache=False)
                rows.extend(res["rows"])
            except FazError as e:
                errors[f"{lt} (permitidos)"] = str(e)
        allowed = {"total": len(rows), "falhas": sum(1 for r in rows if r["situacao"] == "falha")}
    rows.sort(key=lambda r: r["data_hora"], reverse=True)

    out = {
        "quem": q.quem.strip(), "destino": (q.destino or "").strip(), "filtro_origem": who.expr("traffic"),
        "periodo": {"inicio": q.start.strftime("%Y-%m-%d %H:%M"), "fim": q.end.strftime("%Y-%m-%d %H:%M")},
        "camadas": camadas, "permitidos": allowed, "rows": rows, "erros": errors,
        "origem": {"usuarios": _seen(rows, "usuario"), "ips": _seen(rows, "ip_origem"), "maquinas": _seen(rows, "maquina")},
    }
    out["por_usuario"] = who.field == "user"
    # para consultar a máquina no Vision One: o que foi pesquisado ou o mais visto nos logs. Máquina e usuário
    # vêm dos eventos do mesmo IP, para não misturar duas máquinas.
    ip = who.value if who.field == "srcip" and "/" not in who.value else next(iter(out["origem"]["ips"]), None)
    same = [r for r in rows if r.get("ip_origem") == ip] if ip else rows
    out["maquina"] = {
        "ip": ip,
        "nome": next(iter(_seen(same, "maquina", 1)), None) or (who.value if who.field == "srcname" else None),
        "usuario": who.value if who.field == "user" else next(iter(_seen(same, "usuario", 1)), None),
    }
    out.update(conclude(out, who.field, target_kind))
    if errors:
        def nome(k: str) -> str:
            base = k.removesuffix(" (permitidos)")
            label = LAYERS.get(base, (base,))[0]
            return f"acessos permitidos ({label})" if base != k else label
        nomes = ", ".join(nome(k) for k in errors)
        out["aviso"] = (f"Não foi possível consultar: {nomes}. O resultado considera só os outros tipos de log "
                        "e pode estar incompleto.")
    return out


def conclude(d: dict, who_field: str, target_kind: str | None) -> dict:
    """Conclusão em linguagem simples: status, título, resumo e o que fazer."""
    rows = d["rows"]
    alvo = f" para {d['destino']}" if d["destino"] else ""
    with_blocks = [c for c in d["camadas"] if c["bloqueios"]]
    if with_blocks:
        last = rows[0]
        _, onde = LAYERS.get(last["tipo_log"], ("", "pelo firewall"))
        resumo = f"{last['motivo']} Último bloqueio em {last['data_hora']}"
        if last.get("firewall"):
            resumo += f" no firewall {last['firewall']}"
        if last.get("regra"):
            resumo += f", regra {last['regra']}"
        resumo += "."
        outras = [c["nome"] for c in with_blocks if c["logtype"] != last["tipo_log"]]
        if outras:
            resumo += f" Também há bloqueios em: {', '.join(outras)}."
        return {"status": "bloqueado", "titulo": f"Acesso bloqueado {onde}", "resumo": resumo,
                "orientacao": last["orientacao"]}
    if rows:
        ok = [r for r in rows if r["situacao"] == "permitido"]
        falhas = [r for r in rows if r["situacao"] == "falha"]
        if falhas and not ok:
            return {"status": "falha", "titulo": "O firewall permitiu, mas a conexão falhou",
                    "resumo": f"{len(falhas)} conexão(ões){alvo} liberada(s) pelo firewall terminaram com problema: "
                              f"{falhas[0]['motivo']}",
                    "orientacao": falhas[0]["orientacao"]}
        resumo = (f"{len(ok)} acesso(s){alvo} permitido(s) no período e nenhum bloqueio no filtro web, no controle de "
                  "aplicações, no filtro DNS ou nas regras do firewall.")
        if falhas:
            resumo += f" {len(falhas)} conexão(ões) falharam no destino (o firewall liberou, mas o destino não respondeu)."
        return {"status": "permitido", "titulo": "Nenhum bloqueio: o firewall permitiu o acesso", "resumo": resumo,
                "orientacao": ("A causa provavelmente não é o firewall. Confirme com o usuário o endereço exato e o horário "
                               "do problema, se o site está no ar e se a máquina dele está na rede da Marista. Se o "
                               "problema continuar, encaminhe ao N2 com este diagnóstico.")}
    dica = ("Confira o login do usuário (ou procure pelo IP ou pelo nome da máquina: redes sem login, como Wi-Fi de "
            "visitantes, não registram usuário)" if who_field == "user" else "Confira o IP, MAC ou nome da máquina")
    return {"status": "sem_eventos", "titulo": "Nenhum evento encontrado",
            "resumo": f"O FortiAnalyzer não tem registros de {d['quem']}{alvo} no período escolhido.",
            "orientacao": (f"{dica}, aumente o período ou escolha o firewall da unidade. Se o usuário estava fora da rede "
                           "(em casa ou no 4G), o acesso não passa por este firewall.")}
