"""Relatórios de acesso com gráficos: geral, por usuário, IP, site ou aplicação.

Usa a mesma busca oficial de logs do FortiAnalyzer (logview/logsearch) que a aba Logs:
filtro web para sites e categorias, controle de aplicações para aplicações. O total de
eventos de cada tipo de log vem do próprio FortiAnalyzer; os gráficos são montados com
os eventos mais recentes do período, até REPORT_MAX_ROWS por tipo de log (quando o
período tem mais eventos que isso, o relatório avisa que os gráficos são uma amostra).
"""
import hashlib
import json
import uuid
from collections import Counter
from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, model_validator

from .. import database
from ..config import settings
from .diagnosis import target_filter, who_filter
from .faz_filters import LogFilter, LogQuery
from .fortianalyzer import FazError
from .logsearch import run_query

LOGTYPE_NAMES = {"webfilter": "filtro web", "app-ctrl": "controle de aplicações"}

KINDS = {
    # tipo: (nome, tipos de log, gráficos)
    "geral": ("Geral", ("webfilter", "app-ctrl"),
              ("acao", "categorias", "sites", "sites_bloqueados", "aplicacoes", "usuarios", "ips", "firewalls", "tempo")),
    "usuario": ("Usuário", ("webfilter", "app-ctrl"),
                ("acao", "categorias", "sites", "sites_bloqueados", "aplicacoes", "categorias_app", "ips", "maquinas", "tempo")),
    "ip": ("IP de origem", ("webfilter", "app-ctrl"),
           ("acao", "categorias", "sites", "sites_bloqueados", "aplicacoes", "usuarios", "maquinas", "tempo")),
    "site": ("Site", ("webfilter",), ("acao", "usuarios", "ips", "maquinas", "firewalls", "tempo")),
    "aplicacao": ("Aplicação", ("app-ctrl",), ("acao", "usuarios", "ips", "maquinas", "firewalls", "tempo")),
}

# id: (título, gráfico, tipo de log usado (None = todos), coluna, só bloqueados, rótulo da coluna)
CHARTS = {
    "acao": ("Permitidos x bloqueados", "pie", None, None, False, "Situação"),
    "categorias": ("Categorias de sites", "pie", "webfilter", "categoria", False, "Categoria"),
    "sites": ("Sites mais acessados", "bar", "webfilter", "site", False, "Site"),
    "sites_bloqueados": ("Sites mais bloqueados", "bar", "webfilter", "site", True, "Site"),
    "aplicacoes": ("Aplicações mais usadas", "bar", "app-ctrl", "aplicacao", False, "Aplicação"),
    "categorias_app": ("Categorias de aplicações", "pie", "app-ctrl", "categoria", False, "Categoria"),
    "usuarios": ("Usuários com mais acessos", "bar", None, "usuario", False, "Usuário"),
    "ips": ("IPs de origem", "bar", None, "ip_origem", False, "IP"),
    "maquinas": ("Máquinas", "bar", None, "maquina", False, "Máquina"),
    "firewalls": ("Eventos por firewall", "pie", None, "firewall", False, "Firewall"),
    "tempo": ("Acessos ao longo do tempo", "line", None, None, False, "Horário"),
}

BLOCKED_TITLES = {"sites": "Sites mais bloqueados", "aplicacoes": "Aplicações mais bloqueadas",
                  "usuarios": "Usuários com mais bloqueios", "tempo": "Bloqueios ao longo do tempo"}

EVENT_COLUMNS = [("data_hora", "Data/hora"), ("tipo_log", "Tipo de log"), ("usuario", "Usuário"), ("ip_origem", "IP de origem"),
                 ("maquina", "Máquina"), ("site", "Site"), ("aplicacao", "Aplicação"), ("categoria", "Categoria"),
                 ("situacao", "Situação"), ("firewall", "Firewall"), ("regra", "Regra")]
CACHE_TTL = 300
DETAIL_MAX = 3000          # linhas da tabela detalhada
DISCOVERY_ROUNDS = 3       # buscas extras para completar a lista de usuários
DISCOVERY_EXCLUDE = 150    # usuários já vistos excluídos por busca extra (o filtro do FAZ fica longo)
DISCOVERY_LIMIT = 1000


def _row_limit(q: "ReportQuery") -> int:
    return settings.report_max_rows if q.tipo == "geral" else settings.report_max_rows_filtered


class ReportQuery(BaseModel):
    adom: str = Field(default_factory=lambda: settings.faz_default_adom)
    devices: list[str] = []
    devname: str | None = None
    start: datetime
    end: datetime
    tipo: Literal["geral", "usuario", "ip", "site", "aplicacao"] = "geral"
    valor: str | None = Field(default=None, max_length=256)
    somente_bloqueios: bool = False
    top: int = Field(default=10, ge=3, le=30)

    @model_validator(mode="after")
    def _check(self):
        self.valor = (self.valor or "").strip() or None
        if self.tipo != "geral" and not self.valor:
            raise ValueError(f"Informe o {KINDS[self.tipo][0].lower()} do relatório.")
        try:
            self.base_query(KINDS[self.tipo][1][0])
            self.value_filter()
        except ValidationError as e:
            raise ValueError("; ".join(str(err.get("msg", "")).replace("Value error, ", "") for err in e.errors()))
        return self

    def value_filter(self) -> LogFilter | None:
        v = self.valor
        if self.tipo == "usuario":
            return who_filter(v, "user")
        if self.tipo == "ip":
            return LogFilter(field="srcip", op="=", value=v)
        if self.tipo == "site":
            return target_filter(v)[0]
        if self.tipo == "aplicacao":
            return LogFilter(field="app", op="~", value=v)
        return None

    def base_query(self, logtype: str) -> LogQuery:
        flt = self.value_filter() if self.valor else None
        return LogQuery(adom=self.adom, devices=self.devices, devname=self.devname, start=self.start, end=self.end,
                        logtype=logtype, only_blocked=self.somente_bloqueios, filters=[flt] if flt else [])

    def title(self) -> str:
        nome = KINDS[self.tipo][0]
        base = "Relatório geral de acessos" if self.tipo == "geral" else f"Relatório de acessos: {nome.lower()} {self.valor}"
        return base + (" (somente bloqueios)" if self.somente_bloqueios else "")


def _top(counter: Counter, n: int, others: bool) -> list[list]:
    items = [[k, c] for k, c in counter.most_common(n)]
    rest = sum(counter.values()) - sum(c for _, c in items)
    if others and rest > 0:
        items.append(["Outros", rest])
    return items


def _timeline(rows: list[dict], start: datetime, end: datetime, since: str | None = None) -> dict:
    """Permitidos e bloqueados por hora (períodos de até 2 dias) ou por dia, com os intervalos vazios em zero.

    since: com amostra, a linha começa no evento mais antigo lido (antes dele não há dados, e não zero acessos).
    """
    hourly = end - start <= timedelta(days=2)
    fmt, step = ("%Y-%m-%d %H:00", timedelta(hours=1)) if hourly else ("%Y-%m-%d", timedelta(days=1))
    cut = 13 if hourly else 10
    ok, bl = Counter(), Counter()
    for r in rows:
        key = (r.get("data_hora") or "")[:cut]
        if key:
            (bl if r["bloqueado"] else ok)[key] += 1
    t = start
    if since:
        try:
            t = max(start, datetime.strptime(since[:cut], fmt.replace(":00", "") if hourly else fmt))
        except ValueError:
            pass
    t = t.replace(minute=0, second=0, microsecond=0) if hourly else t.replace(hour=0, minute=0, second=0, microsecond=0)
    labels = []
    while t <= end and len(labels) < 400:
        labels.append(t.strftime(fmt)[:cut])
        t += step
    return {"agrupamento": "hora" if hourly else "dia", "rotulos": labels,
            "permitidos": [ok.get(k, 0) for k in labels], "bloqueados": [bl.get(k, 0) for k in labels]}


def build_charts(q: ReportQuery, rows: list[dict], since: str | None = None) -> list[dict]:
    out = []
    for cid in KINDS[q.tipo][2]:
        titulo, kind, lt, col, only_blocked, label = CHARTS[cid]
        base = [r for r in rows if (lt is None or r["tipo_log"] == lt) and (not only_blocked or r["bloqueado"])]
        if q.somente_bloqueios:
            if cid in ("sites_bloqueados", "acao"):
                continue  # com "somente bloqueios", seriam iguais a "Sites mais bloqueados" / 100% bloqueados
            titulo = BLOCKED_TITLES.get(cid, titulo)
        chart = {"id": cid, "titulo": titulo, "tipo": kind, "coluna": label, "base": len(base),
                 "fonte": LOGTYPE_NAMES.get(lt, "todos os tipos de log")}
        if cid == "acao":
            bl = sum(1 for r in base if r["bloqueado"])
            chart["itens"] = [[k, v] for k, v in (("Permitidos", len(base) - bl), ("Bloqueados", bl)) if v]
        elif cid == "tempo":
            chart.update(_timeline(base, q.start, q.end, since))
            chart["itens"] = list(zip(chart["rotulos"], chart["permitidos"], chart["bloqueados"]))
        else:
            counter = Counter(r.get(col) for r in base if r.get(col))
            chart["sem_valor"] = len(base) - sum(counter.values())  # ex.: eventos sem usuário (rede sem login)
            # pizza: até 7 fatias + "Outros" (as 8 cores fixas da paleta); barras: o top escolhido
            chart["itens"] = _top(counter, min(q.top, 7) if kind == "pie" else q.top, others=kind == "pie")
            chart["distintos"] = len(counter)
        if chart["itens"]:
            out.append(chart)
    return out


def _join(values: set, n: int = 3) -> str:
    vals = sorted(v for v in values if v)
    return ", ".join(vals[:n]) + (f" (+{len(vals) - n})" if len(vals) > n else "")


def build_detail(q: ReportQuery, rows: list[dict], extra: list[dict], complete: bool) -> dict:
    """Tabela completa: por usuário (quem acessou) ou, no relatório de um usuário, por destino (o que acessou).

    extra: eventos das buscas que completam a lista de usuários; quem só aparece nelas fica com a contagem parcial.
    """
    by_dest = q.tipo == "usuario"
    groups: dict = {}
    seen_main = set()
    for src, data in (("main", rows), ("extra", extra)):
        for r in data:
            if by_dest:
                key = ("Site", r["site"] or r["ip_destino"]) if r["tipo_log"] == "webfilter" else ("Aplicação", r["aplicacao"])
                if not key[1]:
                    continue
            else:
                key = r["usuario"] or f"(sem login) {r['ip_origem']}"
            if src == "main":
                seen_main.add(key)
            elif key in seen_main:
                continue  # já contado nos eventos principais
            g = groups.setdefault(key, {"acessos": 0, "bloqueados": 0, "ips": set(), "maquinas": set(), "firewalls": set(),
                                        "categorias": set(), "usuarios": set(), "primeiro": r["data_hora"],
                                        "ultimo": r["data_hora"], "parcial": src == "extra"})
            g["acessos"] += 1
            g["bloqueados"] += 1 if r["bloqueado"] else 0
            g["ips"].add(r["ip_origem"]); g["maquinas"].add(r["maquina"]); g["firewalls"].add(r["firewall"])
            g["categorias"].add(r["categoria"]); g["usuarios"].add(r["usuario"])
            g["primeiro"] = min(g["primeiro"], r["data_hora"]); g["ultimo"] = max(g["ultimo"], r["data_hora"])
    lines = []
    # quem tem login primeiro; os eventos sem usuário (rede sem login, ex.: Wi-Fi de visitantes) vêm por IP, no fim
    no_login = lambda key: isinstance(key, str) and key.startswith("(sem login)")  # noqa: E731
    for key, g in sorted(groups.items(), key=lambda kv: (no_login(kv[0]), -kv[1]["acessos"], str(kv[0]))):
        line = {"acessos": g["acessos"], "permitidos": g["acessos"] - g["bloqueados"], "bloqueados": g["bloqueados"],
                "primeiro": g["primeiro"], "ultimo": g["ultimo"], "firewalls": _join(g["firewalls"]), "parcial": g["parcial"]}
        if by_dest:
            line.update(tipo=key[0], destino=key[1], categoria=_join(g["categorias"], 2), ips=_join(g["ips"]))
        else:
            line.update(usuario=key, ips=_join(g["ips"]), maquinas=_join(g["maquinas"]))
        lines.append(line)
    if by_dest:
        cols = [("destino", "Site ou aplicação"), ("tipo", "Tipo"), ("categoria", "Categoria"), ("acessos", "Acessos"),
                ("permitidos", "Permitidos"), ("bloqueados", "Bloqueados"), ("primeiro", "Primeiro acesso"),
                ("ultimo", "Último acesso"), ("ips", "IP de origem"), ("firewalls", "Firewall")]
        titulo = f"O que {q.valor} acessou"
    else:
        cols = [("usuario", "Usuário"), ("ips", "IP de origem"), ("maquinas", "Máquina"), ("acessos", "Acessos"),
                ("permitidos", "Permitidos"), ("bloqueados", "Bloqueados"), ("primeiro", "Primeiro acesso"),
                ("ultimo", "Último acesso"), ("firewalls", "Firewall")]
        titulo = {"site": f"Usuários que acessaram {q.valor}", "aplicacao": f"Usuários que usaram {q.valor}",
                  "ip": f"Usuários no IP {q.valor}"}.get(q.tipo, "Usuários")
    if q.somente_bloqueios:
        cols = [c for c in cols if c[0] not in ("permitidos", "bloqueados")]
        titulo = titulo.replace("acessaram", "tiveram bloqueio em").replace("usaram", "tiveram bloqueio em")
    sem_login = sum(1 for k in groups if no_login(k))
    return {"titulo": titulo, "colunas": cols, "linhas": lines[:DETAIL_MAX], "total": len(lines),
            "usuarios": len(groups) - sem_login, "sem_login": sem_login,
            "completo": complete,
            "parciais": sum(1 for x in lines if x["parcial"] and not no_login(x.get("usuario", ""))),
            "agrupamento": "destino" if by_dest else "usuario"}


def _discover_users(q: ReportQuery, lt: str, rows: list[dict]) -> tuple[list[dict], bool]:
    """Completa a lista de usuários quando o período tem mais eventos do que o relatório lê.

    Busca de novo excluindo os usuários já vistos (user!="..."): os que sobram aparecem nos eventos mais recentes
    dessa busca. Para quando uma busca não traz ninguém novo ou já leu tudo o que sobrou.
    """
    known = {r["usuario"] for r in rows if r["usuario"]}
    extra = []
    for _ in range(DISCOVERY_ROUNDS):
        if len(known) > DISCOVERY_EXCLUDE:
            return extra, False
        try:
            excl = [LogFilter(field="user", op="!=", value=u) for u in sorted(known)]
        except ValueError:
            return extra, False
        lq = q.base_query(lt)
        lq.filters = lq.filters + excl
        lq.limit = DISCOVERY_LIMIT
        try:
            res = run_query(lq, use_cache=False, save_cache=False, policy_names=False)
        except FazError:
            return extra, False
        extra.extend(res["rows"])
        new = {r["usuario"] for r in res["rows"] if r["usuario"]} - known
        if res["total"] <= res["returned"]:
            return extra, True  # leu tudo o que sobrou
        if not new:
            return extra, False  # o que sobra são eventos sem usuário (rede sem login)
        known |= new
    return extra, False


def _firewall_names(q: ReportQuery) -> str:
    if q.devname:
        return q.devname
    if not q.devices:
        return "Todos"
    devs = database.cache_get(f"faz:devices:{q.adom}") or []
    names = {d.get("sn"): d.get("name") for d in devs if isinstance(d, dict)}
    return ", ".join(names.get(sn) or sn for sn in q.devices)


def _cache_key(q: ReportQuery) -> str:
    raw = json.dumps(q.model_dump(mode="json"), sort_keys=True) + f"{settings.report_max_rows}:{settings.report_max_rows_filtered}"
    return "report:" + hashlib.sha1(raw.encode()).hexdigest()


def run_report(q: ReportQuery, use_cache: bool = True) -> dict:
    key = _cache_key(q)
    if use_cache and (hit := database.cache_get(key)):
        hit["cache"] = True
        return hit
    rows, fontes, erros, oldest, extra, complete = [], {}, {}, [], [], True
    for lt in KINDS[q.tipo][1]:
        lq = q.base_query(lt)
        lq.limit = _row_limit(q)  # acima do limite da aba Logs: o relatório só guarda as contagens
        fontes[lt] = {"nome": LOGTYPE_NAMES[lt], "filtro": lq.filter_expr(), "total": 0, "lidos": 0}
        try:
            res = run_query(lq, use_cache=False, save_cache=False, policy_names=False)
        except FazError as e:
            fontes[lt]["erro"] = erros[lt] = str(e)
            continue
        fontes[lt].update(total=max(res["total"], res["returned"]), lidos=res["returned"])
        if fontes[lt]["total"] > res["returned"] and res["rows"]:
            oldest.append(min(r["data_hora"] for r in res["rows"]))
            if q.tipo != "usuario":  # quem acessou: completa a lista de usuários com buscas extras
                more, done = _discover_users(q, lt, res["rows"])
                extra.extend(more)
                complete = complete and done
            else:
                complete = False
        rows.extend(res["rows"])
    if len(erros) == len(fontes):
        raise FazError("Não foi possível consultar o FortiAnalyzer: " + "; ".join(f"{LOGTYPE_NAMES[k]}: {v}" for k, v in erros.items()))
    rows.sort(key=lambda r: r["data_hora"], reverse=True)

    amostra = any(f["total"] > f["lidos"] for f in fontes.values())
    bloqueados = sum(1 for r in rows if r["bloqueado"])
    out = {
        "titulo": q.title(), "tipo": q.tipo, "tipo_nome": KINDS[q.tipo][0], "valor": q.valor,
        "periodo": {"inicio": q.start.strftime("%Y-%m-%d %H:%M"), "fim": q.end.strftime("%Y-%m-%d %H:%M")},
        "somente_bloqueios": q.somente_bloqueios,
        "fontes": fontes, "erros": erros, "amostra": amostra, "limite_amostra": _row_limit(q),
        "firewall": _firewall_names(q),
        "resumo": {
            "eventos": sum(f["total"] for f in fontes.values()),
            "lidos": len(rows), "bloqueados": bloqueados, "permitidos": len(rows) - bloqueados,
            "usuarios": len({r["usuario"] for r in rows if r["usuario"]}),
            "ips": len({r["ip_origem"] for r in rows if r["ip_origem"]}),
            "sites": len({r["site"] for r in rows if r["site"] and r["tipo_log"] == "webfilter"}),
            "aplicacoes": len({r["aplicacao"] for r in rows if r["aplicacao"] and r["tipo_log"] == "app-ctrl"}),
        },
        "graficos": build_charts(q, rows, max(oldest) if oldest else None),
        "detalhe": build_detail(q, rows, extra, complete and not erros),
        "eventos": [{k: r.get(k, "") for k, _ in EVENT_COLUMNS} for r in rows],
        "gerado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cache": False,
    }
    if amostra:
        lidos = " e ".join(f"{f['lidos']:,} de {f['total']:,} no {f['nome']}".replace(",", ".")
                           for f in fontes.values() if f["total"] > f["lidos"])
        mais_antigo = max(oldest) if oldest else ""
        out["aviso_amostra"] = (f"O período tem mais eventos do que o relatório lê: os gráficos e as contagens usam os "
                                f"mais recentes ({lidos}), desde {mais_antigo}.")
        d = out["detalhe"]
        if q.tipo != "usuario" and d["completo"]:
            out["aviso_amostra"] += (" A lista de usuários está completa: buscas extras trouxeram quem não apareceu "
                                     "nesses eventos" + (f" ({d['parciais']} usuário(s), com contagem parcial)." if d["parciais"] else "."))
        elif q.tipo != "usuario":
            out["aviso_amostra"] += (" A lista de usuários pode não estar completa. Para ter certeza, diminua o período "
                                     "(por exemplo, um dia por vez) ou escolha o firewall.")
        else:
            out["aviso_amostra"] += " Para o período inteiro, diminua o período ou escolha o firewall."
    if erros:
        out["aviso"] = ("Não foi possível consultar: " + ", ".join(LOGTYPE_NAMES[k] for k in erros) +
                        ". O relatório mostra só o restante.")
    if not erros:
        database.cache_set(key, out, ttl=CACHE_TTL)
    return out


def store(report: dict) -> str:
    """Guarda o relatório por 1 h para exportar em PDF ou Excel."""
    rid = uuid.uuid4().hex
    database.temp_set(f"report:{rid}", report)
    return rid
