"""Validação dos campos de pesquisa e montagem da expressão de filtro do FortiAnalyzer.

Todo valor digitado é validado antes de entrar na expressão (IPs com ipaddress,
portas numéricas, textos sem aspas/barras), evitando injeção de filtro.
Sintaxe de filtro do LogView: campo=valor, campo~"texto" (contém), unidos por "and".
"""
import ipaddress
import re
from datetime import datetime

from pydantic import BaseModel, Field, field_validator, model_validator

from ..config import settings

LOGTYPES = {
    "traffic": "Tráfego (firewall)",
    "webfilter": "Filtro web (navegação)",
    "app-ctrl": "Controle de aplicações",
    "dns": "Filtro DNS",
    "ips": "IPS (intrusão)",
    "virus": "Antivírus",
    "ssl": "Inspeção SSL",
    "event": "Eventos do sistema",
}

# Valor do campo "action" que representa bloqueio em cada tipo de log (FortiOS 7.x)
BLOCK_ACTIONS = {
    "traffic": "deny",
    "webfilter": "blocked",
    "app-ctrl": "block",
    "dns": "block",
    "ips": "dropped",
    "virus": "blocked",
    "ssl": "blocked",
}

SAFE_NAME = re.compile(r"^[\w.\-]{1,64}$")
SAFE_TEXT = re.compile(r'^[^"\\\x00-\x1f]{1,256}$')  # qualquer texto sem aspas, barra invertida ou controle
SAFE_ACTION = re.compile(r"^[a-z\-]{1,20}$")


def _text(v):
    if v in (None, ""):
        return None
    v = str(v).strip()
    if not v:
        return None
    if not SAFE_TEXT.match(v):
        raise ValueError("valor contém caracteres não permitidos (aspas ou barra invertida)")
    return v


def _ip_or_net(v):
    if v in (None, ""):
        return None
    v = str(v).strip()
    try:
        if "/" in v:
            return str(ipaddress.ip_network(v, strict=False))
        return str(ipaddress.ip_address(v))
    except ValueError:
        raise ValueError("IP ou rede inválido")


class LogQuery(BaseModel):
    adom: str = Field(default_factory=lambda: settings.faz_default_adom)
    devices: list[str] = []          # números de série (devid) dos firewalls; vazio = todos
    logtype: str = "traffic"
    start: datetime
    end: datetime
    # rede
    srcip: str | None = None
    dstip: str | None = None
    srcport: int | None = Field(default=None, ge=1, le=65535)
    dstport: int | None = Field(default=None, ge=1, le=65535)
    # usuário
    user: str | None = None
    # navegação
    url: str | None = None
    hostname: str | None = None
    # firewall
    policy: str | None = None        # número da regra (policyid) ou nome (policyname)
    profile: str | None = None       # perfil/política de segurança (ex.: web filter)
    srcintf: str | None = None
    dstintf: str | None = None
    action: str | None = None
    only_blocked: bool = False
    limit: int = 500

    @field_validator("adom")
    @classmethod
    def _adom(cls, v):
        if not SAFE_NAME.match(v):
            raise ValueError("ADOM inválido")
        return v

    @field_validator("devices")
    @classmethod
    def _devices(cls, v):
        for d in v:
            if not SAFE_NAME.match(d):
                raise ValueError(f"Equipamento inválido: {d}")
        return v

    @field_validator("logtype")
    @classmethod
    def _logtype(cls, v):
        if v not in LOGTYPES:
            raise ValueError(f"Tipo de log deve ser um de {sorted(LOGTYPES)}")
        return v

    @field_validator("srcip", "dstip")
    @classmethod
    def _ip(cls, v):
        return _ip_or_net(v)

    @field_validator("user", "url", "hostname", "policy", "profile", "srcintf", "dstintf")
    @classmethod
    def _txt(cls, v):
        return _text(v)

    @field_validator("action")
    @classmethod
    def _action(cls, v):
        if v in (None, ""):
            return None
        if not SAFE_ACTION.match(v):
            raise ValueError("Ação inválida")
        return v

    @field_validator("srcport", "dstport", mode="before")
    @classmethod
    def _empty_port(cls, v):
        return None if v in ("", None) else v

    @model_validator(mode="after")
    def _period(self):
        if self.end <= self.start:
            raise ValueError("A data final precisa ser maior que a data inicial.")
        self.limit = max(1, min(self.limit, settings.faz_max_results))
        return self

    def filter_expr(self) -> str:
        p: list[str] = []
        if self.srcip:
            p.append(f"srcip={self.srcip}")
        if self.dstip:
            p.append(f"dstip={self.dstip}")
        if self.srcport:
            p.append(f"srcport={self.srcport}")
        if self.dstport:
            p.append(f"dstport={self.dstport}")
        if self.user:
            p.append(f'user~"{self.user}"')
        if self.url:
            p.append(f'url~"{self.url}"')
        if self.hostname:
            field = "qname" if self.logtype == "dns" else "hostname"  # logs DNS guardam o domínio em qname
            p.append(f'{field}~"{self.hostname}"')
        if self.policy:
            p.append(f"policyid={self.policy}" if self.policy.isdigit() else f'policyname~"{self.policy}"')
        if self.profile:
            p.append(f'profile~"{self.profile}"')
        if self.srcintf:
            p.append(f'srcintf~"{self.srcintf}"')
        if self.dstintf:
            p.append(f'dstintf~"{self.dstintf}"')
        action = self.action or (BLOCK_ACTIONS.get(self.logtype) if self.only_blocked else None)
        if action:
            p.append(f"action={action}")
        return " and ".join(p)

    def describe(self) -> str:
        """Texto curto do que foi pesquisado (histórico)."""
        flt = self.filter_expr()
        return f"{self.logtype}: {flt or '(sem filtro)'}"

    def faz_time(self, which: str) -> str:
        return getattr(self, which).strftime("%Y-%m-%d %H:%M:%S")
