import ipaddress
import logging
import re
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

from .config import settings
from .faz_client import FazClient, FazError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
audit = logging.getLogger("auditoria")

LOGTYPES = {"traffic", "event", "webfilter", "app-ctrl", "virus", "ips", "dns", "ssl", "emailfilter"}
SAFE_VALUE = re.compile(r"^[\w.\-:@/ ]{1,128}$")  # evita injeção na expressão de filtro do FAZ
SAFE_NAME = re.compile(r"^[\w.\-]{1,64}$")

app = FastAPI(title="Consulta FortiAnalyzer - Sustentação Marista")
_client: FazClient | None = None


def client() -> FazClient:
    global _client
    if _client is None:
        if settings.mock:
            from .mock_faz import transport
            _client = FazClient("http://faz-mock", "mock", transport=transport)
        else:
            if not settings.faz_url or not settings.api_token:
                raise HTTPException(500, "FAZ_URL e FAZ_API_TOKEN precisam estar definidos no ambiente.")
            _client = FazClient(settings.faz_url, settings.api_token, verify=settings.verify_tls)
    return _client


@app.on_event("shutdown")
async def _shutdown():
    if _client:
        await _client.close()


class LogQuery(BaseModel):
    adom: str = Field(default_factory=lambda: settings.default_adom)
    devices: list[str] = []
    logtype: str = "traffic"
    start: datetime
    end: datetime
    srcip: str | None = None
    dstip: str | None = None
    user: str | None = None
    hostname: str | None = None
    action: str | None = None
    dstport: int | None = None
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
                raise ValueError(f"Dispositivo inválido: {d}")
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
        if v in (None, ""):
            return None
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError("IP inválido")

    @field_validator("action")
    @classmethod
    def _action(cls, v):
        if v in (None, ""):
            return None
        if not re.fullmatch(r"[a-z\-]{1,20}", v):
            raise ValueError("Ação inválida")
        return v

    @field_validator("user", "hostname")
    @classmethod
    def _safe(cls, v):
        if v in (None, ""):
            return None
        v = v.strip()
        if not SAFE_VALUE.match(v):
            raise ValueError("Valor contém caracteres não permitidos")
        return v

    def filter_expr(self) -> str:
        parts = []
        if self.srcip:
            parts.append(f"srcip={self.srcip}")
        if self.dstip:
            parts.append(f"dstip={self.dstip}")
        if self.dstport:
            parts.append(f"dstport={self.dstport}")
        if self.action:
            parts.append(f"action={self.action}")
        if self.user:
            parts.append(f'user~"{self.user}"')
        if self.hostname:
            parts.append(f'hostname~"{self.hostname}"')
        return " and ".join(parts)


def _who(request: Request) -> str:
    # Atrás de um proxy com SSO, use o header que ele injeta (ex.: X-Forwarded-User)
    return request.headers.get("x-forwarded-user") or (request.client.host if request.client else "?")


@app.get("/api/adoms")
async def adoms():
    try:
        return await client().list_adoms()
    except FazError as e:
        raise HTTPException(502, str(e))


@app.get("/api/adoms/{adom}/devices")
async def devices(adom: str):
    if not SAFE_NAME.match(adom):
        raise HTTPException(400, "ADOM inválido")
    try:
        return await client().list_devices(adom)
    except FazError as e:
        raise HTTPException(502, str(e))


@app.post("/api/logs")
async def search_logs(q: LogQuery, request: Request):
    if q.end <= q.start:
        raise HTTPException(400, "A data final precisa ser maior que a inicial.")
    limit = max(1, min(q.limit, settings.max_results))
    flt = q.filter_expr()
    audit.info("usuario=%s adom=%s tipo=%s periodo=%s..%s dispositivos=%s filtro=%r",
               _who(request), q.adom, q.logtype, q.start, q.end, q.devices or "todos", flt)
    try:
        result = await client().search_logs(
            adom=q.adom,
            logtype=q.logtype,
            start=q.start.strftime("%Y-%m-%d %H:%M:%S"),
            end=q.end.strftime("%Y-%m-%d %H:%M:%S"),
            filter_expr=flt,
            devices=q.devices,
            limit=limit,
        )
    except FazError as e:
        raise HTTPException(502, str(e))
    result["filter"] = flt
    return result


@app.get("/")
async def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")
