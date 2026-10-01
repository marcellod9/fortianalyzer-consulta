"""Cliente da API oficial JSON-RPC do FortiAnalyzer (testado contra FAZ 7.4.x).

Endpoint único: POST {FAZ_URL}/jsonrpc
Autenticação: token de administrador REST API, header "Authorization: Bearer <token>"
(suportado a partir do FortiAnalyzer 7.2.2).

URLs usadas:
  get    /sys/status                               versão e hostname (teste de conexão)
  get    /dvmdb/adom                               ADOMs
  get    /dvmdb/adom/{adom}/device                 firewalls da ADOM
  add    /logview/adom/{adom}/logsearch            cria tarefa de busca (apiver 3) -> tid
  get    /logview/adom/{adom}/logsearch/{tid}      lê resultado até percentage = 100
  delete /logview/adom/{adom}/logsearch/{tid}      libera a tarefa no FAZ
"""
import itertools
import threading
import time
from typing import Any

import requests

from ..config import settings
from .telemetry import timed


class FazError(Exception):
    pass


class FazClient:
    source = "fortianalyzer"

    def __init__(self, url: str, token: str, verify: Any = True, session: requests.Session | None = None,
                 timeout: int = 30):
        self.url = url.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self._ids = itertools.count(1)
        self._id_lock = threading.Lock()
        self._http = session or requests.Session()
        self._http.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})

    def close(self) -> None:
        self._http.close()

    def _next_id(self) -> int:
        with self._id_lock:
            return next(self._ids)

    def call(self, method: str, url: str, **params) -> Any:
        body = {"id": self._next_id(), "jsonrpc": "2.0", "method": method, "params": [{"url": url, **params}]}
        try:
            resp = self._http.post(f"{self.url}/jsonrpc", json=body, verify=self.verify, timeout=self.timeout)
        except requests.exceptions.SSLError as e:
            raise FazError("Falha de certificado TLS ao conectar no FortiAnalyzer. Ajuste FAZ_VERIFY_TLS "
                           "para o caminho da CA interna.") from e
        except requests.exceptions.RequestException as e:
            raise FazError(f"Não foi possível conectar ao FortiAnalyzer: {e}") from e
        if resp.status_code in (401, 403):
            raise FazError("FortiAnalyzer recusou o token (HTTP %s). Verifique FAZ_API_TOKEN e os Trusted Hosts "
                           "do administrador REST." % resp.status_code)
        if resp.status_code >= 400:
            raise FazError(f"FortiAnalyzer respondeu HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as e:
            raise FazError("Resposta inválida do FortiAnalyzer (não é JSON)") from e
        if data.get("error"):
            raise FazError(f"{url}: {data['error']}")
        result = data.get("result")
        # dvmdb/sys devolvem result como lista com status; logview devolve dict
        if isinstance(result, list):
            if not result:
                return None
            status = result[0].get("status", {}) or {}
            if status.get("code", 0) != 0:
                msg = status.get("message", "erro")
                if status.get("code") == -11:
                    msg = "sem permissão para este recurso (perfil do administrador REST)"
                raise FazError(f"{url}: {msg}")
            return result[0].get("data")
        return result

    # ---- diagnóstico ------------------------------------------------------
    def status(self) -> dict:
        with timed(self.source, "sys/status"):
            data = self.call("get", "/sys/status") or {}
        return {"hostname": data.get("Hostname"), "versao": data.get("Version"),
                "serial": data.get("Serial Number"), "plataforma": data.get("Platform Type")}

    # ---- inventário -------------------------------------------------------
    def list_adoms(self) -> list[dict]:
        with timed(self.source, "dvmdb/adom"):
            data = self.call("get", "/dvmdb/adom", fields=["name", "desc"]) or []
        return [{"name": a["name"], "desc": a.get("desc", "")} for a in data]

    def list_devices(self, adom: str) -> list[dict]:
        with timed(self.source, f"dvmdb/adom/{adom}/device"):
            data = self.call("get", f"/dvmdb/adom/{adom}/device",
                             fields=["name", "sn", "ip", "platform_str", "desc"]) or []
        return [{"name": d.get("name"), "sn": d.get("sn"), "ip": d.get("ip"),
                 "platform": d.get("platform_str"), "desc": d.get("desc")} for d in data]

    # ---- busca de logs ----------------------------------------------------
    def search_logs(self, adom: str, logtype: str, start: str, end: str, filter_expr: str = "",
                    devices: list[str] | None = None, limit: int = 500) -> dict:
        base = f"/logview/adom/{adom}/logsearch"
        device = [{"devid": d} for d in devices] if devices else [{"devid": "All_FortiGate"}]
        with timed(self.source, f"logsearch {logtype} [{filter_expr}]"):
            created = self.call(
                "add", base, apiver=3, device=device, logtype=logtype, filter=filter_expr,
                **{"time-order": "desc", "case-sensitive": False, "time-range": {"start": start, "end": end}},
            ) or {}
            tid = created.get("tid")
            if tid is None:
                raise FazError(f"FortiAnalyzer não devolveu tid: {created}")
            try:
                deadline = time.monotonic() + settings.faz_search_timeout
                while True:
                    res = self.call("get", f"{base}/{tid}", apiver=3, offset=0, limit=limit) or {}
                    if res.get("percentage", 0) >= 100:
                        rows = res.get("data") or []
                        return {"total": res.get("total-lines", len(rows)),
                                "returned": res.get("return-lines", len(rows)), "logs": rows}
                    if time.monotonic() > deadline:
                        raise FazError("Tempo limite da busca excedido; reduza o período ou refine o filtro.")
                    time.sleep(1)
            finally:
                try:
                    self.call("delete", f"{base}/{tid}", apiver=3)
                except Exception:
                    pass


_client: FazClient | None = None
_client_lock = threading.Lock()


def get_client():
    """Cliente real, ou simulado quando PORTAL_DEMO=true."""
    global _client
    with _client_lock:
        if _client is None:
            if settings.demo:
                from ..demo.faz_demo import DemoFazClient
                _client = DemoFazClient()
            else:
                if not settings.faz_configured:
                    raise FazError("FortiAnalyzer não configurado: defina FAZ_URL e FAZ_API_TOKEN em config\\.env.")
                _client = FazClient(settings.faz_url, settings.faz_token, verify=settings.faz_verify)
        return _client


def reset_client() -> None:
    global _client
    with _client_lock:
        if _client is not None:
            try:
                _client.close()
            except Exception:
                pass
        _client = None
