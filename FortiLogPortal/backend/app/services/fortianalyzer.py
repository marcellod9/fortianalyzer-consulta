"""Cliente da API oficial JSON-RPC do FortiAnalyzer (testado contra FAZ 7.4.x).

Endpoint único: POST {FAZ_URL}/jsonrpc
Autenticação: token de administrador REST API, header "Authorization: Bearer <token>"
(suportado a partir do FortiAnalyzer 7.2.2).

URLs usadas:
  get    /sys/status                               versão e hostname (teste de conexão)
  get    /dvmdb/adom                               ADOMs
  get    /dvmdb/adom/{adom}/device                 firewalls da ADOM
  add    /logview/adom/{adom}/logsearch            cria tarefa de busca (apiver 3, limit/offset da página) -> tid
  get    /logview/adom/{adom}/logsearch/{tid}      lê a página até percentage = 100 (uma página por tarefa)
  delete /logview/adom/{adom}/logsearch/{tid}      libera a tarefa no FAZ
  get    /eventmgmt/adom/{adom}/alerts             alertas do Event Monitor (perfil: Event Management)
  add    /fortiview/adom/{adom}/{view}/run         FortiView (ex.: top-threats) -> tid
  get    /fortiview/adom/{adom}/{view}/run/{tid}   lê o resultado até percentage = 100
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


# Máximo de linhas por leitura do logsearch ("limit: N is bigger than max value 1000"); acima disso, lê em páginas
PAGE_MAX = 1000


def _coord(v, limit: int) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if -limit <= f <= limit and f != 0 else None


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
        """Firewalls da ADOM. Clusters HA vêm como um item, com os membros em ha_members."""
        with timed(self.source, f"dvmdb/adom/{adom}/device"):
            # sem "fields": a tabela ha_slave (membros do cluster) só vem no objeto completo
            data = self.call("get", f"/dvmdb/adom/{adom}/device") or []
        out = []
        for d in data:
            members = [{"name": m.get("name"), "sn": m.get("sn"), "role": m.get("role")}
                       for m in (d.get("ha_slave") or []) if isinstance(m, dict)]
            out.append({"name": d.get("name"), "sn": d.get("sn"), "ip": d.get("ip"),
                        "platform": d.get("platform_str"), "desc": d.get("desc"),
                        "ha_members": members if len(members) > 1 else [],
                        # latitude/longitude do dispositivo no Device Manager (no FortiGate: gui-device-latitude/longitude), usadas no mapa em tempo real
                        "lat": _coord(d.get("latitude"), 90), "lon": _coord(d.get("longitude"), 180)})
        return sorted(out, key=lambda x: (x["name"] or "").lower())

    # ---- busca de logs ----------------------------------------------------
    # Cada tarefa (tid) entrega uma página só: o "add" já leva limit e offset (o FAZ para de procurar quando acha
    # "limit" eventos; sem limit, ele usa o padrão de 100) e o "get" lê essa página. A próxima página é uma busca
    # nova com offset maior. O total vem em "total-count" e é um piso: com a página cheia, pode haver mais.
    def search_logs(self, adom: str, logtype: str, start: str, end: str, filter_expr: str = "",
                    devices: list[str] | None = None, limit: int = 500) -> dict:
        rows: list = []
        total = 0
        prev_first = None
        with timed(self.source, f"logsearch {logtype} [{filter_expr}]"):
            while len(rows) < limit:
                size = min(PAGE_MAX, limit - len(rows))
                data, page_total = self._search_page(adom, logtype, start, end, filter_expr, devices, len(rows), size)
                total = max(total, page_total or 0)
                if not data or (rows and data[:1] == prev_first):
                    break  # acabou (ou o FAZ ignorou o offset e repetiu a página)
                prev_first = data[:1]
                rows.extend(data[: limit - len(rows)])
                if len(data) < size and (not page_total or len(rows) >= page_total):
                    break  # página incompleta e o total não indica mais eventos
        more = len(rows) >= limit and total <= len(rows)  # página cheia: pode haver mais do que o total informado
        return {"total": max(total, len(rows)), "returned": len(rows), "logs": rows, "mais": more or total > len(rows)}

    # ---- Event Monitor (alertas dos event handlers) ---------------------------
    ALERT_PAGE = 1000  # a API aceita até 2000 por leitura

    def list_alerts(self, adom: str, start: str, end: str, limit: int = 2000) -> dict:
        """Alertas do período, do mais novo para o mais antigo, em páginas (limit/offset)."""
        alerts: list = []
        with timed(self.source, "eventmgmt/alerts"):
            while len(alerts) < limit:
                size = min(self.ALERT_PAGE, limit - len(alerts))
                res = self.call("get", f"/eventmgmt/adom/{adom}/alerts", apiver=3, limit=size, offset=len(alerts),
                                **{"time-order": "desc", "time-range": {"start": start, "end": end}})
                if isinstance(res, dict):
                    status = res.get("status") or {}
                    if isinstance(status, dict) and status.get("code", 0) not in (0, None):
                        msg = status.get("message", "erro")
                        if status.get("code") == -11:
                            msg = "sem permissão para este recurso (perfil do administrador REST)"
                        raise FazError(f"/eventmgmt/adom/{adom}/alerts: {msg}")
                    page = res.get("data") or []
                else:
                    page = res or []
                page = [a for a in page if isinstance(a, dict)]
                alerts.extend(page)
                if len(page) < size:
                    break
        return {"alerts": alerts[:limit], "mais": len(alerts) >= limit}

    # ---- FortiView ---------------------------------------------------------------
    def fortiview(self, adom: str, view: str, start: str, end: str, devices: list[str] | None = None,
                  limit: int = 50, sort_by: str | None = None) -> list[dict]:
        """Mesma consulta das telas FortiView do FAZ (ex.: Threats > Top Threats)."""
        base = f"/fortiview/adom/{adom}/{view}/run"
        device = [{"devid": d} for d in devices] if devices else [{"devname": "All_Device"}]
        params = {"apiver": 3, "device": device, "limit": limit, "offset": 0, "case-sensitive": False,
                  "time-range": {"start": start, "end": end}}
        if sort_by:
            params["sort-by"] = [{"field": sort_by, "order": "desc"}]
        with timed(self.source, f"fortiview {view}"):
            created = self.call("add", base, **params) or {}
            tid = created.get("tid") if isinstance(created, dict) else None
            if tid is None:
                raise FazError(f"FortiView {view}: o FortiAnalyzer não devolveu tid ({created})")
            deadline = time.monotonic() + settings.faz_search_timeout
            time.sleep(0.5)
            while True:
                res = self.call("get", f"{base}/{tid}", apiver=3) or {}
                pct = res.get("percentage") if isinstance(res, dict) else None
                try:
                    done = pct is None or float(pct) >= 100
                except (TypeError, ValueError):
                    done = True
                if done:
                    data = res.get("data") if isinstance(res, dict) else res
                    return [r for r in (data or []) if isinstance(r, dict)]
                if time.monotonic() > deadline:
                    raise FazError(f"FortiView {view}: tempo limite excedido; reduza o período.")
                time.sleep(1)

    def _search_page(self, adom: str, logtype: str, start: str, end: str, filter_expr: str,
                     devices: list[str] | None, offset: int, limit: int) -> tuple[list, int | None]:
        base = f"/logview/adom/{adom}/logsearch"
        device = [{"devid": d} for d in devices] if devices else [{"devid": "All_FortiGate"}]
        created = self.call(
            "add", base, apiver=3, device=device, logtype=logtype, filter=filter_expr, limit=limit, offset=offset,
            **{"time-order": "desc", "case-sensitive": False, "time-range": {"start": start, "end": end}},
        ) or {}
        tid = created.get("tid")
        if tid is None:
            raise FazError(f"FortiAnalyzer não devolveu tid: {created}")
        try:
            deadline = time.monotonic() + settings.faz_search_timeout
            invalid_tid = 0
            started = time.monotonic()
            time.sleep(0.5)  # o FAZ pode demorar a registrar a tarefa recém-criada
            while True:
                try:
                    res = self.call("get", f"{base}/{tid}", apiver=3, offset=offset, limit=limit) or {}
                except FazError as e:
                    # "Invalid tid ... for fetching result" (-32005): tarefa ainda não disponível
                    if "Invalid tid" in str(e) and invalid_tid < 5 and time.monotonic() < deadline:
                        invalid_tid += 1
                        time.sleep(1)
                        continue
                    raise
                if res.get("percentage", 0) >= 100:
                    total = res.get("total-count", res.get("total-lines"))
                    return res.get("data") or [], (total if isinstance(total, int) and not isinstance(total, bool) else None)
                if time.monotonic() > deadline:
                    raise FazError("Tempo limite da busca excedido; reduza o período ou refine o filtro.")
                # buscas curtas (ex.: mapa em tempo real) terminam em 1 a 2 s: confere a cada 0,5 s no começo
                time.sleep(0.5 if time.monotonic() - started < 5 else 1)
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
