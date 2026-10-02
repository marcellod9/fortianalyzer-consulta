"""Cliente da API pública oficial do Trend Vision One (v3.0).

Base: V1_BASE_URL (ex.: https://api.xdr.trendmicro.com para a região EUA)
Autenticação: header "Authorization: Bearer <chave de API>"
Referência: https://automation.trendmicro.com/xdr/api-v3

Endpoints usados (somente leitura, exceto o envio opcional ao Sandbox):
  GET  /v3.0/healthcheck/connectivity               teste de conexão
  GET  /v3.0/threatintel/suspiciousObjects          lista de Suspicious Objects (IOC da organização)
  GET  /v3.0/threatintel/suspiciousObjectExceptions lista de exceções (objetos confiáveis)
  GET  /v3.0/search/detections                      detecções no ambiente (header TMV1-Query)
  GET  /v3.0/workbench/alerts                       alertas do Workbench
  GET  /v3.0/eiqs/endpoints                         procura a máquina no inventário (header TMV1-Query)
  GET  /v3.0/endpointSecurity/endpoints             inventário de endpoints
  GET  /v3.0/endpointSecurity/endpoints/{id}        situação do agente da máquina (status, último contato)
  GET  /v3.0/sandbox/submissionUsage                cota diária do Sandbox (envios restantes)
  POST /v3.0/sandbox/urls/analyze                   envia URL ao Sandbox (opcional, consome cota)
  GET  /v3.0/sandbox/tasks/{id}                     status da análise
  GET  /v3.0/sandbox/analysisResults/{id}           resultado (riskLevel, threatTypes...)
  GET  /v3.0/sandbox/analysisResults/{id}/suspiciousObjects   IOCs extraídos pelo Sandbox
"""
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

import requests

from ..config import settings
from .telemetry import timed

API = "/v3.0"
GUID_RE = re.compile(r"[\w\-]{1,80}", re.ASCII)


class V1Error(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class VisionOneClient:
    source = "visionone"

    def __init__(self, base_url: str, token: str, verify: Any = True, session: requests.Session | None = None,
                 timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self._http = session or requests.Session()
        self._http.headers.update({"Authorization": f"Bearer {token}", "User-Agent": "FortiLogPortal/0.1"})

    def close(self) -> None:
        self._http.close()

    # ---- HTTP -------------------------------------------------------------
    def _request(self, method: str, path_or_url: str, *, params: dict | None = None, headers: dict | None = None,
                 json: Any = None) -> requests.Response:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base_url}{API}{path_or_url}"
        if not url.startswith(self.base_url):
            raise V1Error("nextLink fora do domínio configurado em V1_BASE_URL")
        try:
            resp = self._http.request(method, url, params=params, headers=headers, json=json,
                                      verify=self.verify, timeout=self.timeout)
        except requests.exceptions.SSLError as e:
            raise V1Error("Falha de certificado TLS ao conectar no Vision One (proxy com inspeção SSL?). "
                          "Ajuste V1_VERIFY_TLS para o caminho da CA corporativa.") from e
        except requests.exceptions.RequestException as e:
            raise V1Error(f"Não foi possível conectar ao Vision One: {e}") from e
        if resp.status_code >= 400:
            raise V1Error(self._error_message(resp), resp.status_code)
        return resp

    @staticmethod
    def _error_message(resp: requests.Response) -> str:
        detail = ""
        try:
            err = resp.json().get("error") or {}
            detail = f"{err.get('code', '')} {err.get('message', '')}".strip()
        except ValueError:
            detail = resp.text[:200]
        hints = {
            401: "chave de API inválida ou expirada (V1_API_TOKEN)",
            403: "a função da chave de API não tem permissão para este recurso",
            404: "recurso não encontrado (confira V1_BASE_URL / região do tenant)",
            429: "limite de requisições do Vision One atingido; tente novamente em instantes",
        }
        hint = hints.get(resp.status_code, "erro na API do Vision One")
        return f"Vision One HTTP {resp.status_code}: {hint}" + (f" ({detail})" if detail else "")

    def _get(self, path: str, **kw) -> dict:
        resp = self._request("GET", path, **kw)
        return resp.json() if resp.content else {}

    def _paged(self, path: str, *, params: dict | None = None, headers: dict | None = None,
               max_items: int = 1000) -> list[dict]:
        """Segue nextLink até max_items."""
        items: list[dict] = []
        data = self._get(path, params=params, headers=headers)
        while True:
            items.extend(data.get("items") or [])
            nxt = data.get("nextLink")
            if not nxt or len(items) >= max_items:
                return items[:max_items]
            data = self._get(nxt, headers=headers)

    # ---- diagnóstico --------------------------------------------------------
    def connectivity(self) -> dict:
        with timed(self.source, "healthcheck/connectivity"):
            return self._get("/healthcheck/connectivity")

    # ---- Threat Intelligence ------------------------------------------------
    def suspicious_objects(self, max_items: int = 5000) -> list[dict]:
        with timed(self.source, "threatintel/suspiciousObjects"):
            return self._paged("/threatintel/suspiciousObjects", params={"top": 200}, max_items=max_items)

    def suspicious_exceptions(self, max_items: int = 5000) -> list[dict]:
        with timed(self.source, "threatintel/suspiciousObjectExceptions"):
            return self._paged("/threatintel/suspiciousObjectExceptions", params={"top": 200}, max_items=max_items)

    # ---- Search -----------------------------------------------------------------
    def search_detections(self, query: str, start: datetime, end: datetime, top: int = 50) -> list[dict]:
        with timed(self.source, f"search/detections [{query}]"):
            return self._paged("/search/detections",
                               params={"startDateTime": iso_utc(start), "endDateTime": iso_utc(end), "top": top},
                               headers={"TMV1-Query": query}, max_items=top)

    # ---- Workbench --------------------------------------------------------------
    def workbench_alerts(self, start: datetime, end: datetime, max_items: int = 500,
                         tmv1_filter: str | None = None) -> list[dict]:
        headers = {"TMV1-Filter": tmv1_filter} if tmv1_filter else None
        with timed(self.source, "workbench/alerts"):
            return self._paged("/workbench/alerts",
                               params={"startDateTime": iso_utc(start), "endDateTime": iso_utc(end),
                                       "orderBy": "createdDateTime desc"},
                               headers=headers, max_items=max_items)

    # ---- Endpoints ----------------------------------------------------------------
    def endpoints(self, max_items: int = 500) -> list[dict]:
        with timed(self.source, "endpointSecurity/endpoints"):
            return self._paged("/endpointSecurity/endpoints", params={"top": 200}, max_items=max_items)

    def search_endpoints(self, query: str, max_items: int = 20) -> list[dict]:
        """Máquinas do inventário que atendem à consulta (ex.: ip eq '10.0.0.1' or endpointName eq 'PC-01')."""
        with timed(self.source, f"eiqs/endpoints [{query}]"):
            return self._paged("/eiqs/endpoints", headers={"TMV1-Query": query}, max_items=max_items)

    def endpoint_details(self, agent_guid: str) -> dict:
        if not GUID_RE.fullmatch(agent_guid or ""):
            raise V1Error("Identificador de endpoint inválido.")
        with timed(self.source, "endpointSecurity/endpoints/{id}"):
            return self._get(f"/endpointSecurity/endpoints/{agent_guid}")

    # ---- Sandbox ----------------------------------------------------------------
    def sandbox_usage(self) -> dict:
        """Cota diária do Sandbox (submissionRemainingCount: envios que ainda restam hoje)."""
        with timed(self.source, "sandbox/submissionUsage"):
            return self._get("/sandbox/submissionUsage")

    def sandbox_submit_url(self, url: str) -> dict:
        with timed(self.source, "sandbox/urls/analyze"):
            resp = self._request("POST", "/sandbox/urls/analyze", json=[{"url": url}])
        data = resp.json() or []
        item = data[0] if isinstance(data, list) and data else {}
        if item.get("status", 0) >= 400:
            body = item.get("body") or {}
            raise V1Error(f"Sandbox recusou a URL: {(body.get('error') or {}).get('message', body)}", item.get("status"))
        task_id = None
        for h in item.get("headers") or []:
            if h.get("name") == "Operation-Location":
                task_id = h.get("value", "").rstrip("/").split("/")[-1]
        body = item.get("body") or {}
        return {"task_id": task_id or body.get("id"), "id": body.get("id"), "url": body.get("url", url)}

    def sandbox_task(self, task_id: str) -> dict:
        with timed(self.source, "sandbox/tasks"):
            return self._get(f"/sandbox/tasks/{task_id}")

    def sandbox_result(self, result_id: str) -> dict:
        with timed(self.source, "sandbox/analysisResults"):
            return self._get(f"/sandbox/analysisResults/{result_id}")

    def sandbox_result_iocs(self, result_id: str) -> list[dict]:
        with timed(self.source, "sandbox/analysisResults/suspiciousObjects"):
            return self._get(f"/sandbox/analysisResults/{result_id}/suspiciousObjects").get("items") or []


def default_window() -> tuple[datetime, datetime]:
    end = datetime.now().astimezone()
    return end - timedelta(days=settings.v1_lookback_days), end


def object_value(obj: dict) -> str:
    """Suspicious Objects trazem o valor no campo com o nome do tipo (url, domain, ip, fileSha1...)."""
    return str(obj.get(obj.get("type", ""), "") or obj.get("value", ""))


def host_of(url: str) -> str:
    try:
        return (urlsplit(url if "://" in url else f"http://{url}").hostname or "").lower()
    except ValueError:
        return ""


_client: VisionOneClient | None = None
_lock = threading.Lock()


def get_client():
    global _client
    with _lock:
        if _client is None:
            if settings.demo:
                from ..demo.v1_demo import DemoVisionOneClient
                _client = DemoVisionOneClient()
            else:
                if not settings.v1_configured:
                    raise V1Error("Vision One não configurado: defina V1_BASE_URL e V1_API_TOKEN em config\\.env.")
                _client = VisionOneClient(settings.v1_base_url, settings.v1_token, verify=settings.v1_verify)
        return _client


def reset_client() -> None:
    global _client
    with _lock:
        if _client is not None:
            try:
                _client.close()
            except Exception:
                pass
        _client = None
