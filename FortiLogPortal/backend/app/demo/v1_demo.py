"""Vision One simulado (somente com PORTAL_DEMO=true), no formato das respostas da API v3.0."""
import hashlib
import re
import uuid
from datetime import datetime, timedelta, timezone

from ..services.visionone import V1Error
from .faz_demo import USERS, _device


def _ts(days_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


SUSPICIOUS = [
    {"type": "domain", "domain": "malware-test.example", "riskLevel": "high", "scanAction": "block",
     "description": "Distribuição de malware (demo)", "inExceptionList": False,
     "lastModifiedDateTime": _ts(2), "expiredDateTime": _ts(-28)},
    {"type": "url", "url": "http://phishing-demo.example/login", "riskLevel": "high", "scanAction": "block",
     "description": "Phishing de credenciais (demo)", "inExceptionList": False,
     "lastModifiedDateTime": _ts(1), "expiredDateTime": _ts(-29)},
    {"type": "ip", "ip": "45.33.32.156", "riskLevel": "medium", "scanAction": "log",
     "description": "Varredura de portas (demo)", "inExceptionList": False,
     "lastModifiedDateTime": _ts(5), "expiredDateTime": _ts(-25)},
]
EXCEPTIONS = [{"type": "domain", "domain": "maristabrasil.org", "description": "Domínio institucional (demo)",
               "lastModifiedDateTime": _ts(30)}]
ALERTS = [
    {"id": "WB-DEMO-0001", "model": "Possible Credential Phishing", "severity": "high", "score": 78,
     "status": "Open", "investigationStatus": "New", "createdDateTime": _ts(1),
     "workbenchLink": "https://portal.xdr.trendmicro.com/", "indicators": [
         {"id": 1, "type": "url", "value": "http://phishing-demo.example/login"},
         {"id": 2, "type": "ip", "value": "203.0.113.50"},
         {"id": 3, "type": "fileSha1", "value": "3395856ce81f2b7382dee72602f798b642f14140"}],
     "impactScope": {"accountCount": 1, "emailAddressCount": 1, "entities": [
         {"entityType": "account", "entityValue": "MARISTA\\maria.souza"},
         {"entityType": "emailAddress", "entityValue": "maria.souza@maristabrasil.org"}]}},
    {"id": "WB-DEMO-0002", "model": "Malware Download Detected", "severity": "critical", "score": 92,
     "status": "In Progress", "investigationStatus": "In Progress", "createdDateTime": _ts(3),
     "workbenchLink": "https://portal.xdr.trendmicro.com/", "indicators": [
         {"id": 1, "type": "domain", "value": "malware-test.example"},
         {"id": 2, "type": "hostname", "value": {"name": "NB-SUPORTE-12"}}],
     "impactScope": {"desktopCount": 1, "entities": [
         {"entityType": "host", "entityValue": {"name": "NB-SUPORTE-12", "ips": ["10.10.12.34"], "guid": "demo-suporte12"}}]}},
    {"id": "WB-DEMO-0003", "model": "Unusual Sign-in Location", "severity": "medium", "score": 45,
     "status": "Closed", "investigationStatus": "Closed", "investigationResult": "False Positive",
     "createdDateTime": _ts(9), "workbenchLink": "https://portal.xdr.trendmicro.com/", "indicators": [],
     "impactScope": {"accountCount": 1, "entities": [{"entityType": "account", "entityValue": "MARISTA\\joao.silva"}]}},
]

# Inventário de endpoints: computadores (Windows/Mac) têm o agente; celulares não. Uma em cada dez máquinas
# está com o agente sem comunicação há 12 dias e uma em cada 25 está isolada, para mostrar os avisos.
_EQ = re.compile(r"(\w+) eq '([^']*)'")
_NAME = re.compile(r"(NB-ADM|PC-LAB|MacBook|NB)-(\d{2})(\d{3})", re.I)
_ENDPOINTS: dict[str, dict] = {}
SUPORTE = {"name": "NB-SUPORTE-12", "ip": "10.10.12.34", "guid": "demo-suporte12"}  # a máquina do alerta WB-DEMO-0002
_SANDBOX: dict[str, str] = {}  # tarefa do Sandbox -> URL enviada


def _endpoint(name: str, ip: str, mac: str, osname: str, seed: int, guid: str | None = None) -> dict:
    guid = guid or "demo-" + hashlib.sha1(name.upper().encode()).hexdigest()[:12]
    if guid in _ENDPOINTS:  # a mesma máquina achada pelo IP e pelo nome: mantém os dados da primeira
        return _ENDPOINTS[guid]
    user = [u for u in USERS if u][seed % 5]
    ep = {"agentGuid": guid, "endpointName": {"updatedDateTime": _ts(0.1), "value": name},
          "ip": {"updatedDateTime": _ts(0.1), "value": [ip]}, "macAddress": {"updatedDateTime": _ts(0.1), "value": [mac]},
          "loginAccount": {"updatedDateTime": _ts(0.2), "value": [f"MARISTA\\{user}"]},
          "osName": osname, "osDescription": "macOS 14 Sonoma" if osname == "macOS" else "Windows 11 Pro (64 bit)",
          "productCode": "xes", "installedProductCodes": ["sao"], "componentUpdatePolicy": "N",
          "componentUpdateStatus": "onSchedule", "componentVersion": "outdatedVersion" if seed % 10 == 7 else "latestVersion",
          "policyName": "Padrão Marista (demo)", "protectionManager": "Standard Endpoint Protection", "_seed": seed}
    _ENDPOINTS[guid] = ep
    return ep


def _from_ip(ip: str) -> dict | None:
    try:
        o = [int(x) for x in ip.split(".")]
    except ValueError:
        return None
    if len(o) != 4:
        return None
    if ip == SUPORTE["ip"]:
        return _from_name(SUPORTE["name"])
    dev = _device(ip)
    if dev.get("devtype") in ("Android Phone", "iPhone"):
        return None  # celular: sem agente Trend
    if dev:
        return _endpoint(dev["srcname"], ip, dev["srcmac"], dev["osname"], o[3])
    if o[3] % 2:
        return None  # rede sem identificação de dispositivos: metade das máquinas sem o agente
    return _endpoint(f"NB-{o[2]:02d}{o[3]:03d}", ip, f"00:1a:2b:{o[1]:02x}:{o[2]:02x}:{o[3]:02x}", "Windows", o[3])


def _from_name(name: str) -> dict | None:
    if name.upper() == SUPORTE["name"]:
        return _endpoint(SUPORTE["name"], SUPORTE["ip"], "00:1a:2b:0a:0c:22", "Windows", 34, guid=SUPORTE["guid"])
    m = _NAME.fullmatch(name)
    if not m:
        return None
    o2, o3 = int(m.group(2)) % 256, int(m.group(3))
    o3 = o3 if 2 <= o3 <= 254 else o3 % 250 + 2
    return _endpoint(name.upper() if m.group(1).upper() != "MACBOOK" else name, f"10.10.{o2}.{o3}",
                     f"00:1a:2b:0a:{o2:02x}:{o3:02x}", "macOS" if m.group(1).upper() == "MACBOOK" else "Windows", o3)


class DemoVisionOneClient:
    source = "visionone-demo"

    def close(self):
        pass

    def connectivity(self):
        return {"status": "available"}

    def suspicious_objects(self, max_items=5000):
        return SUSPICIOUS

    def suspicious_exceptions(self, max_items=5000):
        return EXCEPTIONS

    def search_detections(self, query, start, end, top=50):
        q = query.lower()
        if "malware-test.example" in q:
            return [{"eventTimeDT": _ts(3), "malName": "TROJ_GEN.R002C0DEMO", "endpointHostName": "NB-SUPORTE-12",
                     "request": "http://malware-test.example/payload.exe", "act": ["Block"]}]
        if "45.33.32.156" in q:
            return [{"eventTimeDT": _ts(5), "ruleName": "Port Scan Detected", "src": "45.33.32.156",
                     "dst": "10.10.0.20", "act": ["Log"]}]
        return []

    def workbench_alerts(self, start, end, max_items=500, tmv1_filter=None):
        return ALERTS

    def endpoints(self, max_items=500):
        """Inventário (formato de endpointSecurity/endpoints): na demonstração, só as máquinas já geradas."""
        return [self._list_item(ep) for ep in list(_ENDPOINTS.values())[:max_items]]

    def inventory_for(self, ips):
        """Demonstração: a rede simulada é grande demais para listar inteira; monta só as máquinas pedidas."""
        for ip in ips:
            _from_ip(ip)
        return self.endpoints(max_items=len(_ENDPOINTS))

    def _list_item(self, ep):
        d = self.endpoint_details(ep["agentGuid"])
        return {**d, "osName": ep["osName"], "ipAddresses": [d["lastUsedIp"]]}

    def search_endpoints(self, query, max_items=20):
        out = []
        for field, value in _EQ.findall(query):
            ep = _from_ip(value) if field == "ip" else _from_name(value) if field == "endpointName" else None
            if ep and all(e["agentGuid"] != ep["agentGuid"] for e in out):
                out.append(ep)
        return [{k: v for k, v in e.items() if k != "_seed"} for e in out[:max_items]]

    def endpoint_details(self, agent_guid):
        ep = _ENDPOINTS.get(agent_guid)
        if not ep:
            raise V1Error("Vision One HTTP 404: recurso não encontrado", 404)
        seed, name, ip = ep["_seed"], ep["endpointName"]["value"], ep["ip"]["value"][0]
        off, last = seed % 10 == 7, _ts(12) if seed % 10 == 7 else _ts(0.01)
        return {"endpointName": name, "agentGuid": agent_guid, "displayName": name, "type": "desktop",
                "os": {"name": ep["osDescription"], "platform": "mac" if ep["osName"] == "macOS" else "windows"},
                "lastUsedIp": ip, "lastLoggedOnUser": ep["loginAccount"]["value"][0],
                "isolationStatus": "on" if seed % 25 == 3 else "off",
                "interfaces": [{"ipAddresses": [ip], "macAddress": ep["macAddress"]["value"][0]}],
                "eppAgent": {"endpointGroup": "Computadores (demo)", "protectionManager": "Standard Endpoint Protection",
                             "productNames": ["Standard Endpoint Protection"], "policyName": ep["policyName"],
                             "status": "off" if off else "on", "lastConnectedDateTime": last, "version": "14.0.13140",
                             "componentVersion": ep["componentVersion"], "componentUpdateStatus": "onSchedule"},
                "edrSensor": {"productNames": ["XDR Endpoint Sensor"], "connectivity": "disconnected" if off else "connected",
                              "status": "enabled", "lastConnectedDateTime": last, "version": "1.2.0.4567"}}

    def sandbox_usage(self):
        return {"submissionReserveCount": 10000, "submissionRemainingCount": 10000 - len(_SANDBOX),
                "submissionCount": len(_SANDBOX), "submissionExemptionCount": 0}

    def sandbox_submit_url(self, url):
        tid = f"demo-task-{uuid.uuid4().hex[:12]}"
        _SANDBOX[tid] = url
        return {"task_id": tid, "id": tid, "url": url}

    def sandbox_task(self, task_id):
        return {"id": task_id, "status": "succeeded", "resourceLocation": f"/v3.0/sandbox/analysisResults/{task_id}"}

    def sandbox_result(self, result_id):
        url = _SANDBOX.get(result_id, "")
        if not any(k in url for k in ("phish", "malware")):
            return {"id": result_id, "type": "url", "riskLevel": "noRisk", "threatTypes": [], "detectionNames": [],
                    "analysisCompletionDateTime": _ts(0)}
        return {"id": result_id, "type": "url", "riskLevel": "high", "threatTypes": ["Phishing"],
                "detectionNames": ["HTML_PHISH.DEMO"], "analysisCompletionDateTime": _ts(0)}

    def sandbox_result_iocs(self, result_id):
        url = _SANDBOX.get(result_id, "")
        return [{"type": "ip", "ip": "203.0.113.50", "riskLevel": "high"}] if any(k in url for k in ("phish", "malware")) else []
