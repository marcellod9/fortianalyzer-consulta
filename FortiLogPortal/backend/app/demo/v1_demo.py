"""Vision One simulado (somente com PORTAL_DEMO=true), no formato das respostas da API v3.0."""
from datetime import datetime, timedelta, timezone


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
         {"id": 3, "type": "fileSha1", "value": "3395856ce81f2b7382dee72602f798b642f14140"}]},
    {"id": "WB-DEMO-0002", "model": "Malware Download Detected", "severity": "critical", "score": 92,
     "status": "In Progress", "investigationStatus": "In Progress", "createdDateTime": _ts(3),
     "workbenchLink": "https://portal.xdr.trendmicro.com/", "indicators": [
         {"id": 1, "type": "domain", "value": "malware-test.example"},
         {"id": 2, "type": "hostname", "value": {"name": "NB-SUPORTE-12"}}]},
]


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
        return [{"agentGuid": "demo-1", "endpointName": {"value": "NB-SUPORTE-12"}, "osName": "Windows",
                 "productCode": "sao", "policyName": "Padrão"}]

    def sandbox_submit_url(self, url):
        return {"task_id": "demo-task-1", "id": "demo-task-1", "url": url}

    def sandbox_task(self, task_id):
        return {"id": task_id, "status": "succeeded", "resourceLocation": f"/v3.0/sandbox/analysisResults/{task_id}"}

    def sandbox_result(self, result_id):
        return {"id": result_id, "type": "url", "riskLevel": "high", "threatTypes": ["Phishing"],
                "detectionNames": ["HTML_PHISH.DEMO"], "analysisCompletionDateTime": _ts(0)}

    def sandbox_result_iocs(self, result_id):
        return [{"type": "ip", "ip": "203.0.113.50", "riskLevel": "high"}]
