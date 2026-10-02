"""Ameaças > Trend inativo: máquinas do firewall cruzadas com o inventário de endpoints do Vision One."""
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.services import trend_coverage as tc

NOW = datetime(2026, 10, 2, 12, 0)


def _ts(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_index_prefers_name_then_ip_and_newest_contact():
    eps = [{"endpointName": "NB-01", "lastUsedIp": "10.0.0.5", "eppAgent": {"status": "on", "lastConnectedDateTime": _ts(0)}},
           {"endpointName": "OLD", "lastUsedIp": "10.0.0.5", "eppAgent": {"status": "off", "lastConnectedDateTime": _ts(30)}}]
    by_name, by_ip = tc.index(eps)
    assert by_name["nb-01"]["endpointName"] == "NB-01"
    assert by_ip["10.0.0.5"]["endpointName"] == "NB-01"  # o mesmo IP: vale a de contato mais recente


def test_run_classifies_machines(monkeypatch):
    machines = [
        {"ip": "10.0.0.1", "maquina": "NB-01.marista.local", "mac": "", "usuario": "ana", "sistema": "Windows", "tipo": "",
         "rede": "lan", "firewall": "FW1", "visto": "2026-10-02 11:00:00", "sessoes": 3},
        {"ip": "10.0.0.2", "maquina": "", "mac": "", "usuario": "", "sistema": "Windows", "tipo": "", "rede": "lan",
         "firewall": "FW1", "visto": "2026-10-02 11:00:00", "sessoes": 1},
        {"ip": "10.0.0.3", "maquina": "PC-SEM", "mac": "", "usuario": "", "sistema": "Windows", "tipo": "", "rede": "lan",
         "firewall": "FW1", "visto": "2026-10-02 11:00:00", "sessoes": 1},
        {"ip": "10.0.0.4", "maquina": "Galaxy", "mac": "", "usuario": "", "sistema": "Android", "tipo": "Android Phone",
         "rede": "wifi", "firewall": "FW1", "visto": "2026-10-02 11:00:00", "sessoes": 1},
    ]
    eps = [{"endpointName": "NB-01", "lastUsedIp": "10.9.9.9", "eppAgent": {"status": "on", "lastConnectedDateTime": _ts(0)}},
           {"endpointName": "PC-OFF", "lastUsedIp": "10.0.0.2", "lastLoggedOnUser": "MARISTA\\joao",
            "eppAgent": {"status": "off", "lastConnectedDateTime": _ts(12), "policyName": "Padrão"}}]

    class V1:
        def endpoints(self, max_items):
            return eps

        def search_endpoints(self, query, max_items=20):
            return []
    monkeypatch.setattr(tc, "machines_from_faz", lambda q: (machines, "teste", []))
    monkeypatch.setattr(tc.visionone, "get_client", lambda: V1())
    monkeypatch.setattr(tc.database, "cache_get", lambda k: None)
    monkeypatch.setattr(tc.database, "cache_set", lambda *a, **k: None)
    out = tc.run(tc.CoverageQuery(start=NOW - timedelta(hours=1), end=NOW))
    r = out["resumo"]
    assert (r["vistas"], r["computadores"], r["ativos"], r["inativos"], r["sem_trend"]) == (4, 3, 1, 1, 1)
    assert [x["estado"] for x in out["linhas"]] == ["desligado", "sem_trend"]
    off = out["linhas"][0]
    assert off["achado_por"] == "IP" and off["maquina"] == "PC-OFF" and off["usuario_trend"] == "MARISTA\\joao"


def test_api_trend_inactive_demo():
    with TestClient(app) as c:
        body = {"start": (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"), "end": NOW.strftime("%Y-%m-%dT%H:%M"),
                "devices": ["FG200FDEMO000001"]}
        r = c.post("/api/threats/trend-inactive", json=body)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["resumo"]["computadores"] and d["resumo"]["ativos"] and d["linhas"]
        assert {x["estado"] for x in d["linhas"]} <= {"desligado", "sem_contato", "sem_trend", "desconhecido"}
        assert all(x["firewall"] == "FW-BRASILIA" for x in d["linhas"])
        assert c.get(f"/api/export/{d['result_id']}.csv").status_code == 200


def test_machine_missing_from_list_is_looked_up_one_by_one(monkeypatch):
    """A lista não trouxe a máquina, mas o Endpoint Inventory acha pelo nome: não pode aparecer como sem Trend."""
    machines = [{"ip": "10.55.10.67", "maquina": "NA055PE0B2VCA", "mac": "e0:0a:f6:b4:10:d1", "usuario": "FELIPE.RSANTOS",
                 "sistema": "Windows", "tipo": "", "rede": "Rede_Adm", "firewall": "fw-br-al-maceio055",
                 "visto": "2026-10-02 12:34:00", "sessoes": 1}]
    queries = []

    class V1:
        def endpoints(self, max_items):
            return []

        def search_endpoints(self, query, max_items=20):
            queries.append(query)
            return [{"agentGuid": "f0518f89", "endpointName": {"value": "NA055PE0B2VCA"}, "ip": {"value": ["10.55.10.67"]}}]

        def endpoint_details(self, guid):
            return {"endpointName": "NA055PE0B2VCA", "lastUsedIp": "10.55.10.67",
                    "lastLoggedOnUser": "NA055PE0B2VCA\\felipe.rsantos",
                    "eppAgent": {"status": "on", "lastConnectedDateTime": _ts(0), "endpointGroup": "Workgroup"},
                    "edrSensor": {"connectivity": "connected", "lastConnectedDateTime": _ts(0)}}
    monkeypatch.setattr(tc, "machines_from_faz", lambda q: (machines, "teste", []))
    monkeypatch.setattr(tc.visionone, "get_client", lambda: V1())
    monkeypatch.setattr(tc.database, "cache_get", lambda k: None)
    monkeypatch.setattr(tc.database, "cache_set", lambda *a, **k: None)
    out = tc.run(tc.CoverageQuery(start=NOW - timedelta(hours=1), end=NOW, incluir_ativos=True))
    assert out["resumo"]["ativos"] == 1 and out["resumo"]["sem_trend"] == 0
    assert out["linhas"][0]["achado_por"].startswith("nome") and out["linhas"][0]["grupo"] == "Workgroup"
    assert "ip eq '10.55.10.67'" in queries[0] and "endpointName eq 'NA055PE0B2VCA'" in queries[0]
