"""Situação da máquina no Vision One: inventário de endpoints, agente e alertas do Workbench."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import database
from app.main import app
from app.services import machine
from app.services.visionone import V1Error

H = {"X-Portal-User": "teste.sustentacao"}


def ts(days_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def inv(name="NB-ADM-01", ip="10.1.2.3", guid="g-1", user="MARISTA\\joao.silva"):
    return {"agentGuid": guid, "endpointName": {"updatedDateTime": ts(), "value": name},
            "ip": {"updatedDateTime": ts(), "value": [ip]}, "macAddress": {"updatedDateTime": ts(), "value": ["AA:BB:CC:00:11:22"]},
            "loginAccount": {"updatedDateTime": ts(), "value": [user]}, "osName": "Windows",
            "osDescription": "Windows 11 Pro", "productCode": "xes", "installedProductCodes": ["sao"],
            "componentVersion": "latestVersion", "policyName": "Padrão"}


def detail(status="on", days=0.01, isolation="off", connectivity="connected"):
    return {"isolationStatus": isolation, "lastLoggedOnUser": "MARISTA\\joao.silva",
            "eppAgent": {"status": status, "lastConnectedDateTime": ts(days), "policyName": "Padrão"},
            "edrSensor": {"connectivity": connectivity, "status": "enabled", "lastConnectedDateTime": ts(days)}}


def alert(aid, entities, status="Open", severity="high", days=1):
    return {"id": aid, "model": f"Modelo {aid}", "severity": severity, "score": 70, "status": status,
            "createdDateTime": ts(days), "workbenchLink": "https://portal.xdr.trendmicro.com/x",
            "impactScope": {"entities": entities}, "indicators": []}


class FakeV1:
    def __init__(self, endpoints=(), details=None, alerts=(), inv_error=None, det_error=None, alerts_error=None):
        self.eps, self.det, self.alerts = list(endpoints), details or {}, list(alerts)
        self.inv_error, self.det_error, self.alerts_error = inv_error, det_error, alerts_error
        self.queries = []

    def search_endpoints(self, query, max_items=20):
        self.queries.append(query)
        if self.inv_error:
            raise self.inv_error
        return self.eps

    def endpoint_details(self, guid):
        if self.det_error:
            raise self.det_error
        return self.det.get(guid, detail())

    def workbench_alerts(self, start, end, max_items=500, tmv1_filter=None):
        if self.alerts_error:
            raise self.alerts_error
        return self.alerts


@pytest.fixture
def fake(monkeypatch):
    database.cache_purge(all_entries=True)

    def use(**kw):
        c = FakeV1(**kw)
        monkeypatch.setattr("app.services.visionone.get_client", lambda: c)
        return c
    return use


def test_query_uses_official_syntax_and_name_variants():
    assert machine.build_query("10.1.2.3", None) == "ip eq '10.1.2.3'"
    assert machine.build_query("10.1.2.3", "nb-adm-01.marista.local") == (
        "ip eq '10.1.2.3' or endpointName eq 'nb-adm-01.marista.local' or endpointName eq 'NB-ADM-01.MARISTA.LOCAL'"
        " or endpointName eq 'nb-adm-01' or endpointName eq 'NB-ADM-01'")
    assert machine.norm_user("MARISTA\\Joao.Silva") == machine.norm_user("joao.silva@marista.org") == "joao.silva"


def test_invalid_input(fake):
    fake()
    with pytest.raises(ValueError, match="IP"):
        machine.machine_status("10.1.2.300")
    with pytest.raises(ValueError, match="Informe"):
        machine.machine_status()
    with pytest.raises(ValueError, match="Nome"):
        machine.machine_status(nome="Maria's iPhone")


def test_name_with_quote_is_left_out_of_the_query(fake):
    c = fake(endpoints=[inv()])
    r = machine.machine_status("10.1.2.3", "Maria's iPhone", "convidado (wifi)")
    assert c.queries == ["ip eq '10.1.2.3'"]
    assert any("só pelo IP" in a for a in r["avisos"]) and any("só pela máquina" in a for a in r["avisos"])
    assert r["consulta"]["usuario"] is None
    with pytest.raises(ValueError, match="Usuário"):
        machine.machine_status(usuario="convidado (wifi)")


def test_edr_only_endpoint_and_missing_details(fake):
    edr_only = {"edrSensor": {"connectivity": "connected", "status": "enabled", "lastConnectedDateTime": ts(0.1)}}
    fake(endpoints=[inv()], details={"g-1": edr_only})
    e = machine.machine_status("10.1.2.3")["endpoints"][0]
    assert e["agente"]["estado"] == "ativo" and e["agente"]["protecao"] is None and e["agente"]["sensor"] == "Conectado"
    fake(endpoints=[inv()], det_error=V1Error("Vision One HTTP 404: recurso não encontrado", 404))
    e = machine.machine_status("10.1.2.3")["endpoints"][0]
    assert e["erro"].startswith("O Vision One não devolveu os detalhes") and e["agente"]["estado"] == "desconhecido"


def test_active_agent_and_alerts_for_machine_and_user(fake):
    fake(endpoints=[inv()], alerts=[
        alert("WB-1", [{"entityType": "host", "entityValue": {"name": "NB-ADM-01.marista.local", "ips": [], "guid": ""}}],
              severity="medium"),
        alert("WB-2", [{"entityType": "account", "entityValue": "MARISTA\\Maria.Souza"}], severity="critical", days=2),
        alert("WB-3", [{"entityType": "emailAddress", "entityValue": "maria.souza@marista.org"}], status="Closed"),
        alert("WB-4", [{"entityType": "host", "entityValue": {"name": "OUTRA", "ips": ["10.9.9.9"], "guid": "g-9"}}]),
    ])
    r = machine.machine_status("10.1.2.3", "NB-ADM-01", "maria.souza")
    e = r["endpoints"][0]
    assert e["nome"] == "NB-ADM-01" and e["encontrado_por"] == ["ip", "nome"]
    assert e["agente"]["estado"] == "ativo" and e["agente"]["sensor"] == "Conectado" and not e["isolada"]
    assert e["macs"] == ["aa:bb:cc:00:11:22"] and "Sensor XDR (Endpoint Sensor)" in e["produtos"]
    assert [a["id"] for a in r["alertas"]] == ["WB-2", "WB-1"]  # mais grave primeiro
    assert r["alertas"][0]["motivos"] == ["usuário MARISTA\\Maria.Souza"]
    assert r["alertas"][1]["motivos"] == ["máquina NB-ADM-01.marista.local"]
    assert r["total_encerrados"] == 1 and r["alertas_encerrados"][0]["motivos"] == ["e-mail maria.souza@marista.org"]
    assert r["status"] == "alerta" and "WB-2" in r["orientacao"]


def test_alert_matched_by_agent_guid_or_ip(fake):
    fake(endpoints=[inv(guid="g-7")], alerts=[
        alert("WB-G", [{"entityType": "host", "entityValue": {"name": "nome-antigo", "ips": [], "guid": "g-7"}}]),
        alert("WB-IP", [{"entityType": "host", "entityValue": {"name": "outro-nome", "ips": ["10.1.2.3"]}}]),
    ])
    r = machine.machine_status("10.1.2.3")
    assert {a["id"]: a["motivos"] for a in r["alertas"]} == {"WB-G": ["máquina nome-antigo"], "WB-IP": ["IP 10.1.2.3"]}


def test_agent_ok_without_alerts(fake):
    fake(endpoints=[inv()])
    r = machine.machine_status("10.1.2.3")
    assert r["status"] == "ok" and r["alertas"] == [] and "Agente Trend ativo" in r["titulo"]


@pytest.mark.parametrize("det,estado,titulo", [
    (detail(status="off", days=3, connectivity="disconnected"), "desligado", "Agente Trend desligado ou offline"),
    (detail(status="on", days=12), "sem_contato", "Agente Trend sem comunicação há 12 dias"),
])
def test_agent_problems(fake, det, estado, titulo):
    fake(endpoints=[inv()], details={"g-1": det})
    r = machine.machine_status("10.1.2.3")
    assert r["endpoints"][0]["agente"]["estado"] == estado
    assert r["status"] == "atencao" and r["titulo"] == titulo and "reiniciar" in r["orientacao"]


def test_isolated_machine(fake):
    fake(endpoints=[inv()], details={"g-1": detail(isolation="on")})
    r = machine.machine_status("10.1.2.3")
    assert r["endpoints"][0]["isolada"] and r["status"] == "isolada" and "não é o firewall" in r["orientacao"]


def test_isolation_comes_before_open_alerts(fake):
    fake(endpoints=[inv()], details={"g-1": detail(isolation="on")},
         alerts=[alert("WB-9", [{"entityType": "host", "entityValue": {"name": "NB-ADM-01", "ips": [], "guid": "g-1"}}])])
    r = machine.machine_status("10.1.2.3")
    assert r["status"] == "isolada" and "WB-9" in r["resumo"] and "WB-9" in r["orientacao"]


def test_no_agent_found(fake):
    fake()
    r = machine.machine_status("10.1.2.3", "Galaxy-S21")
    assert r["status"] == "sem_agente" and "DHCP" in r["orientacao"]


def test_ip_now_with_another_machine(fake):
    fake(endpoints=[inv(name="PC-LAB-07")])
    r = machine.machine_status("10.1.2.3", "NB-ADM-01")
    assert any("está com PC-LAB-07, não com NB-ADM-01" in a for a in r["avisos"])


def test_inventory_permission_error_keeps_alerts(fake):
    fake(inv_error=V1Error("Vision One HTTP 403: a função da chave de API não tem permissão", 403),
         alerts=[alert("WB-U", [{"entityType": "account", "entityValue": "joao.silva"}])])
    r = machine.machine_status("10.1.2.3", usuario="joao.silva")
    assert "Endpoint Inventory" in r["erros"]["inventario"]
    assert [a["id"] for a in r["alertas"]] == ["WB-U"] and r["status"] == "alerta"


def test_details_error_still_shows_machine(fake):
    fake(endpoints=[inv()], det_error=V1Error("Vision One HTTP 403: sem permissão", 403))
    r = machine.machine_status("10.1.2.3")
    e = r["endpoints"][0]
    assert e["agente"]["estado"] == "desconhecido" and "Endpoint Inventory" in e["erro"] and r["status"] == "info"


def test_everything_failing_is_an_error(fake):
    fake(inv_error=V1Error("falhou inventário", 500), alerts_error=V1Error("falhou alertas", 500))
    with pytest.raises(V1Error, match="inventário.*alertas"):
        machine.machine_status("10.1.2.3")


def test_user_only_lists_user_alerts(fake):
    c = fake(alerts=[alert("WB-U", [{"entityType": "account", "entityValue": "MARISTA\\ana.lima"}], status="Closed")])
    r = machine.machine_status(usuario="ana.lima")
    assert c.queries == [] and r["status"] == "ok" and r["total_encerrados"] == 1


def test_alerts_are_cached_between_lookups(fake):
    c = fake(endpoints=[inv()], alerts=[alert("WB-1", [{"entityType": "account", "entityValue": "joao.silva"}])])
    machine.machine_status("10.1.2.3", usuario="joao.silva")
    c.alerts = []
    assert machine.machine_status("10.1.2.3", usuario="joao.silva")["alertas_cache"]
    assert machine.machine_status("10.1.2.3", usuario="joao.silva", refresh=True)["alertas"] == []


def test_api_in_demo_mode():
    database.cache_purge(all_entries=True)
    with TestClient(app) as client:
        r = client.get("/api/v1/machine", params={"ip": "10.10.12.34", "usuario": "maria.souza"}, headers=H)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["endpoints"][0]["nome"] == "NB-SUPORTE-12"
        assert {a["id"] for a in d["alertas"]} == {"WB-DEMO-0001", "WB-DEMO-0002"}
        assert client.get("/api/v1/machine", params={"ip": "x"}, headers=H).status_code == 400
        assert client.get("/api/v1/machine", headers=H).status_code == 400
        hist = client.get("/api/history", params={"type": "maquina"}).json()
        ok = [h for h in hist if h["status"] == "ok"]
        assert ok and ok[0]["term"] == "10.10.12.34 · maria.souza" and "2 alerta(s)" in ok[0]["summary"]
        assert {h["status"] for h in hist} == {"ok", "invalida"}
