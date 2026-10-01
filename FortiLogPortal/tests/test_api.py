"""Fluxo completo pela API em modo demonstração."""
import pytest
from fastapi.testclient import TestClient

from app.main import app

H = {"X-Portal-User": "teste.sustentacao"}
PERIOD = {"start": "2026-10-01T08:00", "end": "2026-10-01T12:00"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.mark.parametrize("path", ["/", "/logs", "/reputacao", "/correlacao", "/historico", "/configuracao"])
def test_pages_render(client, path):
    r = client.get(path)
    assert r.status_code == 200 and "FortiLogPortal" in r.text


def test_old_blocks_page_redirects_to_logs(client):
    r = client.get("/bloqueios", follow_redirects=False)
    assert r.status_code == 307 and r.headers["location"] == "/logs"


def test_blocked_logs_search_and_export(client):
    r = client.post("/api/faz/logs", json={**PERIOD, "logtype": "webfilter", "only_blocked": True, "limit": 50,
                                         "filters": [{"field": "user", "op": "=", "value": "joao.silva"}]}, headers=H)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["rows"] and all(x["bloqueado"] for x in d["rows"])
    assert all(x["usuario"] == "joao.silva" for x in d["rows"])
    for fmt, magic in (("csv", b"\xef\xbb\xbf"), ("xlsx", b"PK"), ("pdf", b"%PDF")):
        e = client.get(f"/api/export/{d['result_id']}.{fmt}", headers=H)
        assert e.status_code == 200 and e.content.startswith(magic)


def test_logs_search_validation_message(client):
    r = client.post("/api/faz/logs", json={**PERIOD, "srcip": "999.1.1.1"})
    assert r.status_code == 422 and "IP" in r.json()["detail"]
    r = client.post("/api/faz/logs", json={**PERIOD, "logtype": "webfilter", "hostname": "facebook.com"}, headers=H)
    assert r.status_code == 200 and r.json()["filter"] == 'hostname~"facebook.com"'


def test_reputation_correlation_history_dashboard(client):
    r = client.post("/api/v1/reputation", json={"indicator": "45.33.32.156"}, headers=H)
    assert r.status_code == 200 and r.json()["reputacao"] == "Suspeito"
    assert client.post("/api/v1/reputation", json={"indicator": "x y"}).status_code == 400
    c = client.post("/api/correlation", json={"indicator": "malware-test.example"}, headers=H)
    assert c.status_code == 200 and any("MALICIOSO" in line for line in c.json()["analise"])
    hist = client.get("/api/history").json()
    assert {"logs", "reputacao", "correlacao"} <= {h["query_type"] for h in hist}
    assert any(h["username"] == "teste.sustentacao" for h in hist)
    assert client.get("/api/export/history.xlsx").content.startswith(b"PK")
    dash = client.get("/api/dashboard/faz?hours=24").json()
    assert dash["sites_mais_bloqueados"] and dash["regras_mais_acionadas"]
    local = client.get("/api/dashboard/local").json()
    assert local["estatisticas"]["total_consultas"] > 0
    assert local["visionone"]["ips_maliciosos"][0]["indicator"] == "45.33.32.156"


def test_status_never_exposes_tokens(client):
    s = client.get("/api/status").json()
    assert "faz_token" not in s["config"] and "v1_token" not in s["config"]
    assert client.post("/api/status/test/faz").json()["ok"] is True


def test_export_unknown_result(client):
    assert client.get("/api/export/deadbeef.csv").status_code == 404
    assert client.get("/api/export/deadbeef.exe").status_code == 400


def test_inventory_falls_back_without_dvmdb_permission(client, monkeypatch):
    from app.routers import api
    from app.services.fortianalyzer import FazError

    class NoPerm:
        def list_adoms(self):
            raise FazError("/dvmdb/adom: sem permissão para este recurso (perfil do administrador REST)")

        def list_devices(self, adom):
            raise FazError(f"/dvmdb/adom/{adom}/device: sem permissão para este recurso")

    monkeypatch.setattr(api, "faz", lambda: NoPerm())
    api.database.cache_purge(all_entries=True)
    r = client.get("/api/faz/adoms")
    assert r.status_code == 200 and r.json()[0]["name"] == api.settings.faz_default_adom
    assert client.get("/api/faz/adoms/root/devices").json() == []


def test_live_logs_overlapping_windows_and_history(client):
    """Tempo real: janelas que se sobrepõem trazem os mesmos eventos; só a 1ª atualização vai ao histórico."""
    base = {"logtype": "traffic", "limit": 1000}
    a = client.post("/api/faz/logs/live?first=true", json={**base, "start": "2026-10-01T10:00:00", "end": "2026-10-01T10:05:00"}, headers=H)
    b = client.post("/api/faz/logs/live", json={**base, "start": "2026-10-01T10:02:00", "end": "2026-10-01T10:07:00"}, headers=H)
    assert a.status_code == 200 and b.status_code == 200, a.text + b.text
    key = lambda r: (r["data_hora"], r["ip_origem"], r["porta_origem"])  # noqa: E731
    in_both = {key(r) for r in a.json()["rows"] if r["data_hora"] >= "2026-10-01 10:02:00"}
    assert in_both and in_both <= {key(r) for r in b.json()["rows"]}
    assert all(not r.get("cache") for r in (a.json(), b.json()))
    hist = [h for h in client.get("/api/history", params={"type": "logs-tempo-real"}).json()]
    assert len([h for h in hist if h["query_type"] == "logs-tempo-real"]) == 1


def test_live_logs_store_for_export(client):
    rows = client.post("/api/faz/logs/live", json={"logtype": "webfilter", "start": "2026-10-01T10:00:00",
                                                   "end": "2026-10-01T10:05:00"}, headers=H).json()["rows"]
    r = client.post("/api/faz/logs/store", json={"logtype": "webfilter", "filter": "", "rows": rows})
    assert r.status_code == 200
    assert client.get(f"/api/export/{r.json()['result_id']}.csv", headers=H).status_code == 200
