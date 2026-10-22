"""Aba Ameaças: alertas do Event Monitor (IOC/botnet) e ranking de ameaças dos logs."""
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import threats
from app.services.fortianalyzer import FazClient, FazError
from test_clients import FakeResp, FakeSession

NOW = datetime(2026, 10, 2, 12, 0)


def test_alerts_use_official_eventmgmt_path_and_page():
    pages = {0: [{"alertid": str(i)} for i in range(1000)], 1000: [{"alertid": "x"}]}

    def handler(method, url, body, kw):
        p = body["params"][0]
        assert body["method"] == "get" and p["url"] == "/eventmgmt/adom/root/alerts"
        assert p["time-range"] == {"start": "2026-10-01 00:00:00", "end": "2026-10-02 00:00:00"} and p["apiver"] == 3
        return FakeResp(200, {"result": {"data": pages[p["offset"]]}})
    c = FazClient("https://faz.local", "tok", session=FakeSession(handler))
    res = c.list_alerts("root", "2026-10-01 00:00:00", "2026-10-02 00:00:00", limit=4000)
    assert len(res["alerts"]) == 1001 and res["mais"] is False


def test_alerts_without_permission_raise():
    c = FazClient("https://faz.local", "tok", session=FakeSession(
        lambda *a: FakeResp(200, {"result": {"status": {"code": -11, "message": "No permission"}}})))
    with pytest.raises(FazError, match="sem permissão"):
        c.list_alerts("root", "2026-10-01 00:00:00", "2026-10-02 00:00:00")


@pytest.mark.parametrize("alert,expected", [
    ({"triggername": "Default-Compromised Host-Detection-IOC-By-Threat"}, True),
    ({"triggername": "Default-Botnet-Communication-Detection-By-Endpoint"}, True),
    ({"subject": "C&C server contacted"}, True),
    ({"triggername": "Default-Admin-Login-Failure"}, False),
])
def test_compromise_alert_detection(alert, expected):
    assert threats.is_compromise_alert(alert) is expected


def test_alert_fields_read_groupby_target_and_details():
    a = {"groupby1": "threat:Emotet", "groupby2": "user:maria.souza", "target": [{"name": "domain", "value": "c2.example"}]}
    assert threats._alert_fields(a) == {"usuario": "maria.souza", "ameaca": "Emotet", "dominio": "c2.example"}
    assert threats._alert_fields({"event_details": {"host_name": "x.example"}})["dominio"] == "x.example"
    assert threats._alert_time({"alerttime": int(NOW.timestamp())}) == "2026-10-02 12:00:00"


def test_inbound_ips_attack_points_to_the_attacked_machine():
    row = {"data_hora": "2026-10-02 10:00:00", "bloqueado": False, "acao_original": "detected", "usuario": "",
           "ip_origem": "185.1.1.1", "ip_destino": "10.1.1.5", "maquina": "", "destino": "10.1.1.5:443", "firewall": "FW",
           "log_original": {"attack": "Log4j", "severity": "critical", "direction": "incoming"}}
    t = threats.threat_row(row, "ips")
    assert t["afetado_ip"] == "10.1.1.5" and t["ameaca"] == "Log4j" and t["severidade"] == "critical"


def test_api_threats_demo(monkeypatch):
    with TestClient(app) as c:
        body = {"start": (NOW - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"), "end": NOW.strftime("%Y-%m-%dT%H:%M")}
        r = c.post("/api/threats", json=body)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["comprometidas"]["maquinas"] and set(d["fontes"]) == set(threats.SOURCES)
        assert d["fontes"]["botnet"]["filtro"].endswith('appcat~"Botnet"')
        assert d["fontes"]["phishing"]["filtro"] == 'catdesc~"Phishing"'
        assert d["ameacas"]["linhas"] and d["maquinas"] and d["graficos"]
        first = d["comprometidas"]["maquinas"][0]
        assert first["reconhecido"] is False  # sem ACK primeiro
        assert c.get(f"/api/export/{d['result_id']}.csv").status_code == 200
        assert c.get("/ameacas").status_code == 200


def test_missing_event_permission_keeps_the_log_ranking(monkeypatch):
    from app.demo.faz_demo import DemoFazClient

    def no_perm(self, *a, **k):
        raise FazError("/eventmgmt/adom/root/alerts: sem permissão para este recurso (perfil do administrador REST)")
    monkeypatch.setattr(DemoFazClient, "list_alerts", no_perm)
    q = threats.ThreatQuery(start=NOW - timedelta(hours=4), end=NOW)
    d = threats.run(q, use_cache=False)
    assert "Event Management" in d["comprometidas"]["erro"] and d["ameacas"]["linhas"]


def test_fortiview_top_threats_uses_official_path_and_polls():
    calls = []

    def handler(method, url, body, kw):
        p = body["params"][0]
        calls.append((body["method"], p["url"]))
        if body["method"] == "add":
            assert p["url"] == "/fortiview/adom/root/top-threats/run" and p["device"] == [{"devname": "All_Device"}]
            assert p["sort-by"] == [{"field": "threatweight", "order": "desc"}]
            return FakeResp(200, {"result": {"tid": 7}})
        done = len(calls) > 2
        return FakeResp(200, {"result": {"percentage": 100 if done else 40, "data": [{"threat": "x"}] if done else []}})
    c = FazClient("https://faz.local", "tok", session=FakeSession(handler))
    rows = c.fortiview("root", "top-threats", "2026-10-01 00:00:00", "2026-10-02 00:00:00", sort_by="threatweight")
    assert rows == [{"threat": "x"}] and calls[-1] == ("get", "/fortiview/adom/root/top-threats/run/7")


def test_top_threats_rows_and_country_map(monkeypatch):
    q = threats.ThreatQuery(start=NOW - timedelta(hours=4), end=NOW)
    d = threats.run(q, use_cache=False)
    t = d["top_threats"]["linhas"][0]
    assert {"ameaca", "categoria", "pontuacao", "incidentes", "bloqueados", "permitidos"} <= set(t)
    assert t["pontuacao"] >= d["top_threats"]["linhas"][-1]["pontuacao"]
    paises = {c["pais"]: c for c in d["mapa"]["paises"]}
    assert "Reserved" not in paises
    if "United States" in paises:
        assert paises["United States"]["mapa"] == "United States of America"


def test_inbound_attack_country_is_the_source():
    row = {"data_hora": "", "bloqueado": True, "usuario": "", "ip_origem": "1.2.3.4", "ip_destino": "10.0.0.1",
           "log_original": {"direction": "incoming", "srccountry": "China", "dstcountry": "Reserved"}}
    assert threats.threat_row(row, "ips")["pais"] == "China"
    row["log_original"] = {"dstcountry": "Russian Federation"}
    assert threats.threat_row(row, "malicioso")["pais"] == "Russian Federation"


def test_world_map_names_cover_the_aliases():
    import json
    from app.config import BASE_DIR
    names = {p["n"] for p in json.loads((BASE_DIR / "frontend/static/vendor/worldmap/world-110m.json").read_text())["paises"]}
    assert set(threats.MAP_NAMES.values()) <= names


def test_device_coordinates_from_dvmdb():
    data = [{"name": "fw-a", "sn": "A", "latitude": "-15.79", "longitude": "-47.88"},
            {"name": "fw-b", "sn": "B", "latitude": "0.000000", "longitude": "0.000000"},
            {"name": "fw-c", "sn": "C", "latitude": "abc", "longitude": "999"}]
    c = FazClient("https://faz.local", "tok", session=FakeSession(
        lambda *a: FakeResp(200, {"result": [{"data": data, "status": {"code": 0}}]})))
    devs = {d["name"]: d for d in c.list_devices("root")}
    assert (devs["fw-a"]["lat"], devs["fw-a"]["lon"]) == (-15.79, -47.88)
    assert devs["fw-b"]["lat"] is None and devs["fw-c"]["lat"] is None and devs["fw-c"]["lon"] is None


def test_api_threats_live_demo():
    with TestClient(app) as c:
        body = {"start": (NOW - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S"), "end": NOW.strftime("%Y-%m-%dT%H:%M:%S")}
        r = c.post("/api/threats/live?first=true", json=body)
        assert r.status_code == 200, r.text
        d = r.json()
        ev = d["eventos"]
        assert ev and len(ev) <= threats.LIVE_MAX and not d["erros"]
        assert len({e["id"] for e in ev}) == len(ev)
        assert {"entrada", "pais", "mapa", "firewall", "bloqueado", "severidade"} <= set(ev[0])
        assert any(e["entrada"] for e in ev) and any(e["pais"] for e in ev)
        # mesma janela de novo: mesmos ids (a tela usa o id para não repetir o arco)
        again = c.post("/api/threats/live", json=body).json()["eventos"]
        assert {e["id"] for e in again} == {e["id"] for e in ev}
        before = len(c.get("/api/history?type=ameacas-tempo-real").json())
        c.post("/api/threats/live", json=body)  # as repetições não entram no histórico
        assert len(c.get("/api/history?type=ameacas-tempo-real").json()) == before >= 1


def test_api_threats_live_one_source_at_a_time():
    with TestClient(app) as c:
        body = {"start": (NOW - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S"), "end": NOW.strftime("%Y-%m-%dT%H:%M:%S")}
        d = c.post("/api/threats/live", json={**body, "fontes": ["ips"]}).json()
        assert d["fontes"] == ["ips"] and d["eventos"] and {e["fonte"] for e in d["eventos"]} == {"ips"}
        assert c.post("/api/threats/live", json={**body, "fontes": ["x"]}).status_code == 422


def test_ips_search_uses_faz_attack_logtype_and_falls_back():
    seen = []

    def handler(method, url, body, kw):
        p = body["params"][0]
        if body["method"] == "add":
            seen.append(p["logtype"])
            if p["logtype"] == "attack" and fail_attack:
                return FakeResp(200, {"result": [{"status": {"code": -3, "message": "invalid logtype"}}]})
            return FakeResp(200, {"result": {"tid": 7}})
        if body["method"] == "get":
            return FakeResp(200, {"result": {"percentage": 100, "data": [{"attack": "x"}], "total-count": 1}})
        return FakeResp(200, {"result": {}})
    fail_attack = False
    c = FazClient("https://faz.local", "tok", session=FakeSession(handler))
    assert c.search_logs("root", "ips", "a", "b", limit=5)["returned"] == 1 and seen == ["attack"]
    fail_attack, seen[:] = True, []
    c = FazClient("https://faz.local", "tok", session=FakeSession(handler))
    assert c.search_logs("root", "ips", "a", "b", limit=5)["returned"] == 1 and seen == ["attack", "ips"]
    seen.clear()
    c.search_logs("root", "ips", "a", "b", limit=5)
    assert seen == ["ips"]  # lembra que esta versão só aceita "ips"


def test_traffic_with_threat_feeds_the_map():
    with TestClient(app) as c:
        body = {"start": (NOW - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"), "end": NOW.strftime("%Y-%m-%dT%H:%M")}
        d = c.post("/api/threats", json=body).json()
        assert d["fontes"]["trafego"]["filtro"].endswith("crscore>0") and d["fontes"]["trafego"]["lidos"]
        rows = [r for r in threats._read_sources(threats.ThreatQuery(**body), 200, ["trafego"])[0]]
        assert rows and all(r["fonte"] == "trafego" and r["ameaca"] for r in rows)
        inbound = [r for r in rows if r["entrada"]]
        assert inbound and all(r["pais"] for r in inbound)


def _traffic(src, dst, srccountry="Reserved", dstcountry="United States"):
    return {"data_hora": "2026-10-02 10:00:00", "bloqueado": True, "acao_original": "deny", "usuario": "",
            "ip_origem": src, "ip_destino": dst, "maquina": "", "destino": f"{dst}:443", "firewall": "FW",
            "log_original": {"threats": ["failed-connection"], "srccountry": srccountry, "dstcountry": dstcountry}}


@pytest.mark.parametrize("src,dst,sc,dc,expected", [
    ("10.2.3.4", "142.251.157.4", "Reserved", "United States", "10.2.3.4"),      # saída: máquina interna
    ("118.193.56.184", "10.2.3.4", "Hong Kong", "Reserved", "10.2.3.4"),         # entrada: alvo interno
    ("118.193.56.184", "172.217.1.1", "Hong Kong", "United States", ""),        # nenhum lado interno
    ("172.217.1.1", "10.9.9.9", "Reserved", "Reserved", "10.9.9.9"),            # origem pública sem país
])
def test_affected_machine_is_never_an_external_address(src, dst, sc, dc, expected):
    t = threats.threat_row(_traffic(src, dst, sc, dc), "trafego")
    assert t["afetado_ip"] == expected
    hosts = threats._hosts([t])
    assert [h["ip"] for h in hosts] == ([expected] if expected else [])


def test_events_are_kept_7_days_and_only_the_new_part_is_searched(monkeypatch):
    calls = []

    def fake(lq, *a, **k):
        calls.append((lq.logtype, lq.faz_time("start"), lq.faz_time("end")))
        when = (lq.end - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
        row = {"data_hora": when, "bloqueado": True, "acao_original": "blocked", "usuario": "", "ip_origem": "10.0.0.9",
               "ip_destino": "8.8.8.8", "maquina": "", "destino": "8.8.8.8:53", "firewall": "FW-KEEP",
               "log_original": {"attack": "X", "virus": "Y", "threats": ["t"]}}
        return {"total": 1, "returned": 1, "rows": [row], "mais": False}
    monkeypatch.setattr(threats, "run_query", fake)
    monkeypatch.setattr(threats, "_search", lambda lq, expr: fake(lq))
    end = datetime(2026, 10, 20, 12, 0)
    first = threats.ThreatQuery(start=end - timedelta(days=1), end=end, devname="keep-test")
    rows, fontes = threats._read_sources(first, 100, keep=True, reuse=True)
    assert len(rows) == len(threats.SOURCES) and not any(f.get("guardados") for f in fontes.values())
    assert all(c[1] == "2026-10-19 12:00:00" for c in calls)

    calls.clear()  # uma hora depois: só busca a última hora (mais a margem de logs atrasados)
    later = threats.ThreatQuery(start=end - timedelta(days=1) + timedelta(hours=1), end=end + timedelta(hours=1), devname="keep-test")
    rows, fontes = threats._read_sources(later, 100, keep=True, reuse=True)
    assert calls and all(c[1] == "2026-10-20 11:45:00" for c in calls)
    assert all(f["guardados"] == 1 for f in fontes.values()) and len(rows) == 2 * len(threats.SOURCES)

    calls.clear()  # período já coberto: nada vai ao FortiAnalyzer
    rows, fontes = threats._read_sources(first, 100, keep=True, reuse=True)
    assert not calls and len(rows) == len(threats.SOURCES)

    calls.clear()  # período começa antes do guardado ou "buscar de novo": consulta inteira
    rows, _ = threats._read_sources(first, 100, keep=True, reuse=False)
    assert all(c[1] == "2026-10-19 12:00:00" for c in calls) and len(calls) == len(threats.SOURCES)
