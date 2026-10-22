"""Categoria FortiGuard de qualquer site pelo FortiGate (rating-lookup), com os logs do FAZ como reserva."""
from app.services import fortigate, reputation


def test_parse_rating_accepts_list_dict_and_id_only():
    assert fortigate.parse_rating({"results": [{"url": "x.com", "category_id": 26, "category_desc": "Malicious Websites"}]}) \
        == {"categoria": "Malicious Websites", "categoria_id": 26}
    assert fortigate.parse_rating({"results": {"category": "Shopping"}})["categoria"] == "Shopping"
    assert fortigate.parse_rating({"results": [{"category": 41}]}) == {"categoria": None, "categoria_id": 41}
    assert fortigate.parse_rating({"results": []}) == {"categoria": None, "categoria_id": None}


def test_fortigate_rating_is_used_for_sites_never_accessed(monkeypatch):
    monkeypatch.setattr(fortigate, "configured", lambda: True)
    monkeypatch.setattr(fortigate, "rating_lookup", lambda host: {"categoria": "Phishing", "categoria_id": 59})
    monkeypatch.setattr(reputation, "fortiguard_from_logs", lambda host: (_ for _ in ()).throw(AssertionError("logs")))
    monkeypatch.setattr(reputation.database, "cache_get", lambda k: None)
    monkeypatch.setattr(reputation.database, "cache_set", lambda *a, **k: None)
    fg = reputation._fortiguard("url", "http://wrs49.winshipway.com/", None, True)
    assert fg["categoria"] == "Phishing" and fg["origem"] == "fortiguard"


def test_fortigate_failure_falls_back_to_logs(monkeypatch):
    def fail(host):
        raise fortigate.FgtError("FortiGate recusou o token (HTTP 401).")
    monkeypatch.setattr(fortigate, "configured", lambda: True)
    monkeypatch.setattr(fortigate, "rating_lookup", fail)
    monkeypatch.setattr(reputation.database, "cache_get", lambda k: None)
    monkeypatch.setattr(reputation, "fortiguard_from_logs",
                        lambda host: {"categoria": "Shopping", "origem": "logs", "visto_em": None, "erro": None})
    fg = reputation._fortiguard("domain", "loja.example", None, True)
    assert fg["categoria"] == "Shopping" and "401" in fg["aviso"]
    assert reputation._fortiguard("ip", "8.8.8.8", None, True) is None


def test_lookup_shows_fortiguard_category_in_verdict(monkeypatch):
    monkeypatch.setattr(fortigate, "configured", lambda: True)
    monkeypatch.setattr(fortigate, "rating_lookup", lambda host: {"categoria": "Malicious Websites", "categoria_id": 26})
    r = reputation.lookup("nunca-acessado.example")
    assert r["fortiguard"]["categoria"] == "Malicious Websites" and r["fortiguard"]["risco"] == "alto"
    assert "Malicious Websites (FortiGuard)" in r["categoria"]


def test_rating_through_fortianalyzer_proxy(monkeypatch):
    from app.services import fortianalyzer

    class Faz:
        def list_devices(self, adom):
            return [{"name": "fw-br-df-aguasclaras030"}]

        def proxy_fortigate(self, adom, device, resource):
            assert device == "fw-br-df-aguasclaras030" and resource.endswith("rating-lookup?url=wrs49.winshipway.com")
            return {"results": [{"category_desc": "Phishing", "category_id": 59}]}
    monkeypatch.setattr(fortianalyzer, "get_client", lambda: Faz())
    monkeypatch.setattr(fortigate.settings, "faz_rating_device", "")
    r = fortigate.rating_via_faz("wrs49.winshipway.com")
    assert r["categoria"] == "Phishing" and r["via"] == "FortiAnalyzer > fw-br-df-aguasclaras030"


def test_proxy_refused_is_not_retried_for_an_hour(monkeypatch):
    from app.services import fortianalyzer
    calls = []

    class Faz:
        def list_devices(self, adom):
            return [{"name": "fw1"}]

        def proxy_fortigate(self, adom, device, resource):
            calls.append(1)
            raise fortianalyzer.FazError("sys/proxy/json: sem permissão para este recurso")
    monkeypatch.setattr(fortianalyzer, "get_client", lambda: Faz())
    monkeypatch.setattr(fortigate.settings, "demo", False)
    monkeypatch.setattr(fortigate.settings, "faz_url", "https://faz")
    monkeypatch.setattr(fortigate.settings, "faz_token", "x")
    fortigate.database.cache_delete(fortigate.PROXY_OFF_KEY)
    assert fortigate.proxy_available()
    try:
        fortigate.rating_via_faz("a.example")
    except fortigate.FgtError as e:
        assert "não repassou" in str(e)
    assert not fortigate.proxy_available() and calls == [1]
    fortigate.database.cache_delete(fortigate.PROXY_OFF_KEY)


def test_faz_proxy_unwraps_device_response():
    from app.services.fortianalyzer import FazClient

    class C(FazClient):
        def __init__(self):
            self.source = "faz"

        def call(self, method, url, **params):
            assert method == "exec" and url == "/sys/proxy/json"
            assert params["data"]["target"] == ["adom/root/device/fw1"]
            return [{"target": "fw1", "status": {"code": 0}, "response": {"results": {"category": "Shopping"}}}]
    assert C().proxy_fortigate("root", "fw1", "/api/v2/monitor/utm/rating-lookup?url=x")["results"]["category"] == "Shopping"
