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
