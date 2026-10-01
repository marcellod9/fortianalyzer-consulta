import pytest

from app.services import reputation


@pytest.mark.parametrize("raw,expected", [
    ("8.8.8.8", ("ip", "8.8.8.8")),
    ("Google.com.", ("domain", "google.com")),
    ("https://exemplo.com/a?b=1", ("url", "https://exemplo.com/a?b=1")),
    ("exemplo.com/path", ("url", "http://exemplo.com/path")),
])
def test_parse_indicator(raw, expected):
    assert reputation.parse_indicator(raw) == expected


@pytest.mark.parametrize("raw", ["", "not a domain", "ftp://x.com", 'http://x.com/"><script>', "999.1.1.1x"])
def test_parse_indicator_rejects(raw):
    with pytest.raises(reputation.IndicatorError):
        reputation.parse_indicator(raw)


def test_lookup_consolidates_demo_sources():
    r = reputation.lookup("malware-test.example")
    assert r["reputacao"] == "Malicioso" and r["risk_score"] >= 80
    assert {"Suspicious Objects", "Workbench"} <= set(r["fontes"])
    assert r["confianca"] == "Alta" and r["erros"] == {}
    clean = reputation.lookup("google.com")
    assert clean["reputacao"] == "Sem registro no Vision One" and clean["risk_score"] == 0
    trusted = reputation.lookup("maristabrasil.org")
    assert trusted["reputacao"] == "Confiável (exceção)"


def test_subdomain_matches_suspicious_domain():
    objs = [{"type": "domain", "domain": "bad.com"}, {"type": "url", "url": "http://evil.org/x"}]
    assert len(reputation._match_objects(objs, "domain", "cdn.bad.com")) == 1
    assert len(reputation._match_objects(objs, "domain", "evil.org")) == 1
    assert len(reputation._match_objects(objs, "url", "https://bad.com/login")) == 1
    assert reputation._match_objects(objs, "domain", "notbad.com") == []
