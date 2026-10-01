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


def test_all_sources_failing_is_not_reported_as_clean():
    from app.services.reputation import consolidate
    errs = {k: "Vision One HTTP 403" for k in ("suspicious_objects", "exceptions", "detections", "workbench")}
    r = consolidate("ip", "57.144.164.196", {}, errs)
    assert r["reputacao"] == "Não foi possível consultar" and r["fontes"] == ["Nenhuma fonte respondeu"]
    r = consolidate("ip", "57.144.164.196", {"exceptions": {"items": []}}, {k: v for k, v in errs.items() if k != "exceptions"})
    assert r["reputacao"] == "Inconclusivo"
    assert consolidate("ip", "57.144.164.196", {}, {})["reputacao"] == "Sem registro no Vision One"


def test_finished_sandbox_result_drives_the_verdict():
    from app.services.reputation import consolidate
    errs = {k: "Vision One HTTP 403" for k in ("suspicious_objects", "exceptions", "detections")}
    sbr = {"risco": "high", "severidade": "Alta", "tipos_ameaca": ["Web Threat"], "deteccoes": ["VAN_WEB_THREAT.UMXX"],
           "concluido_em": "2026-10-01T18:30:58Z", "iocs": []}
    r = consolidate("url", "http://wrs49.winshipway.com/", {"workbench": {"items": []}, "sandbox_result": sbr}, errs)
    assert r["reputacao"] == "Malicioso" and r["risk_score"] == 90 and "Sandbox Analysis" in r["fontes"]
    assert r["severidade"] == "Alta" and "VAN_WEB_THREAT.UMXX" in r["tipo_ameaca"] and r["confianca"] == "Alta"
    clean = consolidate("url", "https://www.globo.com/", {"sandbox_result": {**sbr, "risco": "noRisk", "tipos_ameaca": [],
                                                                            "deteccoes": []}}, {})
    assert clean["reputacao"] == "Sem risco detectado (Sandbox)"
    only_submitted = consolidate("url", "https://x.com/", {"sandbox": {"task_id": "t1"}}, {})
    assert only_submitted["confianca"] == "Baixa"


def test_sandbox_rerun_reuses_previous_sources(monkeypatch):
    from app.services import reputation, visionone
    real = visionone.get_client()
    calls = {"det": 0}

    class Counting:
        def __getattr__(self, name):
            return getattr(real, name)

        def search_detections(self, *a, **kw):
            calls["det"] += 1
            return real.search_detections(*a, **kw)
    monkeypatch.setattr(visionone, "get_client", lambda: Counting())
    monkeypatch.setattr(reputation, "sandbox_status", lambda t: {"status": "succeeded", "resultado": {"risco": "noRisk"}})
    reputation.lookup("http://reuso.example/a", "url")
    assert calls["det"] == 1
    r = reputation.lookup("http://reuso.example/a", "url", sandbox_task="t-1")
    assert calls["det"] == 1 and "Sandbox Analysis" in r["fontes"]
