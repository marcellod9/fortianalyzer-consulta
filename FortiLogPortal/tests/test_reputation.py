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


def test_lookup_uses_fortiguard_and_not_vision_one_iocs(monkeypatch):
    from app.services import visionone

    class NoIoc:
        def __getattr__(self, name):
            raise AssertionError(f"a reputação não consulta mais o Vision One ({name})")
    monkeypatch.setattr(visionone, "get_client", lambda: NoIoc())
    r = reputation.lookup("malware-test.example")
    assert r["reputacao"] == "Malicioso" and r["fontes"] == ["FortiGuard (categoria do site)"] and r["erros"] == {}
    clean = reputation.lookup("google.com", fortiguard_from_faz=False)
    assert clean["reputacao"] == "Sem categoria encontrada" and clean["risk_score"] == 0
    assert clean["fontes"] == ["FortiGuard (sem categoria)"]


def test_finished_sandbox_result_drives_the_verdict():
    from app.services.reputation import consolidate
    sbr = {"risco": "high", "severidade": "Alta", "tipos_ameaca": ["Web Threat"], "deteccoes": ["VAN_WEB_THREAT.UMXX"],
           "concluido_em": "2026-10-01T18:30:58Z", "iocs": []}
    r = consolidate("url", "http://wrs49.winshipway.com/", {"sandbox_result": sbr}, {})
    assert r["reputacao"] == "Malicioso" and r["risk_score"] == 90 and "Sandbox Analysis" in r["fontes"]
    assert r["severidade"] == "Alta" and "VAN_WEB_THREAT.UMXX" in r["tipo_ameaca"] and r["confianca"] == "Alta"
    clean = consolidate("url", "https://www.globo.com/", {"sandbox_result": {**sbr, "risco": "noRisk", "tipos_ameaca": [],
                                                                            "deteccoes": []}}, {})
    assert clean["reputacao"] == "Sem risco detectado (Sandbox)"
    only_submitted = consolidate("url", "https://x.com/", {"sandbox": {"task_id": "t1"}}, {})
    assert only_submitted["confianca"] == "Baixa"


def _fg(cat):
    return {"categoria": cat, "origem": "evento", "visto_em": None, "erro": None}


def test_fortiguard_category_drives_the_verdict():
    from app.services.reputation import consolidate
    r = consolidate("domain", "matt.mercadolivre.com.br", {}, {}, _fg("Shopping"))
    assert r["reputacao"] == "Sem risco conhecido" and r["confianca"] == "Média" and r["risk_score"] == 0
    assert r["fontes"] == ["FortiGuard (categoria do site)"] and "Shopping (FortiGuard)" in r["categoria"]
    assert r["fortiguard"]["risco"] is None and "Shopping" in r["recomendacoes"][0]
    r = consolidate("domain", "login-banco.example", {}, {}, _fg("Phishing"))
    assert r["reputacao"] == "Malicioso" and r["risk_score"] == 90 and r["confianca"] == "Alta"
    assert r["fortiguard"]["risco"] == "alto" and "Phishing" in r["recomendacoes"][0] and r["severidade"] == "Alta"
    r = consolidate("domain", "novo.example", {}, {}, _fg("Newly Registered Domain"))
    assert r["reputacao"] == "Suspeito" and r["severidade"] == "Média" and r["fortiguard"]["risco"] == "medio"
    r = consolidate("domain", "x.example", {}, {}, _fg("Unrated"))
    assert r["reputacao"] == "Não classificado (FortiGuard)" and r["fortiguard"]["nao_classificado"]
    assert "Unrated" in r["recomendacoes"][0] and r["confianca"] == "Baixa"
    # Sandbox sem risco não apaga uma categoria de risco do FortiGuard
    sbr = {"risco": "noRisk", "tipos_ameaca": [], "deteccoes": [], "iocs": []}
    assert consolidate("domain", "login-banco.example", {"sandbox_result": sbr}, {}, _fg("Phishing"))["reputacao"] == "Malicioso"


def test_lookup_takes_fortiguard_category_from_event_or_logs():
    from_logs = reputation.lookup("google.com")
    assert from_logs["reputacao"] == "Sem risco conhecido"
    assert from_logs["fortiguard"]["categoria"] == "Search Engines and Portals"
    assert from_logs["fortiguard"]["origem"] == "logs" and from_logs["fortiguard"]["visto_em"]
    from_event = reputation.lookup("matt.mercadolivre.com.br", fortiguard_category="Shopping")
    assert from_event["fortiguard"]["origem"] == "evento" and from_event["reputacao"] == "Sem risco conhecido"
    assert reputation.lookup("malware-test.example")["fortiguard"]["categoria"] == "Malicious Websites"
    with pytest.raises(reputation.IndicatorError):
        reputation.lookup("8.8.8.8")  # só sites
    with pytest.raises(reputation.IndicatorError):
        reputation.lookup("x.com", fortiguard_category='a"b')


def test_site_result_is_kept_for_7_days_and_refresh_asks_again(monkeypatch):
    saved = {}
    monkeypatch.setattr(reputation.database, "cache_set", lambda k, v, ttl=None: saved.__setitem__(k, (v, ttl)))
    monkeypatch.setattr(reputation.database, "cache_get", lambda k: saved.get(k, (None,))[0])
    calls = []
    monkeypatch.setattr(reputation, "_fortiguard", lambda *a: calls.append(a[-1]) or _fg("Education"))
    r = reputation.lookup("www.talkdrill.com")
    assert not r["cache"] and any(t == reputation.KEEP_TTL for _, t in saved.values())
    assert reputation.lookup("www.talkdrill.com")["cache"] and calls == [False]
    assert not reputation.lookup("www.talkdrill.com", refresh=True)["cache"] and calls == [False, True]
    # o veredito com o Sandbox concluído passa a ser o da consulta simples do mesmo site
    monkeypatch.setattr(reputation, "sandbox_status", lambda t: {"status": "succeeded", "resultado": {"risco": "high", "iocs": []}})
    reputation.lookup("www.talkdrill.com", sandbox_task="t-9")
    assert reputation.lookup("www.talkdrill.com")["reputacao"] == "Malicioso"
