"""Economia do Sandbox: a mesma URL das últimas 24 h não é enviada de novo (cada envio custa 2 créditos)."""
import time

import pytest

from app import database
from app.services import reputation, visionone
from app.services.visionone import V1Error


class FakeV1:
    """Sandbox simulado; o resto (Workbench, detecções...) vem do cliente de demonstração."""

    def __init__(self, demo, remaining=100, task_status="succeeded", usage_error=None):
        self.demo = demo
        self.remaining, self.task_status, self.usage_error = remaining, task_status, usage_error
        self.submitted, self.task_calls, self.n = [], 0, 0

    def __getattr__(self, name):
        return getattr(self.demo, name)

    def sandbox_usage(self):
        if self.usage_error:
            raise V1Error(self.usage_error)
        return {"submissionReserveCount": 100, "submissionRemainingCount": self.remaining}

    def sandbox_submit_url(self, url):
        self.n += 1
        self.submitted.append(url)
        self.remaining -= 1
        return {"task_id": f"t-{id(self)}-{self.n}", "url": url}

    def sandbox_task(self, task_id):
        self.task_calls += 1
        return {"id": task_id, "status": self.task_status, "error": {"message": "falhou"}}

    def sandbox_result(self, rid):
        return {"riskLevel": "noRisk", "threatTypes": [], "detectionNames": [], "analysisCompletionDateTime": "x"}

    def sandbox_result_iocs(self, rid):
        return []


@pytest.fixture
def v1(monkeypatch):
    fake = FakeV1(visionone.get_client())
    monkeypatch.setattr(visionone, "get_client", lambda: fake)
    database.cache_delete(reputation.QUOTA_KEY)
    return fake


def test_same_url_within_24h_is_reused_not_resent(v1):
    first = reputation.sandbox_submit("http://reuso-ok.example/a", "ana")
    assert first["reaproveitado"] is False and v1.submitted == ["http://reuso-ok.example/a"]
    reputation.sandbox_status(first["task_id"])  # concluída e guardada
    # mesma URL com host em maiúsculas e #fragmento: não envia de novo
    again = reputation.sandbox_submit("HTTP://Reuso-OK.example/a#x", "bia")
    assert again["reaproveitado"] is True and again["task_id"] == first["task_id"]
    assert again["status"] == "succeeded" and again["enviado_por"] == "ana" and len(v1.submitted) == 1
    # o resultado já concluído vem do banco local, sem consultar o Vision One
    calls = v1.task_calls
    assert reputation.sandbox_status(first["task_id"])["resultado"]["risco"] == "noRisk"
    assert v1.task_calls == calls


def test_running_task_is_reused_and_failed_one_is_resent(v1):
    v1.task_status = "running"
    first = reputation.sandbox_submit("http://reuso-run.example/", "ana")
    again = reputation.sandbox_submit("http://reuso-run.example/", "ana")
    assert again["reaproveitado"] is True and again["status"] == "running" and len(v1.submitted) == 1
    v1.task_status = "failed"
    third = reputation.sandbox_submit("http://reuso-run.example/", "ana")
    assert third["reaproveitado"] is False and third["task_id"] != first["task_id"] and len(v1.submitted) == 2
    assert database.sandbox_run_get(first["task_id"])["status"] == "failed"


def test_old_run_and_force_send_again(v1):
    first = reputation.sandbox_submit("http://reuso-force.example/", "ana")
    forced = reputation.sandbox_submit("http://reuso-force.example/", "ana", force=True)
    assert forced["reaproveitado"] is False and forced["task_id"] != first["task_id"] and len(v1.submitted) == 2
    with database.connect() as con:
        con.execute("UPDATE sandbox_run SET submitted_at=? WHERE url=?",
                    (time.time() - 25 * 3600, "http://reuso-force.example/"))
    assert reputation.sandbox_submit("http://reuso-force.example/", "ana")["reaproveitado"] is False


def test_quota_zero_blocks_but_unknown_quota_does_not(v1):
    v1.remaining = 0
    with pytest.raises(V1Error, match="cota diária"):
        reputation.sandbox_submit("http://reuso-cota.example/", "ana")
    assert v1.submitted == []
    v1.usage_error = "Vision One HTTP 403"
    assert reputation.sandbox_submit("http://reuso-cota.example/", "ana")["reaproveitado"] is False
    q = reputation.sandbox_quota()
    assert q["restantes"] is None and "403" in q["erro"]


def test_quota_is_cached_until_next_submit(v1):
    assert reputation.sandbox_quota()["restantes"] == 100
    v1.remaining = 50
    assert reputation.sandbox_quota()["restantes"] == 100  # cache curto
    reputation.sandbox_submit("http://reuso-cache.example/", "ana")
    assert reputation.sandbox_quota()["restantes"] == 49


def test_lookup_reports_reuse_and_quota_error(v1, monkeypatch):
    monkeypatch.setattr(reputation.settings, "v1_sandbox_enabled", True)
    r1 = reputation.lookup("http://reuso-lookup.example/", "url", use_sandbox=True, username="ana")
    r2 = reputation.lookup("http://reuso-lookup.example/", "url", use_sandbox=True, username="ana")
    assert r1["detalhes"]["sandbox"]["reaproveitado"] is False
    assert r2["detalhes"]["sandbox"]["reaproveitado"] is True and len(v1.submitted) == 1
    v1.remaining = 0
    r3 = reputation.lookup("http://reuso-lookup2.example/", "url", use_sandbox=True, username="ana")
    assert "cota diária" in r3["erros"]["sandbox"]
