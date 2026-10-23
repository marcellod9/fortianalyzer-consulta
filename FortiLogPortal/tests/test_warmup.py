"""Atualização automática das consultas padrão."""
from app.config import settings
from app.services import warmup


def test_each_tab_runs_and_one_failure_does_not_stop_the_others(monkeypatch):
    done = []
    monkeypatch.setattr(settings, "faz_url", "https://faz.exemplo")
    monkeypatch.setattr(settings, "faz_token", "x")
    monkeypatch.setattr(settings, "warm_tabs", ("ameacas", "dashboard", "relatorios", "logs", "trend", "outra"))
    monkeypatch.setattr(warmup, "_ameacas", lambda: done.append("ameacas") or "ok")

    def boom():
        done.append("dashboard")
        raise RuntimeError("FAZ fora do ar")
    monkeypatch.setattr(warmup, "_dashboard", boom)
    monkeypatch.setattr(warmup, "_relatorios", lambda: done.append("relatorios") or "ok")
    monkeypatch.setattr(warmup, "_logs", lambda: done.append("logs") or "ok")
    monkeypatch.setattr(warmup, "_trend", lambda cycle: done.append("trend") or None)
    out = warmup.run_once()
    assert done == ["ameacas", "dashboard", "relatorios", "logs", "trend"]
    assert out["dashboard"].startswith("falhou") and out["logs"] == "ok" and "trend" not in out


def test_real_jobs_run_against_the_demo_faz():
    # no modo demonstração o cliente do FAZ é simulado: confere que as consultas padrão montam e rodam
    for job in (warmup._ameacas, warmup._dashboard, warmup._relatorios, warmup._logs):
        assert isinstance(job(), str)
    assert warmup._trend(1) is None
