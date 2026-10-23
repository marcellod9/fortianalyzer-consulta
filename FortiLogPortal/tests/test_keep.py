"""Eventos guardados: a consulta seguinte só busca no FAZ o trecho que ainda não foi lido."""
from datetime import datetime, timedelta

from app import database
from app.config import settings
from app.services import logsearch
from app.services.faz_filters import LogQuery

END = datetime(2026, 10, 20, 12, 0)


class FakeFaz:
    def __init__(self):
        self.calls = []

    def search_logs(self, adom, logtype, start, end, filter_expr, devices, limit):
        self.calls.append((start, end, limit))
        when = datetime.strptime(end, "%Y-%m-%d %H:%M:%S") - timedelta(minutes=30)
        log = {"date": when.strftime("%Y-%m-%d"), "time": when.strftime("%H:%M:%S"), "srcip": "10.0.0.1",
               "dstip": "8.8.8.8", "action": "deny", "user": "ana", "devname": "FW-KEEP"}
        return {"logs": [log], "total": 1, "mais": False}


def _q(start, end, **kw):
    return LogQuery(start=start, end=end, user="ana", devname="keep-logs", **kw)


def test_logs_reuse_saved_events_and_fetch_only_the_new_part(monkeypatch):
    faz = FakeFaz()
    monkeypatch.setattr(logsearch, "get_client", lambda: faz)
    first = logsearch.run_query(_q(END - timedelta(days=1), END), keep=True, save_cache=False)
    assert first["guardados"] == 0 and faz.calls[-1][0] == "2026-10-19 12:00:00"

    later = logsearch.run_query(_q(END - timedelta(hours=23), END + timedelta(hours=1)), keep=True, save_cache=False)
    assert faz.calls[-1][0] == "2026-10-20 11:45:00"  # só a hora nova, com 15 min de folga
    assert later["guardados"] == 1 and later["returned"] == 2

    n = len(faz.calls)
    again = logsearch.run_query(_q(END - timedelta(days=1), END), keep=True, save_cache=False)
    assert len(faz.calls) == n and again["returned"] == 1  # período já guardado: nada vai ao FAZ

    fresh = logsearch.run_query(_q(END - timedelta(days=1), END), keep=True, save_cache=False, use_cache=False)
    assert faz.calls[-1][0] == "2026-10-19 12:00:00" and fresh["guardados"] == 0

    other = logsearch.run_query(_q(END - timedelta(days=1), END, srcip="10.9.9.9"), keep=True, save_cache=False)
    assert other["guardados"] == 0  # outros filtros não usam o guardado


def test_keep_can_be_turned_off(monkeypatch):
    faz = FakeFaz()
    monkeypatch.setattr(logsearch, "get_client", lambda: faz)
    monkeypatch.setattr(settings, "keep_days", 0)
    for _ in range(2):
        logsearch.run_query(_q(END - timedelta(days=2), END - timedelta(days=1)), keep=True, save_cache=False)
    assert [c[0] for c in faz.calls] == ["2026-10-18 12:00:00"] * 2


def test_saved_events_respect_the_disk_limit():
    for i in range(5):
        database.cache_set(f"trimtest:{i}", "x" * 1000, ttl=60)
    assert database.cache_trim("trimtest:", 2500) == 3
    assert database.cache_get("trimtest:4") and database.cache_get("trimtest:3") and not database.cache_get("trimtest:0")
