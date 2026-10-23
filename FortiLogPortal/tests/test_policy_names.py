"""Nome da regra completado a partir dos logs de tráfego (filtro web só traz o número)."""
from datetime import datetime

from app.services import logsearch
from app.services.faz_filters import LogQuery


class FakeFaz:
    def __init__(self):
        self.calls = []

    def search_logs(self, adom, logtype, start, end, filter_expr="", devices=None, limit=500):
        self.calls.append((logtype, filter_expr, limit))
        if logtype == "webfilter":
            return {"total": 2, "returned": 2, "logs": [
                {"devname": "fw-br-al-maceio055", "vd": "root", "policyid": 418, "hostname": "a.com", "action": "passthrough"},
                {"devname": "fw-br-al-maceio055", "vd": "root", "policyid": 0, "hostname": "b.com", "action": "blocked"},
            ]}
        assert filter_expr == 'policyid=418 and devname="fw-br-al-maceio055"' and limit == 1
        return {"total": 1, "returned": 1, "logs": [{"policyid": 418, "policyname": "Acesso_Embratel"}]}


def test_webfilter_rule_gets_name_from_traffic_and_is_remembered(monkeypatch):
    fake = FakeFaz()
    monkeypatch.setattr(logsearch, "get_client", lambda: fake)
    q = LogQuery(start=datetime(2026, 10, 1, 9), end=datetime(2026, 10, 1, 10), logtype="webfilter")
    out = logsearch.run_query(q, use_cache=False)
    assert out["rows"][0]["regra"] == "418 - Acesso_Embratel"
    assert out["rows"][0]["explicacao"]["Regra"] == "418 - Acesso_Embratel"
    assert out["rows"][1]["regra"].startswith("0 - bloqueio implícito")
    assert [c[0] for c in fake.calls] == ["webfilter", "traffic"]

    fake.calls.clear()  # segunda vez: o nome já está no banco, sem busca extra
    out = logsearch.run_query(q, use_cache=False)
    assert out["rows"][0]["regra"] == "418 - Acesso_Embratel" and [c[0] for c in fake.calls] == ["webfilter"]
