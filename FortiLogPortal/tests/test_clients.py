"""Clientes FAZ e Vision One contra respostas HTTP simuladas (sem rede)."""
import json
from datetime import datetime, timedelta

import pytest
import requests

from app.services.fortianalyzer import FazClient, FazError
from app.services.visionone import V1Error, VisionOneClient


class FakeResp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body
        self.content = b"" if body is None else json.dumps(body).encode()
        self.text = self.content.decode()

    def json(self):
        if self._body is None:
            raise ValueError("vazio")
        return self._body


class FakeSession(requests.Session):
    def __init__(self, handler):
        super().__init__()
        self.handler = handler
        self.calls = []

    def post(self, url, json=None, **kw):
        self.calls.append(("POST", url, json, kw))
        return self.handler("POST", url, json, kw)

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw.get("json"), kw))
        return self.handler(method, url, kw.get("json"), kw)


def test_faz_logsearch_flow_add_get_delete():
    def handler(method, url, body, kw):
        p = body["params"][0]
        if body["method"] == "add":
            assert p["url"] == "/logview/adom/root/logsearch" and p["apiver"] == 3
            assert p["filter"] == "srcip=10.0.0.1" and p["device"] == [{"devid": "FG1"}]
            return FakeResp(body={"result": {"tid": 42}})
        if body["method"] == "get":
            return FakeResp(body={"result": {"percentage": 100, "total-lines": 1, "return-lines": 1,
                                             "data": [{"srcip": "10.0.0.1"}]}})
        return FakeResp(body={"result": {"status": {"code": 0}}})
    s = FakeSession(handler)
    c = FazClient("https://faz.local", "tok", session=s)
    res = c.search_logs("root", "traffic", "2026-10-01 00:00:00", "2026-10-01 01:00:00", "srcip=10.0.0.1", ["FG1"], 10)
    assert res == {"total": 1, "returned": 1, "logs": [{"srcip": "10.0.0.1"}]}
    assert [cl[2]["method"] for cl in s.calls] == ["add", "get", "delete"]
    assert s.headers["Authorization"] == "Bearer tok"


def test_faz_errors_are_translated():
    c = FazClient("https://faz.local", "tok", session=FakeSession(lambda *a: FakeResp(401, {})))
    with pytest.raises(FazError, match="recusou o token"):
        c.list_adoms()
    c = FazClient("https://faz.local", "tok", session=FakeSession(
        lambda *a: FakeResp(body={"result": [{"status": {"code": -11, "message": "No permission"}}]})))
    with pytest.raises(FazError, match="sem permissão"):
        c.list_adoms()


def test_v1_pagination_follows_nextlink_and_sends_query_header():
    base = "https://api.xdr.trendmicro.com"

    def handler(method, url, body, kw):
        if "skipToken" in url:
            return FakeResp(body={"items": [{"id": 2}]})
        assert kw["headers"]["TMV1-Query"] == 'request:"x.com"'
        return FakeResp(body={"items": [{"id": 1}], "nextLink": f"{base}/v3.0/search/detections?skipToken=abc"})
    s = FakeSession(handler)
    c = VisionOneClient(base, "k", session=s)
    end = datetime.now().astimezone()
    items = c.search_detections('request:"x.com"', end - timedelta(days=1), end, top=50)
    assert items == [{"id": 1}, {"id": 2}]
    assert s.calls[0][1] == f"{base}/v3.0/search/detections"
    assert s.calls[0][3]["params"]["startDateTime"].endswith("Z")


def test_v1_rejects_foreign_nextlink_and_maps_errors():
    c = VisionOneClient("https://api.xdr.trendmicro.com", "k", session=FakeSession(
        lambda *a: FakeResp(body={"items": [], "nextLink": "https://evil.example/v3.0/x"})))
    with pytest.raises(V1Error, match="fora do domínio"):
        c.suspicious_objects()
    c = VisionOneClient("https://api.xdr.trendmicro.com", "k", session=FakeSession(
        lambda *a: FakeResp(403, {"error": {"code": "AccessDenied", "message": "no"}})))
    with pytest.raises(V1Error, match="permissão"):
        c.workbench_alerts(datetime.now(), datetime.now())


def test_v1_sandbox_submit_parses_multistatus():
    body = [{"status": 202, "headers": [{"name": "Operation-Location",
                                         "value": "https://api.xdr.trendmicro.com/v3.0/sandbox/tasks/abc-123"}],
             "body": {"id": "abc-123", "url": "http://x.com"}}]
    c = VisionOneClient("https://api.xdr.trendmicro.com", "k", session=FakeSession(lambda *a: FakeResp(202, body)))
    assert c.sandbox_submit_url("http://x.com")["task_id"] == "abc-123"


def test_faz_retries_invalid_tid(monkeypatch):
    monkeypatch.setattr("app.services.fortianalyzer.time.sleep", lambda s: None)
    gets = {"n": 0}

    def handler(method, url, body, kw):
        if body["method"] == "add":
            return FakeResp(body={"result": {"tid": 7}})
        if body["method"] == "get":
            gets["n"] += 1
            if gets["n"] < 3:
                return FakeResp(body={"error": {"code": -32005, "message": "Server error: Invalid tid 7 for fetching result."}})
            return FakeResp(body={"result": {"percentage": 100, "data": []}})
        return FakeResp(body={"result": {}})
    c = FazClient("https://faz.local", "tok", session=FakeSession(handler))
    assert c.search_logs("root", "dns", "a", "b")["logs"] == []
    assert gets["n"] == 3
