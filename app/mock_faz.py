"""FortiAnalyzer simulado (httpx.MockTransport) para desenvolvimento sem acesso ao FAZ real.

Responde às mesmas URLs JSON-RPC que o cliente usa, então o caminho de código
testado é o mesmo da produção.
"""
import json
import random
from datetime import datetime, timedelta

import httpx

ADOMS = [{"name": "root", "desc": ""}, {"name": "Marista-Escolas", "desc": "Unidades escolares"}]
DEVICES = {
    "root": [{"name": "FGT-SEDE", "sn": "FG100FTK00000001", "ip": "10.0.0.1", "platform_str": "FortiGate-100F"}],
    "Marista-Escolas": [
        {"name": "FGT-UNIDADE-01", "sn": "FG60FTK000000011", "ip": "10.1.0.1", "platform_str": "FortiGate-60F"},
        {"name": "FGT-UNIDADE-02", "sn": "FG60FTK000000012", "ip": "10.2.0.1", "platform_str": "FortiGate-60F"},
    ],
}
USERS = ["joao.silva", "maria.souza", "ana.lima", "", "carlos.pereira"]
HOSTS = ["www.google.com", "portal.marista.edu.br", "www.youtube.com", "login.microsoftonline.com", "tiktok.com"]

_tasks: dict[int, dict] = {}
_next_tid = [1000]


def _fake_logs(adom: str, logtype: str, n: int = 120) -> list[dict]:
    rnd = random.Random(f"{adom}-{logtype}")
    now = datetime.now().replace(microsecond=0)
    devs = DEVICES.get(adom, DEVICES["root"])
    out = []
    for i in range(n):
        t = now - timedelta(minutes=i * 3)
        dev = rnd.choice(devs)
        host = rnd.choice(HOSTS)
        blocked = host == "tiktok.com"
        out.append({
            "itime": t.strftime("%Y-%m-%d %H:%M:%S"),
            "date": t.strftime("%Y-%m-%d"), "time": t.strftime("%H:%M:%S"),
            "devname": dev["name"], "devid": dev["sn"],
            "srcip": f"172.16.{rnd.randint(1, 20)}.{rnd.randint(2, 250)}",
            "dstip": f"142.250.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}",
            "dstport": rnd.choice([443, 443, 80, 53]),
            "user": rnd.choice(USERS),
            "hostname": host,
            "action": "blocked" if blocked and logtype == "webfilter" else ("deny" if blocked else "accept"),
            "policyid": rnd.choice([1, 5, 12]),
            "app": rnd.choice(["HTTPS.BROWSER", "YouTube", "DNS", "Microsoft.Portal"]),
            "sentbyte": rnd.randint(200, 90000), "rcvdbyte": rnd.randint(500, 900000),
            "srcintf": "port2", "dstintf": "wan1",
        })
    return out


def _match(log: dict, expr: str) -> bool:
    # Suporta apenas o subconjunto que o backend gera: campo=valor / campo~valor unidos por "and"
    if not expr:
        return True
    for part in expr.split(" and "):
        part = part.strip()
        if "~" in part:
            k, v = part.split("~", 1)
            if v.strip('"').lower() not in str(log.get(k.strip(), "")).lower():
                return False
        elif "=" in part:
            k, v = part.split("=", 1)
            if str(log.get(k.strip(), "")) != v.strip('"'):
                return False
    return True


def _handle(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    method = body["method"]
    p = body["params"][0]
    url = p["url"]

    def ok(data):
        return httpx.Response(200, json={"id": body["id"], "result": [{"status": {"code": 0, "message": "OK"}, "url": url, "data": data}]})

    def lv(result):
        return httpx.Response(200, json={"id": body["id"], "jsonrpc": "2.0", "result": result})

    if url == "/dvmdb/adom":
        return ok(ADOMS)
    if url.startswith("/dvmdb/adom/") and url.endswith("/device"):
        return ok(DEVICES.get(url.split("/")[3], []))

    if url.startswith("/logview/adom/"):
        parts = url.split("/")
        adom = parts[3]
        if method == "add":
            tid = _next_tid[0]
            _next_tid[0] += 1
            logs = [l for l in _fake_logs(adom, p["logtype"]) if _match(l, p.get("filter", ""))]
            devs = [d["devid"] for d in p.get("device", [])]
            if devs and "All_FortiGate" not in devs:
                logs = [l for l in logs if l["devid"] in devs or l["devname"] in devs]
            _tasks[tid] = {"logs": logs, "polls": 0}
            return lv({"tid": tid})
        tid = int(parts[5])
        if method == "get":
            task = _tasks[tid]
            task["polls"] += 1
            pct = 100 if task["polls"] >= 2 else 50
            lim = p.get("limit", 500)
            data = task["logs"][p.get("offset", 0):p.get("offset", 0) + lim] if pct == 100 else []
            return lv({"percentage": pct, "total-lines": len(task["logs"]), "return-lines": len(data), "data": data})
        if method == "delete":
            _tasks.pop(tid, None)
            return lv({"status": {"code": 0}})

    return httpx.Response(200, json={"id": body["id"], "result": [{"status": {"code": -6, "message": "Invalid url"}}]})


transport = httpx.MockTransport(_handle)
