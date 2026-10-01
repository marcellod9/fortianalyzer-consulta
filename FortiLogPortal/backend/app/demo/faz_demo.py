"""FortiAnalyzer simulado (somente com PORTAL_DEMO=true).

Gera logs no mesmo formato do LogView para demonstrar a interface sem acesso
ao FAZ. Nunca é usado quando PORTAL_DEMO=false.
"""
import random
import re
from datetime import datetime, timedelta

DEVICES = [
    {"name": "FW-BRASILIA", "sn": "FG200FDEMO000001", "ip": "10.10.0.1", "platform": "FortiGate-200F", "desc": "Demo"},
    {"name": "FW-CURITIBA", "sn": "FG100FDEMO000002", "ip": "10.20.0.1", "platform": "FortiGate-100F", "desc": "Demo"},
    {"name": "FW-SAOPAULO", "sn": "FG600FDEMO000003", "ip": "10.30.0.1", "platform": "FortiGate-600F", "desc": "Demo",
     "ha_members": [{"name": "FW-SAOPAULO-A", "sn": "FG600FDEMO000003", "role": "master"},
                    {"name": "FW-SAOPAULO-B", "sn": "FG600FDEMO000004", "role": "slave"}]},
]
USERS = ["joao.silva", "maria.souza", "ana.lima", "carlos.pereira", "", "beatriz.rocha"]
SITES = [
    ("facebook.com", "Social Networking", "blocked", "ftgd_blk"),
    ("instagram.com", "Social Networking", "blocked", "ftgd_blk"),
    ("www.bet365.com", "Gambling", "blocked", "ftgd_blk"),
    ("torrentz.example", "Peer-to-peer File Sharing", "blocked", "ftgd_blk"),
    ("malware-test.example", "Malicious Websites", "blocked", "ftgd_blk"),
    ("www.google.com", "Search Engines and Portals", "passthrough", ""),
    ("portal.maristabrasil.org", "Education", "passthrough", ""),
    ("www.youtube.com", "Streaming Media and Download", "passthrough", ""),
    ("arquivo-proibido.example", "", "blocked", "urlfilter"),
]
APPS = [("Facebook", "Social.Media", "block"), ("BitTorrent", "P2P", "block"), ("Microsoft.Teams", "Collaboration", "pass"),
        ("YouTube", "Video/Audio", "pass"), ("Tor", "Proxy", "block")]
POLICIES = [(1, "Internet_Corporativa", "lan", "wan1"), (2, "Internet_Alunos", "wifi-alunos", "wan1"),
            (5, "Servidores_DMZ", "dmz", "wan2"), (0, "", "lan", "wan1")]


class DemoFazClient:
    source = "fortianalyzer-demo"

    def close(self):
        pass

    def status(self):
        return {"hostname": "FAZ-DEMO", "versao": "v7.4.7-build2731 (demo)", "serial": "FAZ-VMTM-DEMO", "plataforma": "FortiAnalyzer-VM64"}

    def list_adoms(self):
        return [{"name": "root", "desc": "ADOM padrão (demo)"}, {"name": "Marista", "desc": "Unidades (demo)"}]

    def list_devices(self, adom):
        return [{"ha_members": [], **d} for d in DEVICES]

    def _log(self, rnd: random.Random, logtype: str, when: datetime, devs: list[dict]) -> dict:
        dev = rnd.choice(devs)
        pol = rnd.choice(POLICIES)
        user = rnd.choice(USERS)
        src = f"10.{rnd.randint(10, 30)}.{rnd.randint(1, 50)}.{rnd.randint(2, 250)}"
        base = {
            "date": when.strftime("%Y-%m-%d"), "time": when.strftime("%H:%M:%S"), "itime": int(when.timestamp()),
            "devname": dev["name"], "devid": dev["sn"], "srcip": src, "srcport": rnd.randint(1024, 65000),
            "user": user, "srcintf": pol[2], "dstintf": pol[3], "policyid": pol[0], "policyname": pol[1],
            "policytype": "policy",
        }
        if logtype == "webfilter":
            host, cat, action, ev = rnd.choice(SITES)
            base.update({"hostname": host, "url": "/" + rnd.choice(["", "login", "videos", "download.php"]),
                         "dstip": f"157.240.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}", "dstport": 443,
                         "catdesc": cat, "action": action, "eventtype": ev or "ftgd_allow",
                         "profile": "WebFilter_Corporativo" if pol[0] != 2 else "WebFilter_Alunos",
                         "msg": "URL belongs to a denied category in policy" if ev == "ftgd_blk" else
                         ("URL was blocked because it is in the URL filter list" if ev == "urlfilter" else "URL belongs to an allowed category"),
                         "service": "HTTPS"})
            if base["policyid"] == 0:
                base["policyid"], base["policyname"] = 1, "Internet_Corporativa"
        elif logtype == "app-ctrl":
            app, appcat, action = rnd.choice(APPS)
            base.update({"app": app, "appcat": appcat, "action": action, "dstip": f"31.13.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}",
                         "dstport": 443, "profile": "AppControl_Padrao", "hostname": f"{app.lower()}.com"})
            if base["policyid"] == 0:
                base["policyid"], base["policyname"] = 1, "Internet_Corporativa"
        elif logtype == "dns":
            host, cat, action, _ = rnd.choice(SITES)
            base.update({"qname": host, "hostname": host, "catdesc": cat, "dstip": "8.8.8.8", "dstport": 53,
                         "action": "block" if action == "blocked" else "pass", "profile": "DNSFilter_Padrao"})
        else:  # traffic e demais
            deny = base["policyid"] == 0 or rnd.random() < 0.25
            port = rnd.choice([443, 80, 3389, 445, 22, 53, 8080])
            base.update({"dstip": rnd.choice(["8.8.8.8", "1.1.1.1", "200.160.2.3", "185.199.108.153", "45.33.32.156"]),
                         "dstport": port, "service": {443: "HTTPS", 80: "HTTP", 3389: "RDP", 445: "SMB", 22: "SSH",
                                                      53: "DNS", 8080: "tcp/8080"}[port],
                         "action": "deny" if deny else rnd.choice(["accept", "close", "timeout"]),
                         "app": rnd.choice(["HTTPS.BROWSER", "SSL", "DNS", "RDP", ""]),
                         "sentbyte": rnd.randint(100, 90000), "rcvdbyte": rnd.randint(100, 900000)})
            if not deny and base["policyid"] == 0:
                base["policyid"], base["policyname"] = 1, "Internet_Corporativa"
        return base

    @staticmethod
    def _match(log: dict, filter_expr: str) -> bool:
        for part in [p.strip() for p in filter_expr.split(" and ") if p.strip()]:
            m = re.match(r'^(\w+)(!=|=|~)"?(.*?)"?$', part)
            if not m:
                continue
            field, op, val = m.groups()
            cur = str(log.get(field, ""))
            if op == "~":
                ok = val.lower() in cur.lower()
            elif "/" in val and field in ("srcip", "dstip"):
                import ipaddress
                try:
                    ok = ipaddress.ip_address(cur) in ipaddress.ip_network(val)
                except ValueError:
                    ok = False
            else:
                ok = cur == val
            if ok == (op == "!="):
                return False
        return True

    def search_logs(self, adom, logtype, start, end, filter_expr="", devices=None, limit=500):
        t0 = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
        t1 = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
        devs = [d for d in DEVICES if not devices or d["sn"] in devices or d["name"] in devices] or DEVICES
        rnd = random.Random(f"{logtype}{start}{end}")
        span = max(1, int((t1 - t0).total_seconds()))
        logs = []
        for _ in range(3000):
            when = t0 + timedelta(seconds=rnd.randint(0, span))
            lg = self._log(rnd, logtype, when, devs)
            if self._match(lg, filter_expr):
                logs.append(lg)
        logs.sort(key=lambda r: r["itime"], reverse=True)
        return {"total": len(logs), "returned": min(len(logs), limit), "logs": logs[:limit]}
