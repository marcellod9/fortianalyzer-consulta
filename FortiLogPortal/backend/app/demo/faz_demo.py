"""FortiAnalyzer simulado (somente com PORTAL_DEMO=true).

Gera logs no mesmo formato do LogView para demonstrar a interface sem acesso
ao FAZ. Nunca é usado quando PORTAL_DEMO=false.
"""
import random
import re
from datetime import datetime, timedelta

DEVICES = [
    {"name": "FW-BRASILIA", "sn": "FG200FDEMO000001", "ip": "10.10.0.1", "platform": "FortiGate-200F", "desc": "Demo",
     "lat": -15.79, "lon": -47.88},
    {"name": "FW-CURITIBA", "sn": "FG100FDEMO000002", "ip": "10.20.0.1", "platform": "FortiGate-100F", "desc": "Demo",
     "lat": -25.43, "lon": -49.27},
    {"name": "FW-SAOPAULO", "sn": "FG600FDEMO000003", "ip": "10.30.0.1", "platform": "FortiGate-600F", "desc": "Demo",
     "lat": -23.55, "lon": -46.63,
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
    ("login-banco.phish.example", "Phishing", "blocked", "ftgd_blk"),
]
APPS = [("Facebook", "Social.Media", "block"), ("BitTorrent", "P2P", "block"), ("Microsoft.Teams", "Collaboration", "pass"),
        ("YouTube", "Video/Audio", "pass"), ("Tor", "Proxy", "block"), ("Emotet.Botnet", "Botnet", "block")]
COUNTRIES = ["United States", "United States", "Brazil", "Brazil", "Brazil", "Russian Federation", "China", "Netherlands",
             "Germany", "Korea, Republic of", "Viet Nam", "India", "Iran, Islamic Republic of", "Ukraine", "France"]
# IPS: (assinatura, severidade, ação, entrada?)
ATTACKS = [("MS.SMB.Server.SMB1.Trans2.Secondary.Handling.Code.Execution", "critical", "dropped", False),
           ("Apache.Log4j.Error.Log.Remote.Code.Execution", "critical", "dropped", True),
           ("HTTP.URI.SQL.Injection", "high", "detected", True), ("Nmap.Script.Scanner", "low", "detected", True),
           ("Mirai.Botnet.Command", "high", "dropped", False)]
VIRUSES = [("W32/Emotet.ABC!tr", "blocked", "fatura.doc"), ("JS/Agent.NXK!tr", "blocked", "script.js"),
           ("EICAR_TEST_FILE", "blocked", "eicar.com"), ("W32/Qakbot.A!tr", "passthrough", "relatorio.xls")]
# (sistema, tipo, fabricante, prefixo do nome); None = firewall sem identificação de dispositivos nessa rede
DEVICE_KINDS = [None, ("Windows", "Windows PC", "Dell", "NB-ADM"), ("Android", "Android Phone", "Samsung", "Galaxy"),
                ("iOS", "iPhone", "Apple", "iPhone"), ("Windows", "Windows PC", "Lenovo", "PC-LAB"), ("macOS", "Mac", "Apple", "MacBook")]


def _device(src: str) -> dict:
    o = [int(x) for x in src.split(".")]
    kind = DEVICE_KINDS[sum(o) % len(DEVICE_KINDS)]
    if not kind:
        return {}
    osname, devtype, vendor, prefix = kind
    return {"srcname": f"{prefix}-{o[2]:02d}{o[3]:03d}", "srcmac": f"00:1a:2b:{o[1]:02x}:{o[2]:02x}:{o[3]:02x}",
            "osname": osname, "devtype": devtype, "srchwvendor": vendor}


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
            **_device(src),
        }
        base["srccountry"] = "Reserved"
        base["dstcountry"] = rnd.choice(COUNTRIES)
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
        elif logtype == "ips":
            attack, sev, action, inbound = rnd.choice(ATTACKS)
            ext = f"185.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}"
            if inbound:
                base.update({"srcip": ext, "dstip": base["srcip"], "user": "", "srccountry": base["dstcountry"],
                             "dstcountry": "Reserved"})
                for k in ("srcname", "srcmac", "osname", "devtype", "srchwvendor"):
                    base.pop(k, None)
            else:
                base["dstip"] = ext
            base.update({"attack": attack, "severity": sev, "action": action, "dstport": rnd.choice([445, 80, 443]),
                         "direction": "incoming" if inbound else "outgoing", "profile": "IPS_Padrao",
                         "ref": "http://www.fortinet.com/ids/VID12345", "msg": f"applications3: {attack}"})
        elif logtype == "virus":
            virus, action, fname = rnd.choice(VIRUSES)
            host = rnd.choice(["downloads.example", "mail.example"])
            base.update({"virus": virus, "action": action, "filename": fname, "hostname": host, "url": f"/{fname}",
                         "dstip": f"104.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}", "dstport": 443,
                         "profile": "AV_Padrao", "msg": "File is infected."})
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
            if deny or rnd.random() < 0.1:  # o FortiOS soma reputação (crscore) e ameaças no log de tráfego
                inbound = rnd.random() < 0.4
                if inbound:
                    base.update({"srcip": f"45.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}",
                                 "dstip": base["srcip"], "srccountry": base["dstcountry"], "dstcountry": "Reserved",
                                 "user": ""})
                level, score = rnd.choice([("low", 5), ("medium", 10), ("high", 30)])
                base.update({"crscore": score, "crlevel": level, "craction": 2,
                             "threats": ["blocked-connection" if deny else "Network.Service"]})
        return base

    @staticmethod
    def _match(log: dict, filter_expr: str) -> bool:
        for part in [p.strip() for p in filter_expr.split(" and ") if p.strip()]:
            m = re.match(r'^(\w+)(!=|>=|>|=|~)"?(.*?)"?$', part)
            if not m:
                continue
            field, op, val = m.groups()
            cur = str(log.get(field, ""))
            if op in (">", ">="):
                try:
                    n = float(log.get(field) or 0)
                    ok = n > float(val) if op == ">" else n >= float(val)
                except ValueError:
                    ok = False
                if not ok:
                    return False
                continue
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

    def fortiview(self, adom, view, start, end, devices=None, limit=50, sort_by=None):
        """FortiView top-threats no formato da API (campos de uma captura real de 7.6)."""
        if view != "top-threats":
            return []
        rnd = random.Random(f"fv{start[:13]}{end[:13]}")
        rows = []
        items = [(a, "ips", "attack", 4 if s == "critical" else 3 if s == "high" else 2) for a, s, _x, _y in ATTACKS]
        items += [(v, "malware-detected", "virus", 4) for v, _a, _f in VIRUSES]
        items += [("malware-test.example", "Malicious Websites", "webfilter", 4), ("login-banco.phish.example", "Phishing", "webfilter", 4),
                  ("Emotet.Botnet", "Botnet", "app-ctrl", 5), ("blocked-connection", "blocked-connection", "traffic", 2)]
        for threat, ttype, lt, level in items:
            inc = rnd.randint(5, 900)
            blk = inc if rnd.random() < 0.6 else rnd.randint(0, inc)
            w = inc * {5: 50, 4: 30, 3: 10, 2: 5}[level]
            rows.append({"threat": threat, "threattype": ttype, "logtype_str": lt, "threatlevel": str(level),
                         "level_s": {5: "Critical", 4: "High", 3: "Medium", 2: "Low"}[level], "threatweight": str(w),
                         "threat_block": str(w * blk // inc), "threat_pass": str(w - w * blk // inc), "incidents": str(inc),
                         "incident_block": str(blk), "incident_pass": str(inc - blk),
                         "cve_list": "CVE-2021-44228" if "Log4j" in threat else ""})
        rows.sort(key=lambda r: int(r["threatweight"]), reverse=True)
        return rows[:limit]

    def list_alerts(self, adom, start, end, limit=2000):
        """Alertas do Event Monitor no formato da API (handlers padrão de IOC e botnet, mais outros)."""
        t0 = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
        t1 = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
        span = max(60, int((t1 - t0).total_seconds()))
        rnd = random.Random(f"alerts{start[:13]}{end[:13]}")
        hosts = [("NB-ADM-12045", "10.12.12.45", "joao.silva"), ("Galaxy-21107", "10.21.11.107", "maria.souza"),
                 ("PC-LAB-30200", "10.30.30.200", ""), ("MacBook-15088", "10.15.10.88", "ana.lima")]
        handlers = [("Default-Compromised Host-Detection-IOC-By-Threat", "critical", "Emotet", "c2.emotet.example"),
                    ("Default-Botnet-Communication-Detection-By-Endpoint", "high", "Mirai", "cnc.mirai.example"),
                    ("Default-Compromised Host-Detection-IOC-By-Threat", "high", "Phishing.Kit", "login-banco.phish.example"),
                    ("Default-Risky-Destination-Detection-By-Endpoint", "medium", "", "")]
        alerts = []
        for i in range(min(limit, 18)):
            name, ip, user = rnd.choice(hosts)
            handler, sev, threat, domain = rnd.choice(handlers)
            when = t1 - timedelta(seconds=rnd.randint(0, span))
            alerts.append({"alertid": f"2026{i:014d}", "triggername": handler, "severity": sev, "epid": str(1000 + i),
                           "epname": name, "epip": ip, "devname": rnd.choice(DEVICES)["name"],
                           "alerttime": int(when.timestamp()), "ackflag": "yes" if i % 5 == 0 else "no",
                           "subject": f"{threat or 'Destino de risco'} detectado em {name}" + (f" ({domain})" if domain else ""),
                           "groupby1": f"threat:{threat}" if threat else f"endpoint:{name}",
                           "groupby2": f"user:{user}" if user else f"endpoint:{name}",
                           "target": [{"name": "domain", "value": domain}] if domain else []})
        alerts.sort(key=lambda a: a["alerttime"], reverse=True)
        return {"alerts": alerts, "mais": False}

    def search_logs(self, adom, logtype, start, end, filter_expr="", devices=None, limit=500):
        t0 = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
        t1 = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
        devs = [d for d in DEVICES if not devices or d["sn"] in devices or d["name"] in devices] or DEVICES
        span = max(1, int((t1 - t0).total_seconds()))
        logs = []
        if span <= 6 * 3600:
            # períodos curtos: logs fixos por minuto, para buscas que se sobrepõem (tempo real)
            # devolverem os mesmos eventos e os novos irem "chegando" com o relógio
            minute = t0.replace(second=0, microsecond=0)
            while minute <= t1:
                rnd = random.Random(f"{logtype}{minute:%Y%m%d%H%M}")
                for _ in range(rnd.randint(4, 12)):
                    when = minute + timedelta(seconds=rnd.randint(0, 59))
                    lg = self._log(rnd, logtype, when, DEVICES)
                    if t0 <= when <= t1 and lg["devid"] in {d["sn"] for d in devs} and self._match(lg, filter_expr):
                        logs.append(lg)
                minute += timedelta(minutes=1)
        else:
            rnd = random.Random(f"{logtype}{start}{end}")
            for _ in range(3000):
                when = t0 + timedelta(seconds=rnd.randint(0, span))
                lg = self._log(rnd, logtype, when, devs)
                if self._match(lg, filter_expr):
                    logs.append(lg)
        logs.sort(key=lambda r: r["itime"], reverse=True)
        return {"total": len(logs), "returned": min(len(logs), limit), "logs": logs[:limit]}
