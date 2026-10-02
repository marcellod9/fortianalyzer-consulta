"""Diagnóstico de acesso: origem/destino reconhecidos e conclusão em modo demonstração."""
from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.services.diagnosis import DiagnoseQuery, target_filter, who_filter

H = {"X-Portal-User": "teste.sustentacao"}
P = {"start": datetime(2026, 10, 1, 8), "end": datetime(2026, 10, 1, 12)}
PJ = {"start": "2026-10-01T08:00", "end": "2026-10-01T12:00"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_who_and_target_are_recognized():
    assert who_filter("10.54.176.161").expr("traffic") == "srcip=10.54.176.161"
    assert who_filter("10.54.0.0/16").expr("traffic") == "srcip=10.54.0.0/16"
    assert who_filter("00-1A-2B-3C-4D-5E").expr("traffic") == 'srcmac="00:1a:2b:3c:4d:5e"'
    assert who_filter("MARISTA\\francisco.moreira").expr("traffic") == 'user~"francisco.moreira"'
    assert who_filter("10.54.176.161", "user").expr("traffic") == 'user~"10.54.176.161"'
    assert who_filter("NB-ADM-01", "srcname").expr("traffic") == 'srcname~"NB-ADM-01"'
    f, kind = target_filter("https://www.Facebook.com/login")
    assert kind == "site" and f.expr("webfilter") == 'hostname~"facebook.com"' and f.expr("dns") == 'qname~"facebook.com"'
    f, kind = target_filter("8.8.8.8")
    assert kind == "ip" and f.expr("traffic") == "dstip=8.8.8.8"
    assert target_filter("  ") == (None, None)


@pytest.mark.parametrize("data", [{"quem": ""}, {"quem": 'x" or srcip=1.1.1.1'}, {"quem": "joao", "destino": 'a"b.com'},
                                  {"quem": "joao", "adom": "root;x"}, {"quem": "joao", "start": P["end"], "end": P["start"]}])
def test_invalid_queries_are_rejected(data):
    with pytest.raises(ValidationError):
        DiagnoseQuery(**{**P, **data})


def test_blocked_user_and_site(client):
    r = client.post("/api/faz/diagnose", json={**PJ, "quem": "joao.silva", "destino": "www.facebook.com"}, headers=H)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["status"] == "bloqueado" and d["titulo"].startswith("Acesso bloqueado")
    web = next(c for c in d["camadas"] if c["logtype"] == "webfilter")
    assert web["bloqueios"] > 0 and web["filtro"] == 'user~"joao.silva" and hostname~"facebook.com" and action=blocked'
    assert d["rows"] and all(x["bloqueado"] and x["usuario"] == "joao.silva" for x in d["rows"])
    assert d["origem"]["ips"] and d["orientacao"] and d["result_id"] and d["por_usuario"] is True
    # o botão "Ver máquina no Vision One" usa o usuário pesquisado e o IP mais visto nos logs
    assert d["maquina"] == {"ip": d["origem"]["ips"][0], "nome": next(iter(d["origem"]["maquinas"]), None),
                            "usuario": "joao.silva"}
    assert client.get(f"/api/export/{d['result_id']}.xlsx", headers=H).content.startswith(b"PK")
    hist = client.get("/api/history", params={"type": "diagnostico"}).json()
    assert any(h["query_type"] == "diagnostico" and "joao.silva" in h["term"] for h in hist)


def test_allowed_and_nothing_found(client):
    ok = client.post("/api/faz/diagnose", json={**PJ, "quem": "maria.souza", "destino": "google.com"}, headers=H).json()
    assert ok["status"] == "permitido" and ok["permitidos"]["total"] > 0
    assert all(c["bloqueios"] == 0 for c in ok["camadas"]) and "não é o firewall" in ok["orientacao"]
    none = client.post("/api/faz/diagnose", json={**PJ, "quem": "ninguem.existe"}, headers=H).json()
    assert none["status"] == "sem_eventos" and "nome da máquina" in none["orientacao"] and none["rows"] == []
    dns = next(c for c in none["camadas"] if c["logtype"] == "dns")
    assert "IP da máquina" in dns["nota"]


def test_ip_destination_skips_dns_and_finds_firewall_block(client):
    d = client.post("/api/faz/diagnose", json={**PJ, "quem": "10.0.0.0/8", "destino": "45.33.32.156"}, headers=H).json()
    dns = next(c for c in d["camadas"] if c["logtype"] == "dns")
    assert dns["aplica"] is False and dns["filtro"] is None
    fw = next(c for c in d["camadas"] if c["logtype"] == "traffic")
    assert fw["bloqueios"] > 0 and d["status"] == "bloqueado"
    assert d["maquina"]["ip"] == d["origem"]["ips"][0]  # rede pesquisada: usa o IP mais visto


def test_search_by_machine_name(client):
    d = client.post("/api/faz/diagnose", json={**PJ, "quem": "NB-ADM", "quem_tipo": "srcname"}, headers=H).json()
    assert d["rows"] and all(r["maquina"].startswith("NB-ADM") for r in d["rows"])
    assert all(m.startswith("NB-ADM") for m in d["origem"]["maquinas"])
    # a máquina consultada no Vision One é a do IP mais visto (máquina e IP vêm dos mesmos eventos)
    assert any(r["maquina"] == d["maquina"]["nome"] and r["ip_origem"] == d["maquina"]["ip"] for r in d["rows"])
