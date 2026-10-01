from app.services import explain


def test_webfilter_category_block_is_explained():
    log = {"date": "2026-10-01", "time": "10:00:00", "devname": "FW-BRASILIA", "user": "joao.silva",
           "hostname": "facebook.com", "url": "/", "action": "blocked", "eventtype": "ftgd_blk",
           "catdesc": "Social Networking", "policyid": 3, "policyname": "Internet_Corporativa",
           "profile": "WebFilter_Corp", "srcip": "10.0.0.5"}
    row = explain.normalize(log, "webfilter")
    assert row["bloqueado"] is True and row["acao"] == "Block"
    assert row["regra"] == "3 - Internet_Corporativa"
    assert row["explicacao"] == {
        "Usuário": "joao.silva", "Acesso": "facebook.com", "Resultado": "Bloqueado",
        "Motivo": 'Categoria "Social Networking" não permitida pela política de navegação corporativa.',
        "Política": "WebFilter_Corp", "Regra": "3 - Internet_Corporativa", "Firewall": "FW-BRASILIA"}


def test_traffic_implicit_deny_and_allow():
    deny = explain.normalize({"action": "deny", "policyid": 0, "dstip": "1.1.1.1", "dstport": 53}, "traffic")
    assert deny["acao"] == "Deny" and "regra 0" in deny["motivo"]
    assert deny["regra"].startswith("0 - bloqueio implícito")
    assert deny["explicacao"]["Acesso"] == "1.1.1.1:53"
    ok = explain.normalize({"action": "accept", "policyid": 7, "policyname": "LAN-WAN"}, "traffic")
    assert ok["acao"] == "Allow" and not ok["bloqueado"] and "LAN-WAN" in ok["motivo"]


def test_itime_fallback_and_unauthenticated_user():
    row = explain.normalize({"itime": 1790000000, "srcip": "10.9.9.9", "action": "block", "app": "BitTorrent"}, "app-ctrl")
    assert row["data_hora"].startswith("2026-")
    assert "BitTorrent" in row["motivo"]
    assert row["explicacao"]["Usuário"] == "(não autenticado) 10.9.9.9"


def test_columns_cover_required_fields():
    keys = {k for k, _ in explain.COLUMNS}
    for k in ("data_hora", "firewall", "ip_origem", "ip_destino", "porta_origem", "porta_destino", "usuario", "url",
              "aplicacao", "categoria", "regra", "politica", "interface_entrada", "interface_saida", "acao", "motivo"):
        assert k in keys
