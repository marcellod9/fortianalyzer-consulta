"""Botões Atualizar / Reiniciar da tela de Configuração."""
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import server_actions as sa


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    req, out = tmp_path / "pedidos", tmp_path / "log"
    req.mkdir()
    out.mkdir()
    monkeypatch.setattr(sa, "REQUESTS", req)
    monkeypatch.setattr(sa, "OUT_DIR", out)
    return req, out


def stamp(dt):
    return dt.astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def test_not_available_outside_the_server(tmp_path, monkeypatch):
    monkeypatch.setattr(sa, "REQUESTS", tmp_path / "nao-existe")
    assert sa.status()["disponivel"] is False
    with pytest.raises(RuntimeError):
        sa.request("atualizar", "x@marista.org.br")


def test_request_creates_the_file_and_blocks_a_second_one(dirs):
    req, out = dirs
    sa.request("atualizar", "ana@marista.org.br")
    assert (req / "atualizar").read_text().strip().endswith("ana@marista.org.br")
    assert sa.status()["pendente"] == ["atualizar"]
    with pytest.raises(RuntimeError):
        sa.request("reiniciar", "ana@marista.org.br")
    with pytest.raises(ValueError):
        sa.request("rm -rf", "ana@marista.org.br")


def test_status_reads_the_root_log_in_local_time(dirs):
    _req, out = dirs
    now = datetime.now()
    (out / "acao-admin.log").write_text(f"{stamp(now - timedelta(minutes=5))} atualizar inicio\n")
    (out / "atualizacao.log").write_text("\x1b[1m== 3/7 Código\x1b[0m\nok\n")
    s = sa.status()
    assert s["em_andamento"] and s["ultimo"]["texto"] == "atualizar inicio"
    assert s["saida_atualizacao"] == ["== 3/7 Código", "ok"]
    # um início sem fim há muito tempo não trava os botões
    (out / "acao-admin.log").write_text(f"{stamp(now - timedelta(hours=2))} atualizar inicio\n")
    assert not sa.status()["em_andamento"]
    (out / "acao-admin.log").write_text(f"{stamp(now - timedelta(minutes=5))} atualizar inicio\n{stamp(now)} atualizar ok\n")
    s = sa.status()
    assert not s["em_andamento"] and s["historico"][0]["texto"] == "atualizar ok"


def test_api_server_actions(dirs):
    req, _out = dirs
    with TestClient(app) as c:
        assert c.get("/api/servidor").json()["disponivel"] is True
        assert c.post("/api/servidor/reiniciar").json() == {"ok": True, "acao": "reiniciar"}
        assert (req / "reiniciar").exists()
        assert c.post("/api/servidor/reiniciar").status_code == 409
        assert c.post("/api/servidor/outra").status_code == 404
        assert c.get("/configuracao").status_code == 200
