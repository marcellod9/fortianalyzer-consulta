"""Relatórios de acesso: contagens, gráficos, amostra e exportação (dados de demonstração)."""
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import report_export, reports

END = datetime(2026, 10, 1, 18, 0)


def q(**kw):
    return reports.ReportQuery(start=END - timedelta(hours=24), end=END, **kw)


def test_value_is_required_except_for_general_report():
    with pytest.raises(ValueError, match="usuário"):
        q(tipo="usuario")
    with pytest.raises(ValueError):
        q(tipo="ip", valor="não é ip")
    assert q(tipo="geral", valor="  ").valor is None
    assert q(tipo="usuario", valor="MARISTA\\maria").base_query("webfilter").filter_expr() == 'user~"maria"'
    assert q(tipo="site", valor="https://www.facebook.com/x").base_query("webfilter").filter_expr() == 'hostname~"facebook.com"'
    assert q(tipo="aplicacao", valor="YouTube", somente_bloqueios=True).base_query("app-ctrl").filter_expr() == \
        'app~"YouTube" and action=block'


def test_general_report_counts_and_charts():
    r = reports.run_report(q(tipo="geral"), use_cache=False)
    assert set(r["fontes"]) == {"webfilter", "app-ctrl"} and r["erros"] == {}
    s = r["resumo"]
    assert s["eventos"] == sum(f["total"] for f in r["fontes"].values()) and s["permitidos"] + s["bloqueados"] == s["lidos"]
    by_id = {c["id"]: c for c in r["graficos"]}
    assert {"acao", "categorias", "sites", "aplicacoes", "usuarios", "tempo"} <= set(by_id)
    assert sum(n for _, n in by_id["acao"]["itens"]) == s["lidos"]
    # pizza: no máximo 7 fatias + "Outros", e a soma fecha com a base
    cat = by_id["categorias"]
    assert len(cat["itens"]) <= 8 and sum(n for _, n in cat["itens"]) + cat["sem_valor"] == cat["base"]
    assert all(c["fonte"] == "filtro web" for c in (by_id["sites"], cat))
    t = by_id["tempo"]
    assert t["agrupamento"] == "hora" and len(t["rotulos"]) == 25 and sum(t["permitidos"]) + sum(t["bloqueados"]) == s["lidos"]


def test_report_by_site_uses_webfilter_only_and_drops_its_own_dimension():
    r = reports.run_report(q(tipo="site", valor="facebook.com"), use_cache=False)
    assert list(r["fontes"]) == ["webfilter"]
    ids = [c["id"] for c in r["graficos"]]
    assert "sites" not in ids and "usuarios" in ids
    assert all(e["site"].endswith("facebook.com") for e in r["eventos"])


def test_sample_warning_when_period_has_more_events(monkeypatch):
    monkeypatch.setattr(reports.settings, "report_max_rows", 200)
    r = reports.run_report(q(tipo="geral"), use_cache=False)
    assert r["amostra"] and "200 de" in r["aviso_amostra"] and r["resumo"]["lidos"] == 400
    tempo = next(c for c in r["graficos"] if c["id"] == "tempo")
    assert len(tempo["rotulos"]) < 25  # a linha do tempo começa no evento mais antigo lido


def test_long_period_groups_by_day():
    r = reports.run_report(reports.ReportQuery(start=END - timedelta(days=7), end=END, tipo="geral"), use_cache=False)
    t = next(c for c in r["graficos"] if c["id"] == "tempo")
    assert t["agrupamento"] == "dia" and len(t["rotulos"]) == 8


def test_pdf_and_excel_exports():
    r = reports.run_report(q(tipo="usuario", valor="maria"), use_cache=False)
    pdf, name = report_export.build("pdf", r, reports.EVENT_COLUMNS)
    assert pdf.startswith(b"%PDF") and name.endswith(".pdf")
    xlsx, _ = report_export.build("xlsx", r, reports.EVENT_COLUMNS)
    from io import BytesIO
    from openpyxl import load_workbook
    wb = load_workbook(BytesIO(xlsx))
    assert wb.sheetnames[0] == "Resumo" and wb.sheetnames[-1] == "Eventos"
    assert wb["Eventos"].max_row == len(r["eventos"]) + 1
    assert any(ws._charts for ws in wb.worksheets)
    assert report_export.time_label("2026-10-01 18", "hora") == "01/10 18h"
    assert report_export._step(7) == 2 and report_export._step(1234) == 500


def test_report_api_download_and_history():
    with TestClient(app) as c:
        r = c.post("/api/reports", json={"tipo": "ip", "valor": "10.10.0.0/16", "start": "2026-10-01T00:00", "end": "2026-10-01T18:00"},
                   headers={"X-Portal-User": "ana"})
        assert r.status_code == 200, r.text
        d = r.json()
        assert "eventos" not in d and d["eventos_exportaveis"] == d["resumo"]["lidos"]
        pdf = c.get(f"/api/reports/{d['report_id']}.pdf")
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
        assert c.get(f"/api/reports/{d['report_id']}.csv").status_code == 400
        assert c.get("/api/reports/naoexiste.pdf").status_code == 404
        bad = c.post("/api/reports", json={"tipo": "usuario", "start": "2026-10-01T00:00", "end": "2026-10-01T18:00"})
        assert bad.status_code in (400, 422) and "usuário" in bad.text
        hist = c.get("/api/history?type=relatorio").json()
        assert any("10.10.0.0/16" in h["term"] for h in hist)
        assert c.get("/relatorios").status_code == 200


def test_blocked_only_report_renames_and_skips_redundant_charts():
    r = reports.run_report(q(tipo="geral", somente_bloqueios=True), use_cache=False)
    titles = {c["id"]: c["titulo"] for c in r["graficos"]}
    assert "acao" not in titles and "sites_bloqueados" not in titles
    assert titles["sites"] == "Sites mais bloqueados" and titles["tempo"] == "Bloqueios ao longo do tempo"
    assert r["resumo"]["permitidos"] == 0
