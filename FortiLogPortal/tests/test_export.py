from app.services import export


def test_csv_escapes_formulas_and_uses_semicolon():
    content = export.to_csv([("a", "A"), ("b", "B")], [{"a": "=HYPERLINK(1)", "b": -5}]).decode("utf-8-sig")
    assert content.splitlines() == ["A;B", "'=HYPERLINK(1);-5"]
