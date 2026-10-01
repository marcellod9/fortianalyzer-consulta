"""Configura o ambiente de teste: modo demonstração e banco temporário (nunca acessa APIs reais)."""
import os
import sys
import tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="flp-test-")
os.environ.update({
    "PORTAL_ENV_FILE": str(Path(_tmp) / "nao-existe.env"),
    "PORTAL_DEMO": "true",
    "PORTAL_DB": str(Path(_tmp) / "test.db"),
    "FAZ_MAX_RESULTS": "1000",
})
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app import database  # noqa: E402

database.init_db()
