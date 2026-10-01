"""Páginas HTML (Jinja2 + Bootstrap 5)."""
import hashlib

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..config import BASE_DIR, settings
from ..services.faz_filters import LOGTYPES

templates = Jinja2Templates(directory=str(BASE_DIR / "frontend" / "templates"))
router = APIRouter()


def _asset_version() -> str:
    """Muda sempre que app.css/os .js mudam: o navegador não reaproveita arquivo antigo depois do update."""
    h = hashlib.sha1()
    static = BASE_DIR / "frontend" / "static"
    for f in sorted([*static.glob("css/*.css"), *static.glob("js/*.js")]):
        h.update(f.read_bytes())
    return h.hexdigest()[:10]


ASSET_V = _asset_version()

PAGES = [
    ("/", "dashboard", "Dashboard", "speedometer2"),
    ("/logs", "logs", "Logs", "list-ul"),
    ("/reputacao", "reputacao", "Reputação", "shield-check"),
    ("/correlacao", "correlacao", "Correlação", "diagram-3"),
    ("/historico", "historico", "Histórico", "clock-history"),
    ("/configuracao", "configuracao", "Configuração", "gear"),
]


def _ctx(request: Request, page: str) -> dict:
    return {"request": request, "page": page, "pages": PAGES, "demo": settings.demo, "versao": __version__, "asset_v": ASSET_V,
            "logtypes": LOGTYPES, "default_adom": settings.faz_default_adom,
            "sandbox_enabled": settings.v1_sandbox_enabled, "max_results": settings.faz_max_results}


def _page(name: str):
    def view(request: Request):
        return templates.TemplateResponse(request, f"{name}.html", _ctx(request, name))
    view.__name__ = f"page_{name}"
    return view


@router.get("/bloqueios", include_in_schema=False)
def old_blocks_page():
    """A aba Bloqueios foi incorporada à aba Logs (Somente bloqueios / filtro Bloqueados)."""
    return RedirectResponse("/logs", status_code=307)


for path, name, _title, _icon in PAGES:
    router.add_api_route(path, _page(name), methods=["GET"], include_in_schema=False)
