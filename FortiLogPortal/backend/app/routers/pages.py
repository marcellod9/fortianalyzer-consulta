"""Páginas HTML (Jinja2 + Bootstrap 5)."""
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..config import BASE_DIR, settings
from ..services.faz_filters import LOGTYPES

templates = Jinja2Templates(directory=str(BASE_DIR / "frontend" / "templates"))
router = APIRouter()

PAGES = [
    ("/", "dashboard", "Dashboard", "speedometer2"),
    ("/bloqueios", "bloqueios", "Bloqueios", "slash-circle"),
    ("/logs", "logs", "Logs", "list-ul"),
    ("/reputacao", "reputacao", "Reputação", "shield-check"),
    ("/correlacao", "correlacao", "Correlação", "diagram-3"),
    ("/historico", "historico", "Histórico", "clock-history"),
    ("/configuracao", "configuracao", "Configuração", "gear"),
]


def _ctx(request: Request, page: str) -> dict:
    return {"request": request, "page": page, "pages": PAGES, "demo": settings.demo, "versao": __version__,
            "logtypes": LOGTYPES, "default_adom": settings.faz_default_adom,
            "sandbox_enabled": settings.v1_sandbox_enabled, "max_results": settings.faz_max_results}


def _page(name: str):
    def view(request: Request):
        return templates.TemplateResponse(request, f"{name}.html", _ctx(request, name))
    view.__name__ = f"page_{name}"
    return view


for path, name, _title, _icon in PAGES:
    router.add_api_route(path, _page(name), methods=["GET"], include_in_schema=False)
