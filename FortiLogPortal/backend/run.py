"""Inicia o FortiLogPortal em http://127.0.0.1:8000 (ou PORTAL_HOST/PORTAL_PORT).

Uso (na pasta FortiLogPortal):  python backend\\run.py [--no-browser] [--reload]
"""
import argparse
import sys
import threading
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn  # noqa: E402

from app.config import settings  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser(description="FortiLogPortal")
    p.add_argument("--no-browser", action="store_true", help="não abrir o navegador")
    p.add_argument("--reload", action="store_true", help="recarregar ao alterar o código (desenvolvimento)")
    args = p.parse_args()

    url = f"http://{settings.host}:{settings.port}"
    print(f"FortiLogPortal em {url}  (Ctrl+C para parar)")
    if not args.no_browser:
        threading.Timer(2.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=args.reload,
        app_dir=str(Path(__file__).resolve().parent),
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
