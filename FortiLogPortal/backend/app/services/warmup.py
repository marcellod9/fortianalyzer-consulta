"""Atualização automática: o portal refaz sozinho a consulta padrão de cada aba.

A cada PORTAL_WARM_MIN minutos (padrão 15) uma thread de fundo repete o que cada tela consulta ao abrir, com os
filtros padrão (ADOM padrão, todos os firewalls). Os eventos ficam guardados (logsearch.incremental) e quem abre a
tela depois só espera o FAZ devolver os minutos novos. Consultas que dependem do que a pessoa digita (Diagnóstico,
Reputação, uma máquina específica) não têm padrão e continuam sob demanda.

As buscas no FAZ passam pela mesma fila das pessoas (FAZ_PARALLEL_SEARCHES), uma aba de cada vez.
"""
import logging
import threading
import time
from datetime import datetime, timedelta

from ..config import settings

log = logging.getLogger("portal")
_stop = threading.Event()
PAUSE_BETWEEN_TABS = 20  # segundos

NAMES = {"ameacas": "Ameaças", "dashboard": "Dashboard", "relatorios": "Relatórios", "logs": "Logs",
         "trend": "Trend inativo (inventário do Vision One)"}


def _now() -> datetime:
    return datetime.now().replace(second=0, microsecond=0)


def _ameacas() -> str:
    from . import threats
    r = threats.warm(hours=24)  # padrão da tela: último 1 dia
    return f"{r['lidos']} eventos novos, {r['guardados']} já guardados" + (f"; falhas: {', '.join(r['erros'])}" if r["erros"] else "")


def _dashboard() -> str:
    from . import dashboard
    d = dashboard.faz_overview(24, refresh=True, reuse=True)  # padrão da tela: últimas 24h
    return f"{d['amostra']} bloqueios" + (f"; falhas: {', '.join(d['erros'])}" if d.get("erros") else "")


def _relatorios() -> str:
    from . import reports
    end = _now()
    rep = reports.run_report(reports.ReportQuery(start=end - timedelta(days=1), end=end))  # geral, último 1 dia, top 10
    return f"{rep['resumo'].get('eventos', 0)} eventos"


def _logs() -> str:
    from .faz_filters import LogQuery
    from .logsearch import run_query
    end = _now()
    res = run_query(LogQuery(logtype="traffic", start=end - timedelta(hours=1), end=end, limit=500),
                    keep=True, save_cache=False)  # padrão da tela: tráfego, última 1 hora, 500 linhas
    return f"{res['returned']} eventos ({res.get('guardados', 0)} já guardados)"


def _trend(cycle: int) -> str | None:
    if not settings.v1_configured or cycle % 2:
        return None  # o inventário (dezenas de milhares de máquinas) é renovado a cada 2 rodadas
    from . import trend_coverage
    return f"{len(trend_coverage.inventory(refresh=True))} máquinas no inventário"


def run_once(cycle: int = 0, background: bool = False) -> dict:
    """Uma rodada de todas as abas ligadas; uma falha não impede as outras."""
    out = {}
    for tab in settings.warm_tabs:
        if tab not in NAMES or (tab != "trend" and not settings.faz_configured):
            continue
        t0 = time.monotonic()
        try:
            msg = _trend(cycle) if tab == "trend" else {"ameacas": _ameacas, "dashboard": _dashboard,
                                                         "relatorios": _relatorios, "logs": _logs}[tab]()
            if msg is None:
                continue
            out[tab] = msg
            log.info("Atualização automática: %s em %ds (%s)", NAMES[tab], time.monotonic() - t0, msg)
        except Exception as e:  # nunca derruba o portal
            out[tab] = f"falhou: {e}"
            log.warning("Atualização automática: %s falhou: %s", NAMES[tab], e)
        if background:
            # pausa entre as abas: as buscas de quem está usando o portal passam na frente
            if _stop.wait(PAUSE_BETWEEN_TABS):
                break
    return out


def start() -> threading.Thread | None:
    if settings.warm_min <= 0 or settings.demo or settings.keep_days <= 0:
        return None
    if not settings.faz_configured and not settings.v1_configured:
        return None
    _stop.clear()

    def loop():
        _stop.wait(30)  # deixa o portal terminar de subir
        cycle = 0
        while not _stop.is_set():
            run_once(cycle, background=True)
            cycle += 1
            _stop.wait(settings.warm_min * 60)

    t = threading.Thread(target=loop, name="atualizacao-automatica", daemon=True)
    t.start()
    log.info("Atualização automática a cada %d min: %s (ADOM %s, todos os firewalls)", settings.warm_min,
             ", ".join(NAMES[t] for t in settings.warm_tabs if t in NAMES), settings.faz_default_adom)
    return t


def stop() -> None:
    _stop.set()
