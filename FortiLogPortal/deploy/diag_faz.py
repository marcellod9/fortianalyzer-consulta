"""Diagnóstico das buscas no FortiAnalyzer: roda a mesma busca com períodos e limites diferentes e mostra o resultado.

Uso (com o portal parado, para não haver outras buscas ao mesmo tempo):
  sudo systemctl stop radar-marista
  sudo -u radar env TZ=America/Sao_Paulo /opt/radar-marista/.venv/bin/python /opt/radar-marista/deploy/diag_faz.py
  sudo systemctl start radar-marista
"""
import sys, time
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "backend"))
from datetime import datetime, timedelta
from app.services.fortianalyzer import FazClient, FazError
from app.config import settings
c = FazClient(settings.faz_url, settings.faz_token, verify=settings.faz_verify, timeout=60)
c.SEARCH_RETRIES = 0  # sem novas tentativas: mostra o erro como o FAZ devolveu
end = datetime.now().replace(second=0, microsecond=0)
print(f"Horário enviado ao FortiAnalyzer: {end:%Y-%m-%d %H:%M} ({time.strftime('%Z %z')})", flush=True)
for horas in (1, 4, 24):
    for lt, flt, lim in (("traffic", "action=deny", 100), ("traffic", "action=deny", 1000), ("webfilter", "action=blocked", 1000)):
        t = time.time()
        try:
            r = c.search_logs(settings.faz_default_adom, lt, (end - timedelta(hours=horas)).strftime("%Y-%m-%d %H:%M:%S"),
                              end.strftime("%Y-%m-%d %H:%M:%S"), flt, limit=lim)
            res = f"ok, {r['returned']} eventos"
        except FazError as e:
            res = "FALHA " + str(e)[-70:]
        print(f"{horas:>2}h {lt:9} {flt:15} limite {lim:>4}: {res} ({time.time()-t:.0f}s)", flush=True)
