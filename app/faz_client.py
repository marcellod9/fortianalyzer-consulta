"""Cliente mínimo da API JSON-RPC do FortiAnalyzer.

Fluxo de busca de logs (LogView, apiver 3):
  1. "add"    /logview/adom/{adom}/logsearch        -> cria a tarefa, devolve tid
  2. "get"    /logview/adom/{adom}/logsearch/{tid}  -> repete até percentage == 100
  3. "delete" /logview/adom/{adom}/logsearch/{tid}  -> libera a tarefa no FAZ

Autenticação por token de API (FortiAnalyzer 7.2.2+): header
"Authorization: Bearer <token>".
"""
import asyncio
import itertools
import time
from typing import Any

import httpx

from .config import settings


class FazError(Exception):
    pass


class FazClient:
    def __init__(self, url: str, token: str, verify: Any = True, transport=None):
        self._ids = itertools.count(1)
        self._http = httpx.AsyncClient(
            base_url=url,
            verify=verify,
            timeout=30,
            headers={"Authorization": f"Bearer {token}"},
            transport=transport,
        )

    async def close(self):
        await self._http.aclose()

    async def call(self, method: str, url: str, **params) -> Any:
        body = {
            "id": next(self._ids),
            "jsonrpc": "2.0",
            "method": method,
            "params": [{"url": url, **params}],
        }
        resp = await self._http.post("/jsonrpc", json=body)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data and data["error"]:
            raise FazError(f"{url}: {data['error']}")
        result = data.get("result")
        # dvmdb devolve result como lista com status; logview devolve dict
        if isinstance(result, list):
            status = result[0].get("status", {})
            if status.get("code", 0) != 0:
                raise FazError(f"{url}: {status.get('message')}")
            return result[0].get("data")
        return result

    # ---- inventário -------------------------------------------------------
    async def list_adoms(self) -> list[dict]:
        data = await self.call("get", "/dvmdb/adom", fields=["name", "desc"]) or []
        return [{"name": a["name"], "desc": a.get("desc", "")} for a in data]

    async def list_devices(self, adom: str) -> list[dict]:
        data = await self.call(
            "get", f"/dvmdb/adom/{adom}/device", fields=["name", "sn", "ip", "platform_str"]
        ) or []
        return [
            {"name": d["name"], "sn": d.get("sn"), "ip": d.get("ip"), "platform": d.get("platform_str")}
            for d in data
        ]

    # ---- busca de logs ----------------------------------------------------
    async def search_logs(
        self,
        adom: str,
        logtype: str,
        start: str,
        end: str,
        filter_expr: str = "",
        devices: list[str] | None = None,
        limit: int = 500,
    ) -> dict:
        base = f"/logview/adom/{adom}/logsearch"
        device = [{"devid": d} for d in devices] if devices else [{"devid": "All_FortiGate"}]
        created = await self.call(
            "add",
            base,
            apiver=3,
            device=device,
            logtype=logtype,
            filter=filter_expr,
            **{"time-order": "desc", "case-sensitive": False,
               "time-range": {"start": start, "end": end}},
        )
        tid = created.get("tid")
        if tid is None:
            raise FazError(f"FortiAnalyzer não devolveu tid: {created}")

        try:
            deadline = time.monotonic() + settings.search_timeout
            while True:
                res = await self.call("get", f"{base}/{tid}", apiver=3, offset=0, limit=limit)
                if res.get("percentage", 0) >= 100:
                    return {
                        "total": res.get("total-lines", len(res.get("data", []))),
                        "returned": res.get("return-lines", len(res.get("data", []))),
                        "logs": res.get("data", []),
                    }
                if time.monotonic() > deadline:
                    raise FazError("Tempo limite da busca excedido; reduza o intervalo ou refine o filtro.")
                await asyncio.sleep(1)
        finally:
            try:
                await self.call("delete", f"{base}/{tid}", apiver=3)
            except Exception:
                pass
