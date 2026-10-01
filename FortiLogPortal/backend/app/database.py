"""Banco SQLite local (database/fortilogportal.db).

Tabelas:
  query_history   histórico de consultas (quem, quando, tipo, termo, resultado)
  app_log         logs internos (erros, falhas de integração, tempo de resposta)
  cache           cache de respostas das APIs (com expiração)
  settings        configurações não sensíveis editáveis pela interface
  temp_data       informações temporárias (ex.: último resultado para exportar)
  ioc_lookup      resultado consolidado das consultas de reputação (dashboard)
  policy_name     nome das regras por firewall, aprendido dos logs de tráfego
"""
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Iterator

from .config import settings

SCHEMA_VERSION = 1
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS query_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    username TEXT NOT NULL,
    query_type TEXT NOT NULL,
    term TEXT NOT NULL,
    params TEXT,
    status TEXT NOT NULL,
    result_count INTEGER DEFAULT 0,
    blocked_count INTEGER DEFAULT 0,
    summary TEXT,
    duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS ix_hist_ts ON query_history(ts);
CREATE INDEX IF NOT EXISTS ix_hist_type ON query_history(query_type);

CREATE TABLE IF NOT EXISTS app_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    level TEXT NOT NULL,
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS ix_log_ts ON app_log(ts);

CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS temp_data (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ioc_lookup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    indicator TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    verdict TEXT NOT NULL,
    risk_score INTEGER,
    source TEXT
);
CREATE INDEX IF NOT EXISTS ix_ioc_ts ON ioc_lookup(ts);

CREATE TABLE IF NOT EXISTS policy_name (
    device TEXT NOT NULL,
    policyid TEXT NOT NULL,
    name TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (device, policyid)
);
"""


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        conn = sqlite3.connect(settings.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def init_db() -> None:
    with connect() as c:
        c.executescript(SCHEMA)
        c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))


# ---- histórico ------------------------------------------------------------
def add_history(username: str, query_type: str, term: str, status: str, *, params: dict | None = None,
                result_count: int = 0, blocked_count: int = 0, summary: str = "", duration_ms: int | None = None) -> int:
    with connect() as c:
        cur = c.execute(
            "INSERT INTO query_history(ts, username, query_type, term, params, status, result_count, blocked_count,"
            " summary, duration_ms) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), username, query_type, term[:500], json.dumps(params or {}, default=str, ensure_ascii=False),
             status, result_count, blocked_count, summary[:1000], duration_ms),
        )
        return cur.lastrowid


def list_history(limit: int = 200, query_type: str | None = None, term: str | None = None) -> list[dict]:
    sql = "SELECT * FROM query_history"
    where, args = [], []
    if query_type:
        where.append("query_type = ?")
        args.append(query_type)
    if term:
        where.append("(term LIKE ? OR username LIKE ?)")
        args += [f"%{term}%", f"%{term}%"]
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with connect() as c:
        return [dict(r) for r in c.execute(sql, args)]


def history_stats(days: int = 14) -> dict:
    since = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    with connect() as c:
        tot = c.execute("SELECT COUNT(*) n, COALESCE(SUM(blocked_count),0) b FROM query_history").fetchone()
        iocs = c.execute("SELECT COUNT(*) n FROM ioc_lookup").fetchone()["n"]
        daily = c.execute(
            "SELECT substr(ts,1,10) dia, COUNT(*) n, COALESCE(SUM(blocked_count),0) b FROM query_history"
            " WHERE ts >= ? GROUP BY dia ORDER BY dia", (since,)).fetchall()
        by_type = c.execute("SELECT query_type, COUNT(*) n FROM query_history GROUP BY query_type").fetchall()
    days_map = {r["dia"]: (r["n"], r["b"]) for r in daily}
    serie = []
    for i in range(days):
        d = (datetime.now() - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        n, b = days_map.get(d, (0, 0))
        serie.append({"dia": d, "consultas": n, "bloqueios": b})
    return {
        "total_consultas": tot["n"],
        "total_bloqueios": tot["b"],
        "total_iocs": iocs,
        "historico_diario": serie,
        "por_tipo": {r["query_type"]: r["n"] for r in by_type},
    }


# ---- reputação (dashboard Vision One) ---------------------------------------
def add_ioc_lookup(indicator: str, ioc_type: str, verdict: str, risk_score: int | None, source: str) -> None:
    with connect() as c:
        c.execute("INSERT INTO ioc_lookup(ts, indicator, ioc_type, verdict, risk_score, source) VALUES (?,?,?,?,?,?)",
                  (now_iso(), indicator[:500], ioc_type, verdict, risk_score, source))


def ioc_dashboard(limit: int = 10) -> dict:
    with connect() as c:
        def top(ioc_type: str):
            return [dict(r) for r in c.execute(
                "SELECT indicator, MAX(risk_score) risk_score, COUNT(*) consultas, MAX(ts) ultima FROM ioc_lookup"
                " WHERE ioc_type = ? AND verdict IN ('Malicioso','Suspeito') GROUP BY indicator"
                " ORDER BY risk_score DESC, consultas DESC LIMIT ?", (ioc_type, limit))]
        return {
            "dominios_maliciosos": top("domain"),
            "ips_maliciosos": top("ip"),
            "urls_risco": top("url"),
            "ultimas": [dict(r) for r in c.execute("SELECT * FROM ioc_lookup ORDER BY id DESC LIMIT ?", (limit,))],
        }


# ---- logs internos ------------------------------------------------------------
def add_app_log(level: str, source: str, message: str, duration_ms: int | None = None) -> None:
    try:
        with connect() as c:
            c.execute("INSERT INTO app_log(ts, level, source, message, duration_ms) VALUES (?,?,?,?,?)",
                      (now_iso(), level, source, message[:2000], duration_ms))
    except sqlite3.Error:
        pass  # log interno nunca deve derrubar a requisição


def list_app_log(limit: int = 200, level: str | None = None) -> list[dict]:
    sql, args = "SELECT * FROM app_log", []
    if level:
        sql += " WHERE level = ?"
        args.append(level)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with connect() as c:
        return [dict(r) for r in c.execute(sql, args)]


def integration_stats() -> list[dict]:
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT source, COUNT(*) chamadas, ROUND(AVG(duration_ms)) media_ms, MAX(duration_ms) max_ms,"
            " SUM(CASE WHEN level='ERROR' THEN 1 ELSE 0 END) falhas FROM app_log"
            " WHERE duration_ms IS NOT NULL GROUP BY source")]


# ---- nomes das regras ---------------------------------------------------------
def policy_names_get(keys: set[tuple[str, str]]) -> dict[tuple[str, str], str]:
    if not keys:
        return {}
    with connect() as c:
        out = {}
        for dev, pid in keys:
            r = c.execute("SELECT name FROM policy_name WHERE device = ? AND policyid = ?", (dev, pid)).fetchone()
            if r:
                out[(dev, pid)] = r["name"]
        return out


def policy_names_set(items: dict[tuple[str, str], str]) -> None:
    if not items:
        return
    with connect() as c:
        c.executemany("INSERT OR REPLACE INTO policy_name(device, policyid, name, updated_at) VALUES (?,?,?,?)",
                      [(d, p, n, now_iso()) for (d, p), n in items.items()])


# ---- cache ------------------------------------------------------------------
def cache_get(key: str) -> Any | None:
    with connect() as c:
        r = c.execute("SELECT value, expires_at FROM cache WHERE key = ?", (key,)).fetchone()
    if not r or r["expires_at"] < time.time():
        return None
    return json.loads(r["value"])


def cache_set(key: str, value: Any, ttl: int | None = None) -> None:
    ttl = settings.cache_ttl if ttl is None else ttl
    now = time.time()
    with connect() as c:
        c.execute("INSERT OR REPLACE INTO cache(key, value, created_at, expires_at) VALUES (?,?,?,?)",
                  (key, json.dumps(value, default=str, ensure_ascii=False), now, now + ttl))


def cache_purge(all_entries: bool = False) -> int:
    with connect() as c:
        if all_entries:
            return c.execute("DELETE FROM cache").rowcount
        return c.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),)).rowcount


# ---- configurações e temporários ----------------------------------------------
def setting_get(key: str, default: Any = None) -> Any:
    with connect() as c:
        r = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return json.loads(r["value"]) if r else default


def setting_set(key: str, value: Any) -> None:
    with connect() as c:
        c.execute("INSERT OR REPLACE INTO settings(key, value, updated_at) VALUES (?,?,?)",
                  (key, json.dumps(value, ensure_ascii=False), now_iso()))


def temp_set(key: str, value: Any, ttl: int = 3600) -> None:
    with connect() as c:
        c.execute("DELETE FROM temp_data WHERE expires_at < ?", (time.time(),))
        c.execute("INSERT OR REPLACE INTO temp_data(key, value, expires_at) VALUES (?,?,?)",
                  (key, json.dumps(value, default=str, ensure_ascii=False), time.time() + ttl))


def temp_get(key: str) -> Any | None:
    with connect() as c:
        r = c.execute("SELECT value, expires_at FROM temp_data WHERE key = ?", (key,)).fetchone()
    if not r or r["expires_at"] < time.time():
        return None
    return json.loads(r["value"])
