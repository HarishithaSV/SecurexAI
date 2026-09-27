"""
SQLite persistence layer for SOC Assistant.
"""
import sqlite3
import json
import os
from contextlib import contextmanager
from datetime import datetime

from config import config


def _ensure_db_dir():
    db_dir = os.path.dirname(config.DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)


@contextmanager
def get_conn():
    _ensure_db_dir()
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT,
    rule_id TEXT,
    rule_description TEXT,
    agent_name TEXT,
    agent_ip TEXT,
    level INTEGER,
    raw_log TEXT,
    timestamp TEXT,
    status TEXT DEFAULT 'new',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sigma_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    sigma_rule_id TEXT,
    sigma_title TEXT,
    sigma_level TEXT,
    mitre_techniques TEXT,
    matched_fields TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    severity_score INTEGER,
    verdict TEXT,
    summary TEXT,
    recommended_actions TEXT,
    mitre_techniques TEXT,
    llm_provider TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER,
    action TEXT,
    details TEXT,
    actor TEXT DEFAULT 'system',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level);
CREATE INDEX IF NOT EXISTS idx_sigma_alert ON sigma_matches(alert_id);
CREATE INDEX IF NOT EXISTS idx_analyses_alert ON analyses(alert_id);
"""


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def insert_alert(alert: dict) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO alerts
               (source_id, rule_id, rule_description, agent_name, agent_ip,
                level, raw_log, timestamp, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.get("source_id"),
                alert.get("rule_id"),
                alert.get("rule_description"),
                alert.get("agent_name"),
                alert.get("agent_ip"),
                alert.get("level"),
                json.dumps(alert.get("raw_log", {})),
                alert.get("timestamp", datetime.utcnow().isoformat()),
                alert.get("status", "new"),
            ),
        )
        return cur.lastrowid


def list_alerts(status=None, limit=100, offset=0):
    query = "SELECT * FROM alerts"
    params = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_alert(alert_id: int):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None


def update_alert_status(alert_id: int, status: str):
    with get_conn() as conn:
        conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))


def alert_exists(source_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM alerts WHERE source_id = ?", (source_id,)
        ).fetchone()
        return row is not None


def insert_sigma_match(alert_id: int, match: dict) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO sigma_matches
               (alert_id, sigma_rule_id, sigma_title, sigma_level,
                mitre_techniques, matched_fields)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                alert_id,
                match.get("id"),
                match.get("title"),
                match.get("level"),
                json.dumps(match.get("mitre_techniques", [])),
                json.dumps(match.get("matched_fields", {})),
            ),
        )
        return cur.lastrowid


def get_sigma_matches(alert_id: int):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM sigma_matches WHERE alert_id = ?", (alert_id,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["mitre_techniques"] = json.loads(d["mitre_techniques"] or "[]")
            d["matched_fields"] = json.loads(d["matched_fields"] or "{}")
            result.append(d)
        return result


def insert_analysis(alert_id: int, analysis: dict) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO analyses
               (alert_id, severity_score, verdict, summary,
                recommended_actions, mitre_techniques, llm_provider)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                alert_id,
                analysis.get("severity_score"),
                analysis.get("verdict"),
                analysis.get("summary"),
                json.dumps(analysis.get("recommended_actions", [])),
                json.dumps(analysis.get("mitre_techniques", [])),
                analysis.get("llm_provider", "none"),
            ),
        )
        return cur.lastrowid


def get_latest_analysis(alert_id: int):
    with get_conn() as conn:
        row = conn.execute(
            """SELECT * FROM analyses WHERE alert_id = ?
               ORDER BY created_at DESC LIMIT 1""",
            (alert_id,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["recommended_actions"] = json.loads(d["recommended_actions"] or "[]")
        d["mitre_techniques"] = json.loads(d["mitre_techniques"] or "[]")
        return d


def log_action(alert_id, action, details="", actor="system"):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_log (alert_id, action, details, actor) VALUES (?, ?, ?, ?)",
            (alert_id, action, details, actor),
        )


def get_dashboard_stats():
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        by_status = conn.execute(
            "SELECT status, COUNT(*) c FROM alerts GROUP BY status"
        ).fetchall()
        by_level = conn.execute(
            "SELECT level, COUNT(*) c FROM alerts GROUP BY level ORDER BY level DESC"
        ).fetchall()
        by_verdict = conn.execute(
            """SELECT verdict, COUNT(*) c FROM analyses
               WHERE id IN (SELECT MAX(id) FROM analyses GROUP BY alert_id)
               GROUP BY verdict"""
        ).fetchall()
        recent = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 10"
        ).fetchall()
        return {
            "total_alerts": total,
            "by_status": {r["status"]: r["c"] for r in by_status},
            "by_level": {r["level"]: r["c"] for r in by_level},
            "by_verdict": {r["verdict"]: r["c"] for r in by_verdict if r["verdict"]},
            "recent_alerts": [dict(r) for r in recent],
        }
