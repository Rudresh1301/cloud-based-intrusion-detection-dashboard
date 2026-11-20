"""
Local SQLite database – fallback when Firebase is unavailable.
Optimized with singleton caching, database indexing, and prepared batch upserts.
"""
import sqlite3
import os
import json
import uuid
from datetime import datetime, timezone
import streamlit as st

@st.cache_resource(show_spinner=False)
def get_local_db(db_path: str = "data/local_ids.db") -> "LocalDatabase":
    """Cached singleton LocalDatabase instance to prevent reconnecting and re-creating schema on every rerun."""
    return LocalDatabase(db_path)

class LocalDatabase:
    """Thread-safe SQLite store for alerts, analysis history and settings."""

    def __init__(self, db_path: str = "data/local_ids.db"):
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    # ── schema & indexes ────────────────────────────────────
    def _create_tables(self):
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id           TEXT PRIMARY KEY,
                timestamp    TEXT,
                source_ip    TEXT,
                alert_type   TEXT,
                severity     TEXT,
                status       TEXT DEFAULT 'New',
                description  TEXT,
                evidence     TEXT,
                username     TEXT,
                recommended_action TEXT,
                detection_method   TEXT,
                created_at   TEXT,
                updated_at   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);

            CREATE TABLE IF NOT EXISTS analysis_history (
                id            TEXT PRIMARY KEY,
                timestamp     TEXT,
                total_records INTEGER,
                threats_found INTEGER,
                dataset_name  TEXT,
                summary_json  TEXT,
                created_at    TEXT
            );
            CREATE TABLE IF NOT EXISTS settings (
                key        TEXT PRIMARY KEY,
                value      TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS alert_status_log (
                id         TEXT PRIMARY KEY,
                alert_id   TEXT,
                old_status TEXT,
                new_status TEXT,
                changed_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_status_log_alert ON alert_status_log(alert_id);
        """)
        self.conn.commit()

    # ── alerts ──────────────────────────────────────────────
    def save_alerts(self, alerts_df):
        """Batch upsert alerts from a DataFrame using executemany for high performance."""
        if alerts_df is None or alerts_df.empty:
            return
        cur = self.conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        records = []
        for row in alerts_df.to_dict('records'):
            aid = row.get("alert_id", str(uuid.uuid4()))
            records.append((
                str(aid),
                str(row.get("timestamp", "")),
                str(row.get("source_ip", "")),
                str(row.get("alert_type", "")),
                str(row.get("severity", "")),
                str(row.get("status", "New")),
                str(row.get("description", row.get("evidence", ""))),
                str(row.get("evidence", "")),
                str(row.get("username", "")),
                str(row.get("recommended_action", "")),
                str(row.get("detection_method", "rule-based")),
                now, now,
            ))
        cur.executemany("""
            INSERT OR REPLACE INTO alerts
                (id, timestamp, source_ip, alert_type, severity, status,
                 description, evidence, username, recommended_action,
                 detection_method, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, records)
        self.conn.commit()

    def get_alerts(self, filters: dict | None = None):
        """Return alerts as list of dicts, optionally filtered."""
        query = "SELECT * FROM alerts"
        params = []
        clauses = []
        if filters:
            if "severity" in filters and filters["severity"]:
                placeholders = ",".join("?" * len(filters["severity"]))
                clauses.append(f"severity IN ({placeholders})")
                params.extend(filters["severity"])
            if "status" in filters and filters["status"]:
                placeholders = ",".join("?" * len(filters["status"]))
                clauses.append(f"status IN ({placeholders})")
                params.extend(filters["status"])
            if "source_ip" in filters and filters["source_ip"]:
                clauses.append("source_ip LIKE ?")
                params.append(f"%{filters['source_ip']}%")
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY timestamp DESC"
        cur = self.conn.cursor()
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]

    def update_alert_status(self, alert_id: str, new_status: str):
        """Change an alert's status and log the change in an atomic transaction."""
        cur = self.conn.cursor()
        cur.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,))
        row = cur.fetchone()
        old_status = dict(row)["status"] if row else "Unknown"
        now = datetime.now(timezone.utc).isoformat()
        cur.execute("UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
                     (new_status, now, alert_id))
        cur.execute("""
            INSERT INTO alert_status_log (id, alert_id, old_status, new_status, changed_at)
            VALUES (?, ?, ?, ?, ?)
        """, (str(uuid.uuid4()), alert_id, old_status, new_status, now))
        self.conn.commit()

    def get_alert_status_history(self, alert_id: str):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM alert_status_log WHERE alert_id = ? ORDER BY changed_at DESC", (alert_id,))
        return [dict(r) for r in cur.fetchall()]

    def get_alert_counts(self) -> dict:
        cur = self.conn.cursor()
        cur.execute("SELECT status, COUNT(*) as cnt FROM alerts GROUP BY status")
        return {row["status"]: row["cnt"] for row in cur.fetchall()}

    # ── analysis history ────────────────────────────────────
    def save_analysis(self, summary: dict):
        cur = self.conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cur.execute("""
            INSERT INTO analysis_history (id, timestamp, total_records, threats_found,
                                          dataset_name, summary_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()), now,
            summary.get("total_records", 0),
            summary.get("threats_found", 0),
            summary.get("dataset_name", "uploaded"),
            json.dumps(summary),
            now,
        ))
        self.conn.commit()

    def get_analysis_history(self):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM analysis_history ORDER BY created_at DESC LIMIT 20")
        return [dict(r) for r in cur.fetchall()]

    # ── settings ────────────────────────────────────────────
    def save_setting(self, key: str, value):
        now = datetime.now(timezone.utc).isoformat()
        cur = self.conn.cursor()
        cur.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                     (key, json.dumps(value), now))
        self.conn.commit()

    def get_setting(self, key: str, default=None):
        cur = self.conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cur.fetchone()
        if row:
            try:
                return json.loads(dict(row)["value"])
            except (json.JSONDecodeError, KeyError):
                return default
        return default

    # ── cleanup ─────────────────────────────────────────────
    def close(self):
        if self.conn:
            self.conn.close()
