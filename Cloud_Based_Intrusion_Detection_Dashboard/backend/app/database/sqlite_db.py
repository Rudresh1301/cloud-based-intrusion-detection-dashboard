import sqlite3
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

log = logging.getLogger(__name__)

class SQLiteDatabase:
    """Thread-safe SQLite store providing full local fallback matching Firestore collections."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        conn = self._get_connection()
        cur = conn.cursor()
        cur.executescript("""
            -- 1. Security Logs
            CREATE TABLE IF NOT EXISTS security_logs (
                id             TEXT PRIMARY KEY,
                timestamp      TEXT NOT NULL,
                source_ip      TEXT NOT NULL,
                username       TEXT,
                event_type     TEXT NOT NULL,
                status         TEXT NOT NULL,
                endpoint       TEXT NOT NULL,
                classification TEXT DEFAULT 'Normal',
                risk_score     INTEGER DEFAULT 0,
                created_at     TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON security_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_logs_ip ON security_logs(source_ip);
            CREATE INDEX IF NOT EXISTS idx_logs_class ON security_logs(classification);

            -- 2. Threat Alerts
            CREATE TABLE IF NOT EXISTS threat_alerts (
                id                 TEXT PRIMARY KEY,
                timestamp          TEXT NOT NULL,
                source_ip          TEXT NOT NULL,
                username           TEXT,
                alert_type         TEXT NOT NULL,
                severity           TEXT NOT NULL,
                status             TEXT DEFAULT 'New',
                description        TEXT,
                evidence           TEXT,
                recommended_action TEXT,
                detection_method   TEXT DEFAULT 'rule-based',
                risk_score         INTEGER DEFAULT 50,
                created_at         TEXT NOT NULL,
                updated_at         TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON threat_alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_ip ON threat_alerts(source_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_sev ON threat_alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON threat_alerts(status);

            -- 3. IP Intelligence
            CREATE TABLE IF NOT EXISTS ip_intelligence (
                ip_address         TEXT PRIMARY KEY,
                total_events       INTEGER DEFAULT 0,
                suspicious_events  INTEGER DEFAULT 0,
                attack_categories  TEXT, -- JSON list
                risk_score         INTEGER DEFAULT 0,
                first_observed     TEXT,
                last_observed      TEXT,
                threat_status      TEXT DEFAULT 'Clean',
                country            TEXT DEFAULT 'Local/Private',
                country_code       TEXT DEFAULT 'LOC',
                city               TEXT DEFAULT 'Internal Network',
                isp                TEXT DEFAULT 'Enterprise Gateway',
                latitude           REAL,
                longitude          REAL,
                updated_at         TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ip_risk ON ip_intelligence(risk_score);

            -- 4. Analysis History
            CREATE TABLE IF NOT EXISTS analysis_history (
                id             TEXT PRIMARY KEY,
                timestamp      TEXT NOT NULL,
                filename       TEXT NOT NULL,
                total_records  INTEGER NOT NULL,
                threats_found  INTEGER NOT NULL,
                suspicious_ips INTEGER NOT NULL,
                risk_level     TEXT NOT NULL,
                storage_url    TEXT,
                summary_json   TEXT,
                created_at     TEXT NOT NULL
            );

            -- 5. User Settings
            CREATE TABLE IF NOT EXISTS user_settings (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            -- 6. Generated Reports
            CREATE TABLE IF NOT EXISTS reports (
                id            TEXT PRIMARY KEY,
                filename      TEXT NOT NULL,
                generated_at  TEXT NOT NULL,
                total_events  INTEGER NOT NULL,
                threats_found INTEGER NOT NULL,
                risk_level    TEXT NOT NULL,
                file_path     TEXT NOT NULL,
                storage_type  TEXT NOT NULL
            );
        """)
        conn.commit()
        conn.close()

    # --- Logs ---
    def save_logs(self, logs: List[Dict[str, Any]]) -> int:
        if not logs:
            return 0
        conn = self._get_connection()
        cur = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        inserted = 0
        for log_item in logs:
            cur.execute("""
                INSERT OR IGNORE INTO security_logs 
                (id, timestamp, source_ip, username, event_type, status, endpoint, classification, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_item["id"],
                str(log_item["timestamp"]),
                str(log_item["source_ip"]),
                str(log_item.get("username", "")),
                str(log_item["event_type"]),
                str(log_item["status"]),
                str(log_item["endpoint"]),
                str(log_item.get("classification", "Normal")),
                int(log_item.get("risk_score", 0)),
                now
            ))
            if cur.rowcount > 0:
                inserted += 1
        conn.commit()
        conn.close()
        return inserted

    def get_logs(self, page: int = 1, page_size: int = 50, search: str = "", classification: str = "") -> Dict[str, Any]:
        conn = self._get_connection()
        cur = conn.cursor()
        offset = (page - 1) * page_size
        query = "SELECT * FROM security_logs WHERE 1=1"
        params = []
        if search:
            query += " AND (source_ip LIKE ? OR username LIKE ? OR endpoint LIKE ? OR event_type LIKE ?)"
            s_param = f"%{search}%"
            params.extend([s_param, s_param, s_param, s_param])
        if classification and classification.lower() != "all":
            query += " AND classification = ?"
            params.append(classification)

        # Count total
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cur.execute(count_query, params)
        total = cur.fetchone()[0]

        # Get items
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([page_size, offset])
        cur.execute(query, params)
        rows = [dict(row) for row in cur.fetchall()]
        conn.close()
        return {"items": rows, "total": total, "page": page, "page_size": page_size}

    # --- Alerts ---
    def save_alerts(self, alerts: List[Dict[str, Any]]) -> int:
        if not alerts:
            return 0
        conn = self._get_connection()
        cur = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        inserted = 0
        for alert in alerts:
            cur.execute("""
                INSERT OR IGNORE INTO threat_alerts
                (id, timestamp, source_ip, username, alert_type, severity, status, description, evidence, recommended_action, detection_method, risk_score, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["id"],
                str(alert["timestamp"]),
                str(alert["source_ip"]),
                str(alert.get("username", "unknown")),
                str(alert["alert_type"]),
                str(alert["severity"]),
                str(alert.get("status", "New")),
                str(alert.get("description", "")),
                str(alert.get("evidence", "")),
                str(alert.get("recommended_action", "")),
                str(alert.get("detection_method", "rule-based")),
                int(alert.get("risk_score", 50)),
                now,
                now
            ))
            if cur.rowcount > 0:
                inserted += 1
        conn.commit()
        conn.close()
        return inserted

    def get_alerts(self, page: int = 1, page_size: int = 50, severity: str = "", status: str = "", search: str = "") -> Dict[str, Any]:
        conn = self._get_connection()
        cur = conn.cursor()
        offset = (page - 1) * page_size
        query = "SELECT * FROM threat_alerts WHERE 1=1"
        params = []
        if severity and severity.lower() != "all":
            query += " AND severity = ?"
            params.append(severity)
        if status and status.lower() != "all":
            query += " AND status = ?"
            params.append(status)
        if search:
            query += " AND (source_ip LIKE ? OR alert_type LIKE ? OR evidence LIKE ?)"
            s_param = f"%{search}%"
            params.extend([s_param, s_param, s_param])

        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cur.execute(count_query, params)
        total = cur.fetchone()[0]

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([page_size, offset])
        cur.execute(query, params)
        rows = [dict(row) for row in cur.fetchall()]
        conn.close()
        return {"items": rows, "total": total, "page": page, "page_size": page_size}

    def update_alert_status(self, alert_id: str, new_status: str) -> bool:
        conn = self._get_connection()
        cur = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cur.execute("UPDATE threat_alerts SET status = ?, updated_at = ? WHERE id = ?", (new_status, now, alert_id))
        success = cur.rowcount > 0
        conn.commit()
        conn.close()
        return success

    # --- IP Intelligence ---
    def save_ip_intel(self, ip_data_list: List[Dict[str, Any]]):
        if not ip_data_list:
            return
        conn = self._get_connection()
        cur = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        for item in ip_data_list:
            cats = json.dumps(item.get("attack_categories", []))
            cur.execute("""
                INSERT INTO ip_intelligence
                (ip_address, total_events, suspicious_events, attack_categories, risk_score, first_observed, last_observed, threat_status, country, country_code, city, isp, latitude, longitude, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    total_events = excluded.total_events,
                    suspicious_events = excluded.suspicious_events,
                    attack_categories = excluded.attack_categories,
                    risk_score = excluded.risk_score,
                    last_observed = excluded.last_observed,
                    threat_status = excluded.threat_status,
                    updated_at = excluded.updated_at
            """, (
                str(item["ip_address"]),
                int(item.get("total_events", 0)),
                int(item.get("suspicious_events", 0)),
                cats,
                int(item.get("risk_score", 0)),
                str(item.get("first_observed", "")),
                str(item.get("last_observed", "")),
                str(item.get("threat_status", "Clean")),
                str(item.get("country", "Local/Private")),
                str(item.get("country_code", "LOC")),
                str(item.get("city", "Internal Network")),
                str(item.get("isp", "Enterprise Gateway")),
                item.get("latitude"),
                item.get("longitude"),
                now
            ))
        conn.commit()
        conn.close()

    def get_ip_intel_list(self, search: str = "", threat_status: str = "") -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.cursor()
        query = "SELECT * FROM ip_intelligence WHERE 1=1"
        params = []
        if search:
            query += " AND ip_address LIKE ?"
            params.append(f"%{search}%")
        if threat_status and threat_status.lower() != "all":
            query += " AND threat_status = ?"
            params.append(threat_status)
        query += " ORDER BY risk_score DESC, suspicious_events DESC"
        cur.execute(query, params)
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            try:
                d["attack_categories"] = json.loads(d.get("attack_categories") or "[]")
            except Exception:
                d["attack_categories"] = []
            rows.append(d)
        conn.close()
        return rows

    # --- Analysis History ---
    def save_analysis_history(self, history: Dict[str, Any]):
        conn = self._get_connection()
        cur = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cur.execute("""
            INSERT INTO analysis_history 
            (id, timestamp, filename, total_records, threats_found, suspicious_ips, risk_level, storage_url, summary_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(history["id"]),
            str(history.get("timestamp", now)),
            str(history.get("filename", "unknown.csv")),
            int(history.get("total_records", 0)),
            int(history.get("threats_found", 0)),
            int(history.get("suspicious_ips", 0)),
            str(history.get("risk_level", "LOW RISK")),
            str(history.get("storage_url", "")),
            json.dumps(history.get("summary", {})),
            now
        ))
        conn.commit()
        conn.close()

    def get_analysis_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM analysis_history ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    # --- Reports ---
    def save_report(self, report: Dict[str, Any]):
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO reports (id, filename, generated_at, total_events, threats_found, risk_level, file_path, storage_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report["id"],
            report["filename"],
            report["generated_at"],
            report["total_events"],
            report["threats_found"],
            report["risk_level"],
            report["file_path"],
            report["storage_type"]
        ))
        conn.commit()
        conn.close()

    def get_reports(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM reports ORDER BY generated_at DESC")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    # --- Settings ---
    def get_setting(self, key: str, default: Any = None) -> Any:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT value FROM user_settings WHERE key = ?", (key,))
        row = cur.fetchone()
        conn.close()
        if row:
            try:
                return json.loads(row[0])
            except Exception:
                return row[0]
        return default

    def set_setting(self, key: str, value: Any):
        conn = self._get_connection()
        cur = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cur.execute("""
            INSERT INTO user_settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """, (key, json.dumps(value), now))
        conn.commit()
        conn.close()

    # --- Cleanup ---
    def clear_all(self):
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM security_logs")
        cur.execute("DELETE FROM threat_alerts")
        cur.execute("DELETE FROM ip_intelligence")
        cur.execute("DELETE FROM analysis_history")
        conn.commit()
        conn.close()
