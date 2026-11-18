"""
SQLite Logger for WAF request events and analytics.
Implements the schema from Section 3.4 of WAF_Lab_Architecture.md.
"""

import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DEFAULT_DB_PATH = os.path.join(PROJECT_ROOT, "data", "waf_logs.db")


class WAFLogger:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS waf_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src_ip TEXT,
                    method TEXT,
                    path TEXT,
                    attack_type TEXT,
                    detection_source TEXT,
                    ml_score REAL,
                    action TEXT,
                    latency_ms REAL,
                    reason TEXT
                );
            """)
            conn.commit()

    def log_event(
        self,
        src_ip: str,
        method: str,
        path: str,
        attack_type: str,
        detection_source: str,
        ml_score: float,
        action: str,
        latency_ms: float,
        reason: str = ""
    ) -> int:
        timestamp = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO waf_logs (
                    timestamp, src_ip, method, path, attack_type,
                    detection_source, ml_score, action, latency_ms, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, src_ip, method, path, attack_type,
                detection_source, float(ml_score), action, float(latency_ms), reason
            ))
            conn.commit()
            return cursor.lastrowid

    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM waf_logs ORDER BY id DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
