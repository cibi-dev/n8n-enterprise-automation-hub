"""Transactional SQLite Storage Engine for Forensic Triage Records."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from typing import Any, Dict, List, Optional

from triage.models import CrimeCategory, IncidentPriority, SanitizedIncidentReport, utcnow_iso


class ForensicTriageStorage:
    """Persistent SQLite database manager for forensic triage records."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS forensic_incidents (
                    storage_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL,
                    sanitized_text TEXT NOT NULL,
                    pii_counts_json TEXT NOT NULL,
                    crime_category TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    custody_sha256 TEXT NOT NULL,
                    affected_assets_json TEXT NOT NULL,
                    suspect_indicators_json TEXT NOT NULL,
                    reported_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_incident_category ON forensic_incidents(crime_category);
                CREATE INDEX IF NOT EXISTS idx_incident_priority ON forensic_incidents(priority);
                CREATE INDEX IF NOT EXISTS idx_incident_custody ON forensic_incidents(custody_sha256);
            """)

    def save_incident(self, report: SanitizedIncidentReport) -> SanitizedIncidentReport:
        """Store sanitized report and return report with populated storage_id."""
        storage_id = f"triage-{uuid.uuid4().hex[:12]}"
        created_at = utcnow_iso()

        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO forensic_incidents (
                    storage_id, incident_id, title, sanitized_text, pii_counts_json,
                    crime_category, priority, custody_sha256, affected_assets_json,
                    suspect_indicators_json, reported_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    storage_id,
                    report.incident_id,
                    report.title,
                    report.sanitized_text,
                    json.dumps(report.redacted_pii_counts),
                    report.crime_category.value,
                    report.priority.value,
                    report.custody_sha256,
                    json.dumps(report.affected_assets),
                    json.dumps(report.suspect_indicators),
                    report.reported_at,
                    created_at,
                ),
            )

        return SanitizedIncidentReport(
            incident_id=report.incident_id,
            title=report.title,
            sanitized_text=report.sanitized_text,
            redacted_pii_counts=report.redacted_pii_counts,
            crime_category=report.crime_category,
            priority=report.priority,
            custody_sha256=report.custody_sha256,
            affected_assets=report.affected_assets,
            suspect_indicators=report.suspect_indicators,
            reported_at=report.reported_at,
            storage_id=storage_id,
        )

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored incident by its incident_id."""
        with self._lock, self._get_connection() as conn:
            row = conn.execute("SELECT * FROM forensic_incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if not row:
                return None
            return dict(row)

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate triage incident statistics by category and priority."""
        with self._lock, self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM forensic_incidents").fetchone()[0]
            cat_rows = conn.execute("SELECT crime_category, COUNT(*) FROM forensic_incidents GROUP BY crime_category").fetchall()
            prio_rows = conn.execute("SELECT priority, COUNT(*) FROM forensic_incidents GROUP BY priority").fetchall()

            return {
                "total_incidents": total,
                "by_category": {r[0]: r[1] for r in cat_rows},
                "by_priority": {r[0]: r[1] for r in prio_rows},
            }
