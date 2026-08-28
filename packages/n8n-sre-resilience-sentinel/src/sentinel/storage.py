"""Transactional SQLite Storage Engine for SRE Health States & Rollback Audits."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from sentinel.models import ProbeSample, RollbackAction, ServiceHealthState, utcnow_iso


class SREHealthStorage:
    """Persistent SQLite database manager for health states and rollback logs."""

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
                CREATE TABLE IF NOT EXISTS service_health (
                    service_name TEXT PRIMARY KEY,
                    consecutive_failures INTEGER NOT NULL,
                    is_degraded INTEGER NOT NULL,
                    active_slot TEXT NOT NULL,
                    last_sample_json TEXT,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS rollback_history (
                    action_id TEXT PRIMARY KEY,
                    service_name TEXT NOT NULL,
                    previous_slot TEXT NOT NULL,
                    target_slot TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    execution_time_ms REAL NOT NULL,
                    success INTEGER NOT NULL,
                    timestamp TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rollback_service ON rollback_history(service_name);
            """)

    def get_health_state(self, service_name: str) -> ServiceHealthState:
        """Retrieve current health state for a service, or initialize a default state."""
        with self._lock, self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM service_health WHERE service_name = ?", (service_name,)
            ).fetchone()
            if not row:
                return ServiceHealthState(service_name=service_name)

            sample_obj = None
            if row["last_sample_json"]:
                sample_dict = json.loads(row["last_sample_json"])
                sample_obj = ProbeSample.model_validate(sample_dict)

            return ServiceHealthState(
                service_name=row["service_name"],
                consecutive_failures=row["consecutive_failures"],
                is_degraded=bool(row["is_degraded"]),
                active_slot=row["active_slot"],
                last_sample=sample_obj,
                updated_at=row["updated_at"],
            )

    def record_probe_sample(
        self, sample: ProbeSample, failure_threshold: int = 3
    ) -> ServiceHealthState:
        """Update service health tracking state based on new probe sample."""
        current = self.get_health_state(sample.service_name)

        if sample.is_healthy:
            new_failures = 0
            is_degraded = False
        else:
            new_failures = current.consecutive_failures + 1
            is_degraded = new_failures >= failure_threshold

        updated_state = ServiceHealthState(
            service_name=sample.service_name,
            consecutive_failures=new_failures,
            is_degraded=is_degraded,
            active_slot=current.active_slot,
            last_sample=sample,
            updated_at=utcnow_iso(),
        )

        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO service_health (
                    service_name, consecutive_failures, is_degraded, active_slot,
                    last_sample_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    updated_state.service_name,
                    updated_state.consecutive_failures,
                    1 if updated_state.is_degraded else 0,
                    updated_state.active_slot,
                    json.dumps(sample.model_dump()),
                    updated_state.updated_at,
                ),
            )

        return updated_state

    def record_rollback(self, action: RollbackAction) -> None:
        """Store rollback execution audit entry and update active slot in health state."""
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO rollback_history (
                    action_id, service_name, previous_slot, target_slot, reason,
                    execution_time_ms, success, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action.action_id,
                    action.service_name,
                    action.previous_slot,
                    action.target_slot,
                    action.reason,
                    action.execution_time_ms,
                    1 if action.success else 0,
                    action.timestamp,
                ),
            )
            # Update active slot in service_health table
            if action.success:
                conn.execute(
                    """
                    INSERT INTO service_health (
                        service_name, consecutive_failures, is_degraded, active_slot,
                        last_sample_json, updated_at
                    ) VALUES (?, 0, 0, ?, NULL, ?)
                    ON CONFLICT(service_name) DO UPDATE SET
                        active_slot = excluded.active_slot,
                        consecutive_failures = 0,
                        is_degraded = 0,
                        updated_at = excluded.updated_at
                    """,
                    (action.service_name, action.target_slot, action.timestamp),
                )

    def get_rollbacks(self, service_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve historical rollback audit records."""
        with self._lock, self._get_connection() as conn:
            if service_name:
                rows = conn.execute(
                    "SELECT * FROM rollback_history WHERE service_name = ? ORDER BY timestamp DESC",
                    (service_name,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM rollback_history ORDER BY timestamp DESC"
                ).fetchall()
            return [dict(r) for r in rows]
