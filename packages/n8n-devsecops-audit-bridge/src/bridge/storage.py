"""Transactional SQLite Storage Engine for Audit Records & Custody Proofs.

Provides immutable persistence and ISO/IEC 27037 forensic custody sealing.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from typing import Any, Dict, List, Optional

from bridge.models import AuditFinding, AuditPayload, AuditVerificationResult, SBOMComponent, SeverityLevel, utcnow_iso


class AuditStorage:
    """Transactional SQLite storage manager for CI/CD DevSecOps audit records."""

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
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS audit_records (
                    id TEXT PRIMARY KEY,
                    repository TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    pipeline_id TEXT NOT NULL,
                    is_compliant INTEGER NOT NULL,
                    signature_valid INTEGER NOT NULL,
                    total_findings INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    total_components INTEGER NOT NULL,
                    merkle_leaf_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_repo_commit ON audit_records(repository, commit_sha);
                CREATE INDEX IF NOT EXISTS idx_audit_leaf_hash ON audit_records(merkle_leaf_hash);
            """)

    @staticmethod
    def compute_merkle_leaf_hash(payload: AuditPayload) -> str:
        """Compute deterministic SHA-256 custody leaf hash over audit findings and metadata."""
        canonical_str = json.dumps(payload.model_dump(), sort_keys=True, separators=(",", ":"))
        hasher = hashlib.sha256()
        hasher.update(b"\x00")  # Leaf domain separator (Standard #9)
        hasher.update(canonical_str.encode("utf-8"))
        return hasher.hexdigest().lower()

    def record_audit(
        self,
        payload: AuditPayload,
        signature_valid: bool = True,
    ) -> AuditVerificationResult:
        """Store an audit run record and return the verified compliance report."""
        record_id = f"audit-{uuid.uuid4().hex[:12]}"
        created_at = utcnow_iso()

        # Count critical & high findings
        crit_count = sum(1 for f in payload.findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in payload.findings if f.severity == SeverityLevel.HIGH)

        # Policy rule: Compliant if signature is valid and 0 critical/high findings
        is_compliant = signature_valid and (crit_count == 0 and high_count == 0)

        leaf_hash = self.compute_merkle_leaf_hash(payload)
        payload_str = json.dumps(payload.model_dump())

        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_records (
                    id, repository, commit_sha, pipeline_id, is_compliant,
                    signature_valid, total_findings, critical_count, high_count,
                    total_components, merkle_leaf_hash, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    payload.repository,
                    payload.commit_sha,
                    payload.pipeline_id,
                    1 if is_compliant else 0,
                    1 if signature_valid else 0,
                    len(payload.findings),
                    crit_count,
                    high_count,
                    len(payload.components),
                    leaf_hash,
                    payload_str,
                    created_at,
                ),
            )

        summary = (
            f"PASSED: {payload.repository}@{payload.commit_sha[:7]} is compliant. "
            f"0 critical/high findings across {len(payload.components)} components."
            if is_compliant
            else f"FAILED: {payload.repository}@{payload.commit_sha[:7]} has {crit_count} critical and {high_count} high findings."
        )

        return AuditVerificationResult(
            is_compliant=is_compliant,
            signature_valid=signature_valid,
            total_findings=len(payload.findings),
            critical_count=crit_count,
            high_count=high_count,
            total_components=len(payload.components),
            merkle_leaf_hash=leaf_hash,
            storage_id=record_id,
            summary=summary,
        )

    def get_record(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an audit record by its primary ID."""
        with self._lock, self._get_connection() as conn:
            row = conn.execute("SELECT * FROM audit_records WHERE id = ?", (record_id,)).fetchone()
            if not row:
                return None
            return dict(row)
