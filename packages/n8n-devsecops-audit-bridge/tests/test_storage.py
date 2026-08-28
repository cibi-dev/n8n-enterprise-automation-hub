"""Unit tests for SQLite transactional storage in n8n-devsecops-audit-bridge."""

import pytest

from bridge.models import (
    AuditFinding,
    AuditPayload,
    SBOMComponent,
    SeverityLevel,
)
from bridge.storage import AuditStorage


def test_storage_record_compliant_audit():
    storage = AuditStorage(db_path=":memory:")

    payload = AuditPayload(
        repository="cibi-dev/secure-repo",
        commit_sha="abcdef1234567890abcdef1234567890abcdef12",
        pipeline_id="pipe-101",
        findings=[
            AuditFinding(
                rule_id="INFO_01",
                message="Informative rule",
                severity=SeverityLevel.INFO,
                file_path="src/main.py",
                start_line=1,
            )
        ],
        components=[
            SBOMComponent(name="pytest", version="8.3.0", licenses=["MIT"])
        ],
    )

    result = storage.record_audit(payload, signature_valid=True)
    assert result.is_compliant is True
    assert result.signature_valid is True
    assert result.total_findings == 1
    assert result.critical_count == 0
    assert result.high_count == 0
    assert result.total_components == 1
    assert len(result.merkle_leaf_hash) == 64
    assert result.storage_id is not None

    # Retrieve and verify database record
    rec = storage.get_record(result.storage_id)
    assert rec is not None
    assert rec["repository"] == "cibi-dev/secure-repo"
    assert rec["is_compliant"] == 1


def test_storage_record_non_compliant_critical_finding():
    storage = AuditStorage(db_path=":memory:")

    payload = AuditPayload(
        repository="cibi-dev/vulnerable-repo",
        commit_sha="1122334455667788990011223344556677889900",
        pipeline_id="pipe-102",
        findings=[
            AuditFinding(
                rule_id="B602",
                message="Subprocess call with shell=True",
                severity=SeverityLevel.HIGH,
                file_path="src/runner.py",
                start_line=50,
                cwe_ids=[78],
            )
        ],
        components=[],
    )

    result = storage.record_audit(payload, signature_valid=True)
    assert result.is_compliant is False
    assert result.high_count == 1
    assert "FAILED" in result.summary


def test_storage_record_invalid_signature_fails_compliance():
    storage = AuditStorage(db_path=":memory:")

    payload = AuditPayload(
        repository="cibi-dev/unauthorized-repo",
        commit_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pipeline_id="pipe-103",
        findings=[],
        components=[],
    )

    result = storage.record_audit(payload, signature_valid=False)
    assert result.is_compliant is False
    assert result.signature_valid is False


def test_compute_merkle_leaf_hash_deterministic():
    payload1 = AuditPayload(
        repository="cibi-dev/repo-a",
        commit_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        pipeline_id="pipe-1",
        findings=[],
        components=[],
        timestamp="2026-08-28T12:00:00Z",
    )
    payload2 = AuditPayload(
        repository="cibi-dev/repo-a",
        commit_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        pipeline_id="pipe-1",
        findings=[],
        components=[],
        timestamp="2026-08-28T12:00:00Z",
    )

    hash1 = AuditStorage.compute_merkle_leaf_hash(payload1)
    hash2 = AuditStorage.compute_merkle_leaf_hash(payload2)
    assert hash1 == hash2


def test_storage_get_nonexistent_record():
    storage = AuditStorage(db_path=":memory:")
    assert storage.get_record("nonexistent-id") is None
