"""Unit tests for models in n8n-devsecops-audit-bridge."""

import pytest
from pydantic import ValidationError

from bridge.models import (
    AuditFinding,
    AuditPayload,
    AuditVerificationResult,
    SBOMComponent,
    SeverityLevel,
)


def test_audit_finding_valid():
    finding = AuditFinding(
        rule_id="B101",
        message="Use of assert detected",
        severity=SeverityLevel.LOW,
        file_path="src/main.py",
        start_line=42,
        cwe_ids=[703],
        scanner_name="bandit",
    )
    assert finding.rule_id == "B101"
    assert finding.severity == SeverityLevel.LOW
    assert finding.cwe_ids == [703]


def test_audit_finding_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        AuditFinding(
            rule_id="B101",
            message="Test",
            file_path="test.py",
            injected_field="malicious",  # type: ignore
        )


def test_sbom_component_valid():
    comp = SBOMComponent(
        name="pydantic",
        version="2.8.2",
        purl="pkg:pypi/pydantic@2.8.2",
        component_type="library",
        licenses=["MIT"],
    )
    assert comp.name == "pydantic"
    assert comp.licenses == ["MIT"]


def test_sbom_component_extra_forbidden():
    with pytest.raises(ValidationError):
        SBOMComponent(
            name="pydantic",
            version="2.8.2",
            unknown_arg="extra",  # type: ignore
        )


def test_audit_payload_validation():
    payload = AuditPayload(
        repository="cibi-dev/test-repo",
        commit_sha="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        pipeline_id="run-9988",
        findings=[],
        components=[],
    )
    assert payload.repository == "cibi-dev/test-repo"
    assert len(payload.commit_sha) == 40


def test_audit_payload_invalid_sha():
    with pytest.raises(ValidationError):
        AuditPayload(
            repository="cibi-dev/test-repo",
            commit_sha="invalid_sha_with_non_hex_symbols!",
            pipeline_id="run-1",
        )


def test_verification_result_model():
    res = AuditVerificationResult(
        is_compliant=True,
        signature_valid=True,
        total_findings=0,
        critical_count=0,
        high_count=0,
        total_components=15,
        merkle_leaf_hash="a" * 64,
        storage_id="audit-1234",
        summary="All tests passing",
    )
    assert res.is_compliant is True
    assert res.total_components == 15
