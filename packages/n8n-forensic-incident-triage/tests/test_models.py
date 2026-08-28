"""Unit tests for domain models in n8n-forensic-incident-triage."""

import pytest
from pydantic import ValidationError

from triage.models import CrimeCategory, IncidentPriority, SanitizedIncidentReport


def test_sanitized_incident_report_valid():
    report = SanitizedIncidentReport(
        incident_id="INC-2026-001",
        title="Ransomware attack on production DB",
        sanitized_text="Production server encrypted by threat actor [REDACTED_EMAIL]",
        redacted_pii_counts={"email": 1},
        crime_category=CrimeCategory.RANSOMWARE_EXTORTION,
        priority=IncidentPriority.CRITICAL,
        custody_sha256="c" * 64,
        affected_assets=["db.internal.corp"],
        suspect_indicators=["@lockbit_operator"],
    )
    assert report.incident_id == "INC-2026-001"
    assert report.crime_category == CrimeCategory.RANSOMWARE_EXTORTION
    assert report.priority == IncidentPriority.CRITICAL
    assert report.redacted_pii_counts["email"] == 1


def test_sanitized_incident_report_extra_forbidden():
    with pytest.raises(ValidationError):
        SanitizedIncidentReport(
            incident_id="INC-1",
            title="T",
            sanitized_text="S",
            custody_sha256="c" * 64,
            injected="malicious",  # type: ignore
        )


def test_crime_category_enum_values():
    assert CrimeCategory.UNAUTHORIZED_ACCESS.value == "unauthorized_access"
    assert CrimeCategory.DATA_THEFT.value == "data_theft"
    assert CrimeCategory.DOS_ATTACK.value == "dos_attack"


def test_incident_priority_enum_values():
    assert IncidentPriority.CRITICAL.value == "critical"
    assert IncidentPriority.LOW.value == "low"
