"""Unit tests for SQLite storage and statistics in n8n-forensic-incident-triage."""

import pytest

from triage.classifier import process_incident_triage
from triage.models import CrimeCategory, IncidentPriority
from triage.storage import ForensicTriageStorage


def test_storage_save_and_retrieve():
    storage = ForensicTriageStorage(":memory:")

    report = process_incident_triage(
        raw_text="Extortion attack with LockBit encryptor demanding ransom.",
        incident_id="INC-100",
        title="Ransomware Test",
    )

    saved = storage.save_incident(report)
    assert saved.storage_id is not None

    retrieved = storage.get_incident("INC-100")
    assert retrieved is not None
    assert retrieved["incident_id"] == "INC-100"
    assert retrieved["crime_category"] == CrimeCategory.RANSOMWARE_EXTORTION.value
    assert retrieved["priority"] == IncidentPriority.CRITICAL.value


def test_storage_get_nonexistent():
    storage = ForensicTriageStorage(":memory:")
    assert storage.get_incident("NONEXISTENT") is None


def test_storage_stats():
    storage = ForensicTriageStorage(":memory:")

    r1 = process_incident_triage("LockBit ransomware attack", "INC-01")
    r2 = process_incident_triage("Confidential leak data breach", "INC-02")
    r3 = process_incident_triage("Routine server restart failure", "INC-03")

    storage.save_incident(r1)
    storage.save_incident(r2)
    storage.save_incident(r3)

    stats = storage.get_stats()
    assert stats["total_incidents"] == 3
    assert stats["by_category"]["ransomware_extortion"] == 1
    assert stats["by_category"]["data_theft"] == 1
    assert stats["by_category"]["other"] == 1
    assert stats["by_priority"]["critical"] == 2
    assert stats["by_priority"]["low"] == 1
