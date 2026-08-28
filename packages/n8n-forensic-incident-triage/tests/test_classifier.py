"""Unit tests for penal classification and custody sealing in n8n-forensic-incident-triage."""

import pytest

from triage.classifier import (
    classify_crime_category,
    compute_custody_hash,
    extract_assets_and_indicators,
    process_incident_triage,
)
from triage.models import CrimeCategory, IncidentPriority


def test_classify_ransomware():
    text = "Threat group deployed LockBit ransomware and encrypted all database files demanding Bitcoin."
    cat, prio = classify_crime_category(text)
    assert cat == CrimeCategory.RANSOMWARE_EXTORTION
    assert prio == IncidentPriority.CRITICAL


def test_classify_data_theft():
    text = "Evidence of confidential data breach with customer database dump exfiltrated to paste site."
    cat, prio = classify_crime_category(text)
    assert cat == CrimeCategory.DATA_THEFT
    assert prio == IncidentPriority.CRITICAL


def test_classify_unauthorized_access():
    text = "Attacker performed SSH brute force and gained unauthorized access via webshell backdoor."
    cat, prio = classify_crime_category(text)
    assert cat == CrimeCategory.UNAUTHORIZED_ACCESS
    assert prio == IncidentPriority.HIGH


def test_classify_financial_scam():
    text = "Employee fell for CEO fraud phishing email resulting in fraudulent wire transfer."
    cat, prio = classify_crime_category(text)
    assert cat == CrimeCategory.FINANCIAL_SCAM
    assert prio == IncidentPriority.HIGH


def test_classify_dos_attack():
    text = "Massive SYN flood botnet attack caused denial of service across edge load balancers."
    cat, prio = classify_crime_category(text)
    assert cat == CrimeCategory.DOS_ATTACK
    assert prio == IncidentPriority.HIGH


def test_classify_identity_fraud():
    text = "Suspect created cloned account and committed identity theft on social platform."
    cat, prio = classify_crime_category(text)
    assert cat == CrimeCategory.IDENTITY_FRAUD
    assert prio == IncidentPriority.MEDIUM


def test_classify_malware_distribution():
    text = "Infected USB drive executed dropper payload establishing C2 command and control beacon."
    cat, prio = classify_crime_category(text)
    assert cat == CrimeCategory.MALWARE_DISTRIBUTION
    assert prio == IncidentPriority.MEDIUM


def test_classify_other_generic():
    text = "Routine system update failed due to disk space shortage."
    cat, prio = classify_crime_category(text)
    assert cat == CrimeCategory.OTHER
    assert prio == IncidentPriority.LOW


def test_extract_assets_and_indicators():
    text = "Attack targeted auth.corp.internal and api.payments.com by suspect @shadow_broker"
    assets, indicators = extract_assets_and_indicators(text)
    assert "auth.corp.internal" in assets
    assert "api.payments.com" in assets
    assert "@shadow_broker" in indicators


def test_compute_custody_hash_deterministic():
    h1 = compute_custody_hash("Incident description", "INC-01", "2026-08-28T12:00:00Z")
    h2 = compute_custody_hash("Incident description", "INC-01", "2026-08-28T12:00:00Z")
    assert h1 == h2
    assert len(h1) == 64


def test_process_incident_triage_full_pipeline():
    raw_text = (
        "Attacker at 10.0.0.5 emailed victim@corp.com demanding Bitcoin after encrypting db.prod.internal. "
        "Threat actor handle is @dark_extortionist"
    )
    report = process_incident_triage(raw_text, incident_id="INC-999", title="Critical Ransomware")

    assert report.incident_id == "INC-999"
    assert report.crime_category == CrimeCategory.RANSOMWARE_EXTORTION
    assert report.priority == IncidentPriority.CRITICAL
    assert "[REDACTED_IP]" in report.sanitized_text
    assert "[REDACTED_EMAIL]" in report.sanitized_text
    assert "10.0.0.5" not in report.sanitized_text
    assert "@dark_extortionist" in report.suspect_indicators
    assert "db.prod.internal" in report.affected_assets
    assert len(report.custody_sha256) == 64
