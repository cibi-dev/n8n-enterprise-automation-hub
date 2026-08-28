"""Unit tests for models in n8n-osint-threat-feed-enricher."""

import pytest
from pydantic import ValidationError

from enricher.models import ThreatAdvisory, ThreatDigest, ThreatFeedSource


def test_threat_advisory_valid():
    adv = ThreatAdvisory(
        id="CVE-2026-9999",
        title="Critical RCE in Web Framework",
        description="Remote code execution vulnerability via unsanitized parameter",
        source_feed=ThreatFeedSource.CISA_KEV,
        cve_id="CVE-2026-9999",
        cvss_score=9.8,
        is_known_exploited=True,
        ransomware_campaign="LockBit 4.0",
        raw_hash="a" * 64,
    )
    assert adv.id == "CVE-2026-9999"
    assert adv.is_known_exploited is True
    assert adv.ransomware_campaign == "LockBit 4.0"


def test_threat_advisory_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        ThreatAdvisory(
            id="1",
            title="T",
            description="D",
            raw_hash="a" * 64,
            injected_field="illegal",  # type: ignore
        )


def test_threat_advisory_invalid_cve():
    with pytest.raises(ValidationError) as exc:
        ThreatAdvisory(
            id="1",
            title="T",
            description="D",
            cve_id="VULN-2026-1",
            raw_hash="a" * 64,
        )
    assert "Invalid CVE identifier" in str(exc.value)


def test_threat_advisory_none_cve():
    adv = ThreatAdvisory(
        id="adv-01",
        title="Generic Advisory",
        description="No CVE assigned yet",
        cve_id=None,
        raw_hash="0" * 64,
    )
    assert adv.cve_id is None


def test_threat_advisory_cvss_bounds():
    with pytest.raises(ValidationError):
        ThreatAdvisory(
            id="1",
            title="T",
            description="D",
            cvss_score=11.0,  # Out of bounds (>10.0)
            raw_hash="a" * 64,
        )

    with pytest.raises(ValidationError):
        ThreatAdvisory(
            id="1",
            title="T",
            description="D",
            cvss_score=-1.0,  # Out of bounds (<0.0)
            raw_hash="a" * 64,
        )


def test_threat_digest_valid():
    digest = ThreatDigest(
        advisories=[],
        total_ingested=10,
        unique_count=8,
        duplicate_count=2,
        critical_count=1,
    )
    assert digest.total_ingested == 10
    assert digest.unique_count == 8
    assert digest.duplicate_count == 2
