"""Unit tests for Obsidian and Telegram formatters in n8n-osint-threat-feed-enricher."""

import pytest

from enricher.formatter import format_obsidian_digest, format_telegram_alert
from enricher.models import ThreatAdvisory, ThreatDigest, ThreatFeedSource


def test_format_obsidian_digest():
    adv = ThreatAdvisory(
        id="CVE-2026-0001",
        title="Linux Kernel Privilege Escalation",
        description="Local privilege escalation via io_uring",
        source_feed=ThreatFeedSource.CISA_KEV,
        cve_id="CVE-2026-0001",
        cvss_score=8.8,
        is_known_exploited=True,
        ransomware_campaign="Akira",
        reference_urls=["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
        raw_hash="a" * 64,
    )
    digest = ThreatDigest(
        advisories=[adv],
        total_ingested=5,
        unique_count=1,
        duplicate_count=4,
        critical_count=1,
        generated_at="2026-08-28T12:00:00Z",
    )

    md = format_obsidian_digest(digest, date_str="2026-08-28")
    assert "Threat Intelligence Briefing — 2026-08-28" in md
    assert "Akira" in md
    assert "io_uring" in md
    assert "# 🛡️ Threat Intelligence Briefing" in md
    assert "tags: [threat-intel, cve, osint, security]" in md


def test_format_obsidian_digest_empty():
    digest = ThreatDigest(
        advisories=[],
        total_ingested=0,
        unique_count=0,
        duplicate_count=0,
        critical_count=0,
    )
    md = format_obsidian_digest(digest)
    assert "*No critical or actively exploited vulnerabilities in this stream.*" in md


def test_format_telegram_alert():
    adv = ThreatAdvisory(
        id="CVE-2026-7777",
        title="Critical Zero-Day in VPN Gateway",
        description="Pre-authentication remote code execution",
        source_feed=ThreatFeedSource.CISA_KEV,
        cve_id="CVE-2026-7777",
        cvss_score=9.9,
        is_known_exploited=True,
        reference_urls=["https://example.com/vpn-advisory"],
        raw_hash="b" * 64,
    )
    alert = format_telegram_alert(adv)
    assert "OSINT Threat Alert: CVE-2026-7777" in alert
    assert "ACTIVELY EXPLOITED (CISA KEV)" in alert
    assert "9.9" in alert
