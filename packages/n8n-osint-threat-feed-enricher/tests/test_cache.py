"""Unit tests for SQLite deduplication cache in n8n-osint-threat-feed-enricher."""

import pytest

from enricher.cache import ThreatFeedCache
from enricher.models import ThreatAdvisory, ThreatFeedSource


def test_cache_exact_and_fuzzy_deduplication():
    cache = ThreatFeedCache(":memory:")

    adv1 = ThreatAdvisory(
        id="CVE-2026-1001",
        title="Remote code execution in Web Server",
        description="Buffer overflow vulnerability allowing arbitrary code execution",
        source_feed=ThreatFeedSource.NVD_CVE,
        cve_id="CVE-2026-1001",
        cvss_score=9.8,
        raw_hash="1" * 64,
    )

    # Identical content but different source / casing
    adv2_duplicate = ThreatAdvisory(
        id="CVE-2026-1001-CISA",
        title="Remote code execution in Web Server",
        description="Buffer overflow vulnerability allowing arbitrary code execution",
        source_feed=ThreatFeedSource.CISA_KEV,
        cve_id="CVE-2026-1001",
        cvss_score=9.8,
        raw_hash="2" * 64,
    )

    # Completely different advisory
    adv3_unique = ThreatAdvisory(
        id="CVE-2026-2002",
        title="Information Disclosure in Database Driver",
        description="Leak of sensitive memory contents via error message response",
        source_feed=ThreatFeedSource.NVD_CVE,
        cve_id="CVE-2026-2002",
        cvss_score=5.3,
        raw_hash="3" * 64,
    )

    digest = cache.deduplicate_stream([adv1, adv2_duplicate, adv3_unique], similarity_threshold=0.70)
    assert digest.total_ingested == 3
    assert digest.unique_count == 2
    assert digest.duplicate_count == 1
    assert digest.critical_count == 1

    # Ingesting same stream again should prune all seen items
    digest_second_run = cache.deduplicate_stream([adv1, adv3_unique], similarity_threshold=0.70)
    assert digest_second_run.unique_count == 0
    assert digest_second_run.duplicate_count == 2


def test_cache_is_exact_duplicate():
    cache = ThreatFeedCache(":memory:")
    adv = ThreatAdvisory(
        id="CVE-2026-9000",
        title="Test Title",
        description="Test Desc",
        cve_id="CVE-2026-9000",
        raw_hash="f" * 64,
    )
    assert cache.is_exact_duplicate("f" * 64) is False
    cache.deduplicate_stream([adv])
    assert cache.is_exact_duplicate("f" * 64) is True
