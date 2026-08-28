"""Unit tests for CISA and NVD feed parsers in n8n-osint-threat-feed-enricher."""

import json
import pytest

from enricher.models import ThreatFeedSource
from enricher.parsers import (
    compute_content_hash,
    parse_cisa_kev_catalog,
    parse_nvd_cve_feed,
)


def test_compute_content_hash_deterministic():
    h1 = compute_content_hash("Title", "Description", "CVE-2026-1000")
    h2 = compute_content_hash("Title", "Description", "CVE-2026-1000")
    assert h1 == h2
    assert len(h1) == 64


def test_parse_cisa_kev_catalog_valid():
    cisa_json = {
        "title": "CISA KEV",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vulnerabilityName": "Test Active Exploitation",
                "shortDescription": "Actively exploited in the wild by threat actors",
                "dateAdded": "2026-08-20",
                "knownRansomwareCampaignUse": "Known",
            }
        ],
    }

    advisories = parse_cisa_kev_catalog(cisa_json)
    assert len(advisories) == 1
    adv = advisories[0]
    assert adv.cve_id == "CVE-2024-1234"
    assert adv.is_known_exploited is True
    assert adv.source_feed == ThreatFeedSource.CISA_KEV
    assert adv.ransomware_campaign == "Known"
    assert adv.cvss_score == 9.8


def test_parse_cisa_kev_catalog_invalid_json():
    with pytest.raises(ValueError):
        parse_cisa_kev_catalog("{malformed_json")

    with pytest.raises(ValueError):
        parse_cisa_kev_catalog(["not a dict"])  # type: ignore


def test_parse_nvd_cve_feed_valid():
    nvd_json = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-5555",
                    "descriptions": [{"lang": "en", "value": "Heap-based buffer overflow in image decoder"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 7.8}}]
                    },
                    "published": "2026-08-25T10:00:00.000",
                    "references": [{"url": "https://example.com/advisory"}],
                }
            }
        ]
    }

    advisories = parse_nvd_cve_feed(nvd_json)
    assert len(advisories) == 1
    adv = advisories[0]
    assert adv.cve_id == "CVE-2026-5555"
    assert adv.cvss_score == 7.8
    assert adv.is_known_exploited is False
    assert adv.source_feed == ThreatFeedSource.NVD_CVE
    assert "https://example.com/advisory" in adv.reference_urls


def test_parse_nvd_cve_feed_invalid():
    with pytest.raises(ValueError):
        parse_nvd_cve_feed("invalid")

    with pytest.raises(ValueError):
        parse_nvd_cve_feed(12345)  # type: ignore

    # Empty vulnerabilities list
    assert parse_nvd_cve_feed({"vulnerabilities": []}) == []
    assert parse_nvd_cve_feed({}) == []


def test_parse_cisa_empty():
    assert parse_cisa_kev_catalog({"vulnerabilities": []}) == []
    assert parse_cisa_kev_catalog({}) == []


def test_parse_nvd_feed_with_non_dict_elements():
    doc = {"vulnerabilities": ["string_element", {"cve": None}, {"cve": {"id": "CVE-2026-8888"}}]}
    advisories = parse_nvd_cve_feed(doc)
    assert len(advisories) == 1
    assert advisories[0].cve_id == "CVE-2026-8888"

