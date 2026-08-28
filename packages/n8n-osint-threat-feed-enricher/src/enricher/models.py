"""Immutable Pydantic v2 domain models for OSINT Threat Feed Enricher.

Conforms to Canonical Security Standards #7 and #15 (CWE-502 defense).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


def utcnow_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ThreatFeedSource(str, Enum):
    """Supported OSINT intelligence feed sources."""
    CISA_KEV = "cisa_kev"
    NVD_CVE = "nvd_cve"
    GITHUB_ADVISORY = "github_advisory"
    GENERIC_RSS = "generic_rss"


class ThreatAdvisory(BaseModel):
    """Normalized security advisory extracted from OSINT threat streams."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., min_length=1, description="Unique advisory identifier or CVE string")
    title: str = Field(..., min_length=1, description="Advisory summary headline")
    description: str = Field(..., min_length=1, description="Detailed vulnerability description")
    source_feed: ThreatFeedSource = Field(default=ThreatFeedSource.GENERIC_RSS, description="Originating feed source")
    cve_id: Optional[str] = Field(default=None, description="Primary CVE identifier (e.g. CVE-2026-1234)")
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0, description="CVSS v3.1 base score")
    is_known_exploited: bool = Field(default=False, description="Flagged in CISA Known Exploited Vulnerabilities catalog")
    ransomware_campaign: Optional[str] = Field(default=None, description="Associated ransomware group or campaign")
    published_at: str = Field(default_factory=utcnow_iso, description="Publication timestamp")
    reference_urls: List[str] = Field(default_factory=list, description="External reference and patch URLs")
    raw_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 content digest for exact deduplication")

    @field_validator("cve_id")
    @classmethod
    def validate_cve(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip().upper()
        if not clean.startswith("CVE-"):
            raise ValueError(f"Invalid CVE identifier: '{v}'. Must start with 'CVE-'")
        return clean


class ThreatDigest(BaseModel):
    """Aggregated and deduplicated threat intelligence report."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    advisories: List[ThreatAdvisory] = Field(default_factory=list, description="Unique deduplicated advisories")
    total_ingested: int = Field(..., ge=0, description="Total raw advisories received")
    unique_count: int = Field(..., ge=0, description="Number of unique advisories after MinHash deduplication")
    duplicate_count: int = Field(..., ge=0, description="Number of duplicate advisories pruned")
    critical_count: int = Field(..., ge=0, description="Number of critical/known-exploited threats")
    generated_at: str = Field(default_factory=utcnow_iso, description="Digest generation timestamp")
