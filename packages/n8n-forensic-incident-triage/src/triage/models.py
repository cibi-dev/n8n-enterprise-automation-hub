"""Immutable Pydantic v2 domain models for Forensic Incident Triage.

Conforms to Canonical Security Standards #7, #9, and #15 (CWE-502 / ISO-IEC 27037).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


def utcnow_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CrimeCategory(str, Enum):
    """Categorization of cybercrime and security incident modalities."""
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_THEFT = "data_theft"
    RANSOMWARE_EXTORTION = "ransomware_extortion"
    IDENTITY_FRAUD = "identity_fraud"
    FINANCIAL_SCAM = "financial_scam"
    DOS_ATTACK = "dos_attack"
    MALWARE_DISTRIBUTION = "malware_distribution"
    OTHER = "other"


class IncidentPriority(str, Enum):
    """Normalized triage urgency and response priority."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SanitizedIncidentReport(BaseModel):
    """Sanitized and cryptographically certified forensic incident report."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: str = Field(..., min_length=1, description="Unique incident tracking identifier")
    title: str = Field(..., min_length=1, description="Incident title or summary")
    sanitized_text: str = Field(..., min_length=1, description="PII-redacted narrative description")
    redacted_pii_counts: Dict[str, int] = Field(default_factory=dict, description="Counts of sanitized PII entities")
    crime_category: CrimeCategory = Field(default=CrimeCategory.OTHER, description="Classified criminal infraction")
    priority: IncidentPriority = Field(default=IncidentPriority.MEDIUM, description="Assigned investigation priority")
    custody_sha256: str = Field(..., min_length=64, max_length=64, description="ISO/IEC 27037 SHA-256 evidence digest")
    affected_assets: List[str] = Field(default_factory=list, description="Affected infrastructure or systems")
    suspect_indicators: List[str] = Field(default_factory=list, description="Identified IOCs or threat actor handles")
    reported_at: str = Field(default_factory=utcnow_iso, description="Report timestamp (ISO 8601 UTC)")
    storage_id: Optional[str] = Field(default=None, description="Database record tracking key")
