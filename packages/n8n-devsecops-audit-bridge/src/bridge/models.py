"""Immutable Pydantic v2 models for DevSecOps Audit Bridge.

Enforces schema validation (extra='forbid', frozen=True) conforming to
Canonical Security Standard #7 and #15 (CWE-502 defense).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


def utcnow_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SeverityLevel(str, Enum):
    """Normalized vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditFinding(BaseModel):
    """Normalized security finding extracted from SARIF / SAST reports."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Field(..., min_length=1, description="Scanner rule or check identifier (e.g. B101)")
    message: str = Field(..., min_length=1, description="Finding description or remediation hint")
    severity: SeverityLevel = Field(default=SeverityLevel.MEDIUM, description="Normalized severity level")
    file_path: str = Field(..., min_length=1, description="Path to affected file")
    start_line: int = Field(default=1, ge=1, description="Line number of finding")
    cwe_ids: List[int] = Field(default_factory=list, description="Associated CWE identifier numbers")
    scanner_name: str = Field(default="bandit", description="Name of originating SAST scanner")


class SBOMComponent(BaseModel):
    """Normalized software bill of materials component extracted from CycloneDX."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., min_length=1, description="Component package name")
    version: str = Field(..., min_length=1, description="Component version string")
    purl: Optional[str] = Field(default=None, description="Package URL (PURL)")
    component_type: str = Field(default="library", description="Component classification (library/framework/application)")
    licenses: List[str] = Field(default_factory=list, description="Declared SPDX license identifiers")


class AuditPayload(BaseModel):
    """Complete webhook payload containing CI audit results and SBOM."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    repository: str = Field(..., min_length=1, description="Target repository name (owner/repo)")
    commit_sha: str = Field(..., min_length=7, max_length=64, description="Git commit hash")
    pipeline_id: str = Field(..., min_length=1, description="CI execution run ID")
    findings: List[AuditFinding] = Field(default_factory=list, description="List of identified security findings")
    components: List[SBOMComponent] = Field(default_factory=list, description="List of dependencies from SBOM")
    timestamp: str = Field(default_factory=utcnow_iso, description="Audit execution UTC timestamp")

    @field_validator("commit_sha")
    @classmethod
    def validate_sha(cls, v: str) -> str:
        clean = v.strip().lower()
        if not all(c in "0123456789abcdef" for c in clean):
            raise ValueError(f"Invalid hexadecimal commit hash: '{v}'")
        return clean


class AuditVerificationResult(BaseModel):
    """Cryptographic verification and audit summarization result."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_compliant: bool = Field(..., description="Whether audit meets security gate policy")
    signature_valid: bool = Field(..., description="Whether HMAC webhook signature was verified")
    total_findings: int = Field(..., ge=0, description="Total count of security findings")
    critical_count: int = Field(..., ge=0, description="Number of CRITICAL severity findings")
    high_count: int = Field(..., ge=0, description="Number of HIGH severity findings")
    total_components: int = Field(..., ge=0, description="Total number of components in SBOM")
    merkle_leaf_hash: str = Field(..., min_length=64, max_length=64, description="Custody SHA-256 digest")
    storage_id: Optional[str] = Field(default=None, description="Unique SQLite audit run record ID")
    summary: str = Field(..., description="Executive summary of audit compliance")
