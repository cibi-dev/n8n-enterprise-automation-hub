"""Immutable Pydantic v2 domain models for SRE Resilience Sentinel.

Conforms to Canonical Security Standards #7 and #15 (CWE-502 defense).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


def utcnow_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ProbeTarget(BaseModel):
    """Configuration target for a monitored service probe."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    service_name: str = Field(..., min_length=1, description="Target service identifier")
    url: str = Field(..., min_length=1, description="HTTP/HTTPS endpoint URL to probe")
    expected_status: int = Field(default=200, ge=100, le=599, description="Expected HTTP response status code")
    timeout_ms: float = Field(default=2000.0, ge=50.0, le=30000.0, description="Max probe latency timeout in ms")
    failure_threshold: int = Field(default=3, ge=1, le=20, description="Consecutive failures before triggering rollback")


class ProbeSample(BaseModel):
    """Sample measurement result from a single synthetic probe execution."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    service_name: str = Field(..., min_length=1, description="Name of probed service")
    is_healthy: bool = Field(..., description="Whether probe succeeded within SLA thresholds")
    status_code: Optional[int] = Field(default=None, description="Observed HTTP status code")
    latency_ms: float = Field(..., ge=0.0, description="Total probe round-trip latency in ms")
    error_message: Optional[str] = Field(default=None, description="Failure reason or error string")
    timestamp: str = Field(default_factory=utcnow_iso, description="Measurement timestamp")


class ServiceHealthState(BaseModel):
    """Aggregated health state and flapping mitigation tracker for a service."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    service_name: str = Field(..., min_length=1, description="Name of monitored service")
    consecutive_failures: int = Field(default=0, ge=0, description="Consecutive failed probes count")
    is_degraded: bool = Field(default=False, description="Whether failure threshold has been breached")
    active_slot: Literal["blue", "green"] = Field(default="blue", description="Currently active deployment slot")
    last_sample: Optional[ProbeSample] = Field(default=None, description="Most recent probe sample")
    updated_at: str = Field(default_factory=utcnow_iso, description="Last update timestamp")


class RollbackAction(BaseModel):
    """Record of an automated atomic deployment slot rollback."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str = Field(..., min_length=1, description="Unique rollback transaction ID")
    service_name: str = Field(..., min_length=1, description="Target service rolled back")
    previous_slot: Literal["blue", "green"] = Field(..., description="Unhealthy slot prior to rollback")
    target_slot: Literal["blue", "green"] = Field(..., description="Healthy slot rolled back to")
    reason: str = Field(..., min_length=1, description="Triggering breach justification")
    execution_time_ms: float = Field(..., ge=0.0, description="Atomic symlink switch latency in ms")
    success: bool = Field(..., description="Whether rollback completed cleanly")
    timestamp: str = Field(default_factory=utcnow_iso, description="Execution timestamp")
