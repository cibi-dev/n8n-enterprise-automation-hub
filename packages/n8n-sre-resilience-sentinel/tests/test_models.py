"""Unit tests for domain models in n8n-sre-resilience-sentinel."""

import pytest
from pydantic import ValidationError

from sentinel.models import (
    ProbeSample,
    ProbeTarget,
    RollbackAction,
    ServiceHealthState,
)


def test_probe_target_valid():
    target = ProbeTarget(
        service_name="api-gateway",
        url="https://api.corp.internal/healthz",
        expected_status=200,
        timeout_ms=1500.0,
        failure_threshold=5,
    )
    assert target.service_name == "api-gateway"
    assert target.failure_threshold == 5


def test_probe_target_extra_forbidden():
    with pytest.raises(ValidationError):
        ProbeTarget(
            service_name="api",
            url="http://localhost",
            injected="bad",  # type: ignore
        )


def test_probe_sample_valid():
    sample = ProbeSample(
        service_name="api",
        is_healthy=True,
        status_code=200,
        latency_ms=12.5,
    )
    assert sample.is_healthy is True
    assert sample.latency_ms == 12.5


def test_service_health_state_defaults():
    state = ServiceHealthState(service_name="payment-svc")
    assert state.consecutive_failures == 0
    assert state.is_degraded is False
    assert state.active_slot == "blue"


def test_rollback_action_valid():
    action = RollbackAction(
        action_id="roll-01",
        service_name="payment-svc",
        previous_slot="blue",
        target_slot="green",
        reason="SLA breach",
        execution_time_ms=0.45,
        success=True,
    )
    assert action.previous_slot == "blue"
    assert action.target_slot == "green"
    assert action.execution_time_ms < 1.0


def test_probe_target_boundary_values():
    with pytest.raises(ValidationError):
        ProbeTarget(service_name="s", url="http://x", expected_status=99)  # <100

    with pytest.raises(ValidationError):
        ProbeTarget(service_name="s", url="http://x", expected_status=600)  # >599

    with pytest.raises(ValidationError):
        ProbeTarget(service_name="s", url="http://x", failure_threshold=0)  # <1


def test_service_health_state_custom():
    sample = ProbeSample(service_name="s", is_healthy=False, latency_ms=100.0)
    state = ServiceHealthState(
        service_name="s",
        consecutive_failures=3,
        is_degraded=True,
        active_slot="green",
        last_sample=sample,
    )
    assert state.active_slot == "green"
    assert state.is_degraded is True
    assert state.last_sample is not None


def test_probe_sample_extra_forbidden():
    with pytest.raises(ValidationError):
        ProbeSample(service_name="s", is_healthy=True, latency_ms=1.0, bad_field=123)  # type: ignore


def test_service_health_state_extra_forbidden():
    with pytest.raises(ValidationError):
        ServiceHealthState(service_name="s", bad_field="extra")  # type: ignore


def test_rollback_action_extra_forbidden():
    with pytest.raises(ValidationError):
        RollbackAction(
            action_id="r-1", service_name="s", previous_slot="blue", target_slot="green",
            reason="r", execution_time_ms=1.0, success=True, bad_arg=True  # type: ignore
        )


