"""Unit tests for SQLite storage in n8n-sre-resilience-sentinel."""

import pytest

from sentinel.models import ProbeSample, RollbackAction
from sentinel.storage import SREHealthStorage


def test_storage_track_health_and_degradation():
    storage = SREHealthStorage(":memory:")

    # Initial state
    state0 = storage.get_health_state("api-service")
    assert state0.consecutive_failures == 0
    assert state0.is_degraded is False

    # 1 Failure
    sample_fail = ProbeSample(service_name="api-service", is_healthy=False, latency_ms=100.0)
    state1 = storage.record_probe_sample(sample_fail, failure_threshold=2)
    assert state1.consecutive_failures == 1
    assert state1.is_degraded is False

    # 2nd Consecutive Failure -> Triggers Degraded
    state2 = storage.record_probe_sample(sample_fail, failure_threshold=2)
    assert state2.consecutive_failures == 2
    assert state2.is_degraded is True

    # Recovery sample -> Resets failures
    sample_ok = ProbeSample(service_name="api-service", is_healthy=True, latency_ms=10.0)
    state3 = storage.record_probe_sample(sample_ok, failure_threshold=2)
    assert state3.consecutive_failures == 0
    assert state3.is_degraded is False


def test_storage_rollback_history():
    storage = SREHealthStorage(":memory:")

    action = RollbackAction(
        action_id="r-01",
        service_name="svc-a",
        previous_slot="blue",
        target_slot="green",
        reason="Failures exceeded",
        execution_time_ms=0.5,
        success=True,
    )
    storage.record_rollback(action)

    history = storage.get_rollbacks("svc-a")
    assert len(history) == 1
    assert history[0]["target_slot"] == "green"

    # State active_slot updated
    st = storage.get_health_state("svc-a")
    assert st.active_slot == "green"
    assert st.consecutive_failures == 0


def test_storage_get_all_rollbacks_unfiltered():
    storage = SREHealthStorage(":memory:")
    action1 = RollbackAction(
        action_id="r-01", service_name="svc-1", previous_slot="blue", target_slot="green",
        reason="Fail 1", execution_time_ms=0.2, success=True
    )
    action2 = RollbackAction(
        action_id="r-02", service_name="svc-2", previous_slot="green", target_slot="blue",
        reason="Fail 2", execution_time_ms=0.3, success=True
    )
    storage.record_rollback(action1)
    storage.record_rollback(action2)

    all_records = storage.get_rollbacks(service_name=None)
    assert len(all_records) == 2


def test_storage_multiple_services():
    storage = SREHealthStorage(":memory:")
    sample1 = ProbeSample(service_name="svc-1", is_healthy=False, latency_ms=50.0)
    sample2 = ProbeSample(service_name="svc-2", is_healthy=True, latency_ms=10.0)

    st1 = storage.record_probe_sample(sample1, failure_threshold=3)
    st2 = storage.record_probe_sample(sample2, failure_threshold=3)

    assert st1.service_name == "svc-1"
    assert st1.consecutive_failures == 1
    assert st2.service_name == "svc-2"
    assert st2.consecutive_failures == 0


def test_storage_empty_rollbacks():
    storage = SREHealthStorage(":memory:")
    assert storage.get_rollbacks("nonexistent") == []


def test_storage_failed_rollback_does_not_switch_active_slot():
    storage = SREHealthStorage(":memory:")
    action = RollbackAction(
        action_id="r-fail", service_name="svc-f", previous_slot="blue", target_slot="green",
        reason="Fail", execution_time_ms=0.5, success=False
    )
    storage.record_rollback(action)
    st = storage.get_health_state("svc-f")
    assert st.active_slot == "blue"  # Unchanged because success=False


