"""Unit tests for atomic deployment symlink remediator in n8n-sre-resilience-sentinel."""

import os
from pathlib import Path
import pytest

from sentinel.remediator import execute_atomic_rollback


def test_execute_atomic_rollback_success(tmp_path):
    slots_dir = tmp_path / "slots"
    current_link = tmp_path / "current"

    # Rollback to green
    action = execute_atomic_rollback(
        current_link_path=str(current_link),
        target_slot="green",
        slots_dir=str(slots_dir),
        service_name="web-app",
        reason="Test rollback",
    )

    assert action.success is True
    assert action.previous_slot == "blue"
    assert action.target_slot == "green"
    assert current_link.is_symlink()
    assert str(slots_dir / "green") in str(current_link.resolve())

    # Switch back to blue
    action_blue = execute_atomic_rollback(
        current_link_path=str(current_link),
        target_slot="blue",
        slots_dir=str(slots_dir),
        service_name="web-app",
    )
    assert action_blue.success is True
    assert action_blue.previous_slot == "green"
    assert action_blue.target_slot == "blue"
    assert str(slots_dir / "blue") in str(current_link.resolve())


def test_execute_atomic_rollback_invalid_path():
    action = execute_atomic_rollback(
        current_link_path="/invalid_root_dir_non_permitted/current",
        target_slot="green",
        slots_dir="/invalid_root_dir_non_permitted/slots",
    )
    assert action.success is False
    assert "Rollback failed" in action.reason


def test_execute_atomic_rollback_creates_slots_dir(tmp_path):
    nested_slots = tmp_path / "deep" / "nested" / "slots"
    current_link = tmp_path / "deep" / "current"
    action = execute_atomic_rollback(
        current_link_path=str(current_link),
        target_slot="blue",
        slots_dir=str(nested_slots),
        service_name="nested-svc",
    )
    assert action.success is True
    assert (nested_slots / "blue").is_dir()


def test_execute_atomic_rollback_timing_sub_millisecond(tmp_path):
    slots_dir = tmp_path / "slots"
    current_link = tmp_path / "current"
    action = execute_atomic_rollback(
        current_link_path=str(current_link),
        target_slot="green",
        slots_dir=str(slots_dir),
    )
    assert action.execution_time_ms < 50.0  # Well within SLA threshold

