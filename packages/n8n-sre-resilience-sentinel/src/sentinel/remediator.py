"""Atomic Deployment Symlink Remediator.

Implements zero-downtime atomic symlink switching conforming to Standard #10 & #17.
"""

from __future__ import annotations

import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Literal

from sentinel.models import RollbackAction, utcnow_iso


def execute_atomic_rollback(
    current_link_path: str,
    target_slot: Literal["blue", "green"],
    slots_dir: str,
    service_name: str = "service-app",
    reason: str = "Automated SRE health check degradation breach",
) -> RollbackAction:
    """Execute sub-millisecond atomic Linux symlink swap to rollback unhealthy slot.

    Args:
        current_link_path: Path to active 'current' symlink pointing to active slot.
        target_slot: Slot to switch to ('blue' or 'green').
        slots_dir: Parent directory containing slot release folders.
        service_name: Name of target service.
        reason: Justification for triggering rollback.

    Returns:
        RollbackAction model containing measured execution latency.
    """
    link_p = Path(current_link_path).absolute()
    slots_p = Path(slots_dir).absolute()
    target_p = slots_p / target_slot

    # Determine previous slot
    previous_slot: Literal["blue", "green"] = "green" if target_slot == "blue" else "blue"

    t0 = time.perf_counter()
    action_id = f"rollback-{uuid.uuid4().hex[:10]}"

    try:
        # Create parent directories if missing
        slots_p.mkdir(parents=True, exist_ok=True)
        target_p.mkdir(parents=True, exist_ok=True)

        # Atomic switch: create temporary symlink in same directory then os.replace
        temp_link = link_p.parent / f".tmp_link_{uuid.uuid4().hex[:8]}"
        if temp_link.is_symlink() or temp_link.exists():
            temp_link.unlink()

        os.symlink(str(target_p), str(temp_link))
        os.replace(str(temp_link), str(link_p))

        t1 = time.perf_counter()
        exec_ms = (t1 - t0) * 1000.0

        return RollbackAction(
            action_id=action_id,
            service_name=service_name,
            previous_slot=previous_slot,
            target_slot=target_slot,
            reason=reason,
            execution_time_ms=round(exec_ms, 3),
            success=True,
        )
    except Exception as e:
        t1 = time.perf_counter()
        exec_ms = (t1 - t0) * 1000.0

        return RollbackAction(
            action_id=action_id,
            service_name=service_name,
            previous_slot=previous_slot,
            target_slot=target_slot,
            reason=f"Rollback failed: {e}",
            execution_time_ms=round(exec_ms, 3),
            success=False,
        )
