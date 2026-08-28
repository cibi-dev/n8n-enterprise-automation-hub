"""Performance Benchmark for n8n-sre-resilience-sentinel.

Evaluates atomic symlink rollback latency and health state tracking throughput.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sentinel.models import ProbeSample
from sentinel.remediator import execute_atomic_rollback
from sentinel.storage import SREHealthStorage


def run_benchmarks() -> dict:
    results = {}

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_p = Path(tmp_dir)
        slots_dir = tmp_p / "slots"
        current_link = tmp_p / "current"

        # 1. Atomic Rollback Symlink Latency
        iterations = 1000
        t0 = time.perf_counter()
        for i in range(iterations):
            target = "green" if (i % 2 == 0) else "blue"
            execute_atomic_rollback(
                current_link_path=str(current_link),
                target_slot=target,
                slots_dir=str(slots_dir),
                service_name="bench-svc",
            )
        t1 = time.perf_counter()
        avg_latency_ms = ((t1 - t0) / iterations) * 1000.0
        results["atomic_rollback_avg_latency_ms"] = round(avg_latency_ms, 3)
        results["atomic_rollbacks_per_sec"] = round(iterations / (t1 - t0), 2)

    # 2. SQLite Health State Tracking Rate
    storage = SREHealthStorage(":memory:")
    sample = ProbeSample(service_name="bench-svc", is_healthy=True, latency_ms=5.0)
    t0 = time.perf_counter()
    for _ in range(10000):
        storage.record_probe_sample(sample)
    t1 = time.perf_counter()
    health_updates_rps = 10000 / (t1 - t0)
    results["health_updates_per_sec"] = round(health_updates_rps, 2)

    print("=" * 60)
    print("  SRE RESILIENCE SENTINEL BENCHMARK RESULTS")
    print("=" * 60)
    for k, v in results.items():
        print(f"  {k:32s}: {v}")
    print("=" * 60)

    with open("resultados.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


if __name__ == "__main__":
    run_benchmarks()
