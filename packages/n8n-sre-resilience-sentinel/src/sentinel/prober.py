"""Synthetic Blackbox Probing Engine.

Conforms to Canonical Security Standards #10 and #17 (strict timeout & resource bounds).
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from typing import Optional

from sentinel.models import ProbeSample, ProbeTarget


def execute_synthetic_probe(target: ProbeTarget) -> ProbeSample:
    """Execute a single synthetic health probe against target URL with bounded timeout.

    Args:
        target: Target configuration parameters.

    Returns:
        ProbeSample measurement model.
    """
    if not (target.url.startswith("http://") or target.url.startswith("https://")):
        return ProbeSample(
            service_name=target.service_name,
            is_healthy=False,
            status_code=None,
            latency_ms=0.0,
            error_message="Invalid URL scheme: only http and https permitted",
        )

    timeout_sec = max(0.05, target.timeout_ms / 1000.0)
    t0 = time.perf_counter()

    req = urllib.request.Request(
        target.url,
        headers={"User-Agent": "n8n-sre-resilience-sentinel/0.1.0"},
        method="GET",
    )

    try:
        # Standard #14: scheme audited and restricted to http/https only
        with urllib.request.urlopen(req, timeout=timeout_sec) as response:  # nosec B310
            t1 = time.perf_counter()
            latency_ms = (t1 - t0) * 1000.0
            status_code = response.getcode()
            is_healthy = (status_code == target.expected_status) and (latency_ms <= target.timeout_ms)

            return ProbeSample(
                service_name=target.service_name,
                is_healthy=is_healthy,
                status_code=status_code,
                latency_ms=round(latency_ms, 3),
                error_message=None if is_healthy else f"Expected status {target.expected_status}, got {status_code}",
            )
    except urllib.error.HTTPError as e:
        t1 = time.perf_counter()
        latency_ms = (t1 - t0) * 1000.0
        return ProbeSample(
            service_name=target.service_name,
            is_healthy=(e.code == target.expected_status),
            status_code=e.code,
            latency_ms=round(latency_ms, 3),
            error_message=f"HTTPError {e.code}: {e.reason}",
        )
    except Exception as e:
        t1 = time.perf_counter()
        latency_ms = (t1 - t0) * 1000.0
        return ProbeSample(
            service_name=target.service_name,
            is_healthy=False,
            status_code=None,
            latency_ms=round(latency_ms, 3),
            error_message=f"Connection failure: {str(e)}",
        )
