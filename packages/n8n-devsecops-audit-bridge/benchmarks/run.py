from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from bridge.models import AuditFinding, AuditPayload, SBOMComponent, SeverityLevel
from bridge.parser import parse_cyclonedx_sbom, parse_sarif_report
from bridge.storage import AuditStorage
from bridge.verifier import verify_hmac_signature


def run_benchmarks() -> dict:
    results = {}

    # 1. HMAC Verification Throughput
    payload_bytes = b'{"repository": "cibi-dev/test", "status": "verified"}' * 20
    secret = "benchmark-secret-key-1234"
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    iterations = 2000
    t0 = time.perf_counter()
    for _ in range(iterations):
        verify_hmac_signature(payload_bytes, sig, secret)
    t1 = time.perf_counter()
    hmac_rps = iterations / (t1 - t0)
    results["hmac_verifications_per_sec"] = round(hmac_rps, 2)

    # 2. SARIF Parsing Throughput
    mock_sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "Bandit", "rules": [{"id": f"B10{i}"} for i in range(10)]}},
                "results": [
                    {
                        "ruleId": f"B10{i % 10}",
                        "level": "warning",
                        "message": {"text": f"Vulnerability {i}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"file_{i}.py"}}}],
                    }
                    for i in range(50)
                ],
            }
        ]
    }
    t0 = time.perf_counter()
    for _ in range(500):
        parse_sarif_report(mock_sarif)
    t1 = time.perf_counter()
    sarif_rps = 500 / (t1 - t0)
    results["sarif_reports_per_sec"] = round(sarif_rps, 2)

    # 3. Storage Audit Record Throughput
    storage = AuditStorage(":memory:")
    payload = AuditPayload(
        repository="cibi-dev/benchmark-repo",
        commit_sha="a" * 40,
        pipeline_id="bench-run",
        findings=[AuditFinding(rule_id="B101", message="test", file_path="a.py", severity=SeverityLevel.LOW)],
        components=[SBOMComponent(name="pkg", version="1.0.0")],
    )
    t0 = time.perf_counter()
    for _ in range(1000):
        storage.record_audit(payload, signature_valid=True)
    t1 = time.perf_counter()
    storage_rps = 1000 / (t1 - t0)
    results["audit_records_per_sec"] = round(storage_rps, 2)

    print("=" * 60)
    print("  DEVSECOPS AUDIT BRIDGE BENCHMARK RESULTS")
    print("=" * 60)
    for k, v in results.items():
        print(f"  {k:32s}: {v}")
    print("=" * 60)

    with open("resultados.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


if __name__ == "__main__":
    run_benchmarks()
