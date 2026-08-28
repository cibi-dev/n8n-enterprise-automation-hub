"""Performance Benchmark for n8n-forensic-incident-triage.

Evaluates PII sanitization throughput, penal classification and SQLite storage rates.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from triage.classifier import process_incident_triage
from triage.sanitizer import sanitize_pii
from triage.storage import ForensicTriageStorage


def run_benchmarks() -> dict:
    results = {}

    sample_narrative = (
        "Incident at 192.168.1.50 reported by investigator john.doe@agency.gov (phone: +1 555-0199). "
        "Threat actor @blackhat_dev deployed LockBit 3.0 ransomware, exfiltrating database from db.corp.internal. "
        "Credit card details like 4532-1234-5678-9010 were dumped online."
    )

    # 1. PII Sanitization Throughput
    iterations = 20000
    t0 = time.perf_counter()
    for _ in range(iterations):
        sanitize_pii(sample_narrative)
    t1 = time.perf_counter()
    sanitization_rps = iterations / (t1 - t0)
    results["pii_sanitizations_per_sec"] = round(sanitization_rps, 2)

    # 2. Complete Triage & Evidence Hashing Throughput
    t0 = time.perf_counter()
    for i in range(10000):
        process_incident_triage(sample_narrative, incident_id=f"BENCH-{i}")
    t1 = time.perf_counter()
    triage_rps = 10000 / (t1 - t0)
    results["triages_processed_per_sec"] = round(triage_rps, 2)

    # 3. SQLite Storage Persistence Rate
    storage = ForensicTriageStorage(":memory:")
    sample_report = process_incident_triage(sample_narrative, incident_id="SAMPLE-01")
    t0 = time.perf_counter()
    for i in range(5000):
        sample_report_i = sample_report.model_copy(update={"incident_id": f"REC-{i}"})
        storage.save_incident(sample_report_i)
    t1 = time.perf_counter()
    storage_rps = 5000 / (t1 - t0)
    results["records_persisted_per_sec"] = round(storage_rps, 2)

    print("=" * 60)
    print("  FORENSIC INCIDENT TRIAGE BENCHMARK RESULTS")
    print("=" * 60)
    for k, v in results.items():
        print(f"  {k:32s}: {v}")
    print("=" * 60)

    with open("resultados.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


if __name__ == "__main__":
    run_benchmarks()
