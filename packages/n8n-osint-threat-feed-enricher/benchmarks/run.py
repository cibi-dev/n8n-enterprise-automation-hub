"""Performance Benchmark for n8n-osint-threat-feed-enricher.

Evaluates MinHash signature generation, Jaccard similarity and cache deduplication throughput.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from enricher.cache import ThreatFeedCache
from enricher.minhash import compute_minhash_signature, estimate_jaccard_similarity
from enricher.models import ThreatAdvisory, ThreatFeedSource


def run_benchmarks() -> dict:
    results = {}

    sample_desc = (
        "A critical vulnerability in Apache Tomcat allows remote unauthenticated attackers "
        "to execute arbitrary code via a specially crafted HTTP request triggering buffer overflow."
    )

    # 1. MinHash Signature Generation Throughput
    iterations = 5000
    t0 = time.perf_counter()
    for _ in range(iterations):
        compute_minhash_signature(sample_desc)
    t1 = time.perf_counter()
    minhash_rps = iterations / (t1 - t0)
    results["minhash_signatures_per_sec"] = round(minhash_rps, 2)

    # 2. Jaccard Estimation Throughput
    sig1 = compute_minhash_signature(sample_desc)
    sig2 = compute_minhash_signature(sample_desc + " Exploitation confirmed in ransomware campaign.")
    t0 = time.perf_counter()
    for _ in range(100000):
        estimate_jaccard_similarity(sig1, sig2)
    t1 = time.perf_counter()
    jaccard_rps = 100000 / (t1 - t0)
    results["jaccard_estimations_per_sec"] = round(jaccard_rps, 2)

    # 3. Stream Deduplication Throughput
    cache = ThreatFeedCache(":memory:")
    stream = [
        ThreatAdvisory(
            id=f"CVE-2026-{1000 + i}",
            title=f"Advisory {i}: {sample_desc[:40]}",
            description=sample_desc,
            source_feed=ThreatFeedSource.NVD_CVE,
            cve_id=f"CVE-2026-{1000 + i}",
            raw_hash=f"{i:064x}",
        )
        for i in range(200)
    ]
    t0 = time.perf_counter()
    for _ in range(20):
        cache.deduplicate_stream(stream, persist=False)
    t1 = time.perf_counter()
    dedup_rps = (200 * 20) / (t1 - t0)
    results["advisories_deduplicated_per_sec"] = round(dedup_rps, 2)

    print("=" * 60)
    print("  OSINT THREAT FEED ENRICHER BENCHMARK RESULTS")
    print("=" * 60)
    for k, v in results.items():
        print(f"  {k:32s}: {v}")
    print("=" * 60)

    with open("resultados.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


if __name__ == "__main__":
    run_benchmarks()
