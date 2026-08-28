"""Performance Benchmark for n8n-rag-knowledge-sync-hub.

Evaluates AST chunking, dense vectorization and SQLite Top-K search throughput.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rag_sync.chunker import chunk_python_file
from rag_sync.indexer import VectorKnowledgeIndexer
from rag_sync.vectorizer import HashingVectorizer


def run_benchmarks() -> dict:
    results = {}

    sample_code = """
import hashlib
from typing import List

class CryptographicSigner:
    \"\"\"Sign and verify payload hashes using SHA-256.\"\"\"

    def __init__(self, secret: str):
        self.secret = secret

    def sign_payload(self, payload: str) -> str:
        return hashlib.sha256((payload + self.secret).encode()).hexdigest()

def verify_signature(payload: str, signature: str, secret: str) -> bool:
    expected = hashlib.sha256((payload + secret).encode()).hexdigest()
    return expected == signature
"""

    # 1. AST Chunking Throughput
    iterations = 10000
    t0 = time.perf_counter()
    for _ in range(iterations):
        chunk_python_file("sample.py", sample_code)
    t1 = time.perf_counter()
    chunking_rps = iterations / (t1 - t0)
    results["ast_files_chunked_per_sec"] = round(chunking_rps, 2)

    # 2. Vectorization Throughput
    vectorizer = HashingVectorizer(dim=64)
    t0 = time.perf_counter()
    for _ in range(20000):
        vectorizer.vectorize(sample_code)
    t1 = time.perf_counter()
    vec_rps = 20000 / (t1 - t0)
    results["vectorizations_per_sec"] = round(vec_rps, 2)

    # 3. Vector DB Indexing & Top-K Search Throughput
    indexer = VectorKnowledgeIndexer(":memory:")
    chunks = chunk_python_file("sample.py", sample_code)
    indexer.index_chunks(chunks)

    t0 = time.perf_counter()
    for _ in range(5000):
        indexer.search("cryptographic signature SHA-256", top_k=5)
    t1 = time.perf_counter()
    search_rps = 5000 / (t1 - t0)
    results["semantic_searches_per_sec"] = round(search_rps, 2)

    print("=" * 60)
    print("  RAG KNOWLEDGE SYNC HUB BENCHMARK RESULTS")
    print("=" * 60)
    for k, v in results.items():
        print(f"  {k:32s}: {v}")
    print("=" * 60)

    with open("resultados.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


if __name__ == "__main__":
    run_benchmarks()
