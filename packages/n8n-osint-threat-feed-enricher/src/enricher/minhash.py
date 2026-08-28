"""MinHash LSH Deduplication Engine for Security Advisories.

Computes compact 64-integer MinHash signatures over $n$-gram shingles to estimate
Jaccard similarity in sub-millisecond time.
"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Iterable, List, Set

NUM_PERMUTATIONS = 64
MERSENNE_PRIME = (1 << 61) - 1

# Deterministic coefficients for universal hashing: h_i(x) = (a_i * x + b_i) % MERSENNE_PRIME
HASH_A = [
    (i * 1000000007 + 1234567) % (1 << 31) | 1 for i in range(1, NUM_PERMUTATIONS + 1)
]
HASH_B = [
    (i * 32416190071 + 9876543) % (1 << 31) for i in range(1, NUM_PERMUTATIONS + 1)
]


def tokenize_shingles(text: str, k: int = 3) -> Set[int]:
    """Tokenize and normalize text into k-word shingles and hash them to 64-bit integers."""
    # Normalize: lowercase, strip punctuation
    clean_text = re.sub(r"[^\w\s]", " ", text.lower())
    words = clean_text.split()
    if not words:
        return set()

    if len(words) < k:
        shingles = [" ".join(words)]
    else:
        shingles = [" ".join(words[i : i + k]) for i in range(len(words) - k + 1)]

    shingle_hashes: Set[int] = set()
    for s in shingles:
        digest = hashlib.sha256(s.encode("utf-8")).digest()
        # Extract lower 64 bits as integer
        val = struct.unpack(">Q", digest[:8])[0]
        shingle_hashes.add(val)

    return shingle_hashes


def compute_minhash_signature(text: str, num_perm: int = NUM_PERMUTATIONS) -> List[int]:
    """Compute deterministic MinHash signature vector for input text."""
    shingles = tokenize_shingles(text)
    if not shingles:
        return [0] * num_perm

    sig: List[int] = []
    for i in range(num_perm):
        a = HASH_A[i]
        b = HASH_B[i]
        min_val = float("inf")
        for h in shingles:
            val = (a * h + b) % MERSENNE_PRIME
            if val < min_val:
                min_val = val
        sig.append(int(min_val))

    return sig


def estimate_jaccard_similarity(sig_a: List[int], sig_b: List[int]) -> float:
    """Estimate Jaccard similarity between two MinHash signature vectors."""
    if not sig_a or not sig_b or len(sig_a) != len(sig_b):
        return 0.0

    matches = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
    return matches / len(sig_a)
