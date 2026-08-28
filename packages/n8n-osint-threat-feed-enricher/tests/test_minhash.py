"""Unit tests for MinHash and Jaccard similarity estimation in n8n-osint-threat-feed-enricher."""

import pytest
from enricher.minhash import (
    compute_minhash_signature,
    estimate_jaccard_similarity,
    tokenize_shingles,
)


def test_tokenize_shingles():
    text = "Critical remote code execution vulnerability in Apache HTTP server"
    shingles = tokenize_shingles(text, k=3)
    assert len(shingles) > 0
    assert all(isinstance(s, int) for s in shingles)

    # Empty string produces empty set
    assert tokenize_shingles("") == set()


def test_compute_minhash_signature_length():
    text = "Vulnerability in Linux kernel allows privilege escalation via eBPF subsystem"
    sig = compute_minhash_signature(text, num_perm=64)
    assert len(sig) == 64
    assert all(isinstance(v, int) for v in sig)

    # Empty text produces zero vector
    empty_sig = compute_minhash_signature("")
    assert len(empty_sig) == 64
    assert all(v == 0 for v in empty_sig)


def test_estimate_jaccard_similarity_identical_texts():
    text = "SQL Injection in authentication endpoint allows authentication bypass"
    sig1 = compute_minhash_signature(text)
    sig2 = compute_minhash_signature(text)

    sim = estimate_jaccard_similarity(sig1, sig2)
    assert sim == 1.0


def test_estimate_jaccard_similarity_near_duplicates():
    text1 = "Critical remote code execution vulnerability in OpenSSH server version 9.2p1 via buffer overflow"
    text2 = "Critical remote code execution vulnerability in OpenSSH server version 9.3p1 through buffer overflow"

    sig1 = compute_minhash_signature(text1)
    sig2 = compute_minhash_signature(text2)

    sim = estimate_jaccard_similarity(sig1, sig2)
    assert sim >= 0.50  # High similarity for near duplicate descriptions


def test_estimate_jaccard_similarity_disjoint_texts():
    text1 = "Authentication bypass via SQL injection in WordPress plugin"
    text2 = "Memory corruption in NVIDIA graphics driver kernel module on Windows 11"

    sig1 = compute_minhash_signature(text1)
    sig2 = compute_minhash_signature(text2)

    sim = estimate_jaccard_similarity(sig1, sig2)
    assert sim <= 0.15  # Disjoint domains have minimal to zero similarity


def test_estimate_jaccard_invalid_inputs():
    assert estimate_jaccard_similarity([], []) == 0.0
    assert estimate_jaccard_similarity([1, 2], [1]) == 0.0


def test_tokenize_shingles_short_text():
    # Text with fewer than k words
    shingles = tokenize_shingles("Short text", k=3)
    assert len(shingles) == 1


def test_compute_minhash_custom_num_perm():
    sig = compute_minhash_signature("Custom permutation test", num_perm=32)
    assert len(sig) == 32

