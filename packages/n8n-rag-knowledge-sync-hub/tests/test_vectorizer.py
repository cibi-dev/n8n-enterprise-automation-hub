"""Unit tests for feature-hashing vectorizer in n8n-rag-knowledge-sync-hub."""

import numpy as np
import pytest

from rag_sync.vectorizer import HashingVectorizer


def test_vectorizer_dimension_and_norm():
    vec = HashingVectorizer(dim=64)
    v = vec.vectorize("def calculate_metrics(data): return np.mean(data)")
    assert len(v) == 64
    norm = np.linalg.norm(np.array(v))
    assert pytest.approx(norm, abs=1e-4) == 1.0


def test_vectorizer_empty_text():
    vec = HashingVectorizer(dim=64)
    v = vec.vectorize("")
    assert len(v) == 64
    assert all(x == 0.0 for x in v)


def test_cosine_similarity_identical_and_orthogonal():
    vec = HashingVectorizer(dim=64)
    v1 = vec.vectorize("authentication token HMAC SHA256 security")
    v2 = vec.vectorize("authentication token HMAC SHA256 security")
    sim = vec.cosine_similarity(v1, v2)
    assert pytest.approx(sim, abs=1e-4) == 1.0

    # Zero vector cosine similarity
    zero_vec = [0.0] * 64
    sim_zero = vec.cosine_similarity(v1, zero_vec)
    assert sim_zero == 0.0


def test_vectorizer_short_text_single_word():
    vec = HashingVectorizer(dim=64)
    v = vec.vectorize("word")
    assert len(v) == 64
    norm = np.linalg.norm(np.array(v))
    assert pytest.approx(norm, abs=1e-4) == 1.0


def test_vectorizer_two_words():
    vec = HashingVectorizer(dim=64)
    v = vec.vectorize("hello world")
    assert len(v) == 64
    norm = np.linalg.norm(np.array(v))
    assert pytest.approx(norm, abs=1e-4) == 1.0

