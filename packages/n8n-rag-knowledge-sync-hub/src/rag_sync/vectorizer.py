"""Deterministic Feature-Hashing Embedding Vectorizer.

Conforms to Canonical Security Standards #8 and #17 (pure NumPy, zero network deps).
"""

from __future__ import annotations

import hashlib
import re
from typing import List
import numpy as np


class HashingVectorizer:
    """Deterministic, zero-dependency subword feature hashing vectorizer.

    Projects arbitrary code and text into a normalized D-dimensional hypersphere.
    """

    def __init__(self, dim: int = 64) -> None:
        self.dim = dim

    def _tokenize_shingles(self, text: str) -> List[str]:
        cleaned = re.sub(r"[^\w\s]", " ", text.lower())
        words = cleaned.split()
        if not words:
            return []
        if len(words) < 3:
            return words
        return [" ".join(words[i : i + 3]) for i in range(len(words) - 2)]

    def vectorize(self, text: str) -> List[float]:
        """Convert input text to a normalized dense vector of dimension D.

        Args:
            text: Input string snippet.

        Returns:
            List of floats representing the L2-normalized vector.
        """
        shingles = self._tokenize_shingles(text)
        vec = np.zeros(self.dim, dtype=np.float32)

        if not shingles:
            return vec.tolist()

        for shingle in shingles:
            digest = hashlib.md5(shingle.encode("utf-8"), usedforsecurity=False).digest()
            idx = int.from_bytes(digest[:4], "little") % self.dim
            sign = 1.0 if (digest[4] % 2 == 0) else -1.0
            vec[idx] += sign

        norm = np.linalg.norm(vec)
        if norm > 1e-9:
            vec = vec / norm

        return vec.tolist()

    @staticmethod
    def cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
        """Compute cosine similarity between two dense vectors."""
        a = np.asarray(vec_a, dtype=np.float32)
        b = np.asarray(vec_b, dtype=np.float32)
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a < 1e-9 or norm_b < 1e-9:
            return 0.0
        return float(np.dot(a, b) / (norm_a * norm_b))
