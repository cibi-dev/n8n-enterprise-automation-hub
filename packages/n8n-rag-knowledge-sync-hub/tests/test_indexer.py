"""Unit tests for SQLite vector indexer and semantic search in n8n-rag-knowledge-sync-hub."""

import pytest

from rag_sync.chunker import chunk_python_file
from rag_sync.indexer import VectorKnowledgeIndexer


def test_indexer_index_and_deduplicate():
    indexer = VectorKnowledgeIndexer(":memory:")

    code = "def authenticate_user(token: str) -> bool: return True\ndef revoke_token(token: str): pass"
    chunks = chunk_python_file("auth.py", code)

    # First indexing run
    new_c, skip_c = indexer.index_chunks(chunks)
    assert new_c == 2
    assert skip_c == 0

    # Second indexing run with same chunks -> All skipped
    new_c2, skip_c2 = indexer.index_chunks(chunks)
    assert new_c2 == 0
    assert skip_c2 == 2


def test_indexer_semantic_search():
    indexer = VectorKnowledgeIndexer(":memory:")

    code1 = "def authenticate_hmac_signature(key: bytes, msg: bytes): return True"
    code2 = "def render_html_template(template_name: str): return '<html></html>'"

    chunks1 = chunk_python_file("auth.py", code1)
    chunks2 = chunk_python_file("web.py", code2)

    indexer.index_chunks(chunks1 + chunks2)

    matches = indexer.search("hmac signature verification key", top_k=2)
    assert len(matches) >= 1
    assert matches[0].name == "authenticate_hmac_signature"


def test_indexer_stats():
    indexer = VectorKnowledgeIndexer(":memory:")
    code = "class DatabaseConnection:\n    def connect(self): pass\n"
    chunks = chunk_python_file("db.py", code)
    indexer.index_chunks(chunks)

    stats = indexer.get_stats()
    assert stats["total_chunks"] == 1
    assert stats["unique_files"] == 1
    assert stats["by_type"]["class"] == 1


def test_indexer_search_empty_db():
    indexer = VectorKnowledgeIndexer(":memory:")
    matches = indexer.search("any query", top_k=5)
    assert matches == []


def test_indexer_search_zero_query():
    indexer = VectorKnowledgeIndexer(":memory:")
    chunks = chunk_python_file("f.py", "def f(): pass")
    indexer.index_chunks(chunks)
    matches = indexer.search("", top_k=1)
    assert len(matches) == 1
    assert matches[0].score == 0.0

