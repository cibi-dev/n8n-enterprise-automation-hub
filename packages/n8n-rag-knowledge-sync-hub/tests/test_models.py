"""Unit tests for domain models in n8n-rag-knowledge-sync-hub."""

import pytest
from pydantic import ValidationError

from rag_sync.models import CodeChunk, SearchMatch, SyncResult


def test_code_chunk_valid():
    chunk = CodeChunk(
        chunk_id="chk-01",
        file_path="src/main.py",
        chunk_type="function",
        name="run_engine",
        content="def run_engine(): pass",
        content_hash="a" * 64,
        line_start=1,
        line_end=5,
    )
    assert chunk.chunk_id == "chk-01"
    assert chunk.chunk_type == "function"
    assert chunk.name == "run_engine"


def test_code_chunk_extra_forbidden():
    with pytest.raises(ValidationError):
        CodeChunk(
            chunk_id="chk-01",
            file_path="src/main.py",
            chunk_type="function",
            name="run",
            content="def run(): pass",
            content_hash="a" * 64,
            injected="forbidden",  # type: ignore
        )


def test_sync_result_valid():
    res = SyncResult(
        repository_path="/repo",
        total_files_scanned=10,
        chunks_extracted=45,
        new_chunks_indexed=40,
        skipped_duplicates=5,
        execution_time_ms=12.4,
    )
    assert res.total_files_scanned == 10
    assert res.chunks_extracted == 45


def test_search_match_valid():
    match = SearchMatch(
        chunk_id="chk-01",
        file_path="src/main.py",
        chunk_type="function",
        name="run",
        score=0.954,
        content="def run(): pass",
    )
    assert match.score == 0.954


def test_sync_result_extra_forbidden():
    with pytest.raises(ValidationError):
        SyncResult(
            repository_path="/repo",
            execution_time_ms=1.0,
            bad_field=True,  # type: ignore
        )


def test_search_match_extra_forbidden():
    with pytest.raises(ValidationError):
        SearchMatch(
            chunk_id="c-1",
            file_path="f",
            chunk_type="t",
            name="n",
            score=1.0,
            content="c",
            injected="no",  # type: ignore
        )

