"""Unit tests for Obsidian note formatter in n8n-rag-knowledge-sync-hub."""

import pytest

from rag_sync.chunker import chunk_python_file
from rag_sync.models import SyncResult
from rag_sync.obsidian import format_obsidian_codebase_note


def test_format_obsidian_codebase_note():
    code = "def process_data(): pass\nclass DataPipeline: pass"
    chunks = chunk_python_file("pipeline.py", code)
    sync_res = SyncResult(
        repository_path="/home/cibi/Proyectos/sample-repo",
        total_files_scanned=1,
        chunks_extracted=2,
        new_chunks_indexed=2,
        skipped_duplicates=0,
        execution_time_ms=15.0,
    )

    note = format_obsidian_codebase_note(
        repo_name="sample-repo",
        sync_result=sync_res,
        chunks=chunks,
    )

    assert "# Codebase Knowledge: sample-repo" in note
    assert "[[00_Atlas/Home|Home Atlas]]" in note
    assert "`process_data`" in note
    assert "`DataPipeline`" in note
    assert "rag-index" in note


def test_format_obsidian_empty_chunks():
    sync_res = SyncResult(
        repository_path="/home/cibi/Proyectos/empty-repo",
        total_files_scanned=0,
        chunks_extracted=0,
        new_chunks_indexed=0,
        skipped_duplicates=0,
        execution_time_ms=5.0,
    )
    note = format_obsidian_codebase_note(
        repo_name="empty-repo",
        sync_result=sync_res,
        chunks=[],
    )
    assert "# Codebase Knowledge: empty-repo" in note
    assert "| **Files Scanned** | `0` |" in note

