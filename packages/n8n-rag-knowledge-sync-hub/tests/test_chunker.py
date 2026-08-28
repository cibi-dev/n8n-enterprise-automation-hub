"""Unit tests for AST and Markdown chunking in n8n-rag-knowledge-sync-hub."""

import pytest

from rag_sync.chunker import (
    chunk_markdown_file,
    chunk_python_file,
    compute_sha256,
)


def test_chunk_python_file_functions_and_classes():
    code = """
import os

def helper_function(x: int) -> int:
    \"\"\"Helper calculation.\"\"\"
    return x * 2

async def async_fetch(url: str):
    return url

class AgentCoordinator:
    def __init__(self):
        self.state = {}
"""
    chunks = chunk_python_file("src/agent.py", code)
    assert len(chunks) == 3
    names = [c.name for c in chunks]
    assert "helper_function" in names
    assert "async_fetch" in names
    assert "AgentCoordinator" in names


def test_chunk_python_syntax_error_fallback():
    code = "def broken_syntax( - incomplete"
    chunks = chunk_python_file("broken.py", code)
    assert len(chunks) == 1
    assert chunks[0].chunk_type == "raw_file"
    assert chunks[0].content == code


def test_chunk_python_script_no_defs():
    code = "print('Hello world!')\nx = 10 + 20\n"
    chunks = chunk_python_file("script.py", code)
    assert len(chunks) == 1
    assert chunks[0].chunk_type == "raw_file"


def test_chunk_markdown_file():
    md = """# Architecture Overview

This document outlines the system.

## Ingestion Pipeline
Ingestion takes place via webhook.

### Storage Engine
Storage uses SQLite WAL mode.
"""
    chunks = chunk_markdown_file("docs/arch.md", md)
    assert len(chunks) == 3
    headers = [c.name for c in chunks]
    assert "Architecture Overview" in headers
    assert "Ingestion Pipeline" in headers
    assert "Storage Engine" in headers


def test_compute_sha256_deterministic():
    h1 = compute_sha256("test content")
    h2 = compute_sha256("test content")
    assert h1 == h2
    assert len(h1) == 64


def test_chunk_empty_python():
    chunks = chunk_python_file("empty.py", "")
    assert chunks == []


def test_chunk_empty_markdown():
    chunks = chunk_markdown_file("empty.md", "")
    assert chunks == []


def test_chunk_markdown_no_headers():
    chunks = chunk_markdown_file("note.md", "Just plain text without markdown headers.")
    assert len(chunks) == 1
    assert chunks[0].name == "note"

