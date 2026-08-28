"""Immutable Pydantic v2 domain models for RAG Knowledge Sync Hub.

Conforms to Canonical Security Standards #7 and #15 (CWE-502 defense).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


def utcnow_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CodeChunk(BaseModel):
    """Extracted semantic unit of code or documentation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    chunk_id: str = Field(..., min_length=1, description="Unique chunk deterministic identifier")
    file_path: str = Field(..., min_length=1, description="Relative or repository file path")
    chunk_type: Literal["function", "class", "markdown_section", "raw_file"] = Field(
        ..., description="Semantic entity kind"
    )
    name: str = Field(..., min_length=1, description="Function, class or section header name")
    content: str = Field(..., min_length=1, description="Source code or text chunk content")
    content_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 digest of content")
    line_start: int = Field(default=1, ge=1, description="Starting 1-indexed line number")
    line_end: int = Field(default=1, ge=1, description="Ending 1-indexed line number")
    embedding: Optional[List[float]] = Field(default=None, description="Normalized dense feature vector")


class SyncResult(BaseModel):
    """Report summary of codebase ingestion and indexing synchronization."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_path: str = Field(..., min_length=1, description="Root path of indexed repository")
    total_files_scanned: int = Field(default=0, ge=0, description="Total source files processed")
    chunks_extracted: int = Field(default=0, ge=0, description="Total code chunks extracted")
    new_chunks_indexed: int = Field(default=0, ge=0, description="New or modified chunks added to index")
    skipped_duplicates: int = Field(default=0, ge=0, description="Unmodified chunks skipped via hash matching")
    execution_time_ms: float = Field(..., ge=0.0, description="Total indexing duration in ms")
    timestamp: str = Field(default_factory=utcnow_iso, description="Sync timestamp (ISO 8601 UTC)")


class SearchMatch(BaseModel):
    """Semantic vector search result match."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    chunk_id: str = Field(..., min_length=1, description="Matched chunk ID")
    file_path: str = Field(..., min_length=1, description="Source file path")
    chunk_type: str = Field(..., description="Matched chunk entity type")
    name: str = Field(..., description="Entity name or header")
    score: float = Field(..., description="Cosine similarity score [-1.0, 1.0]")
    content: str = Field(..., description="Content snippet")
