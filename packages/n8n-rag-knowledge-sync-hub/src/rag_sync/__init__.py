"""n8n-rag-knowledge-sync-hub package."""

from rag_sync.chunker import (
    chunk_markdown_file,
    chunk_python_file,
    compute_sha256,
)
from rag_sync.indexer import VectorKnowledgeIndexer
from rag_sync.models import (
    CodeChunk,
    SearchMatch,
    SyncResult,
)
from rag_sync.obsidian import format_obsidian_codebase_note
from rag_sync.vectorizer import HashingVectorizer

__version__ = "0.1.0"

__all__ = [
    "CodeChunk",
    "SyncResult",
    "SearchMatch",
    "compute_sha256",
    "chunk_python_file",
    "chunk_markdown_file",
    "HashingVectorizer",
    "VectorKnowledgeIndexer",
    "format_obsidian_codebase_note",
]
