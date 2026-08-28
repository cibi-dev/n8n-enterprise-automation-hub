"""SQLite Vector Database Indexer and Semantic Search Engine."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional
import numpy as np

from rag_sync.models import CodeChunk, SearchMatch, utcnow_iso
from rag_sync.vectorizer import HashingVectorizer


class VectorKnowledgeIndexer:
    """Persistent SQLite database manager for semantic code chunks and vectors."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._vectorizer = HashingVectorizer(dim=64)
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS code_chunks (
                    chunk_id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    chunk_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    content TEXT NOT NULL,
                    content_hash TEXT NOT NULL UNIQUE,
                    line_start INTEGER NOT NULL,
                    line_end INTEGER NOT NULL,
                    vector_blob BLOB NOT NULL,
                    indexed_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_chunk_file ON code_chunks(file_path);
                CREATE INDEX IF NOT EXISTS idx_chunk_hash ON code_chunks(content_hash);
            """)

    def index_chunks(self, chunks: List[CodeChunk]) -> tuple[int, int]:
        """Index a batch of code chunks.

        Returns:
            (new_chunks_count, skipped_duplicates_count)
        """
        new_count = 0
        skipped_count = 0
        now_ts = utcnow_iso()

        with self._lock, self._get_connection() as conn:
            for chunk in chunks:
                # Check if hash already exists
                existing = conn.execute(
                    "SELECT chunk_id FROM code_chunks WHERE content_hash = ?",
                    (chunk.content_hash,),
                ).fetchone()

                if existing:
                    skipped_count += 1
                    continue

                # Generate vector if missing
                embedding = chunk.embedding or self._vectorizer.vectorize(chunk.content)
                vec_array = np.array(embedding, dtype=np.float32)
                vec_blob = vec_array.tobytes()

                conn.execute(
                    """
                    INSERT OR REPLACE INTO code_chunks (
                        chunk_id, file_path, chunk_type, name, content,
                        content_hash, line_start, line_end, vector_blob, indexed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        chunk.chunk_id,
                        chunk.file_path,
                        chunk.chunk_type,
                        chunk.name,
                        chunk.content,
                        chunk.content_hash,
                        chunk.line_start,
                        chunk.line_end,
                        vec_blob,
                        now_ts,
                    ),
                )
                new_count += 1

        return new_count, skipped_count

    def search(self, query: str, top_k: int = 5) -> List[SearchMatch]:
        """Execute semantic Top-K cosine similarity search against indexed vectors."""
        query_vec = np.array(self._vectorizer.vectorize(query), dtype=np.float32)
        matches: List[SearchMatch] = []

        with self._lock, self._get_connection() as conn:
            rows = conn.execute(
                "SELECT chunk_id, file_path, chunk_type, name, content, vector_blob FROM code_chunks"
            ).fetchall()

            scored_items = []
            for row in rows:
                vec_array = np.frombuffer(row["vector_blob"], dtype=np.float32)
                norm_q = np.linalg.norm(query_vec)
                norm_v = np.linalg.norm(vec_array)
                if norm_q < 1e-9 or norm_v < 1e-9:
                    score = 0.0
                else:
                    score = float(np.dot(query_vec, vec_array) / (norm_q * norm_v))

                scored_items.append((score, row))

            scored_items.sort(key=lambda x: x[0], reverse=True)

            for score, row in scored_items[:top_k]:
                matches.append(
                    SearchMatch(
                        chunk_id=row["chunk_id"],
                        file_path=row["file_path"],
                        chunk_type=row["chunk_type"],
                        name=row["name"],
                        score=round(score, 4),
                        content=row["content"][:300],
                    )
                )

        return matches

    def get_stats(self) -> Dict[str, Any]:
        """Retrieve total index count and file distribution."""
        with self._lock, self._get_connection() as conn:
            total_chunks = conn.execute("SELECT COUNT(*) FROM code_chunks").fetchone()[0]
            files_count = conn.execute("SELECT COUNT(DISTINCT file_path) FROM code_chunks").fetchone()[0]
            type_rows = conn.execute("SELECT chunk_type, COUNT(*) FROM code_chunks GROUP BY chunk_type").fetchall()

            return {
                "total_chunks": total_chunks,
                "unique_files": files_count,
                "by_type": {r[0]: r[1] for r in type_rows},
            }
