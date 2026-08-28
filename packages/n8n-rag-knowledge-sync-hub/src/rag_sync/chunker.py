"""AST Code and Markdown Document Chunker.

Conforms to Canonical Security Standards #8 and #15 (safe AST parsing).
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import List

from rag_sync.models import CodeChunk


def compute_sha256(content: str) -> str:
    """Compute SHA-256 hex digest of UTF-8 content string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest().lower()


def chunk_python_file(file_path: str, source_code: str) -> List[CodeChunk]:
    """Parse Python source code using AST and extract function and class chunks."""
    chunks: List[CodeChunk] = []
    lines = source_code.splitlines()

    try:
        tree = ast.parse(source_code, filename=file_path)
    except SyntaxError:
        # Fallback to whole-file chunk if syntax error
        content_hash = compute_sha256(source_code)
        chunk_id = f"raw-{content_hash[:16]}"
        return [
            CodeChunk(
                chunk_id=chunk_id,
                file_path=file_path,
                chunk_type="raw_file",
                name=Path(file_path).name,
                content=source_code,
                content_hash=content_hash,
                line_start=1,
                line_end=max(1, len(lines)),
            )
        ]

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = node.end_lineno or start
            chunk_lines = lines[start - 1 : end]
            content = "\n".join(chunk_lines)
            content_hash = compute_sha256(content)
            chunk_id = f"fn-{content_hash[:16]}"

            chunks.append(
                CodeChunk(
                    chunk_id=chunk_id,
                    file_path=file_path,
                    chunk_type="function",
                    name=node.name,
                    content=content,
                    content_hash=content_hash,
                    line_start=start,
                    line_end=end,
                )
            )
        elif isinstance(node, ast.ClassDef):
            start = node.lineno
            end = node.end_lineno or start
            chunk_lines = lines[start - 1 : end]
            content = "\n".join(chunk_lines)
            content_hash = compute_sha256(content)
            chunk_id = f"cls-{content_hash[:16]}"

            chunks.append(
                CodeChunk(
                    chunk_id=chunk_id,
                    file_path=file_path,
                    chunk_type="class",
                    name=node.name,
                    content=content,
                    content_hash=content_hash,
                    line_start=start,
                    line_end=end,
                )
            )

    if not chunks and source_code.strip():
        content_hash = compute_sha256(source_code)
        chunk_id = f"raw-{content_hash[:16]}"
        chunks.append(
            CodeChunk(
                chunk_id=chunk_id,
                file_path=file_path,
                chunk_type="raw_file",
                name=Path(file_path).name,
                content=source_code,
                content_hash=content_hash,
                line_start=1,
                line_end=max(1, len(lines)),
            )
        )

    return chunks


def chunk_markdown_file(file_path: str, markdown_text: str) -> List[CodeChunk]:
    """Split Markdown document into section chunks based on markdown headers."""
    chunks: List[CodeChunk] = []
    lines = markdown_text.splitlines()

    current_header = Path(file_path).stem
    current_lines: List[str] = []
    start_line = 1

    for i, line in enumerate(lines, start=1):
        header_match = re.match(r"^(#{1,3})\s+(.+)$", line)
        if header_match:
            if current_lines:
                content = "\n".join(current_lines).strip()
                if content:
                    content_hash = compute_sha256(content)
                    chunks.append(
                        CodeChunk(
                            chunk_id=f"md-{content_hash[:16]}",
                            file_path=file_path,
                            chunk_type="markdown_section",
                            name=current_header,
                            content=content,
                            content_hash=content_hash,
                            line_start=start_line,
                            line_end=i - 1,
                        )
                    )
            current_header = header_match.group(2).strip()
            current_lines = [line]
            start_line = i
        else:
            current_lines.append(line)

    if current_lines:
        content = "\n".join(current_lines).strip()
        if content:
            content_hash = compute_sha256(content)
            chunks.append(
                CodeChunk(
                    chunk_id=f"md-{content_hash[:16]}",
                    file_path=file_path,
                    chunk_type="markdown_section",
                    name=current_header,
                    content=content,
                    content_hash=content_hash,
                    line_start=start_line,
                    line_end=len(lines),
                )
            )

    return chunks
