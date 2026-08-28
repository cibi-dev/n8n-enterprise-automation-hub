"""CLI entry-point for n8n-rag-knowledge-sync-hub."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional

from rag_sync.chunker import chunk_markdown_file, chunk_python_file
from rag_sync.indexer import VectorKnowledgeIndexer
from rag_sync.models import CodeChunk, SyncResult
from rag_sync.obsidian import format_obsidian_codebase_note


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rag-sync",
        description="Local Codebase AST Chunker, Vector Synchronizer and Obsidian Vault Indexer",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. scan-and-sync
    s_parser = subparsers.add_parser("scan-and-sync", help="Scan codebase, extract AST chunks and sync vector DB")
    s_parser.add_argument("repo_path", help="Path to local repository directory")
    s_parser.add_argument("--db", default="codebase_rag.db", help="SQLite vector database path")
    s_parser.add_argument("--obsidian-out", default=None, help="Optional output path for Obsidian note")

    # 2. search
    q_parser = subparsers.add_parser("search", help="Execute semantic search query against indexed chunks")
    q_parser.add_argument("query", help="Semantic text query")
    q_parser.add_argument("--top-k", type=int, default=5, help="Number of matches to retrieve")
    q_parser.add_argument("--db", default="codebase_rag.db", help="SQLite vector database path")

    # 3. stats
    st_parser = subparsers.add_parser("stats", help="Show aggregated vector index statistics")
    st_parser.add_argument("--db", default="codebase_rag.db", help="SQLite vector database path")

    return parser


def handle_scan_and_sync(args: argparse.Namespace) -> int:
    repo_p = Path(args.repo_path).resolve()
    if not repo_p.is_dir():
        print(f"Error: Directory not found: {repo_p}", file=sys.stderr)
        return 1

    t0 = time.perf_counter()
    files_scanned = 0
    all_chunks: List[CodeChunk] = []

    for fpath in repo_p.rglob("*"):
        if not fpath.is_file() or any(p in fpath.parts for p in [".git", "__pycache__", ".venv", "node_modules"]):
            continue

        rel_path = str(fpath.relative_to(repo_p))

        if fpath.suffix == ".py":
            try:
                code = fpath.read_text(encoding="utf-8")
                chunks = chunk_python_file(rel_path, code)
                all_chunks.extend(chunks)
                files_scanned += 1
            except Exception:
                continue
        elif fpath.suffix == ".md":
            try:
                text = fpath.read_text(encoding="utf-8")
                chunks = chunk_markdown_file(rel_path, text)
                all_chunks.extend(chunks)
                files_scanned += 1
            except Exception:
                continue

    indexer = VectorKnowledgeIndexer(db_path=args.db)
    new_indexed, skipped = indexer.index_chunks(all_chunks)

    t1 = time.perf_counter()
    duration_ms = (t1 - t0) * 1000.0

    sync_result = SyncResult(
        repository_path=str(repo_p),
        total_files_scanned=files_scanned,
        chunks_extracted=len(all_chunks),
        new_chunks_indexed=new_indexed,
        skipped_duplicates=skipped,
        execution_time_ms=round(duration_ms, 2),
    )

    if args.obsidian_out:
        obsidian_note = format_obsidian_codebase_note(
            repo_name=repo_p.name,
            sync_result=sync_result,
            chunks=all_chunks,
        )
        out_p = Path(args.obsidian_out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(obsidian_note, encoding="utf-8")

    print(json.dumps(sync_result.model_dump(), indent=2))
    return 0


def handle_search(args: argparse.Namespace) -> int:
    indexer = VectorKnowledgeIndexer(db_path=args.db)
    matches = indexer.search(args.query, top_k=args.top_k)
    data = [m.model_dump() for m in matches]
    print(json.dumps(data, indent=2))
    return 0


def handle_stats(args: argparse.Namespace) -> int:
    indexer = VectorKnowledgeIndexer(db_path=args.db)
    stats = indexer.get_stats()
    print(json.dumps(stats, indent=2))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 1

    if args.subcommand == "scan-and-sync":
        return handle_scan_and_sync(args)
    elif args.subcommand == "search":
        return handle_search(args)
    elif args.subcommand == "stats":
        return handle_stats(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
