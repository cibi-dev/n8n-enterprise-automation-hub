"""CLI entry-point for n8n-forensic-incident-triage."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from triage.classifier import process_incident_triage
from triage.sanitizer import sanitize_pii
from triage.storage import ForensicTriageStorage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic-triage",
        description="Local Cybercrime Incident Triage and Evidence Custody Processor",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. sanitize
    s_parser = subparsers.add_parser("sanitize", help="Sanitize PII from text or file")
    s_parser.add_argument("file", help="Path to raw incident text file")

    # 2. triage
    t_parser = subparsers.add_parser("triage", help="Execute complete triage, classification and custody sealing")
    t_parser.add_argument("file", help="Path to raw incident report file")
    t_parser.add_argument("--id", default="INC-001", help="Incident ID")
    t_parser.add_argument("--title", default="Cybercrime Incident", help="Incident title")
    t_parser.add_argument("--db", default="forensic_triage.db", help="SQLite database path")
    t_parser.add_argument("--no-persist", action="store_true", help="Skip storing to database")

    # 3. stats
    st_parser = subparsers.add_parser("stats", help="Show aggregated database statistics")
    st_parser.add_argument("--db", default="forensic_triage.db", help="SQLite database path")

    return parser


def handle_sanitize(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: File not found: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")
    sanitized, counts = sanitize_pii(text)
    res = {"sanitized_text": sanitized, "redacted_pii_counts": counts}
    print(json.dumps(res, indent=2))
    return 0


def handle_triage(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: File not found: {path}", file=sys.stderr)
        return 1

    raw_text = path.read_text(encoding="utf-8")
    report = process_incident_triage(raw_text, incident_id=args.id, title=args.title)

    if not args.no_persist:
        storage = ForensicTriageStorage(db_path=args.db)
        report = storage.save_incident(report)

    print(json.dumps(report.model_dump(), indent=2))
    return 0


def handle_stats(args: argparse.Namespace) -> int:
    storage = ForensicTriageStorage(db_path=args.db)
    stats = storage.get_stats()
    print(json.dumps(stats, indent=2))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 1

    if args.subcommand == "sanitize":
        return handle_sanitize(args)
    elif args.subcommand == "triage":
        return handle_triage(args)
    elif args.subcommand == "stats":
        return handle_stats(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
