"""CLI entry-point for n8n-osint-threat-feed-enricher."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from enricher.cache import ThreatFeedCache
from enricher.formatter import format_obsidian_digest, format_telegram_alert
from enricher.models import ThreatAdvisory, ThreatDigest
from enricher.parsers import parse_cisa_kev_catalog, parse_nvd_cve_feed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint-enricher",
        description="Local OSINT Security Threat Feed Aggregator and MinHash Deduplication Engine",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. parse-cisa
    c_parser = subparsers.add_parser("parse-cisa", help="Parse CISA KEV JSON catalog")
    c_parser.add_argument("file", help="Path to CISA KEV JSON file")

    # 2. parse-nvd
    n_parser = subparsers.add_parser("parse-nvd", help="Parse NVD 2.0 CVE JSON response")
    n_parser.add_argument("file", help="Path to NVD JSON file")

    # 3. dedup-stream
    d_parser = subparsers.add_parser("dedup-stream", help="Deduplicate threat advisories using MinHash and cache")
    d_parser.add_argument("input_file", help="Path to JSON file containing list of ThreatAdvisory objects")
    d_parser.add_argument("--db", default="osint_threats.db", help="Path to SQLite threat cache")
    d_parser.add_argument("--threshold", type=float, default=0.70, help="MinHash Jaccard similarity threshold")
    d_parser.add_argument("--format", choices=["json", "obsidian", "telegram"], default="json", help="Output format")
    d_parser.add_argument("--no-persist", action="store_true", help="Do not store unique items to DB")

    return parser


def handle_parse_cisa(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: File not found: {path}", file=sys.stderr)
        return 1

    advisories = parse_cisa_kev_catalog(path.read_text(encoding="utf-8"))
    res = [a.model_dump() for a in advisories]
    print(json.dumps(res, indent=2))
    return 0


def handle_parse_nvd(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: File not found: {path}", file=sys.stderr)
        return 1

    advisories = parse_nvd_cve_feed(path.read_text(encoding="utf-8"))
    res = [a.model_dump() for a in advisories]
    print(json.dumps(res, indent=2))
    return 0


def handle_dedup_stream(args: argparse.Namespace) -> int:
    path = Path(args.input_file)
    if not path.is_file():
        print(f"Error: File not found: {path}", file=sys.stderr)
        return 1

    raw_items = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw_items, dict) and "advisories" in raw_items:
        raw_items = raw_items["advisories"]

    if not isinstance(raw_items, list):
        print("Error: Input JSON must be a list of advisories", file=sys.stderr)
        return 1

    advisories = [ThreatAdvisory.model_validate(item) for item in raw_items]
    cache = ThreatFeedCache(db_path=args.db)
    digest = cache.deduplicate_stream(
        advisories,
        similarity_threshold=args.threshold,
        persist=not args.no_persist,
    )

    if args.format == "obsidian":
        print(format_obsidian_digest(digest))
    elif args.format == "telegram":
        for a in digest.advisories[:5]:
            print(format_telegram_alert(a))
            print("\n" + "=" * 40 + "\n")
    else:
        print(json.dumps(digest.model_dump(), indent=2))

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 1

    if args.subcommand == "parse-cisa":
        return handle_parse_cisa(args)
    elif args.subcommand == "parse-nvd":
        return handle_parse_nvd(args)
    elif args.subcommand == "dedup-stream":
        return handle_dedup_stream(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
