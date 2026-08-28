"""CLI Interface for n8n-devsecops-audit-bridge.

Can be invoked standalone or via local n8n Execute Command / HTTP nodes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from bridge.models import AuditPayload
from bridge.parser import parse_cyclonedx_sbom, parse_sarif_report
from bridge.storage import AuditStorage
from bridge.verifier import validate_webhook_url, verify_hmac_signature


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devsecops-audit-bridge",
        description="Local DevSecOps Audit Bridge for SARIF/CycloneDX ingestion and HMAC verification",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. verify-signature
    v_parser = subparsers.add_parser("verify-signature", help="Verify HMAC signature of a file or string")
    v_parser.add_argument("payload_file", help="Path to payload file to verify")
    v_parser.add_argument("--signature", required=True, help="HMAC-SHA256 signature string or header")
    v_parser.add_argument("--secret", default=os.getenv("WEBHOOK_SECRET", ""), help="Shared webhook secret")

    # 2. parse-sarif
    s_parser = subparsers.add_parser("parse-sarif", help="Extract normalized security findings from SARIF file")
    s_parser.add_argument("sarif_file", help="Path to SARIF JSON report")

    # 3. parse-sbom
    b_parser = subparsers.add_parser("parse-sbom", help="Extract components from CycloneDX SBOM file")
    b_parser.add_argument("sbom_file", help="Path to CycloneDX JSON file")

    # 4. process-audit
    p_parser = subparsers.add_parser("process-audit", help="Process and store a complete audit payload in SQLite")
    p_parser.add_argument("--payload", required=True, help="Path to AuditPayload JSON file")
    p_parser.add_argument("--db", default="devsecops_audit.db", help="Path to SQLite database")
    p_parser.add_argument("--signature", default=None, help="Optional signature to verify against payload")
    p_parser.add_argument("--secret", default=os.getenv("WEBHOOK_SECRET", ""), help="Shared secret if verifying")

    # 5. validate-url
    u_parser = subparsers.add_parser("validate-url", help="Validate outbound webhook URL against SSRF")
    u_parser.add_argument("url", help="Target URL to check")
    u_parser.add_argument("--no-dns", action="store_true", help="Skip active DNS lookup")

    return parser


def handle_verify_signature(args: argparse.Namespace) -> int:
    path = Path(args.payload_file)
    if not path.is_file():
        print(f"Error: Payload file not found: {path}", file=sys.stderr)
        return 1

    payload_bytes = path.read_bytes()
    is_valid = verify_hmac_signature(payload_bytes, args.signature, args.secret)
    res = {"signature_valid": is_valid, "file": str(path)}
    print(json.dumps(res, indent=2))
    return 0 if is_valid else 1


def handle_parse_sarif(args: argparse.Namespace) -> int:
    path = Path(args.sarif_file)
    if not path.is_file():
        print(f"Error: SARIF file not found: {path}", file=sys.stderr)
        return 1

    findings = parse_sarif_report(path.read_text(encoding="utf-8"))
    res = {"total_findings": len(findings), "findings": [f.model_dump() for f in findings]}
    print(json.dumps(res, indent=2))
    return 0


def handle_parse_sbom(args: argparse.Namespace) -> int:
    path = Path(args.sbom_file)
    if not path.is_file():
        print(f"Error: SBOM file not found: {path}", file=sys.stderr)
        return 1

    components = parse_cyclonedx_sbom(path.read_text(encoding="utf-8"))
    res = {"total_components": len(components), "components": [c.model_dump() for c in components]}
    print(json.dumps(res, indent=2))
    return 0


def handle_process_audit(args: argparse.Namespace) -> int:
    path = Path(args.payload)
    if not path.is_file():
        print(f"Error: Payload file not found: {path}", file=sys.stderr)
        return 1

    raw_data = path.read_bytes()
    sig_valid = True
    if args.signature:
        sig_valid = verify_hmac_signature(raw_data, args.signature, args.secret)

    payload_dict = json.loads(raw_data.decode("utf-8"))
    payload = AuditPayload.model_validate(payload_dict)

    storage = AuditStorage(db_path=args.db)
    result = storage.record_audit(payload, signature_valid=sig_valid)

    print(json.dumps(result.model_dump(), indent=2))
    return 0 if result.is_compliant else 1


def handle_validate_url(args: argparse.Namespace) -> int:
    allowed, reason = validate_webhook_url(args.url, resolve_dns=not args.no_dns)
    res = {"url": args.url, "is_allowed": allowed, "reason": reason}
    print(json.dumps(res, indent=2))
    return 0 if allowed else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 1

    if args.subcommand == "verify-signature":
        return handle_verify_signature(args)
    elif args.subcommand == "parse-sarif":
        return handle_parse_sarif(args)
    elif args.subcommand == "parse-sbom":
        return handle_parse_sbom(args)
    elif args.subcommand == "process-audit":
        return handle_process_audit(args)
    elif args.subcommand == "validate-url":
        return handle_validate_url(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
