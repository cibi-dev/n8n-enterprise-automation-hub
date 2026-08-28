"""CLI entry-point for n8n-sre-resilience-sentinel."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Literal, Optional, cast

from sentinel.models import ProbeTarget
from sentinel.prober import execute_synthetic_probe
from sentinel.remediator import execute_atomic_rollback
from sentinel.storage import SREHealthStorage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sre-sentinel",
        description="Local SRE Blackbox Health Monitoring and Automated Rollback Orchestrator",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. probe
    p_parser = subparsers.add_parser("probe", help="Execute single synthetic health probe")
    p_parser.add_argument("--url", required=True, help="Target endpoint URL")
    p_parser.add_argument("--service", default="app-service", help="Service identifier")
    p_parser.add_argument("--expected-status", type=int, default=200, help="Expected HTTP status code")
    p_parser.add_argument("--timeout-ms", type=float, default=2000.0, help="Timeout in ms")

    # 2. check-and-remediate
    c_parser = subparsers.add_parser("check-and-remediate", help="Probe, track health, and auto-rollback on breach")
    c_parser.add_argument("--url", required=True, help="Target endpoint URL")
    c_parser.add_argument("--service", default="app-service", help="Service identifier")
    c_parser.add_argument("--link-path", required=True, help="Path to 'current' symlink")
    c_parser.add_argument("--slots-dir", required=True, help="Path to slots parent directory")
    c_parser.add_argument("--threshold", type=int, default=3, help="Consecutive failure threshold")
    c_parser.add_argument("--db", default="sre_health.db", help="SQLite database path")

    # 3. manual-rollback
    r_parser = subparsers.add_parser("manual-rollback", help="Force atomic blue-green rollback")
    r_parser.add_argument("--service", default="app-service", help="Service identifier")
    r_parser.add_argument("--link-path", required=True, help="Path to 'current' symlink")
    r_parser.add_argument("--slots-dir", required=True, help="Path to slots parent directory")
    r_parser.add_argument("--target-slot", choices=["blue", "green"], required=True, help="Target slot")
    r_parser.add_argument("--db", default="sre_health.db", help="SQLite database path")

    # 4. history
    h_parser = subparsers.add_parser("history", help="Show rollback audit history")
    h_parser.add_argument("--service", default=None, help="Filter by service name")
    h_parser.add_argument("--db", default="sre_health.db", help="SQLite database path")

    return parser


def handle_probe(args: argparse.Namespace) -> int:
    target = ProbeTarget(
        service_name=args.service,
        url=args.url,
        expected_status=args.expected_status,
        timeout_ms=args.timeout_ms,
    )
    sample = execute_synthetic_probe(target)
    print(json.dumps(sample.model_dump(), indent=2))
    return 0 if sample.is_healthy else 1


def handle_check_and_remediate(args: argparse.Namespace) -> int:
    target = ProbeTarget(
        service_name=args.service,
        url=args.url,
        failure_threshold=args.threshold,
    )
    storage = SREHealthStorage(db_path=args.db)

    # 1. Execute probe
    sample = execute_synthetic_probe(target)

    # 2. Update health state
    state = storage.record_probe_sample(sample, failure_threshold=args.threshold)

    result_payload = {
        "sample": sample.model_dump(),
        "health_state": state.model_dump(),
        "rollback_executed": False,
        "rollback_action": None,
    }

    # 3. Trigger remediation if degraded
    if state.is_degraded:
        next_slot: Literal["blue", "green"] = "green" if state.active_slot == "blue" else "blue"
        action = execute_atomic_rollback(
            current_link_path=args.link_path,
            target_slot=next_slot,
            slots_dir=args.slots_dir,
            service_name=args.service,
            reason=f"Breached failure threshold ({args.threshold} consecutive failures: {sample.error_message})",
        )
        storage.record_rollback(action)
        result_payload["rollback_executed"] = True
        result_payload["rollback_action"] = action.model_dump()

    print(json.dumps(result_payload, indent=2))
    return 0 if not state.is_degraded else 2


def handle_manual_rollback(args: argparse.Namespace) -> int:
    storage = SREHealthStorage(db_path=args.db)
    slot_literal = cast(Literal["blue", "green"], args.target_slot)
    action = execute_atomic_rollback(
        current_link_path=args.link_path,
        target_slot=slot_literal,
        slots_dir=args.slots_dir,
        service_name=args.service,
        reason="Manual operator rollback override",
    )
    storage.record_rollback(action)
    print(json.dumps(action.model_dump(), indent=2))
    return 0 if action.success else 1


def handle_history(args: argparse.Namespace) -> int:
    storage = SREHealthStorage(db_path=args.db)
    records = storage.get_rollbacks(args.service)
    print(json.dumps(records, indent=2))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 1

    if args.subcommand == "probe":
        return handle_probe(args)
    elif args.subcommand == "check-and-remediate":
        return handle_check_and_remediate(args)
    elif args.subcommand == "manual-rollback":
        return handle_manual_rollback(args)
    elif args.subcommand == "history":
        return handle_history(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
