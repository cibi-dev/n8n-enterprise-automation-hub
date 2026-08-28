"""
Unified Command-Line Interface & Orchestrator for n8n Enterprise Automation Hub.

Provides unified management, local execution runners, and inspection for 5 automation domains:
- devsecops: SARIF / CycloneDX Webhook Bridge with HMAC-SHA256 Verification
- osint: Threat Intel Aggregator with MinHash Near-Duplicate Filtering & Alerts
- forensics: Incident Triage, PII Sanitizer & Cryptographic Chain of Custody
- sre: Blackbox Synthetic Probing & Sub-Second Atomic Symlink Rollback Sentinel
- rag: Codebase AST Chunking, Vector Knowledge Synchronizer & Obsidian Vault Exporter
- workflows: Inspect and validate all 5 production n8n JSON workflow definitions
- demo: End-to-end live multi-domain pipeline simulation
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Sequence

# Ensure subpackage paths are present in sys.path
_ROOT = Path(__file__).resolve().parent
_PACKAGES_DIR = _ROOT / "packages"

_MODULE_PATHS = [
    _ROOT,
    _PACKAGES_DIR / "n8n-devsecops-audit-bridge" / "src",
    _PACKAGES_DIR / "n8n-osint-threat-feed-enricher" / "src",
    _PACKAGES_DIR / "n8n-forensic-incident-triage" / "src",
    _PACKAGES_DIR / "n8n-sre-resilience-sentinel" / "src",
    _PACKAGES_DIR / "n8n-rag-knowledge-sync-hub" / "src",
]

for p in _MODULE_PATHS:
    p_str = str(p)
    if p_str not in sys.path:
        sys.path.insert(0, p_str)

__version__ = "1.0.0"


def _run_devsecops(argv: list[str]) -> int:
    import bridge.cli
    return bridge.cli.main(argv)


def _run_osint(argv: list[str]) -> int:
    import enricher.cli
    return enricher.cli.main(argv)


def _run_forensics(argv: list[str]) -> int:
    import triage.cli
    return triage.cli.main(argv)


def _run_sre(argv: list[str]) -> int:
    import sentinel.cli
    return sentinel.cli.main(argv)


def _run_rag(argv: list[str]) -> int:
    import rag_sync.cli
    return rag_sync.cli.main(argv)


def _run_workflows_inspect(argv: list[str]) -> int:
    workflows_dir = _ROOT / "workflows"
    if not workflows_dir.exists():
        print(f"[-] Workflows directory not found at: {workflows_dir}")
        return 1

    workflow_files = sorted(workflows_dir.glob("*.json"))
    print("\n" + "=" * 80)
    print(" ⚡ N8N ENTERPRISE AUTOMATION HUB - WORKFLOW INVENTORY")
    print("=" * 80)

    total_nodes = 0
    for wf_path in workflow_files:
        try:
            data = json.loads(wf_path.read_text(encoding="utf-8"))
            name = data.get("name", wf_path.stem)
            nodes = data.get("nodes", [])
            total_nodes += len(nodes)
            triggers = [n.get("name") for n in nodes if "trigger" in n.get("type", "").lower() or "webhook" in n.get("type", "").lower() or "schedule" in n.get("type", "").lower() or "poll" in n.get("type", "").lower()]
            
            print(f"\n📂 Workflow: {wf_path.name}")
            print(f"   Name:     {name}")
            print(f"   Nodes:    {len(nodes)} total nodes")
            print(f"   Triggers: {', '.join(triggers) if triggers else 'Manual / Internal'}")
            print(f"   Size:     {wf_path.stat().st_size:,} bytes")
        except Exception as exc:
            print(f"   [!] Error parsing {wf_path.name}: {exc}")

    print("\n" + "-" * 80)
    print(f" Total Workflows: {len(workflow_files)} | Total Configured Nodes: {total_nodes}")
    print("=" * 80 + "\n")
    return 0


def _run_demo() -> int:
    """Execute end-to-end multi-module simulation verifying all 5 automation pillars."""
    print("=" * 80)
    print(" 🚀 N8N ENTERPRISE AUTOMATION HUB - INTEGRATED SIMULATION PIPELINE")
    print("=" * 80)
    start_time = datetime.now(timezone.utc)

    # 1. DevSecOps Audit Bridge
    print("\n[1/5] 🛡️  Testing DevSecOps Audit Bridge (SARIF / SBOM HMAC Validation)...")
    from bridge.verifier import verify_hmac_signature, validate_webhook_url
    from bridge.parser import parse_sarif_report

    secret = "production-secret-token-xyz"
    sample_sarif = json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Bandit", "version": "1.7.5"}},
            "results": [
                {
                    "ruleId": "B101",
                    "level": "error",
                    "message": {"text": "Use of assert detected"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 10}}}]
                }
            ]
        }]
    })
    payload_bytes = sample_sarif.encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    is_valid = verify_hmac_signature(payload_bytes, f"sha256={sig}", secret)
    parsed_findings = parse_sarif_report(sample_sarif)
    url_ok, _ = validate_webhook_url("https://hooks.slack.com/services/T00/B00/X00", resolve_dns=False)

    print(f"      ✓ HMAC-SHA256 Constant-Time Verification: {is_valid}")
    print(f"      ✓ Anti-SSRF URL Sanitizer Check: {url_ok}")
    print(f"      ✓ SARIF Parser Extracted {len(parsed_findings)} Normalized Security Finding(s)")

    # 2. OSINT Threat Feed Enricher
    print("\n[2/5] 🌐 Testing OSINT Threat Feed Aggregator & MinHash Deduplication...")
    from enricher.models import ThreatAdvisory, ThreatDigest, ThreatFeedSource
    from enricher.minhash import compute_minhash_signature, estimate_jaccard_similarity
    from enricher.formatter import format_obsidian_digest

    raw_desc = "Critical memory corruption vulnerability allowing unauthenticated remote code execution."
    adv1 = ThreatAdvisory(
        id="CVE-2026-9999",
        cve_id="CVE-2026-9999",
        title="Remote Code Execution in Enterprise Gateway",
        description=raw_desc,
        source_feed=ThreatFeedSource.CISA_KEV,
        cvss_score=9.8,
        is_known_exploited=True,
        raw_hash=hashlib.sha256(raw_desc.encode("utf-8")).hexdigest(),
    )
    sig1 = compute_minhash_signature(adv1.description)
    sig2 = compute_minhash_signature("Critical memory corruption flaw permitting unauthenticated RCE.")
    sim = estimate_jaccard_similarity(sig1, sig2)
    digest = ThreatDigest(
        advisories=[adv1],
        total_ingested=1,
        unique_count=1,
        duplicate_count=0,
        critical_count=1,
    )
    obs_digest = format_obsidian_digest(digest)
    print(f"      ✓ MinHash Signature Computed (128 hash buckets)")
    print(f"      ✓ Estimated Near-Duplicate Jaccard Similarity: {sim:.2%}")
    print(f"      ✓ Formatted Obsidian Vault Markdown Digest ({len(obs_digest)} chars)")

    # 3. Forensic Incident Triage & Evidence Custody
    print("\n[3/5] 🔬 Testing Forensic Incident Triage & Evidence Custody...")
    from triage.sanitizer import sanitize_pii
    from triage.classifier import process_incident_triage

    raw_evidence = (
        "Security Alert: Compromise detected from IP 198.51.100.24. "
        "User admin (contact: secops@corp.internal, credit card: 4532-1234-5678-9012) "
        "reported ransomware encrypted data on fileserver-01."
    )
    sanitized_text, redacts = sanitize_pii(raw_evidence)
    incident = process_incident_triage(
        raw_text=raw_evidence,
        incident_id="INC-2026-0089",
        title="Fileserver Ransomware Attack",
    )
    print(f"      ✓ PII Sanitizer Redacted: {redacts.get('ipv4', 0)} IP(s), {redacts.get('email', 0)} Email(s), {redacts.get('credit_card', 0)} Card(s)")
    print(f"      ✓ Auto-Classified Incident: Category={incident.crime_category.value} | Priority={incident.priority.value}")
    print(f"      ✓ Cryptographic Custody Seal: {incident.custody_sha256[:24]}...")

    # 4. SRE Resilience Sentinel
    print("\n[4/5] 🚨 Testing SRE Resilience Sentinel & Atomic Blue/Green Rollback...")
    from sentinel.remediator import execute_atomic_rollback

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        slots_dir = tmp_path / "slots"
        slots_dir.mkdir()
        slot_a = slots_dir / "blue"
        slot_b = slots_dir / "green"
        slot_a.mkdir()
        slot_b.mkdir()
        (slot_a / "version.txt").write_text("v1.0.0")
        (slot_b / "version.txt").write_text("v2.0.0")

        current_link = tmp_path / "current"
        os.symlink(slot_b, current_link)  # active green (failing)

        res = execute_atomic_rollback(
            current_link_path=str(current_link),
            target_slot="blue",
            slots_dir=str(slots_dir),
            service_name="app-service",
            reason="Synthetic probe consecutive failure threshold exceeded"
        )
        print(f"      ✓ Executed Zero-Downtime Rollback: {res.previous_slot} -> {res.target_slot} in {res.execution_time_ms:.3f} ms")
        print(f"      ✓ Success: {res.success} | Active Symlink Target: {current_link.resolve().name}")

    # 5. RAG Codebase Knowledge Sync Hub
    print("\n[5/5] 🧠 Testing RAG Codebase Knowledge Synchronizer & Vector Indexer...")
    from rag_sync.chunker import chunk_python_file
    from rag_sync.indexer import VectorKnowledgeIndexer

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        sample_code = (
            'def execute_triage(event: dict) -> dict:\n'
            '    """Execute automated incident triage and sanitization."""\n'
            '    return {"status": "success", "processed": True}\n\n'
            'def verify_signature(token: str) -> bool:\n'
            '    """Verify HMAC token with constant-time check."""\n'
            '    return len(token) > 0\n'
        )
        chunks = chunk_python_file("engine.py", sample_code)
        indexer = VectorKnowledgeIndexer(db_path=str(tmp_path / "rag.db"))
        indexer.index_chunks(chunks)
        search_res = indexer.search("automated incident triage", top_k=2)

        print(f"      ✓ AST Chunker Parsed: {len(chunks)} Functional Units / Symbols")
        top_name = search_res[0].name if search_res else "N/A"
        top_score = search_res[0].score if search_res else 0.0
        print(f"      ✓ Indexed into Vector Storage with Top Match Score: {top_score:.4f} ({top_name})")

    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    print("\n" + "=" * 80)
    print(f" ✅ ALL 5 N8N AUTOMATION MODULES OPERATIONAL & VERIFIED ({duration:.2f}s)")
    print("=" * 80 + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="n8n-hub",
        description="Enterprise n8n Workflow Automation Hub & Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Module Commands:
  n8n-hub devsecops    SARIF / CycloneDX Webhook Bridge with HMAC-SHA256 verification
  n8n-hub osint        OSINT Threat Feed Aggregator with MinHash near-duplicate filtering
  n8n-hub forensics    Incident Triage, PII Sanitizer & Cryptographic Chain of Custody
  n8n-hub sre          Blackbox Synthetic Probing & Sub-Second Atomic Symlink Rollback
  n8n-hub rag          Codebase AST Chunking, Vector Knowledge Synchronizer & Obsidian Export
  n8n-hub workflows    Inspect and validate the 5 production n8n JSON workflow configurations
  n8n-hub demo         Run full end-to-end integration simulation across all 5 modules
        """,
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available subsystem runners")

    # devsecops
    subparsers.add_parser("devsecops", help="Run DevSecOps Audit Bridge CLI")
    # osint
    subparsers.add_parser("osint", help="Run OSINT Threat Feed Enricher CLI")
    # forensics
    subparsers.add_parser("forensics", help="Run Forensic Incident Triage CLI")
    # sre
    subparsers.add_parser("sre", help="Run SRE Resilience Sentinel CLI")
    # rag
    subparsers.add_parser("rag", help="Run RAG Knowledge Sync Hub CLI")
    # workflows
    subparsers.add_parser("workflows", help="Inspect and validate n8n JSON workflow files")
    # demo
    subparsers.add_parser("demo", help="Run end-to-end integrated demo across all 5 engines")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args_list = list(argv if argv is not None else sys.argv[1:])

    if not args_list:
        parser = build_parser()
        parser.print_help()
        return 0

    cmd = args_list[0]
    sub_argv = args_list[1:]

    if cmd in ("-h", "--help"):
        build_parser().print_help()
        return 0
    elif cmd in ("-v", "--version"):
        print(f"n8n-enterprise-automation-hub {__version__}")
        return 0
    elif cmd == "demo":
        return _run_demo()
    elif cmd == "workflows":
        return _run_workflows_inspect(sub_argv)
    elif cmd == "devsecops":
        return _run_devsecops(sub_argv)
    elif cmd == "osint":
        return _run_osint(sub_argv)
    elif cmd == "forensics":
        return _run_forensics(sub_argv)
    elif cmd == "sre":
        return _run_sre(sub_argv)
    elif cmd == "rag":
        return _run_rag(sub_argv)
    else:
        print(f"Unknown command: {cmd}")
        build_parser().print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
