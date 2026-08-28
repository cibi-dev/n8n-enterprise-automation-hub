"""
Suite Integration & Workflow Integrity Verification Tests.

Verifies:
1. JSON structure, node parameters, and trigger bindings across all 5 n8n workflow definitions.
2. CLI entrypoints and submodule routing.
3. Domain engine integration, HMAC security verification, and deterministic execution.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import tempfile
import pytest

# Ensure root and packages are in sys.path
_ROOT = Path(__file__).resolve().parent.parent
_PACKAGES = _ROOT / "packages"

for p in [
    _ROOT,
    _PACKAGES / "n8n-devsecops-audit-bridge" / "src",
    _PACKAGES / "n8n-osint-threat-feed-enricher" / "src",
    _PACKAGES / "n8n-forensic-incident-triage" / "src",
    _PACKAGES / "n8n-sre-resilience-sentinel" / "src",
    _PACKAGES / "n8n-rag-knowledge-sync-hub" / "src",
]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import cli


class TestWorkflowFilesIntegrity:
    """Validate format, schema, and node integrity of n8n JSON workflow templates."""

    @pytest.fixture
    def workflows_dir(self) -> Path:
        return _ROOT / "workflows"

    def test_workflow_directory_and_count(self, workflows_dir: Path) -> None:
        assert workflows_dir.exists(), f"Workflows directory missing at {workflows_dir}"
        json_files = list(workflows_dir.glob("*.json"))
        assert len(json_files) == 5, f"Expected 5 workflow templates, found {len(json_files)}"

    @pytest.mark.parametrize(
        "filename,expected_name,min_nodes",
        [
            ("devsecops-audit-bridge.json", "DevSecOps Audit Webhook Bridge & Compliance Archiver", 6),
            ("osint-feed-enricher.json", "OSINT Security Threat Feed Aggregator & MinHash Deduplicator", 6),
            ("forensic-incident-triage.json", "Forensic Incident Triage & Evidence Custody Bridge", 5),
            ("sre-sentinel.json", "SRE Resilience Sentinel & Automated Rollback", 4),
            ("rag-knowledge-sync.json", "RAG Codebase Knowledge Synchronizer & Obsidian Vault Indexer", 4),
        ],
    )
    def test_workflow_structure_and_nodes(
        self, workflows_dir: Path, filename: str, expected_name: str, min_nodes: int
    ) -> None:
        wf_path = workflows_dir / filename
        assert wf_path.exists(), f"Workflow file missing: {filename}"

        content = wf_path.read_text(encoding="utf-8")
        data = json.loads(content)

        assert isinstance(data, dict), f"{filename} is not a valid JSON object"
        assert data.get("name") == expected_name
        nodes = data.get("nodes", [])
        assert isinstance(nodes, list), f"'nodes' must be a list in {filename}"
        assert len(nodes) >= min_nodes, f"{filename} has fewer than {min_nodes} nodes"

        # Validate each node
        node_ids = set()
        for idx, node in enumerate(nodes):
            assert "id" in node, f"Node at index {idx} in {filename} lacks 'id'"
            assert "name" in node, f"Node at index {idx} in {filename} lacks 'name'"
            assert "type" in node, f"Node '{node['name']}' in {filename} lacks 'type'"
            assert "parameters" in node, f"Node '{node['name']}' in {filename} lacks 'parameters'"
            assert node["id"] not in node_ids, f"Duplicate node ID '{node['id']}' in {filename}"
            node_ids.add(node["id"])


class TestCLIAndSubmodules:
    """Validate unified CLI runner and subcommands."""

    def test_cli_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = cli.main(["--version"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "1.0.0" in captured.out

    def test_cli_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = cli.main(["--help"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Enterprise n8n Workflow Automation Hub" in captured.out

    def test_cli_workflows_inspection(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = cli.main(["workflows"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "N8N ENTERPRISE AUTOMATION HUB - WORKFLOW INVENTORY" in captured.out
        assert "devsecops-audit-bridge.json" in captured.out
        assert "sre-sentinel.json" in captured.out
        assert "Total Workflows: 5" in captured.out

    def test_cli_demo_execution(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = cli.main(["demo"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "ALL 5 N8N AUTOMATION MODULES OPERATIONAL & VERIFIED" in captured.out
        assert "HMAC-SHA256 Constant-Time Verification: True" in captured.out
        assert "MinHash Signature Computed" in captured.out
        assert "Auto-Classified Incident" in captured.out
        assert "Executed Zero-Downtime Rollback" in captured.out
        assert "AST Chunker Parsed" in captured.out

    def test_cli_unknown_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = cli.main(["non_existent_cmd"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Unknown command" in captured.out


class TestDomainEnginesDirect:
    """Direct functional verification of domain packages."""

    def test_devsecops_verifier_and_parser(self) -> None:
        from bridge.verifier import verify_hmac_signature, validate_webhook_url
        from bridge.parser import parse_sarif_report, parse_cyclonedx_sbom

        secret = "test-secret"
        payload = b'{"status": "ok"}'
        sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

        assert verify_hmac_signature(payload, f"sha256={sig}", secret) is True
        assert verify_hmac_signature(payload, "sha256=invalid-signature", secret) is False

        # SSRF checks
        allowed, _ = validate_webhook_url("https://api.github.com/repos", resolve_dns=False)
        assert allowed is True
        blocked, _ = validate_webhook_url("http://169.254.169.254/latest/meta-data", resolve_dns=False)
        assert blocked is False

        # SARIF parser
        sarif_sample = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Bandit"}},
                "results": [{
                    "ruleId": "B101",
                    "level": "error",
                    "message": {"text": "assert statement found"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "test.py"}, "region": {"startLine": 5}}}]
                }]
            }]
        }
        findings = parse_sarif_report(sarif_sample)
        assert len(findings) == 1
        assert findings[0].rule_id == "B101"

    def test_osint_minhash_and_digest(self) -> None:
        from enricher.models import ThreatAdvisory, ThreatDigest, ThreatFeedSource
        from enricher.minhash import compute_minhash_signature, estimate_jaccard_similarity
        from enricher.formatter import format_obsidian_digest

        desc1 = "Buffer overflow in OpenSSH server version 9.2p1"
        desc2 = "OpenSSH server 9.2p1 memory buffer overflow flaw"
        sig1 = compute_minhash_signature(desc1)
        sig2 = compute_minhash_signature(desc2)
        similarity = estimate_jaccard_similarity(sig1, sig2)
        assert 0.0 <= similarity <= 1.0

        adv = ThreatAdvisory(
            id="CVE-2026-0001",
            cve_id="CVE-2026-0001",
            title="OpenSSH Buffer Overflow",
            description=desc1,
            source_feed=ThreatFeedSource.NVD_CVE,
            cvss_score=8.8,
            is_known_exploited=False,
            raw_hash=hashlib.sha256(desc1.encode()).hexdigest(),
        )
        digest = ThreatDigest(
            advisories=[adv],
            total_ingested=1,
            unique_count=1,
            duplicate_count=0,
            critical_count=1,
        )
        note = format_obsidian_digest(digest)
        assert "CVE-2026-0001" in note

    def test_forensics_sanitizer_and_classifier(self) -> None:
        from triage.sanitizer import sanitize_pii
        from triage.classifier import process_incident_triage

        raw = "User admin at secops@company.com reported ransomware locked system on 192.168.1.50."
        sanitized, counts = sanitize_pii(raw)
        assert "secops@company.com" not in sanitized
        assert "[REDACTED_EMAIL]" in sanitized

        report = process_incident_triage(
            raw_text=raw,
            incident_id="INC-001",
            title="Ransomware Incident",
        )
        assert len(report.custody_sha256) == 64
        assert report.crime_category.value == "ransomware_extortion"

    def test_sre_atomic_rollback(self) -> None:
        from sentinel.remediator import execute_atomic_rollback

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            slots_dir = tmp_path / "slots"
            slots_dir.mkdir()
            blue = slots_dir / "blue"
            green = slots_dir / "green"
            blue.mkdir()
            green.mkdir()

            current = tmp_path / "current"
            os.symlink(green, current)

            res = execute_atomic_rollback(
                current_link_path=str(current),
                target_slot="blue",
                slots_dir=str(slots_dir),
                service_name="payment-svc",
            )
            assert res.success is True
            assert res.previous_slot == "green"
            assert res.target_slot == "blue"
            assert current.resolve() == blue

    def test_rag_chunking_and_indexing(self) -> None:
        from rag_sync.chunker import chunk_python_file, chunk_markdown_file
        from rag_sync.indexer import VectorKnowledgeIndexer

        code = (
            "def authenticate_user(token: str) -> bool:\n"
            "    return len(token) > 10\n"
        )
        chunks = chunk_python_file("auth.py", code)
        assert len(chunks) == 1
        assert chunks[0].name == "authenticate_user"

        indexer = VectorKnowledgeIndexer(db_path=":memory:")
        new_c, skip_c = indexer.index_chunks(chunks)
        assert new_c == 1
        assert skip_c == 0

        matches = indexer.search("authenticate user token", top_k=1)
        assert len(matches) == 1
        assert matches[0].name == "authenticate_user"
