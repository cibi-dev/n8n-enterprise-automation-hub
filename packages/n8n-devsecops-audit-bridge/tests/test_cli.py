"""Unit tests for CLI commands in n8n-devsecops-audit-bridge."""

import hashlib
import hmac
import json
import tempfile
from pathlib import Path
import pytest

from bridge.cli import main


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "devsecops-audit-bridge" in captured.out


def test_cli_no_args():
    assert main([]) == 1


def test_cli_verify_signature(tmp_path, capsys):
    secret = "my-secret-key"
    payload_file = tmp_path / "payload.json"
    payload_bytes = b'{"hello": "world"}'
    payload_file.write_bytes(payload_bytes)

    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    ret = main(["verify-signature", str(payload_file), "--signature", sig, "--secret", secret])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["signature_valid"] is True

    # Bad signature returns 1
    ret_bad = main(["verify-signature", str(payload_file), "--signature", "0" * 64, "--secret", secret])
    assert ret_bad == 1


def test_cli_verify_signature_missing_file():
    ret = main(["verify-signature", "/nonexistent/path.json", "--signature", "abc", "--secret", "sec"])
    assert ret == 1


def test_cli_parse_sarif(tmp_path, capsys):
    sarif_file = tmp_path / "sarif.json"
    sarif_file.write_text(json.dumps({
        "runs": [
            {
                "tool": {"driver": {"name": "Trivy"}},
                "results": [
                    {
                        "ruleId": "CVE-2026-0001",
                        "level": "error",
                        "message": {"text": "Critical vulnerability"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 10}}}],
                    }
                ],
            }
        ]
    }))

    ret = main(["parse-sarif", str(sarif_file)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["total_findings"] == 1
    assert data["findings"][0]["rule_id"] == "CVE-2026-0001"


def test_cli_parse_sarif_missing_file():
    ret = main(["parse-sarif", "/nonexistent/sarif.json"])
    assert ret == 1


def test_cli_parse_sbom(tmp_path, capsys):
    sbom_file = tmp_path / "sbom.json"
    sbom_file.write_text(json.dumps({
        "components": [
            {"name": "fastapi", "version": "0.111.0", "type": "library"}
        ]
    }))

    ret = main(["parse-sbom", str(sbom_file)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["total_components"] == 1


def test_cli_parse_sbom_missing_file():
    ret = main(["parse-sbom", "/nonexistent/sbom.json"])
    assert ret == 1


def test_cli_process_audit(tmp_path, capsys):
    payload_file = tmp_path / "audit_payload.json"
    db_file = tmp_path / "audit.db"

    payload_file.write_text(json.dumps({
        "repository": "cibi-dev/test-repo",
        "commit_sha": "abcdef1234567890abcdef1234567890abcdef12",
        "pipeline_id": "p-1",
        "findings": [],
        "components": [{"name": "urllib3", "version": "2.2.1", "licenses": ["MIT"]}],
    }))

    ret = main(["process-audit", "--payload", str(payload_file), "--db", str(db_file)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["is_compliant"] is True
    assert data["total_components"] == 1


def test_cli_process_audit_missing_file():
    ret = main(["process-audit", "--payload", "/nonexistent.json"])
    assert ret == 1


def test_cli_validate_url(capsys):
    ret_bad = main(["validate-url", "http://127.0.0.1:8080", "--no-dns"])
    assert ret_bad == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["is_allowed"] is False

    ret_ok = main(["validate-url", "https://8.8.8.8", "--no-dns"])
    assert ret_ok == 0
