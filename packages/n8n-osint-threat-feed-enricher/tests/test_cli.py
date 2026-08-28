"""Unit tests for CLI commands in n8n-osint-threat-feed-enricher."""

import json
import pytest

from enricher.cli import main


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "osint-enricher" in captured.out


def test_cli_no_args():
    assert main([]) == 1


def test_cli_parse_cisa(tmp_path, capsys):
    f = tmp_path / "cisa.json"
    f.write_text(json.dumps({
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1111",
                "vulnerabilityName": "Exploited Router Bug",
                "shortDescription": "Bug in firmware",
            }
        ]
    }))

    ret = main(["parse-cisa", str(f)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data) == 1
    assert data[0]["cve_id"] == "CVE-2026-1111"


def test_cli_parse_cisa_missing_file():
    ret = main(["parse-cisa", "/nonexistent/cisa.json"])
    assert ret == 1


def test_cli_parse_nvd(tmp_path, capsys):
    f = tmp_path / "nvd.json"
    f.write_text(json.dumps({
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-2222",
                    "descriptions": [{"lang": "en", "value": "Desc"}],
                }
            }
        ]
    }))

    ret = main(["parse-nvd", str(f)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data) == 1
    assert data[0]["cve_id"] == "CVE-2026-2222"


def test_cli_parse_nvd_missing_file():
    ret = main(["parse-nvd", "/nonexistent/nvd.json"])
    assert ret == 1


def test_cli_dedup_stream(tmp_path, capsys):
    f = tmp_path / "input.json"
    db = tmp_path / "threats.db"

    f.write_text(json.dumps([
        {
            "id": "CVE-2026-3333",
            "title": "Auth Bypass",
            "description": "Critical bypass in login handler",
            "cve_id": "CVE-2026-3333",
            "raw_hash": "a" * 64,
        }
    ]))

    ret = main(["dedup-stream", str(f), "--db", str(db), "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["total_ingested"] == 1
    assert data["unique_count"] == 1

    # Test obsidian format
    ret_obs = main(["dedup-stream", str(f), "--db", str(db), "--format", "obsidian"])
    assert ret_obs == 0

    # Test telegram format
    ret_tel = main(["dedup-stream", str(f), "--db", str(db), "--format", "telegram"])
    assert ret_tel == 0

    # Test dict format with "advisories" key
    dict_f = tmp_path / "dict_input.json"
    dict_f.write_text(json.dumps({
        "advisories": [
            {
                "id": "CVE-2026-4444",
                "title": "SQL Injection",
                "description": "SQL injection in query filter",
                "cve_id": "CVE-2026-4444",
                "raw_hash": "b" * 64,
            }
        ]
    }))
    ret_dict = main(["dedup-stream", str(dict_f), "--no-persist"])
    assert ret_dict == 0


def test_cli_dedup_stream_missing_file():
    ret = main(["dedup-stream", "/nonexistent.json"])
    assert ret == 1


def test_cli_dedup_stream_invalid_input(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("12345")
    ret = main(["dedup-stream", str(f)])
    assert ret == 1
