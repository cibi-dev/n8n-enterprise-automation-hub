"""Unit tests for CLI commands in n8n-forensic-incident-triage."""

import json
import pytest

from triage.cli import main


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "forensic-triage" in captured.out


def test_cli_no_args():
    assert main([]) == 1


def test_cli_sanitize(tmp_path, capsys):
    f = tmp_path / "raw.txt"
    f.write_text("Investigator email is agent@fbi.gov on IP 10.0.0.1")

    ret = main(["sanitize", str(f)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "[REDACTED_EMAIL]" in data["sanitized_text"]
    assert "[REDACTED_IP]" in data["sanitized_text"]


def test_cli_sanitize_missing_file():
    assert main(["sanitize", "/nonexistent.txt"]) == 1


def test_cli_triage(tmp_path, capsys):
    f = tmp_path / "case.txt"
    db = tmp_path / "triage.db"
    f.write_text("LockBit ransomware encrypted database. Stolen data from corp.com by @attacker")

    ret = main(["triage", str(f), "--id", "CASE-01", "--title", "Case Alpha", "--db", str(db)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["incident_id"] == "CASE-01"
    assert data["crime_category"] == "ransomware_extortion"
    assert data["priority"] == "critical"
    assert "corp.com" in data["affected_assets"]
    assert "@attacker" in data["suspect_indicators"]


def test_cli_triage_no_persist(tmp_path, capsys):
    f = tmp_path / "case2.txt"
    f.write_text("Generic denial of service attack")

    ret = main(["triage", str(f), "--id", "CASE-02", "--no-persist"])
    assert ret == 0


def test_cli_triage_missing_file():
    assert main(["triage", "/nonexistent.txt"]) == 1


def test_cli_stats(tmp_path, capsys):
    db = tmp_path / "triage_stats.db"
    f = tmp_path / "case_stat.txt"
    f.write_text("Phishing scam wire fraud")
    main(["triage", str(f), "--id", "STAT-01", "--db", str(db)])
    capsys.readouterr()  # Clear triage output from buffer

    ret = main(["stats", "--db", str(db)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["total_incidents"] >= 1
