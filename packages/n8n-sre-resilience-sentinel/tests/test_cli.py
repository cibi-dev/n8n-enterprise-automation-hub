"""Unit tests for CLI commands in n8n-sre-resilience-sentinel."""

import json
import urllib.request
import pytest

from sentinel.cli import main


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "sre-sentinel" in captured.out


def test_cli_no_args():
    assert main([]) == 1


def test_cli_probe(monkeypatch, capsys):
    class MockResponse:
        def getcode(self):
            return 200
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: MockResponse())

    ret = main(["probe", "--url", "http://example.com", "--service", "web"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["is_healthy"] is True


def test_cli_check_and_remediate(tmp_path, monkeypatch, capsys):
    class MockFailResponse:
        def getcode(self):
            return 500
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: MockFailResponse())

    current_link = tmp_path / "current"
    slots_dir = tmp_path / "slots"
    db_file = tmp_path / "sre.db"

    # Run 1: 1 failure (threshold 2) -> not degraded
    ret1 = main([
        "check-and-remediate",
        "--url", "http://example.com",
        "--service", "web-svc",
        "--link-path", str(current_link),
        "--slots-dir", str(slots_dir),
        "--threshold", "2",
        "--db", str(db_file),
    ])
    assert ret1 == 0
    capsys.readouterr()

    # Run 2: 2nd failure (threshold 2) -> degraded, auto-rollback executed
    ret2 = main([
        "check-and-remediate",
        "--url", "http://example.com",
        "--service", "web-svc",
        "--link-path", str(current_link),
        "--slots-dir", str(slots_dir),
        "--threshold", "2",
        "--db", str(db_file),
    ])
    assert ret2 == 2
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["rollback_executed"] is True
    assert data["rollback_action"]["target_slot"] == "green"


def test_cli_manual_rollback_and_history(tmp_path, capsys):
    current_link = tmp_path / "current"
    slots_dir = tmp_path / "slots"
    db_file = tmp_path / "sre.db"

    ret = main([
        "manual-rollback",
        "--service", "manual-svc",
        "--link-path", str(current_link),
        "--slots-dir", str(slots_dir),
        "--target-slot", "green",
        "--db", str(db_file),
    ])
    assert ret == 0
    capsys.readouterr()

    ret_hist = main(["history", "--service", "manual-svc", "--db", str(db_file)])
    assert ret_hist == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data) == 1
    assert data[0]["target_slot"] == "green"

    # Unfiltered history
    ret_hist_all = main(["history", "--db", str(db_file)])
    assert ret_hist_all == 0


def test_cli_probe_unhealthy(monkeypatch, capsys):
    class MockFailResponse:
        def getcode(self):
            return 502
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: MockFailResponse())
    ret = main(["probe", "--url", "http://example.com/bad", "--service", "bad-svc"])
    assert ret == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["is_healthy"] is False


def test_cli_manual_rollback_to_blue(tmp_path):
    current_link = tmp_path / "current_blue"
    slots_dir = tmp_path / "slots_blue"
    db_file = tmp_path / "sre_blue.db"

    ret = main([
        "manual-rollback",
        "--service", "svc-blue",
        "--link-path", str(current_link),
        "--slots-dir", str(slots_dir),
        "--target-slot", "blue",
        "--db", str(db_file),
    ])
    assert ret == 0


def test_cli_check_and_remediate_already_healthy(tmp_path, monkeypatch, capsys):
    class MockOkResponse:
        def getcode(self):
            return 200
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: MockOkResponse())

    current_link = tmp_path / "current_ok"
    slots_dir = tmp_path / "slots_ok"
    db_file = tmp_path / "sre_ok.db"

    ret = main([
        "check-and-remediate",
        "--url", "http://example.com/healthz",
        "--service", "healthy-svc",
        "--link-path", str(current_link),
        "--slots-dir", str(slots_dir),
        "--threshold", "3",
        "--db", str(db_file),
    ])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["rollback_executed"] is False
    assert data["health_state"]["is_degraded"] is False


