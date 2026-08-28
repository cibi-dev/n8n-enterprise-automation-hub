"""Unit tests for CLI commands in n8n-rag-knowledge-sync-hub."""

import json
import pytest

from rag_sync.cli import main


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "rag-sync" in captured.out


def test_cli_no_args():
    assert main([]) == 1


def test_cli_scan_and_sync(tmp_path, capsys):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("def run(): pass\nclass App: pass", encoding="utf-8")
    (repo_dir / "README.md").write_text("# App Doc\nDetails here.", encoding="utf-8")

    db_path = tmp_path / "rag.db"
    obs_out = tmp_path / "obsidian_note.md"

    ret = main(["scan-and-sync", str(repo_dir), "--db", str(db_path), "--obsidian-out", str(obs_out)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["total_files_scanned"] == 2
    assert data["new_chunks_indexed"] >= 2
    assert obs_out.is_file()


def test_cli_scan_and_sync_missing_dir():
    assert main(["scan-and-sync", "/nonexistent_path"]) == 1


def test_cli_search_and_stats(tmp_path, capsys):
    repo_dir = tmp_path / "repo2"
    repo_dir.mkdir()
    (repo_dir / "crypto.py").write_text("def compute_hmac(key, data): return True", encoding="utf-8")

    db_path = tmp_path / "rag2.db"
    main(["scan-and-sync", str(repo_dir), "--db", str(db_path)])
    capsys.readouterr()  # Clear buffer

    # Search
    ret_s = main(["search", "hmac computation", "--db", str(db_path), "--top-k", "1"])
    assert ret_s == 0
    captured_s = capsys.readouterr()
    matches = json.loads(captured_s.out)
    assert len(matches) == 1
    assert matches[0]["name"] == "compute_hmac"

    # Stats
    ret_st = main(["stats", "--db", str(db_path)])
    assert ret_st == 0
    captured_st = capsys.readouterr()
    stats = json.loads(captured_st.out)
    assert stats["total_chunks"] >= 1


def test_cli_search_empty_db(tmp_path, capsys):
    empty_db = tmp_path / "empty.db"
    ret = main(["search", "query", "--db", str(empty_db)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data == []


def test_cli_stats_empty_db(tmp_path, capsys):
    empty_db = tmp_path / "empty2.db"
    ret = main(["stats", "--db", str(empty_db)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["total_chunks"] == 0


def test_cli_scan_and_sync_skips_hidden_dirs(tmp_path, capsys):
    repo_dir = tmp_path / "repo3"
    repo_dir.mkdir()
    pycache = repo_dir / "__pycache__"
    pycache.mkdir()
    (pycache / "cached.py").write_text("def ignore_this(): pass")
    (repo_dir / "valid.py").write_text("def valid_fn(): pass")

    db_path = tmp_path / "rag3.db"
    ret = main(["scan-and-sync", str(repo_dir), "--db", str(db_path)])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["total_files_scanned"] == 1


def test_cli_scan_custom_top_k(tmp_path, capsys):
    repo_dir = tmp_path / "repo4"
    repo_dir.mkdir()
    (repo_dir / "mod1.py").write_text("def alpha(): pass")
    (repo_dir / "mod2.py").write_text("def beta(): pass")
    (repo_dir / "mod3.py").write_text("def gamma(): pass")

    db_path = tmp_path / "rag4.db"
    main(["scan-and-sync", str(repo_dir), "--db", str(db_path)])
    capsys.readouterr()

    ret = main(["search", "alpha beta gamma", "--db", str(db_path), "--top-k", "2"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data) == 2


