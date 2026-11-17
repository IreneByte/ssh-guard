from pathlib import Path

import pytest

from sshguard import firewall
from sshguard.cli import main

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG = str(ROOT / "sample_logs" / "auth.log")
ALLOWLIST = str(ROOT / "allowlist.txt")


def run_cli(tmp_path, extra=()):
    # "now" is fixed so the fake log always gives the same answer
    args = [SAMPLE_LOG, "--allowlist", ALLOWLIST, "--now", "2026-11-10 22:30:00",
            "--log-file", str(tmp_path / "guard.log")]
    return main(args + list(extra))


def test_dry_run_is_the_default(tmp_path, capsys, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("a firewall command ran in dry-run mode")

    monkeypatch.setattr(firewall.subprocess, "run", boom)
    assert run_cli(tmp_path) == 0
    out = capsys.readouterr().out
    assert "would block 203.0.113.5" in out
    assert "would block 198.51.100.23" in out


def test_safe_old_and_low_count_ips_are_not_blocked(tmp_path, capsys):
    run_cli(tmp_path)
    out = capsys.readouterr().out
    assert "would block 10.0.0.5" not in out        # allowlisted (with a comment in the file)
    assert "would block 192.168.1.50" not in out    # allowlisted range
    assert "would block 192.0.2.77" not in out      # under the limit
    assert "would block 192.0.2.150" not in out     # too old
    assert "would block 203.0.113.99" not in out    # too old (Nov  3)


def test_summary_numbers(tmp_path, capsys):
    run_cli(tmp_path)
    out = capsys.readouterr().out
    assert "Failed in window: 38 from 5 IPs" in out
    assert "Safe IPs skipped: 2" in out


def test_alerts_are_written_to_log_file(tmp_path):
    run_cli(tmp_path)
    text = (tmp_path / "guard.log").read_text()
    assert "ALERT: 203.0.113.5 had 12 failed logins" in text
    assert "DRY-RUN: would block 203.0.113.5" in text


def test_higher_threshold_blocks_fewer(tmp_path, capsys):
    run_cli(tmp_path, ["--threshold", "10"])
    out = capsys.readouterr().out
    assert "would block 203.0.113.5" in out
    assert "would block 198.51.100.23" not in out


def test_apply_is_refused_on_windows(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(firewall.platform, "system", lambda: "Windows")
    assert run_cli(tmp_path, ["--apply"]) == 1
    assert "Linux" in capsys.readouterr().out


def test_missing_allowlist_stops_the_run(tmp_path, capsys):
    args = [SAMPLE_LOG, "--allowlist", str(tmp_path / "nope.txt"), "--log-file", str(tmp_path / "g.log")]
    assert main(args) == 1
    assert "allowlist" in capsys.readouterr().out


def test_missing_log_file_stops_the_run(tmp_path, capsys):
    args = [str(tmp_path / "nope.log"), "--allowlist", ALLOWLIST, "--log-file", str(tmp_path / "g.log")]
    assert main(args) == 1
    assert "log file" in capsys.readouterr().out


def test_bad_window_is_rejected(tmp_path):
    with pytest.raises(SystemExit):
        run_cli(tmp_path, ["--window", "0"])
