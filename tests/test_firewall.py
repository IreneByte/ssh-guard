import pytest

from sshguard import firewall


class FakeResult:
    def __init__(self, returncode=0, stderr=""):
        self.returncode = returncode
        self.stderr = stderr


def fake_which(name):
    return "/usr/sbin/" + name


def test_dry_run_runs_nothing(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("a command ran in dry-run mode")

    monkeypatch.setattr(firewall.subprocess, "run", boom)
    message = firewall.block_ip("203.0.113.5")
    assert message.startswith("DRY-RUN: would block 203.0.113.5")


def test_apply_adds_rule(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return FakeResult(1) if "-C" in cmd else FakeResult(0)  # -C fails: rule not there yet

    monkeypatch.setattr(firewall.subprocess, "run", fake_run)
    monkeypatch.setattr(firewall.shutil, "which", fake_which)
    assert firewall.block_ip("203.0.113.5", apply=True) == "BLOCKED 203.0.113.5"
    assert calls[-1] == ["iptables", "-I", "INPUT", "-s", "203.0.113.5", "-j", "DROP"]


def test_apply_skips_rule_that_exists(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return FakeResult(0)  # -C works: rule is already there

    monkeypatch.setattr(firewall.subprocess, "run", fake_run)
    monkeypatch.setattr(firewall.shutil, "which", fake_which)
    assert firewall.block_ip("203.0.113.5", apply=True) == "already blocked: 203.0.113.5"
    assert len(calls) == 1


def test_ipv6_uses_ip6tables(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return FakeResult(1) if "-C" in cmd else FakeResult(0)

    monkeypatch.setattr(firewall.subprocess, "run", fake_run)
    monkeypatch.setattr(firewall.shutil, "which", fake_which)
    firewall.block_ip("2001:db8::1", apply=True)
    assert calls[-1][0] == "ip6tables"


def test_failed_command_is_reported(monkeypatch):
    def fake_run(cmd, **kwargs):
        return FakeResult(1, "boom") if "-C" in cmd else FakeResult(4, "Permission denied")

    monkeypatch.setattr(firewall.subprocess, "run", fake_run)
    monkeypatch.setattr(firewall.shutil, "which", fake_which)
    message = firewall.block_ip("203.0.113.5", apply=True)
    assert message.startswith("FAILED to block 203.0.113.5")


def test_apply_needs_linux(monkeypatch):
    monkeypatch.setattr(firewall.platform, "system", lambda: "Windows")
    with pytest.raises(RuntimeError):
        firewall.check_can_apply()


def test_apply_needs_root(monkeypatch):
    monkeypatch.setattr(firewall.platform, "system", lambda: "Linux")
    monkeypatch.setattr(firewall.os, "geteuid", lambda: 1000)
    with pytest.raises(RuntimeError):
        firewall.check_can_apply()


def test_apply_needs_iptables(monkeypatch):
    monkeypatch.setattr(firewall.platform, "system", lambda: "Linux")
    monkeypatch.setattr(firewall.os, "geteuid", lambda: 0)
    monkeypatch.setattr(firewall.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError):
        firewall.check_can_apply()
