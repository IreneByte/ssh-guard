from datetime import datetime

from sshguard.counter import count_failures

NOW = datetime(2026, 11, 10, 22, 30, 0)


def fail(clock, ip, day="Nov 10"):
    return f"{day} {clock} host sshd[1]: Failed password for root from {ip} port 5 ssh2"


def test_counts_per_ip():
    lines = [fail("22:25:00", "1.1.1.1"), fail("22:26:00", "1.1.1.1"), fail("22:27:00", "2.2.2.2")]
    counts, stats = count_failures(lines, NOW, 10)
    assert counts["1.1.1.1"] == 2
    assert counts["2.2.2.2"] == 1
    assert stats["lines"] == 3


def test_old_lines_are_ignored():
    lines = [fail("22:10:00", "1.1.1.1"), fail("21:00:00", "1.1.1.1"), fail("22:25:00", "1.1.1.1")]
    counts, stats = count_failures(lines, NOW, 10)
    assert counts["1.1.1.1"] == 1
    assert stats["outside_window"] == 2


def test_line_from_another_day_is_ignored():
    counts, _ = count_failures([fail("22:25:00", "1.1.1.1", day="Nov  3")], NOW, 10)
    assert len(counts) == 0


def test_future_lines_are_ignored():
    counts, _ = count_failures([fail("22:45:00", "1.1.1.1")], NOW, 10)
    assert len(counts) == 0


def test_edge_of_window_counts():
    # exactly 10 minutes ago and exactly now are both inside
    counts, _ = count_failures([fail("22:20:00", "1.1.1.1"), fail("22:30:00", "1.1.1.1")], NOW, 10)
    assert counts["1.1.1.1"] == 2
