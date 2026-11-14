from datetime import datetime

from sshguard.parser import parse_line

NOW = datetime(2026, 11, 10, 22, 30, 0)


def test_failed_login_is_parsed():
    line = "Nov 10 22:14:03 host sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2"
    assert parse_line(line, NOW) == (datetime(2026, 11, 10, 22, 14, 3), "203.0.113.5")


def test_invalid_user_failed_login_is_parsed():
    line = "Nov 10 22:14:03 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52341 ssh2"
    assert parse_line(line, NOW)[1] == "203.0.113.5"


def test_single_digit_day_is_parsed():
    # syslog writes "Nov  3" with two spaces
    line = "Nov  3 03:12:00 host sshd[1234]: Failed password for root from 203.0.113.99 port 40000 ssh2"
    assert parse_line(line, NOW) == (datetime(2026, 11, 3, 3, 12, 0), "203.0.113.99")


def test_newer_sshd_session_name_is_parsed():
    line = "Nov 10 22:14:03 host sshd-session[77]: Failed password for root from 203.0.113.5 port 1 ssh2"
    assert parse_line(line, NOW) is not None


def test_other_lines_are_ignored():
    ok = "Nov 10 22:10:00 host sshd[1]: Accepted publickey for student from 192.168.1.50 port 5 ssh2"
    invalid = "Nov 10 22:10:00 host sshd[1]: Invalid user admin from 203.0.113.5 port 5"
    cron = "Nov 10 22:10:00 host CRON[9]: pam_unix(cron:session): session opened"
    for line in (ok, invalid, cron, "", "garbage"):
        assert parse_line(line, NOW) is None


def test_bad_ip_is_ignored():
    line = "Nov 10 22:14:03 host sshd[1]: Failed password for root from not-an-ip port 5 ssh2"
    assert parse_line(line, NOW) is None


def test_fake_date_is_ignored():
    line = "Feb 30 22:14:03 host sshd[1]: Failed password for root from 203.0.113.5 port 5 ssh2"
    assert parse_line(line, NOW) is None


def test_december_line_in_january_is_last_year():
    now = datetime(2027, 1, 2, 0, 5, 0)
    line = "Dec 31 23:59:00 host sshd[1]: Failed password for root from 203.0.113.5 port 5 ssh2"
    assert parse_line(line, now)[0] == datetime(2026, 12, 31, 23, 59, 0)
