import pytest

from sshguard.allowlist import is_safe, load_allowlist


def make_list(tmp_path, text):
    path = tmp_path / "allowlist.txt"
    path.write_text(text)
    return load_allowlist(str(path))


def test_exact_ip_and_range(tmp_path):
    networks = make_list(tmp_path, "10.0.0.5\n192.168.0.0/16\n")
    assert is_safe("10.0.0.5", networks)
    assert is_safe("192.168.44.9", networks)
    assert not is_safe("10.0.0.6", networks)


def test_comments_and_blank_lines_are_ignored(tmp_path, capsys):
    networks = make_list(tmp_path, "# my safe IPs\n\n10.0.0.5   # my laptop\n")
    assert is_safe("10.0.0.5", networks)  # the inline comment must not break the IP
    assert "Warning" not in capsys.readouterr().out


def test_bad_entry_is_skipped_with_warning(tmp_path, capsys):
    networks = make_list(tmp_path, "banana\n10.0.0.5\n")
    assert is_safe("10.0.0.5", networks)
    assert "banana" in capsys.readouterr().out


def test_localhost_is_always_safe(tmp_path):
    networks = make_list(tmp_path, "")
    assert is_safe("127.0.0.1", networks)
    assert is_safe("::1", networks)


def test_ipv6_does_not_match_ipv4_range(tmp_path):
    networks = make_list(tmp_path, "10.0.0.0/8\n")
    assert not is_safe("2001:db8::1", networks)


def test_missing_file_raises(tmp_path):
    with pytest.raises(OSError):
        load_allowlist(str(tmp_path / "nope.txt"))
