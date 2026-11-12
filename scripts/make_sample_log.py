"""Make a fake SSH log in sample_logs/auth.log.
All IPs are made-up example IPs. Pretend "now" is 2026-11-10 22:30:00."""
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)  # same file every time
HOST = "ubuntu-wsl"
USERS = ["root", "admin", "ubuntu", "test", "oracle", "pi"]
events = []  # list of (time, text)


def add_failures(ip, count, start, end):
    """Add `count` failed logins from one IP, spread between start and end."""
    seconds = int((end - start).total_seconds())
    for i in range(count):
        when = start + timedelta(seconds=seconds * i // max(count - 1, 1))
        user = random.choice(USERS)
        pid = random.randint(1000, 30000)
        port = random.randint(30000, 60000)
        if user == "root":
            events.append((when, f"sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"))
        else:
            # a real server also logs an "Invalid user" line (we must not count it)
            events.append((when, f"sshd[{pid}]: Invalid user {user} from {ip} port {port}"))
            events.append((when, f"sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2"))


def at(hour, minute, second=0):
    return datetime(2026, 11, 10, hour, minute, second)


# --- the story ---
add_failures("203.0.113.5", 12, at(22, 21, 5), at(22, 28, 50))    # brute force: block
add_failures("198.51.100.23", 6, at(22, 24, 0), at(22, 29, 10))   # just over the limit: block
add_failures("198.51.100.23", 4, at(19, 40), at(19, 42))          # earlier today: outside the window
add_failures("192.0.2.77", 3, at(22, 25), at(22, 27))             # under the limit: do not block
add_failures("10.0.0.5", 9, at(22, 22), at(22, 29))               # in allowlist (exact IP)
add_failures("192.168.1.50", 8, at(22, 23), at(22, 28))           # in allowlist (192.168.0.0/16)
add_failures("192.0.2.150", 20, at(21, 0), at(21, 5))             # too old
add_failures("203.0.113.99", 15, datetime(2026, 11, 3, 3, 12), datetime(2026, 11, 3, 3, 18))  # old, 1-digit day
add_failures("203.0.113.200", 7, datetime(2025, 12, 30, 23, 55), datetime(2025, 12, 30, 23, 59))  # last year

# some normal lines that must be ignored
for minute in (10, 40, 55):
    events.append((at(22, minute), f"sshd[4321]: Accepted publickey for student from 192.168.1.50 port 50000 ssh2: RSA SHA256:abc123"))
    events.append((at(22, minute), "CRON[999]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))

events.sort(key=lambda event: event[0])

lines = []
for when, text in events:
    # syslog pads the day with a space ("Nov  3"), so use :2d
    lines.append(f"{when:%b} {when.day:2d} {when:%H:%M:%S} {HOST} {text}")

out_file = Path(__file__).resolve().parent.parent / "sample_logs" / "auth.log"
out_file.write_text("\n".join(lines) + "\n")
print("Wrote", len(lines), "lines to", out_file)
