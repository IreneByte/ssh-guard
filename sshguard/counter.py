from collections import Counter
from datetime import timedelta

from .parser import parse_line


def count_failures(lines, now, window_minutes):
    """Count failed logins per IP inside the time window.
    Returns (counts, stats)."""
    start = now - timedelta(minutes=window_minutes)
    counts = Counter()
    lines_read = 0
    outside = 0

    for line in lines:
        lines_read += 1
        result = parse_line(line, now)
        if result is None:
            continue  # not a failed login
        when, ip = result
        if when < start or when > now:
            outside += 1  # too old (or in the future), so ignore it
            continue
        counts[ip] += 1

    stats = {"lines": lines_read, "outside_window": outside}
    return counts, stats
