import re
from datetime import datetime
from ipaddress import ip_address

MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

# Example line:
# Nov 10 22:14:03 myhost sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52341 ssh2
FAILED_LOGIN = re.compile(
    r"^(\w{3})\s+(\d{2})\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+"   # month, day, time, host name
    r"sshd(?:-session)?(?:\[\d+\])?:\s+"                      # process name (newer systems say sshd-session)
    r"Failed password for (?:invalid user )?\S+ from (\S+) port"
)


def parse_line(line, now):
    """Return (time, ip) if the line is a failed SSH login. Otherwise return None."""
    match = FAILED_LOGIN.match(line)
    if match is None:
        return None

    month_name, day, clock, ip = match.groups()
    if month_name not in MONTHS:
        return None

    # the IP must be a real IP address
    try:
        ip_address(ip)
    except ValueError:
        return None

    hour, minute, second = clock.split(":")
    try:
        when = datetime(now.year, MONTHS[month_name], int(day),
                        int(hour), int(minute), int(second))
        # log lines have no year, so a date in the future must be from last year
        if when > now:
            when = when.replace(year=now.year - 1)
    except ValueError:
        return None  # not a real date (like Feb 30)
    return when, ip
