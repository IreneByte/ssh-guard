import argparse
from datetime import datetime

from .allowlist import is_safe, load_allowlist
from .counter import count_failures
from .firewall import block_ip, check_can_apply
from .report import build_summary, make_alerts, write_log


def parse_time(text):
    """Turn "2026-11-10 22:30:00" into a datetime."""
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise argparse.ArgumentTypeError('time must look like "2026-11-10 22:30:00"')


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Block IPs that have too many failed SSH logins.")
    parser.add_argument("logfile", help="SSH log file to read")
    parser.add_argument("--window", type=int, default=10, help="minutes to look back (default 10)")
    parser.add_argument("--threshold", type=int, default=5, help="failed logins before a block (default 5)")
    parser.add_argument("--allowlist", default="allowlist.txt", help="file with safe IPs")
    parser.add_argument("--log-file", default="sshguard.log", help="where to write alerts and actions")
    parser.add_argument("--now", type=parse_time, help="pretend this is the current time (for demos and tests)")
    parser.add_argument("--apply", action="store_true",
                        help="add real firewall rules (Linux, root). Without this it is a dry-run.")
    args = parser.parse_args(argv)
    if args.window < 1 or args.threshold < 1:
        parser.error("--window and --threshold must be 1 or more")
    return args


def main(argv=None):
    args = parse_args(argv)
    now = args.now or datetime.now()

    # 1. load the safe IPs (stop if the file is missing, so we never block by mistake)
    try:
        networks = load_allowlist(args.allowlist)
    except OSError as err:
        print(f"Error: cannot read allowlist: {err}")
        return 1

    # 2. check that real blocking is possible, before we do any work
    if args.apply:
        try:
            check_can_apply()
        except RuntimeError as err:
            print(f"Error: {err}")
            return 1

    # 3. count failed logins per IP in the window
    try:
        with open(args.logfile, errors="replace") as f:
            counts, stats = count_failures(f, now, args.window)
    except OSError as err:
        print(f"Error: cannot read log file: {err}")
        return 1

    # 4. split the IPs: safe ones are skipped, the rest are checked against the limit
    safe = {ip: n for ip, n in counts.items() if is_safe(ip, networks)}
    bad = {ip: n for ip, n in counts.items() if n >= args.threshold and ip not in safe}

    # 5. block (or pretend to block) the bad ones, worst first
    actions = [block_ip(ip, args.apply) for ip in sorted(bad, key=bad.get, reverse=True)]

    # 6. show the summary and save the alerts and actions
    summary = build_summary(now, args.window, args.threshold, args.apply,
                            stats, counts, safe, bad, actions)
    print("\n".join(summary))
    write_log(args.log_file, make_alerts(bad, args.window) + actions)
    return 0
