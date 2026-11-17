from datetime import datetime


def make_alerts(bad, window):
    """One alert line for each IP that went over the limit."""
    return [f"ALERT: {ip} had {n} failed logins in {window} min"
            for ip, n in sorted(bad.items(), key=lambda item: item[1], reverse=True)]


def build_summary(now, window, threshold, apply, stats, counts, safe, bad, actions):
    """Make the summary as a list of text lines."""
    mode = "APPLY (real firewall rules)" if apply else "DRY-RUN (nothing is blocked)"
    lines = [
        "=== SSH Guard summary ===",
        f"Mode:             {mode}",
        f"Time window:      last {window} min before {now:%Y-%m-%d %H:%M:%S}",
        f"Limit:            {threshold} failed logins",
        f"Log lines read:   {stats['lines']}",
        f"Failed in window: {sum(counts.values())} from {len(counts)} IPs",
        f"Failed outside window (ignored): {stats['outside_window']}",
        f"Safe IPs skipped: {len(safe)}",
        "",
        "IPs seen in the window:",
    ]

    for ip, n in counts.most_common():
        if ip in safe:
            status = "safe, skipped"
        elif ip in bad:
            status = "OVER LIMIT"
        else:
            status = "under limit"
        lines.append(f"  {ip:<18} {n:>3} failed   {status}")

    if bad:
        lines.append("")
        lines += make_alerts(bad, window)
        lines.append("")
        lines.append("Actions:")
        lines += [f"  {action}" for action in actions]
    else:
        lines.append("")
        lines.append("No IPs went over the limit.")
    return lines


def write_log(log_file, lines):
    """Add lines to the log file, each with a time stamp."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        for line in lines:
            f.write(f"{stamp} {line}\n")
