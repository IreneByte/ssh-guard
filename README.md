# SSH Guard

A small Python + Bash tool. It reads an SSH log, counts failed logins for each
IP address, and blocks IPs that fail too many times. It is like a very simple
fail2ban. I made it to learn how logs, regex, and firewalls fit together.

## What it does

- Reads an SSH log file (only the `Failed password` lines are counted)
- Counts failed logins for each IP inside a time window (default: last 10 minutes)
- Skips safe IPs from `allowlist.txt`
- Marks an IP as bad if it has 5 or more failures (you can change this)
- **Default is dry-run:** it only prints and logs what it would block
- With `--apply` on Linux (as root) it adds real `iptables` rules
- Prints a summary and ALERT lines, and saves them in `sshguard.log`

## Folders and files

- `sshguard/parser.py` - turns one log line into (time, IP)
- `sshguard/counter.py` - counts failures per IP in the window
- `sshguard/allowlist.py` - loads safe IPs and ranges
- `sshguard/firewall.py` - dry-run message or the real `iptables` command
- `sshguard/report.py` - summary, alerts, log file
- `sshguard/cli.py` - the command line and the main steps
- `allowlist.txt` - safe IPs
- `sample_logs/auth.log` - fake log (made by `scripts/make_sample_log.py`)
- `demo.sh` - runs the tool on the fake log
- `unblock.sh` - removes a block
- `tests/` - pytest tests

## Setup on Windows (WSL2)

Do this once.

- Open PowerShell as admin, run `wsl --install`, restart, open the Ubuntu app
- Keep the project inside WSL (like `~/projects`), not in `C:\`
- Install the tools:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git iptables
```

Then in the project folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Try it on the fake log

```bash
./demo.sh
```

You should see a summary. The IPs `203.0.113.5` and `198.51.100.23` go over the limit.
Nothing is really blocked, because this is a dry-run.

The fake log is from Nov 10, 2026, so the demo uses `--now` to pretend it is 22:30 that day.
For a real log you leave `--now` out and it uses the real time.

## Use it on a real log

```bash
python3 -m sshguard /var/log/auth.log
```

Options:

- `--window 10` - minutes to look back
- `--threshold 5` - failed logins before an IP is bad
- `--allowlist allowlist.txt` - file with safe IPs
- `--log-file sshguard.log` - where alerts and actions are saved
- `--now "2026-11-10 22:30:00"` - pretend this is the time (for demos and tests)
- `--apply` - add real firewall rules

If `/var/log/auth.log` does not exist (common on WSL2), save the log from journald first:

```bash
sudo journalctl -u ssh --no-pager > /tmp/ssh.log
python3 -m sshguard /tmp/ssh.log
```

## Real blocking (`--apply`)

```bash
sudo .venv/bin/python -m sshguard /var/log/auth.log --apply
```

- It needs Linux, root, and `iptables`. If one is missing it stops with a message.
- It checks if a rule is already there so it does not add the same rule twice.
- On WSL2 this only changes the firewall inside WSL, not the Windows firewall.
- To remove a block: `sudo ./unblock.sh 203.0.113.5`
- To see the rules: `sudo iptables -S INPUT`
- **Put your own IP in `allowlist.txt` first.** If you block yourself you can lose your SSH connection.

## The allowlist

```
# Safe IPs. One per line.
192.168.0.0/16   # a whole range
10.0.0.5         # one IP
```

- `#` starts a comment
- Blank lines are fine
- A bad line gives a warning and is skipped
- If the file is missing the tool stops, so it never blocks by mistake
- `127.0.0.1` and `::1` are always safe

## Tests

```bash
source .venv/bin/activate
pytest
```

- Parser: normal lines, single-digit days, fake dates, bad IPs, December lines read in January
- Counter: window edges, old lines, future lines
- Allowlist: ranges, comments, bad lines, IPv6
- Firewall: dry-run, `--apply`, rule already there, no root, no iptables
- CLI: dry-run by default, safe and old IPs not blocked, summary numbers, log file
- GitHub Actions runs `pytest`, checks the Bash scripts, and runs the demo on every push

## Honest notes

Simple choices I made:

- Only `Failed password` lines count. Failed public-key logins and "Invalid user" lines do not.
- Log lines have no year. If a date would be in the future, I assume it is from last year.
- The time window is counted back from now, so old log lines are ignored.
- There is no unblock timer. A block stays until you remove it.
- It keeps no memory between runs. Run it every minute with cron and it will just check the rule each time.
- The log is read in one pass, so a very big log file is slow but works.

Not finished yet:

- The tests use a fake `subprocess.run`, so real `iptables` is not covered by the tests.
- IPv6 blocking uses `ip6tables` but I have not tried it on a real machine.
- It does not read the log live (like `tail -f`).
- No email or chat alerts. Alerts are only printed and saved in the log file.
- No support for `nftables` or `ufw`.
