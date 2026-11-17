#!/usr/bin/env bash
# Runs SSH Guard on the fake sample log. This is a dry-run, so nothing is blocked.
set -euo pipefail

# go to the folder this script is in, so the paths always work
cd "$(dirname "$0")"

# "now" is fixed because the fake log is from Nov 10, 2026
python3 -m sshguard sample_logs/auth.log \
  --now "2026-11-10 22:30:00" \
  --log-file /tmp/sshguard-demo.log

echo
echo "Alerts and actions were also saved in /tmp/sshguard-demo.log"
