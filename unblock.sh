#!/usr/bin/env bash
# Removes the firewall block for one IP.
# Usage: sudo ./unblock.sh 203.0.113.5
set -euo pipefail

ip="${1:-}"

if [ -z "$ip" ]; then
  echo "Usage: sudo ./unblock.sh IP_ADDRESS"
  exit 1
fi

# an IP only has hex digits, dots and colons
if ! [[ "$ip" =~ ^[0-9a-fA-F:.]+$ ]]; then
  echo "That does not look like an IP address: $ip"
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this with sudo."
  exit 1
fi

# IPv6 addresses have colons and use ip6tables
if [[ "$ip" == *:* ]]; then
  tool=ip6tables
else
  tool=iptables
fi

if ! command -v "$tool" > /dev/null; then
  echo "$tool is not installed."
  exit 1
fi

# -D deletes the rule that SSH Guard added
"$tool" -D INPUT -s "$ip" -j DROP
echo "Unblocked $ip"
