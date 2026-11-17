import os
import platform
import shutil
import subprocess
from ipaddress import ip_address


def check_can_apply():
    """Stop early if real blocking cannot work here."""
    if platform.system() != "Linux":
        raise RuntimeError("--apply only works on Linux (use WSL2 on Windows).")
    if os.geteuid() != 0:
        raise RuntimeError("--apply needs root. Run it with sudo.")
    if shutil.which("iptables") is None:
        raise RuntimeError("iptables not found. Install it with: sudo apt install iptables")


def block_ip(ip, apply=False):
    """Block one IP. Without apply we only say what we would do (dry-run)."""
    # IPv6 addresses use a different tool
    tool = "ip6tables" if ip_address(ip).version == 6 else "iptables"
    rule = ["-s", ip, "-j", "DROP"]

    if not apply:
        return f"DRY-RUN: would block {ip} ({tool} -I INPUT {' '.join(rule)})"

    if shutil.which(tool) is None:
        return f"SKIPPED {ip}: {tool} not found"

    # -C checks if the rule is already there (exit code 0 means yes)
    check = subprocess.run([tool, "-C", "INPUT"] + rule, capture_output=True, text=True)
    if check.returncode == 0:
        return f"already blocked: {ip}"

    # -I puts the new rule at the top of the INPUT chain
    result = subprocess.run([tool, "-I", "INPUT"] + rule, capture_output=True, text=True)
    if result.returncode != 0:
        return f"FAILED to block {ip}: {result.stderr.strip()}"
    return f"BLOCKED {ip}"
