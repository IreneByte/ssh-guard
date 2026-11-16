from ipaddress import ip_address, ip_network

# these are always safe
ALWAYS_SAFE = ["127.0.0.1", "::1"]


def load_allowlist(path):
    """Read safe IPs and ranges from a text file. Returns a list of networks."""
    entries = list(ALWAYS_SAFE)
    with open(path) as f:
        for line in f:
            line = line.strip()  # cut off comments and spaces
            if line:  # skip blank lines
                entries.append(line)

    networks = []
    for entry in entries:
        try:
            networks.append(ip_network(entry, strict=False))
        except ValueError:
            print(f"Warning: skipping bad allowlist entry: {entry}")
    return networks


def is_safe(ip, networks):
    """True if the IP is inside any safe network."""
    address = ip_address(ip)
    return any(address in network for network in networks)
