import ipaddress
import math
from collections import Counter

_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts, n = Counter(s), len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def parent_domain(query: str) -> str:
    parts = query.rstrip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else query.lower()


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL)
