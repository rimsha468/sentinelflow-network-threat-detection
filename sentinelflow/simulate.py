"""Synthetic enterprise traffic with labelled, injected attacks (for training/eval/tests)."""
from __future__ import annotations

import base64
import random

from .flows import Flow

HOSTS = [f"10.0.0.{i}" for i in range(10, 110)]
DNS_SERVER = "10.0.0.2"
SSH_SERVER = "10.0.2.10"
ATTACKERS = {
    "10.0.0.66": "port_scan", "10.0.0.77": "brute_force", "10.0.0.88": "beacon",
    "10.0.0.99": "dns_tunnel", "10.0.0.55": "exfil",
}
_WORDS = ["mail", "news", "shop", "cdn", "api", "docs", "video", "maps", "img", "static", "login", "blog"]
_TLDS = ["com", "org", "net", "io", "co.uk"]


def _benign(rng: random.Random, duration: float) -> list[Flow]:
    ext = [f"{rng.randint(20, 190)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
           for _ in range(60)]
    domains = [f"{rng.choice(_WORDS)}{rng.randint(1, 99)}.{rng.choice(_TLDS)}" for _ in range(300)]
    flows = []
    for h in HOSTS:
        rate = rng.uniform(0.03, 0.25)                      # web flows / second
        t = rng.expovariate(rate)
        while t < duration:
            dst = rng.choice(ext)
            flows.append(Flow(t, h, dst, rng.choice([443, 443, 443, 80]), "tcp",
                              int(rng.lognormvariate(7.5, 1.0)), int(rng.lognormvariate(10, 1.5)),
                              rng.randint(6, 60)))
            if rng.random() < 0.6:
                flows.append(Flow(t - 0.05, h, DNS_SERVER, 53, "udp", 70, 140, 2,
                                  dns_query=rng.choice(domains)))
            t += rng.expovariate(rate)
    for h in rng.sample(HOSTS, 10):                          # NTP: periodic but legitimate
        t = rng.uniform(0, 300)
        while t < duration:
            flows.append(Flow(t, h, "162.159.200.1", 123, "udp", 76, 76, 2))
            t += 300 + rng.uniform(-0.5, 0.5)
    for h in rng.sample(HOSTS, 6):                           # admins using SSH
        for _ in range(rng.randint(1, 4)):
            flows.append(Flow(rng.uniform(0, duration), h, SSH_SERVER, 22, "tcp",
                              rng.randint(3000, 40000), rng.randint(3000, 60000), rng.randint(30, 300)))
    for h in rng.sample(HOSTS, 3):                           # big legit downloads / one backup upload
        flows.append(Flow(rng.uniform(0, duration - 60), h, rng.choice(ext), 443, "tcp",
                          2_000_000, 250_000_000, 200_000))
    flows.append(Flow(rng.uniform(0, duration - 60), HOSTS[30], rng.choice(ext), 443, "tcp",
                      15_000_000, 200_000, 12_000))
    return flows


def _attacks(rng: random.Random) -> list[Flow]:
    fl: list[Flow] = []
    # T1046 port scan
    t = 900.0
    for _ in range(500):
        fl.append(Flow(t, "10.0.0.66", f"10.0.1.{rng.randint(1, 254)}", rng.randint(1, 1024), "tcp", 0, 0, 1,
                       state=rng.choice(["S0"] * 4 + ["REJ"]), label="port_scan"))
        t += 0.05
    # T1110 SSH brute force
    t = 1500.0
    for _ in range(150):
        fl.append(Flow(t, "10.0.0.77", SSH_SERVER, 22, "tcp", 1800, 1500, 12, label="brute_force"))
        t += 0.5
    # T1071 beaconing (jittered 30 s)
    t = 300.0
    while t < 3500:
        fl.append(Flow(t, "10.0.0.88", "203.0.113.50", 443, "tcp", rng.randint(280, 340),
                       rng.randint(550, 650), 8, label="beacon"))
        t += 30 + rng.uniform(-1, 1)
    # T1071.004 DNS tunnelling
    t = 2000.0
    for _ in range(200):
        label = base64.b32encode(rng.randbytes(15)).decode().lower().rstrip("=")
        fl.append(Flow(t, "10.0.0.99", DNS_SERVER, 53, "udp", 120, 90, 2,
                       dns_query=f"{label}.t.evil-example.net", label="dns_tunnel"))
        t += 0.5
    # T1041 exfiltration
    t = 2700.0
    for _ in range(12):
        fl.append(Flow(t, "10.0.0.55", "198.51.100.7", 443, "tcp", 5_000_000, 50_000, 3500, label="exfil"))
        t += 10
    return fl


def simulate(seed: int = 1, duration: float = 3600.0, attacks: bool = True) -> list[Flow]:
    rng = random.Random(seed)
    flows = _benign(rng, duration)
    if attacks:
        flows += _attacks(rng)
    return sorted(flows, key=lambda f: f.ts)
