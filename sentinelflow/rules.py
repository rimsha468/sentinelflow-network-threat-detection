"""Signature / behavioural detections, each mapped to MITRE ATT&CK."""
from __future__ import annotations

import statistics
from collections import defaultdict

from .alerts import Alert, merge_alerts
from .flows import Flow
from .util import is_internal, parent_domain, shannon_entropy

DEFAULTS = {
    "window": 60.0,
    "scan_min_targets": 100, "scan_min_fail_ratio": 0.7,
    "brute_ports": (21, 22, 445, 3389), "brute_min_attempts": 30,
    "beacon_min_events": 20, "beacon_max_cv": 0.2, "beacon_min_interval": 10.0,
    "beacon_ignore_ports": (53, 123),          # allow-list: DNS / NTP are legitimately periodic
    "dns_min_queries": 20, "dns_min_entropy": 3.0, "dns_min_label_len": 20,
    "exfil_window": 300.0, "exfil_min_bytes": 20_000_000, "exfil_min_ratio": 10.0,
}


def _buckets(flows, width, key):
    out = defaultdict(list)
    for f in flows:
        out[(*key(f), int(f.ts // width))].append(f)
    return out


def detect_port_scan(flows: list[Flow], cfg: dict) -> list[Alert]:
    alerts = []
    for (src, _), fl in _buckets(flows, cfg["window"], lambda f: (f.src,)).items():
        targets = {(f.dst, f.dport) for f in fl}
        fail = sum(f.state in ("S0", "REJ") for f in fl) / len(fl)
        if len(targets) >= cfg["scan_min_targets"] and fail >= cfg["scan_min_fail_ratio"]:
            alerts.append(Alert("rule", "port_scan", src, min(f.ts for f in fl), max(f.ts for f in fl),
                                "high", "T1046", "Network Service Discovery",
                                detail={"targets": len(targets), "fail_ratio": round(fail, 2)}))
    return alerts


def detect_brute_force(flows: list[Flow], cfg: dict) -> list[Alert]:
    alerts = []
    sel = [f for f in flows if f.dport in cfg["brute_ports"]]
    for (src, dst, port, _), fl in _buckets(sel, cfg["window"], lambda f: (f.src, f.dst, f.dport)).items():
        if len(fl) >= cfg["brute_min_attempts"]:
            alerts.append(Alert("rule", "brute_force", src, min(f.ts for f in fl), max(f.ts for f in fl),
                                "high", "T1110", "Brute Force", dst=dst,
                                detail={"port": port, "attempts": len(fl)}))
    return alerts


def detect_beaconing(flows: list[Flow], cfg: dict) -> list[Alert]:
    """Low coefficient-of-variation of inter-arrival times => automated C2 check-in."""
    pairs = defaultdict(list)
    for f in flows:
        if f.dport not in cfg["beacon_ignore_ports"] and not f.dns_query and not is_internal(f.dst):
            pairs[(f.src, f.dst, f.dport)].append(f.ts)
    alerts = []
    for (src, dst, port), ts in pairs.items():
        if len(ts) < cfg["beacon_min_events"]:
            continue
        ts.sort()
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.fmean(gaps)
        if mean < cfg["beacon_min_interval"]:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv <= cfg["beacon_max_cv"]:
            alerts.append(Alert("rule", "c2_beaconing", src, ts[0], ts[-1], "high", "T1071",
                                "Application Layer Protocol", dst=dst,
                                detail={"port": port, "events": len(ts), "mean_interval_s": round(mean, 1),
                                        "cv": round(cv, 3)}))
    return alerts


def detect_dns_tunnel(flows: list[Flow], cfg: dict) -> list[Alert]:
    groups = defaultdict(list)
    for f in flows:
        if not f.dns_query:
            continue
        label = f.dns_query.split(".")[0]
        if len(label) >= cfg["dns_min_label_len"] and shannon_entropy(label) >= cfg["dns_min_entropy"]:
            groups[(f.src, parent_domain(f.dns_query))].append(f)
    alerts = []
    for (src, domain), fl in groups.items():
        if len(fl) >= cfg["dns_min_queries"]:
            alerts.append(Alert("rule", "dns_tunnel", src, min(f.ts for f in fl), max(f.ts for f in fl),
                                "high", "T1071.004", "Application Layer Protocol: DNS",
                                detail={"domain": domain, "suspicious_queries": len(fl)}))
    return alerts


def detect_exfil(flows: list[Flow], cfg: dict) -> list[Alert]:
    ext = [f for f in flows if not is_internal(f.dst) and not f.dns_query]
    alerts = []
    for (src, dst, _), fl in _buckets(ext, cfg["exfil_window"], lambda f: (f.src, f.dst)).items():
        out, inn = sum(f.bytes_out for f in fl), sum(f.bytes_in for f in fl)
        ratio = out / max(inn, 1)
        if out >= cfg["exfil_min_bytes"] and ratio >= cfg["exfil_min_ratio"]:
            alerts.append(Alert("rule", "data_exfiltration", src, min(f.ts for f in fl), max(f.ts for f in fl),
                                "critical", "T1041", "Exfiltration Over C2 Channel", dst=dst,
                                detail={"bytes_out": out, "out_in_ratio": round(ratio, 1)}))
    return alerts


def run_rules(flows: list[Flow], cfg: dict | None = None) -> list[Alert]:
    cfg = {**DEFAULTS, **(cfg or {})}
    found = []
    for det in (detect_port_scan, detect_brute_force, detect_beaconing, detect_dns_tunnel, detect_exfil):
        found += det(flows, cfg)
    return merge_alerts(found, gap=cfg["window"])
