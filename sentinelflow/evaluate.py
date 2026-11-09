"""Host-level evaluation against simulator ground truth."""
from __future__ import annotations

from .simulate import ATTACKERS

EXPECTED_RULE = {"port_scan": "port_scan", "brute_force": "brute_force", "beacon": "c2_beaconing",
                 "dns_tunnel": "dns_tunnel", "exfil": "data_exfiltration"}


def _prf(flagged: set[str], truth: set[str]) -> dict:
    tp = len(flagged & truth)
    p = tp / len(flagged) if flagged else 0.0
    r = tp / len(truth) if truth else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"flagged_hosts": len(flagged), "true_positives": tp, "false_positives": len(flagged - truth),
            "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3)}


def evaluate(alerts) -> dict:
    truth = set(ATTACKERS)
    rule_hosts = {a.src for a in alerts if a.source == "rule"}
    ml_hosts = {a.src for a in alerts if a.source == "ml"}
    per_attack = {}
    for host, kind in ATTACKERS.items():
        per_attack[kind] = {
            "host": host,
            "rule_detected": any(a.src == host and a.rule == EXPECTED_RULE[kind] for a in alerts),
            "ml_detected": host in ml_hosts,
        }
    return {"rules_only": _prf(rule_hosts, truth), "ml_only": _prf(ml_hosts, truth),
            "hybrid": _prf(rule_hosts | ml_hosts, truth), "per_attack": per_attack}
