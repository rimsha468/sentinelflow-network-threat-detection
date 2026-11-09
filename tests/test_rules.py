import random

from sentinelflow.flows import Flow
from sentinelflow.rules import DEFAULTS, run_rules
from sentinelflow.util import is_internal, parent_domain, shannon_entropy


def names(alerts):
    return {a.rule for a in alerts}


def test_port_scan_detected():
    fl = [Flow(i * 0.05, "10.0.0.5", f"10.0.1.{i % 200}", 1 + i, "tcp", 0, 0, 1, state="S0") for i in range(300)]
    assert "port_scan" in names(run_rules(fl))


def test_normal_browsing_not_scan():
    fl = [Flow(i, "10.0.0.5", "93.184.216.34", 443, "tcp", 500, 5000, 10) for i in range(50)]
    assert not run_rules(fl)


def test_brute_force_detected_and_merged():
    fl = [Flow(i * 0.5, "10.0.0.5", "10.0.2.10", 22, "tcp", 1800, 1500, 12) for i in range(150)]
    alerts = [a for a in run_rules(fl) if a.rule == "brute_force"]
    assert len(alerts) == 1 and alerts[0].mitre_id == "T1110"


def test_beaconing_detected():
    rng = random.Random(0)
    t, fl = 0.0, []
    for _ in range(40):
        fl.append(Flow(t, "10.0.0.5", "203.0.113.9", 443, "tcp", 300, 600, 8))
        t += 60 + rng.uniform(-2, 2)
    assert "c2_beaconing" in names(run_rules(fl))


def test_irregular_traffic_not_beaconing():
    rng = random.Random(0)
    fl = [Flow(rng.uniform(0, 3600), "10.0.0.5", "203.0.113.9", 443, "tcp", 300, 600, 8) for _ in range(40)]
    assert "c2_beaconing" not in names(run_rules(fl))


def test_ntp_allowlisted():
    fl = [Flow(i * 300, "10.0.0.5", "162.159.200.1", 123, "udp", 76, 76, 2) for i in range(30)]
    assert not run_rules(fl)


def test_dns_tunnel_detected():
    rng = random.Random(1)
    fl = [Flow(i, "10.0.0.5", "10.0.0.2", 53, "udp", 80, 80, 2,
               dns_query="".join(rng.choices("abcdefghijklmnopqrstuvwxyz234567", k=26)) + ".t.bad-example.net")
          for i in range(30)]
    assert "dns_tunnel" in names(run_rules(fl))


def test_exfil_requires_asymmetry():
    up = [Flow(i * 10, "10.0.0.5", "198.51.100.7", 443, "tcp", 5_000_000, 40_000, 100) for i in range(8)]
    dl = [Flow(i * 10, "10.0.0.6", "198.51.100.7", 443, "tcp", 5_000_000, 50_000_000, 100) for i in range(8)]
    assert "data_exfiltration" in names(run_rules(up))
    assert "data_exfiltration" not in names(run_rules(dl))


def test_thresholds_configurable():
    fl = [Flow(i * 0.5, "10.0.0.5", "10.0.2.10", 22, "tcp", 1, 1, 1) for i in range(10)]
    assert not run_rules(fl)
    assert "brute_force" in names(run_rules(fl, {"brute_min_attempts": 5}))
    assert DEFAULTS["brute_min_attempts"] == 30      # defaults untouched


def test_util():
    assert is_internal("10.1.2.3") and is_internal("192.168.0.1") and not is_internal("203.0.113.5")
    assert parent_domain("a.b.example.com") == "example.com"
    assert shannon_entropy("aaaa") == 0 and shannon_entropy("abcd") == 2
