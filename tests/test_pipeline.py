import json

from sentinelflow.engine import detect
from sentinelflow.evaluate import evaluate
from sentinelflow.flows import read_jsonl, write_jsonl
from sentinelflow.ingest import from_zeek_conn
from sentinelflow.ml import AnomalyModel
from sentinelflow.simulate import simulate


def test_end_to_end_rules_perfect_and_ml_complements():
    model = AnomalyModel().fit(simulate(seed=101, attacks=False))
    res = evaluate(detect(simulate(seed=1), model))
    assert res["rules_only"]["recall"] == 1.0 and res["rules_only"]["false_positives"] == 0
    assert res["hybrid"]["recall"] == 1.0
    ml = res["per_attack"]
    assert ml["port_scan"]["ml_detected"] and ml["dns_tunnel"]["ml_detected"] and ml["exfil"]["ml_detected"]


def test_rules_stable_across_seeds():
    for seed in (2, 3, 4):
        res = evaluate(detect(simulate(seed=seed)))
        assert res["rules_only"]["f1"] == 1.0


def test_model_roundtrip(tmp_path):
    p = tmp_path / "m.joblib"
    AnomalyModel().fit(simulate(seed=5, attacks=False)).save(str(p))
    assert AnomalyModel.load(str(p)).threshold > 0


def test_jsonl_roundtrip(tmp_path):
    fl = simulate(seed=1, duration=120)
    write_jsonl(fl, str(tmp_path / "f.jsonl"))
    assert read_jsonl(str(tmp_path / "f.jsonl")) == fl


def test_zeek_ingest(tmp_path):
    p = tmp_path / "conn.log"
    rec = {"ts": 1.0, "id.orig_h": "10.0.0.5", "id.resp_h": "1.2.3.4", "id.resp_p": 443, "proto": "tcp",
           "orig_bytes": 10, "resp_bytes": None, "orig_pkts": 3, "resp_pkts": 0, "conn_state": "S0"}
    p.write_text(json.dumps(rec) + "\n")
    f = from_zeek_conn(str(p))[0]
    assert f.state == "S0" and f.bytes_in == 0 and f.pkts == 3
