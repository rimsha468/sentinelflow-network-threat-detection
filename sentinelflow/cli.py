from __future__ import annotations

import argparse
import json
import os

from .engine import detect
from .evaluate import evaluate
from .flows import read_jsonl, write_jsonl
from .ingest import from_zeek_conn, from_zeek_dns
from .ml import AnomalyModel
from .simulate import simulate


def _print_alerts(alerts):
    for a in alerts:
        mitre = f"{a.mitre_id} " if a.mitre_id else ""
        print(f"[{a.severity.upper():8}] {a.source:4} {a.rule:18} {a.src:12} -> {a.dst or '-':15} "
              f"t={a.ts_start:7.0f}-{a.ts_end:7.0f}  {mitre}{a.detail}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="sentinelflow", description="Hybrid network threat detection")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("simulate", help="generate synthetic traffic")
    s.add_argument("--out", required=True)
    s.add_argument("--seed", type=int, default=1)
    s.add_argument("--no-attacks", action="store_true")

    t = sub.add_parser("train", help="train anomaly model on baseline traffic")
    t.add_argument("--baseline", required=True)
    t.add_argument("--model", required=True)
    t.add_argument("--ml-method", choices=["zscore", "iforest"], default="zscore")

    d = sub.add_parser("detect", help="run detections")
    d.add_argument("--input", required=True)
    d.add_argument("--model")
    d.add_argument("--out")

    e = sub.add_parser("evaluate", help="end-to-end simulate -> train -> detect -> score")
    e.add_argument("--seed", type=int, default=1)
    e.add_argument("--out")
    e.add_argument("--ml-method", choices=["zscore", "iforest"], default="zscore")

    z = sub.add_parser("ingest-zeek", help="convert Zeek JSON logs to flows")
    z.add_argument("--conn", required=True)
    z.add_argument("--dns")
    z.add_argument("--out", required=True)

    a = p.parse_args(argv)
    if a.cmd == "simulate":
        write_jsonl(simulate(a.seed, attacks=not a.no_attacks), a.out)
        print(f"wrote {a.out}")
    elif a.cmd == "train":
        AnomalyModel(method=a.ml_method).fit(read_jsonl(a.baseline)).save(a.model)
        print(f"model saved to {a.model}")
    elif a.cmd == "detect":
        model = AnomalyModel.load(a.model) if a.model else None
        alerts = detect(read_jsonl(a.input), model)
        _print_alerts(alerts)
        if a.out:
            with open(a.out, "w") as fh:
                json.dump([x.to_dict() for x in alerts], fh, indent=2)
    elif a.cmd == "evaluate":
        model = AnomalyModel(method=a.ml_method).fit(simulate(seed=a.seed + 100, attacks=False))
        alerts = detect(simulate(seed=a.seed), model)
        _print_alerts(alerts)
        res = evaluate(alerts)
        print("\n" + json.dumps(res, indent=2))
        if a.out:
            with open(a.out, "w") as fh:
                json.dump(res, fh, indent=2)
    elif a.cmd == "ingest-zeek":
        flows = from_zeek_conn(a.conn) + (from_zeek_dns(a.dns) if a.dns else [])
        write_jsonl(sorted(flows, key=lambda f: f.ts), a.out)
        print(f"wrote {len(flows)} flows to {a.out}")


if __name__ == "__main__":
    main()
