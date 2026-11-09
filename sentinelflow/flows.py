"""Normalised flow record + JSONL I/O."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass
class Flow:
    ts: float
    src: str
    dst: str
    dport: int
    proto: str
    bytes_out: int
    bytes_in: int
    pkts: int
    state: str = "SF"          # SF = completed, S0 = no reply, REJ = rejected/reset
    dns_query: str = ""
    label: str = "benign"      # ground truth (simulator only)


def write_jsonl(flows: Iterable[Flow], path: str) -> None:
    with open(path, "w") as fh:
        for f in flows:
            fh.write(json.dumps(asdict(f)) + "\n")


def read_jsonl(path: str) -> list[Flow]:
    with open(path) as fh:
        return [Flow(**json.loads(line)) for line in fh if line.strip()]
