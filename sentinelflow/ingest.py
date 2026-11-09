"""Ingest Zeek JSON logs (conn.log / dns.log) into normalised flows."""
from __future__ import annotations

import json

from .flows import Flow

_REJ = {"REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH"}


def _state(zeek_state: str) -> str:
    if zeek_state == "S0":
        return "S0"
    return "REJ" if zeek_state in _REJ else "SF"


def from_zeek_conn(path: str) -> list[Flow]:
    out = []
    with open(path) as fh:
        for line in fh:
            if not line.strip():
                continue
            d = json.loads(line)
            out.append(Flow(
                ts=float(d["ts"]), src=d["id.orig_h"], dst=d["id.resp_h"],
                dport=int(d["id.resp_p"]), proto=d.get("proto", "tcp"),
                bytes_out=int(d.get("orig_bytes") or 0), bytes_in=int(d.get("resp_bytes") or 0),
                pkts=int(d.get("orig_pkts") or 0) + int(d.get("resp_pkts") or 0),
                state=_state(d.get("conn_state", "SF")),
            ))
    return out


def from_zeek_dns(path: str) -> list[Flow]:
    out = []
    with open(path) as fh:
        for line in fh:
            if not line.strip():
                continue
            d = json.loads(line)
            out.append(Flow(
                ts=float(d["ts"]), src=d["id.orig_h"], dst=d["id.resp_h"],
                dport=int(d.get("id.resp_p", 53)), proto="udp", bytes_out=60, bytes_in=120,
                pkts=2, dns_query=d.get("query", ""),
            ))
    return out
