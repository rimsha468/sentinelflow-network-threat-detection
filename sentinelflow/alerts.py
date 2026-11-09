from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field


@dataclass
class Alert:
    source: str            # "rule" | "ml"
    rule: str
    src: str
    ts_start: float
    ts_end: float
    severity: str
    mitre_id: str
    mitre_name: str
    dst: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def merge_alerts(alerts: list[Alert], gap: float) -> list[Alert]:
    """Collapse consecutive alerts for the same (source, rule, src, dst) into one incident."""
    groups = defaultdict(list)
    for a in alerts:
        groups[(a.source, a.rule, a.src, a.dst)].append(a)
    merged = []
    for items in groups.values():
        items.sort(key=lambda a: a.ts_start)
        cur, n = items[0], 1
        for nxt in items[1:]:
            if nxt.ts_start - cur.ts_end <= gap:
                cur.ts_end = max(cur.ts_end, nxt.ts_end)
                n += 1
            else:
                cur.detail["windows"] = n
                merged.append(cur)
                cur, n = nxt, 1
        cur.detail["windows"] = n
        merged.append(cur)
    return sorted(merged, key=lambda a: a.ts_start)
