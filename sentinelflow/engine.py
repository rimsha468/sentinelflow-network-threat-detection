from __future__ import annotations

from .alerts import Alert
from .flows import Flow
from .ml import AnomalyModel
from .rules import run_rules


def detect(flows: list[Flow], model: AnomalyModel | None = None, cfg: dict | None = None) -> list[Alert]:
    alerts = run_rules(flows, cfg)
    if model is not None:
        alerts += model.detect(flows)
    return sorted(alerts, key=lambda a: a.ts_start)
