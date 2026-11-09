"""Unsupervised anomaly detection over per-host time-window features.

Trained on a *baseline* capture of normal traffic; scores new traffic against it.
"""
from __future__ import annotations

from collections import defaultdict

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .alerts import Alert, merge_alerts
from .flows import Flow
from .util import shannon_entropy

# Heavy-tailed counts are log-compressed so a few legitimate bulk transfers don't dominate the model.
FEATURES = ["log_flows", "log_targets", "log_dsts", "fail_ratio", "log_bytes_out",
            "log_bytes_in", "log_mean_pkts", "log_dns_queries", "dns_mean_entropy", "dns_max_label_len"]


def window_features(flows: list[Flow], window: float = 60.0):
    buckets = defaultdict(list)
    for f in flows:
        buckets[(f.src, int(f.ts // window))].append(f)
    keys, rows = [], []
    for key, fl in sorted(buckets.items()):
        n = len(fl)
        labels = [f.dns_query.split(".")[0] for f in fl if f.dns_query]
        rows.append([
            np.log1p(n),
            np.log1p(len({(f.dst, f.dport) for f in fl})),
            np.log1p(len({f.dst for f in fl})),
            sum(f.state in ("S0", "REJ") for f in fl) / n,
            np.log1p(sum(f.bytes_out for f in fl)),
            np.log1p(sum(f.bytes_in for f in fl)),
            np.log1p(float(np.mean([f.pkts for f in fl]))),
            np.log1p(len(labels)),
            float(np.mean([shannon_entropy(x) for x in labels])) if labels else 0.0,
            max((len(x) for x in labels), default=0),
        ])
        keys.append(key)
    return keys, np.array(rows, dtype=float)


class AnomalyModel:
    """Baseline-deviation detector.

    method="zscore" (default): one-sided robust z-score per feature (median/MAD with a scale floor);
        a window's score is its largest *upward* deviation. Only increases matter for threat
        detection, and the per-feature z-scores double as an explanation.
    method="iforest": Isolation Forest benchmark. Symmetric and saturating on out-of-range values,
        so it flags quiet benign windows and ranks extreme attacks no higher than bulk downloads.
    """

    def __init__(self, method: str = "zscore", window: float = 60.0, quantile: float = 0.999, seed: int = 0):
        if method not in ("zscore", "iforest"):
            raise ValueError("method must be 'zscore' or 'iforest'")
        self.method, self.window, self.quantile, self.seed = method, window, quantile, seed
        self.forest = None
        self.center = self.scale = None
        self.threshold = None

    def _z(self, X):
        return (X - self.center) / self.scale

    def _score(self, X):
        if self.method == "iforest":
            return -self.forest.score_samples(X)
        return np.max(np.maximum(self._z(X), 0), axis=1)

    def fit(self, baseline: list[Flow]) -> "AnomalyModel":
        _, X = window_features(baseline, self.window)
        self.center = np.median(X, axis=0)
        mad = 1.4826 * np.median(np.abs(X - self.center), axis=0)
        self.scale = np.maximum(np.maximum(mad, 0.5 * X.std(axis=0)), 0.25)
        if self.method == "iforest":
            self.forest = IsolationForest(n_estimators=300, random_state=self.seed).fit(X)
        self.threshold = float(np.quantile(self._score(X), self.quantile))
        return self

    def detect(self, flows: list[Flow]) -> list[Alert]:
        keys, X = window_features(flows, self.window)
        scores, z = self._score(X), self._z(X)
        alerts = []
        for (src, b), s, zi in zip(keys, scores, z):
            if s <= self.threshold:
                continue
            top = np.argsort(-zi)[:3]
            alerts.append(Alert(
                "ml", "ml_anomaly", src, b * self.window, (b + 1) * self.window, "medium", "",
                "Anomalous behaviour vs baseline",
                detail={"score": round(float(s), 2),
                        "top_features": {FEATURES[i]: round(float(zi[i]), 1) for i in top}}))
        return merge_alerts(alerts, gap=self.window)

    def save(self, path: str) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str) -> "AnomalyModel":
        return joblib.load(path)
