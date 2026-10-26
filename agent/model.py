"""Loads the trained XGBoost model and explains each score.

Explanations use XGBoost's built-in TreeSHAP (pred_contribs=True). Each value is how much
a feature pushed this file's score up (positive) or down (negative), in log-odds.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import xgboost as xgb

from . import config
from .features import FEATURES, LABELS


ALWAYS_SHOWN = {"entropy", "size_log"}  # continuous features, shown even when low


class RiskModel:
    def __init__(self, model_dir: Path | None = None):
        d = Path(model_dir or config.MODEL_DIR)
        self.booster = xgb.Booster()
        self.booster.load_model(str(d / "risk_model.json"))
        self.metrics = json.loads((d / "metrics.json").read_text())
        self.known_bad = self._load_hashes(d / "known_bad_hashes.txt")

    @staticmethod
    def _load_hashes(path: Path) -> set[str]:
        if not path.exists():
            return set()
        out = set()
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.add(line.split()[0].lower())
        return out

    def predict(self, rows: list[dict], sha256s: list[str | None]) -> list[dict]:
        """Score a batch. Returns one dict per row: score (0-100), level, factors."""
        if not rows:
            return []
        x = np.array([[r[f] for f in FEATURES] for r in rows], dtype=float)
        dm = xgb.DMatrix(x, feature_names=FEATURES)
        contrib = self.booster.predict(dm, pred_contribs=True)  # last column is the bias
        margin = contrib.sum(axis=1)
        prob = 1.0 / (1.0 + np.exp(-margin))

        results = []
        for i, row in enumerate(rows):
            sha = (sha256s[i] or "").lower()
            if sha and sha in self.known_bad:
                results.append({
                    "score": 100,
                    "level": "High",
                    "factors": [{"feature": "known_bad_hash", "label": "Matches a known malicious file signature",
                                 "effect": None, "value": None}],
                })
                continue
            score = int(round(float(prob[i]) * 100))
            order = np.argsort(-np.abs(contrib[i, :-1]))
            factors = []
            for j in order:
                if len(factors) == 4:
                    break
                effect = float(contrib[i, j])
                if abs(effect) < 0.15:
                    continue
                name = FEATURES[j]
                if name not in ALWAYS_SHOWN and row[name] == 0:
                    continue  # an absent flag is not worth listing as a reason
                factors.append({"feature": name, "label": LABELS[name], "effect": round(effect, 2),
                                "value": round(float(row[name]), 2)})
            results.append({"score": score, "level": config.level_for(score), "factors": factors})
        return results
