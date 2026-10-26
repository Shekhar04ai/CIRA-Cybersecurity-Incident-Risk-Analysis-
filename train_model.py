"""Train the CIRA file risk model and compare it with a checklist baseline.

IMPORTANT: this script trains on SYNTHETIC data. A generator draws feature values for benign and
malicious files from distributions written by hand (see _benign and _malicious). The model therefore
learns those assumptions. Its metrics measure how well it separates the generator's two groups and say
nothing about real-world detection. To get real results, replace load_dataset() with features extracted
from a labelled corpus (for example EMBER, or samples from MalwareBazaar plus clean files) using
agent.scanner.extract_features, then run this script again.

Usage:  python train_model.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import xgboost as xgb
from sklearn.metrics import brier_score_loss, roc_auc_score
from sklearn.model_selection import train_test_split

from agent.features import FEATURES

OUT = Path(__file__).resolve().parent / "models"
SEED = 7
MALICIOUS_RATE = 0.15


def _clip(x, lo, hi):
    return float(np.clip(x, lo, hi))


def _base(rng) -> dict:
    return dict.fromkeys(FEATURES, 0.0)


def _benign(rng) -> dict:
    f = _base(rng)
    f["size_log"] = _clip(rng.normal(5.5, 1.0), 1, 9)
    f["is_hidden"] = float(rng.random() < 0.01)
    f["in_risky_location"] = float(rng.random() < 0.35)
    r = rng.random()
    if r < 0.70:  # documents, images, media, archives
        f["entropy"] = _clip(rng.normal(6.2, 1.5), 0.5, 8)
    elif r < 0.82:  # installers and portable programs (legitimate, so they overlap with malware)
        parsed = rng.random() < 0.98
        f.update(ext_executable=1.0, entropy=_clip(rng.normal(6.6, 0.6), 3, 8),
                 double_ext=float(rng.random() < 0.0005))
        if parsed:
            f.update(is_pe=1.0, max_section_entropy=_clip(rng.normal(6.4, 0.6), 3, 8),
                     wx_section=float(rng.random() < 0.03), susp_imports=float(rng.poisson(1.2)))
        f["in_risky_location"] = float(rng.random() < 0.6)
    elif r < 0.95:  # scripts
        f.update(ext_script=1.0, entropy=_clip(rng.normal(4.8, 1.2), 0, 8), double_ext=float(rng.random() < 0.0005))
        f["in_risky_location"] = float(rng.random() < 0.4)
    elif r < 0.99:  # macro documents
        f.update(ext_macro_doc=1.0, entropy=_clip(rng.normal(7.0, 0.4), 4, 8))
    else:  # a renamed installer: rare but legitimate
        f.update(is_pe=1.0, mz_mismatch=1.0, entropy=_clip(rng.normal(6.8, 0.5), 3, 8),
                 max_section_entropy=_clip(rng.normal(6.4, 0.6), 3, 8), susp_imports=float(rng.poisson(1.0)))
    return f


def _malicious(rng) -> dict:
    f = _base(rng)
    f["size_log"] = _clip(rng.normal(5.2, 1.0), 1, 9)
    r = rng.random()

    def pe_part(parsed_prob, imports_mean, wx_prob):
        if rng.random() < parsed_prob:  # the rest are packed or damaged so the header cannot be parsed
            f.update(is_pe=1.0, max_section_entropy=_clip(rng.normal(7.0, 0.7), 3, 8),
                     wx_section=float(rng.random() < wx_prob), susp_imports=float(rng.poisson(imports_mean)))

    if r < 0.38:  # packed programs
        f.update(ext_executable=1.0, entropy=_clip(rng.normal(7.1, 0.6), 3, 8),
                 double_ext=float(rng.random() < 0.15), is_hidden=float(rng.random() < 0.10))
        pe_part(0.85, 4.5, 0.35)
        f["in_risky_location"] = float(rng.random() < 0.8)
    elif r < 0.55:  # obfuscated scripts
        f.update(ext_script=1.0, entropy=_clip(rng.normal(5.6, 1.5), 0, 8), double_ext=float(rng.random() < 0.10))
        f["in_risky_location"] = float(rng.random() < 0.8)
    elif r < 0.63:  # macro documents
        f.update(ext_macro_doc=1.0, entropy=_clip(rng.normal(7.0, 0.5), 4, 8))
        f["in_risky_location"] = float(rng.random() < 0.7)
    elif r < 0.73:  # lures: "invoice.pdf.exe" style names
        f.update(double_ext=1.0, entropy=_clip(rng.normal(7.0, 0.8), 2, 8))
        if rng.random() < 0.7:
            f["ext_executable"] = 1.0
            pe_part(0.8, 3.5, 0.3)
        else:
            f["ext_script"] = 1.0
        f["in_risky_location"] = float(rng.random() < 0.8)
    elif r < 0.87:  # programs disguised as other file types
        f.update(mz_mismatch=1.0, entropy=_clip(rng.normal(7.0, 0.8), 2, 8))
        pe_part(0.8, 3.5, 0.3)
        f["in_risky_location"] = float(rng.random() < 0.7)
    else:  # stealthy: looks like an ordinary document, so no model can catch it. Keeps metrics honest.
        f["entropy"] = _clip(rng.normal(6.2, 1.5), 0.5, 8)
        f["in_risky_location"] = float(rng.random() < 0.4)
    return f


def load_dataset(n: int = 20000):
    """Synthetic data. Replace this function to train on real labelled files."""
    rng = np.random.default_rng(SEED)
    rows, labels = [], []
    for _ in range(n):
        mal = rng.random() < MALICIOUS_RATE
        rows.append(_malicious(rng) if mal else _benign(rng))
        labels.append(int(mal))
    y = np.array(labels)
    flip = rng.random(n) < 0.02  # 2% label noise
    y = np.where(flip, 1 - y, y)
    x = np.array([[r[k] for k in FEATURES] for r in rows], dtype=float)
    return x, y


def checklist_score(x: np.ndarray) -> np.ndarray:
    """Baseline: count red flags with equal weight, no learning."""
    ix = {k: i for i, k in enumerate(FEATURES)}
    flags = [
        (x[:, ix["ext_executable"]] == 1) & (x[:, ix["in_risky_location"]] == 1),
        x[:, ix["double_ext"]] == 1,
        x[:, ix["mz_mismatch"]] == 1,
        x[:, ix["wx_section"]] == 1,
        x[:, ix["entropy"]] > 7.2,
        x[:, ix["susp_imports"]] >= 3,
        x[:, ix["ext_macro_doc"]] == 1,
    ]
    return np.sum(flags, axis=0) / len(flags)


def main() -> None:
    x, y = load_dataset()
    x_tr, x_te, y_tr, y_te = train_test_split(x, y, test_size=0.25, random_state=SEED, stratify=y)

    # Monotonic constraints: having a red flag can never lower the score, holding everything else equal.
    # This keeps the model sensible on files unlike anything in the training data.
    raises_risk = {"ext_executable", "ext_script", "ext_macro_doc", "double_ext", "mz_mismatch",
                   "in_risky_location", "is_hidden", "wx_section", "susp_imports"}
    constraints = "(" + ",".join("1" if f in raises_risk else "0" for f in FEATURES) + ")"
    clf = xgb.XGBClassifier(n_estimators=150, max_depth=4, learning_rate=0.1, subsample=0.9,
                            colsample_bytree=0.9, eval_metric="logloss", random_state=SEED,
                            monotone_constraints=constraints)
    clf.fit(x_tr, y_tr)
    prob = clf.predict_proba(x_te)[:, 1]

    metrics = {
        "algorithm": "XGBoost (150 trees, depth 4, monotonic constraints on red-flag features)",
        "data_source": "synthetic",
        "warning": "Trained on synthetic data written by hand. These numbers do not measure real-world detection.",
        "n_train": int(len(y_tr)),
        "n_test": int(len(y_te)),
        "malicious_rate": MALICIOUS_RATE,
        "model_auc": round(float(roc_auc_score(y_te, prob)), 4),
        "model_brier": round(float(brier_score_loss(y_te, prob)), 4),
        "constant_brier": round(float(brier_score_loss(y_te, np.full(len(y_te), y_tr.mean()))), 4),
        "checklist_auc": round(float(roc_auc_score(y_te, checklist_score(x_te))), 4),
        "features": FEATURES,
    }

    OUT.mkdir(exist_ok=True)
    booster = clf.get_booster()
    booster.feature_names = FEATURES
    booster.save_model(str(OUT / "risk_model.json"))
    (OUT / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps({k: v for k, v in metrics.items() if k != "features"}, indent=2))


if __name__ == "__main__":
    main()
