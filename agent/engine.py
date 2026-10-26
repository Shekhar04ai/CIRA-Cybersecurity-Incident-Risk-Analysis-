"""Runs a scan end to end: files, system checks, scoring, health."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import config, health, scanner, system_info
from .model import RiskModel

_model: RiskModel | None = None


def get_model() -> RiskModel:
    global _model
    if _model is None:
        _model = RiskModel()
    return _model


Progress = Callable[[str, int, int], None]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def advice_for(level: str, factors: list[dict], kind: str) -> str:
    names = {f["feature"] for f in factors}
    if "known_bad_hash" in names:
        return "This file matches a known malicious signature. Quarantine it now and do not open it."
    parts = ["Quarantine this file, then run a full scan with Windows Security. Do not open it."
             if level == "High" else
             "Check where this file came from. If you do not recognise it, quarantine it. You can restore it later."]
    if kind == "process":
        parts.insert(0, "This program is running right now. End it in Task Manager first.")
    if "mz_mismatch" in names:
        parts.append("It is a program pretending to be another file type.")
    elif "double_ext" in names:
        parts.append("Its name hides its real file type.")
    elif "wx_section" in names or "susp_imports" in names:
        parts.append("Its code uses techniques common in malware.")
    return " ".join(parts)


def _finding(meta: dict, scored: dict, kind: str) -> dict:
    return {
        "id": uuid.uuid4().hex[:12],
        "kind": kind,
        "name": meta["name"],
        "path": meta["path"],
        "size": meta["size"],
        "sha256": meta.get("sha256"),
        "score": scored["score"],
        "level": scored["level"],
        "factors": scored["factors"],
        "advice": advice_for(scored["level"], scored["factors"], kind),
        "quarantinable": kind == "file",
        "quarantined": False,
        "running": False,
    }


def recompute(result: dict) -> dict:
    """Refresh counts and health after a finding is quarantined or restored."""
    active = [f for f in result["findings"] if not f["quarantined"]]
    result["level_counts"] = {
        "High": sum(1 for f in active if f["level"] == "High"),
        "Medium": sum(1 for f in active if f["level"] == "Medium"),
    }
    result["health"] = health.build(result["findings"], result["ports"], result["config"],
                                    result["disk"], result["junk"])
    return result


def run_scan(folders: list[Path], include_system: bool, progress: Progress | None = None) -> dict:
    progress = progress or (lambda *_: None)
    model = get_model()
    started = _now()

    progress("listing", 0, 0)
    files, truncated = scanner.list_files(folders)
    total = len(files)

    rows, metas = [], []
    for i, path in enumerate(files, 1):
        got = scanner.extract_features(path)
        if got:
            rows.append(got[0])
            metas.append(got[1])
        if i % 25 == 0 or i == total:
            progress("reading", i, total)

    progress("scoring", total, total)
    scored = model.predict(rows, [m["sha256"] for m in metas])
    findings = [_finding(m, s, "file") for m, s in zip(metas, scored) if s["level"] in ("Medium", "High")]
    by_path = {f["path"]: f for f in findings}
    scanned_paths = {m["path"] for m in metas}

    ports, checks, disk, junk = [], [], {"low": False}, {"large": False}
    if include_system:
        progress("system", total, total)
        ports = system_info.listening_ports()
        checks = system_info.config_checks()
        disk = system_info.disk_status()
        junk = system_info.temp_size()

        proc_rows, proc_metas = [], []
        for cand in system_info.suspicious_process_candidates():
            exe = cand["exe"]
            if exe in by_path:
                by_path[exe]["running"] = True
                continue
            if exe in scanned_paths:
                continue
            got = scanner.extract_features(Path(exe))
            if got:
                proc_rows.append(got[0])
                proc_metas.append(got[1])
        for m, s in zip(proc_metas, model.predict(proc_rows, [m["sha256"] for m in proc_metas])):
            if s["level"] in ("Medium", "High"):
                findings.append(_finding(m, s, "process"))

    findings.sort(key=lambda f: -f["score"])
    result = {
        "scan_id": uuid.uuid4().hex[:12],
        "started_at": started,
        "finished_at": _now(),
        "folders": [str(f) for f in folders],
        "files_scanned": len(metas),
        "truncated": truncated,
        "include_system": include_system,
        "findings": findings,
        "ports": ports,
        "config": checks,
        "disk": disk,
        "junk": junk,
    }
    progress("done", total, total)
    return recompute(result)


# ---- saved state -----------------------------------------------------------------------------

def save_last(result: dict) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    (config.DATA_DIR / "last_scan.json").write_text(json.dumps(result))


def save_result(result: dict) -> None:
    save_last(result)
    hist = load_history()
    hist.append({"at": result["finished_at"], "score": result["health"]["score"],
                 "high": result["level_counts"]["High"], "medium": result["level_counts"]["Medium"]})
    (config.DATA_DIR / "history.json").write_text(json.dumps(hist[-30:]))


def load_last() -> dict | None:
    try:
        return json.loads((config.DATA_DIR / "last_scan.json").read_text())
    except (OSError, ValueError):
        return None


def load_history() -> list[dict]:
    try:
        return json.loads((config.DATA_DIR / "history.json").read_text())
    except (OSError, ValueError):
        return []
