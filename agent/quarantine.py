"""Quarantine moves a file into a private folder so it can be restored. Nothing is ever deleted."""
from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import config


class QuarantineError(Exception):
    pass


def _index_file() -> Path:
    return config.QUARANTINE_DIR / "index.json"


def _load() -> list[dict]:
    try:
        return json.loads(_index_file().read_text())
    except (OSError, ValueError):
        return []


def _save(items: list[dict]) -> None:
    config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _index_file().with_suffix(".tmp")
    tmp.write_text(json.dumps(items, indent=2))
    os.replace(tmp, _index_file())


def is_allowed(path: Path) -> bool:
    """Only files inside the user's home folder may be quarantined, never system files or CIRA's own data."""
    try:
        rp = Path(path).resolve()
        home = config.HOME.resolve()
        data = config.DATA_DIR.resolve()
    except OSError:
        return False
    return home in rp.parents and data not in rp.parents


def quarantine(path: str, sha256: str | None, score: int, reason: str) -> dict:
    src = Path(path)
    if not src.is_file():
        raise QuarantineError("The file no longer exists.")
    if not is_allowed(src):
        raise QuarantineError("CIRA only quarantines files inside your user folder.")
    item_id = uuid.uuid4().hex
    config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    dest = config.QUARANTINE_DIR / f"{item_id}.quar"
    size = src.stat().st_size
    try:
        shutil.move(str(src), str(dest))
    except OSError as e:
        raise QuarantineError(f"Could not move the file. It may be in use. ({e.strerror or e})")
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    item = {
        "id": item_id,
        "original_path": str(src),
        "name": src.name,
        "size": size,
        "sha256": sha256,
        "score": score,
        "reason": reason,
        "quarantined_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    items = _load()
    items.append(item)
    _save(items)
    return item


def list_items() -> list[dict]:
    return _load()


def restore(item_id: str) -> dict:
    items = _load()
    item = next((i for i in items if i["id"] == item_id), None)
    if not item:
        raise QuarantineError("That item is not in quarantine.")
    stored = config.QUARANTINE_DIR / f"{item_id}.quar"
    if not stored.is_file():
        raise QuarantineError("The quarantined file is missing from disk.")
    target = Path(item["original_path"])
    if target.exists():
        target = target.with_name(target.name + ".restored")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(stored), str(target))
    except OSError as e:
        raise QuarantineError(f"Could not restore the file. ({e.strerror or e})")
    _save([i for i in items if i["id"] != item_id])
    return {**item, "restored_to": str(target)}
