"""Read-only file scanning: walk folders and turn each file into model features.

Nothing in this module changes, moves or deletes a file.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import numpy as np
import pefile

from . import config
from .features import FEATURES

EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".msi", ".sys", ".pif"}
SCRIPT_EXT = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".xlsb"}
DOC_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip",
}
RISKY_DIRS = {"downloads", "temp", "tmp", "$recycle.bin"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".cira", "site-packages"}

# Windows functions that programs rarely need but malware uses often.
SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
    "URLDownloadToFileA", "URLDownloadToFileW", "WinExec", "IsDebuggerPresent",
    "CryptEncrypt", "InternetOpenUrlA", "InternetOpenUrlW", "QueueUserAPC",
    "AdjustTokenPrivileges", "OpenProcessToken", "VirtualProtect",
}


def shannon_entropy(data: bytes) -> float:
    """Entropy in bits per byte, 0 (uniform) to 8 (random). Packed or encrypted data scores high."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


def sha256_of(path: Path, size: int) -> str | None:
    if size > config.MAX_HASH_BYTES:
        return None
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def in_risky_location(path: Path) -> int:
    """True if the file sits in Downloads or a temp folder. Folders above the user's home do not count."""
    parts = path.parts[:-1]
    try:
        parts = path.relative_to(config.HOME).parts[:-1]
    except ValueError:
        pass
    return int(any(part.lower() in RISKY_DIRS for part in parts))


def is_hidden(name: str, st: os.stat_result) -> int:
    if name.startswith("."):
        return 1
    return int(bool(getattr(st, "st_file_attributes", 0) & 2))  # FILE_ATTRIBUTE_HIDDEN


def has_double_extension(name: str) -> int:
    lower = name.lower()
    if "‮" in lower:  # right-to-left override hides the real extension
        return 1
    parts = lower.split(".")
    if len(parts) < 3:
        return 0
    return int(f".{parts[-2]}" in DOC_EXT and f".{parts[-1]}" in (EXEC_EXT | SCRIPT_EXT))


def pe_features(path: Path, size: int) -> dict:
    out = {"is_pe": 0, "wx_section": 0, "susp_imports": 0, "max_section_entropy": 0.0}
    if size > config.MAX_PE_BYTES:
        return out
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return out
    try:
        out["is_pe"] = 1
        top = 0.0
        for section in pe.sections:
            ch = section.Characteristics
            if ch & 0x20000000 and ch & 0x80000000:  # executable and writable
                out["wx_section"] = 1
            top = max(top, section.get_entropy())
        out["max_section_entropy"] = float(top)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        count = 0
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                if imp.name and imp.name.decode(errors="ignore") in SUSPICIOUS_IMPORTS:
                    count += 1
        out["susp_imports"] = count
    except Exception:
        pass
    finally:
        pe.close()
    return out


def extract_features(path: Path) -> tuple[dict, dict] | None:
    """Return (features, meta) for one file, or None if it cannot be read."""
    try:
        st = os.stat(path)
        with open(path, "rb") as f:
            head = f.read(config.SAMPLE_BYTES)
    except OSError:
        return None
    name = path.name
    ext = path.suffix.lower()
    size = st.st_size

    feats = {k: 0.0 for k in FEATURES}
    feats["ext_executable"] = float(ext in EXEC_EXT)
    feats["ext_script"] = float(ext in SCRIPT_EXT)
    feats["ext_macro_doc"] = float(ext in MACRO_EXT)
    feats["double_ext"] = float(has_double_extension(name))
    feats["mz_mismatch"] = float(head[:2] == b"MZ" and ext not in EXEC_EXT)
    feats["entropy"] = shannon_entropy(head)
    feats["size_log"] = float(np.log10(size + 1))
    feats["in_risky_location"] = float(in_risky_location(path))
    feats["is_hidden"] = float(is_hidden(name, st))
    if head[:2] == b"MZ":
        feats.update({k: float(v) for k, v in pe_features(path, size).items()})

    meta = {"name": name, "path": str(path), "size": size, "sha256": sha256_of(path, size)}
    return feats, meta


def list_files(folders: list[Path], max_files: int = config.MAX_FILES) -> tuple[list[Path], bool]:
    """List regular files under the folders. Returns (files, truncated)."""
    files: list[Path] = []
    for folder in folders:
        for root, dirs, names in os.walk(folder, followlinks=False):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d))]
            for n in names:
                p = Path(root) / n
                if p.is_symlink() or not p.is_file():
                    continue
                files.append(p)
                if len(files) >= max_files:
                    return files, True
    return files, False
