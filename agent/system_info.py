"""Read-only checks of the computer: listening ports, running programs, security settings, disk.

The Windows checks (firewall, Defender, BitLocker) are skipped on other systems and report "unknown".
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil

from . import config
from .scanner import in_risky_location

IS_WINDOWS = sys.platform.startswith("win")

RISKY_PORTS = {
    21: "FTP sends passwords unencrypted",
    23: "Telnet sends everything unencrypted",
    135: "Windows RPC is a common attack entry point",
    139: "NetBIOS file sharing",
    445: "SMB file sharing, used by ransomware worms",
    3389: "Remote Desktop is reachable from the network",
    5900: "VNC remote control is reachable from the network",
    5985: "Windows remote management",
}
ALL_INTERFACES = {"0.0.0.0", "::", "*"}


def _run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    flags = 0x08000000 if IS_WINDOWS else 0  # no console window flash
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=flags)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""


def listening_ports() -> list[dict]:
    """Ports this computer is listening on. A port open on all interfaces is reachable from the network."""
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return []
    seen, out = set(), []
    for c in conns:
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        ip, port = c.laddr.ip, c.laddr.port
        exposed = ip in ALL_INTERFACES
        if not exposed:
            continue  # loopback-only ports cannot be reached from outside
        proc = ""
        if c.pid:
            try:
                proc = psutil.Process(c.pid).name()
            except (psutil.Error, OSError):
                proc = ""
        key = (port, proc)
        if key in seen:
            continue
        seen.add(key)
        risky = port in RISKY_PORTS
        out.append({
            "port": port,
            "process": proc or "unknown",
            "level": "High" if risky else "Low",
            "note": RISKY_PORTS.get(port, "Open to the network"),
        })
    out.sort(key=lambda r: (r["level"] != "High", r["port"]))
    return out


def suspicious_process_candidates() -> list[dict]:
    """Running programs whose file sits in Downloads or a temp folder. The caller scores them."""
    out, seen = [], set()
    for p in psutil.process_iter(["pid", "name", "exe"]):
        exe = p.info.get("exe")
        if not exe or exe in seen:
            continue
        if in_risky_location(Path(exe)):
            seen.add(exe)
            out.append({"pid": p.info["pid"], "name": p.info.get("name") or Path(exe).name, "exe": exe})
    return out


def parse_firewall_states(text: str) -> list[str]:
    """Pull ON/OFF values out of `netsh advfirewall show allprofiles state` output."""
    return [m.upper() for m in re.findall(r"^\s*State\s+(ON|OFF)\s*$", text, flags=re.I | re.M)]


def config_checks() -> list[dict]:
    """Security settings. status is ok, risk or unknown."""
    if not IS_WINDOWS:
        return [
            {"id": "firewall", "label": "Windows Firewall", "status": "unknown", "detail": "Checked on Windows only"},
            {"id": "defender", "label": "Windows Defender real-time protection", "status": "unknown",
             "detail": "Checked on Windows only"},
            {"id": "encryption", "label": "Disk encryption (BitLocker)", "status": "unknown",
             "detail": "Checked on Windows only"},
        ]
    checks = []

    _, out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    states = parse_firewall_states(out)
    if not states:
        checks.append({"id": "firewall", "label": "Windows Firewall", "status": "unknown",
                       "detail": "Could not read the firewall state"})
    elif all(s == "ON" for s in states):
        checks.append({"id": "firewall", "label": "Windows Firewall", "status": "ok", "detail": "On for all profiles"})
    else:
        checks.append({"id": "firewall", "label": "Windows Firewall", "status": "risk",
                       "detail": "Off for at least one network profile"})

    code, out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                      "(Get-MpComputerStatus).RealTimeProtectionEnabled"])
    val = out.strip().lower()
    if code == 0 and val == "true":
        checks.append({"id": "defender", "label": "Windows Defender real-time protection", "status": "ok",
                       "detail": "On"})
    elif code == 0 and val == "false":
        checks.append({"id": "defender", "label": "Windows Defender real-time protection", "status": "risk",
                       "detail": "Off. This is fine only if another antivirus is active"})
    else:
        checks.append({"id": "defender", "label": "Windows Defender real-time protection", "status": "unknown",
                       "detail": "Could not read the Defender state"})

    code, out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                      "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"])
    val = out.strip().lower()
    if code == 0 and val in ("on", "1"):
        checks.append({"id": "encryption", "label": "Disk encryption (BitLocker)", "status": "ok", "detail": "On"})
    elif code == 0 and val in ("off", "0"):
        checks.append({"id": "encryption", "label": "Disk encryption (BitLocker)", "status": "risk",
                       "detail": "Off. A lost or stolen laptop exposes its files"})
    else:
        checks.append({"id": "encryption", "label": "Disk encryption (BitLocker)", "status": "unknown",
                       "detail": "Run CIRA as administrator to check this"})
    return checks


def disk_status() -> dict:
    usage = shutil.disk_usage(config.HOME.anchor or "/")
    free_pct = round(100 * usage.free / usage.total, 1) if usage.total else 100.0
    return {"free_gb": round(usage.free / 1e9, 1), "total_gb": round(usage.total / 1e9, 1), "free_pct": free_pct,
            "low": free_pct < 10}


def temp_size(limit_seconds: float = 8.0, limit_files: int = 20000) -> dict:
    """Size of the temp folder. Stops early on huge folders so the scan stays quick."""
    start, total, count, partial = time.time(), 0, 0, False
    for root, _dirs, names in os.walk(tempfile.gettempdir()):
        for n in names:
            try:
                total += os.path.getsize(os.path.join(root, n))
            except OSError:
                pass
            count += 1
            if count >= limit_files or time.time() - start > limit_seconds:
                partial = True
                break
        if partial:
            break
    return {"gb": round(total / 1e9, 2), "files": count, "partial": partial, "large": total > 1e9}
