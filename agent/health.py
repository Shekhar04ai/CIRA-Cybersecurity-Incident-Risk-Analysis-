"""Health score and ranked fixes.

The score starts at 100 and loses points for each problem. Every fix is worth exactly the points
its problem costs, so the what-if projection is exact for this formula.
"""
from __future__ import annotations

HIGH_PER_FILE, HIGH_CAP = 15, 30
MEDIUM_PER_FILE, MEDIUM_CAP = 4, 15
PORT_EACH, PORT_CAP = 5, 15
POINTS = {"firewall": 15, "defender": 15, "encryption": 8, "disk": 5, "junk": 3}


def health_level(score: int) -> str:
    return "Good" if score >= 80 else "Fair" if score >= 50 else "Poor"


def build(findings: list[dict], ports: list[dict], checks: list[dict], disk: dict, junk: dict) -> dict:
    active = [f for f in findings if not f.get("quarantined")]
    high = [f for f in active if f["level"] == "High"]
    medium = [f for f in active if f["level"] == "Medium"]
    risky_ports = [p for p in ports if p["level"] == "High"]
    status = {c["id"]: c["status"] for c in checks}

    recs: list[dict] = []

    def add(rid: str, title: str, points: int, effort: int, steps: list[str]) -> None:
        if points > 0:
            recs.append({"id": rid, "title": title, "gain": points, "effort": effort,
                         "ratio": round(points / effort, 2), "steps": steps})

    add("quarantine_high", f"Quarantine {len(high)} high-risk item(s)", min(HIGH_CAP, HIGH_PER_FILE * len(high)), 1,
        ["Open each high-risk finding and choose Quarantine.",
         "Run a full scan with Windows Security.",
         "Change passwords if you opened any of these files."])
    add("review_medium", f"Review {len(medium)} medium-risk item(s)", min(MEDIUM_CAP, MEDIUM_PER_FILE * len(medium)), 2,
        ["Check where each file came from.",
         "Quarantine anything you do not recognise. You can restore it later."])
    add("close_ports", f"Close {len(risky_ports)} risky open port(s)", min(PORT_CAP, PORT_EACH * len(risky_ports)), 3,
        ["Turn off the service using the port (for example Remote Desktop or file sharing) if you do not need it.",
         "Otherwise block the port in Windows Firewall."])
    if status.get("firewall") == "risk":
        add("firewall", "Turn on Windows Firewall", POINTS["firewall"], 1,
            ["Open Windows Security, then Firewall and network protection.", "Turn the firewall on for every profile."])
    if status.get("defender") == "risk":
        add("defender", "Turn on real-time protection", POINTS["defender"], 1,
            ["Open Windows Security, then Virus and threat protection.",
             "Turn on real-time protection, or confirm another antivirus is running."])
    if status.get("encryption") == "risk":
        add("encryption", "Turn on disk encryption", POINTS["encryption"], 3,
            ["Open Settings, then Privacy and security, then Device encryption or BitLocker.",
             "Save the recovery key somewhere safe."])
    if disk.get("low"):
        add("disk", "Free up disk space", POINTS["disk"], 2,
            ["Remove programs and large files you no longer use.", "Empty the Recycle Bin."])
    if junk.get("large"):
        add("junk", "Clear temporary files", POINTS["junk"], 1,
            ["Open Settings, then System, then Storage, then Temporary files.", "Remove the temporary files."])

    total_loss = sum(r["gain"] for r in recs)
    score = max(0, 100 - total_loss)
    recs.sort(key=lambda r: (-r["ratio"], -r["gain"]))
    return {"score": score, "level": health_level(score), "recommendations": recs,
            "penalties": [{"id": r["id"], "points": r["gain"]} for r in recs]}


def what_if(health: dict, ids: list[str]) -> dict:
    gains = {r["id"]: r["gain"] for r in health["recommendations"]}
    chosen = [i for i in ids if i in gains]
    projected = min(100, health["score"] + sum(gains[i] for i in chosen))
    return {"current": health["score"], "projected": projected, "level": health_level(projected),
            "applied": chosen}
