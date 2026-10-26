import random
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent import config, engine, health, quarantine, scanner, system_info
from agent import main as agent_main
from agent.model import RiskModel

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
TOKEN = "test-token"


@pytest.fixture()
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    (h / "Downloads").mkdir(parents=True)
    monkeypatch.setattr(config, "HOME", h)
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / ".cira")
    monkeypatch.setattr(config, "QUARANTINE_DIR", tmp_path / ".cira" / "quarantine")
    return h


def random_bytes(n, seed=1):
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


# ---- scanner ---------------------------------------------------------------------------------

def test_entropy_range():
    assert scanner.shannon_entropy(b"\x00" * 1000) == 0.0
    assert scanner.shannon_entropy(random_bytes(50000)) > 7.9


def test_double_extension():
    assert scanner.has_double_extension("invoice.pdf.exe") == 1
    assert scanner.has_double_extension("report.docx") == 0
    assert scanner.has_double_extension("setup.exe") == 0
    assert scanner.has_double_extension("photo‮gpj.exe") == 1


def test_features_for_suspicious_file(home):
    p = home / "Downloads" / "invoice.pdf.exe"
    p.write_bytes(random_bytes(100_000))
    feats, meta = scanner.extract_features(p)
    assert feats["double_ext"] == 1 and feats["ext_executable"] == 1
    assert feats["in_risky_location"] == 1 and feats["entropy"] > 7.5
    assert meta["sha256"] and meta["size"] == 100_000


def test_disguised_program_is_flagged(home):
    p = home / "photo.jpg"
    p.write_bytes(b"MZ" + random_bytes(5000))
    feats, _ = scanner.extract_features(p)
    assert feats["mz_mismatch"] == 1


def test_real_pe_file_is_parsed():
    import pip
    exes = list((Path(pip.__file__).parent / "_vendor" / "distlib").glob("*.exe"))
    if not exes:
        pytest.skip("no sample .exe available")
    out = scanner.pe_features(exes[0], exes[0].stat().st_size)
    assert out["is_pe"] == 1 and out["max_section_entropy"] > 0


def test_list_files_skips_symlinks_and_limits(home):
    d = home / "Downloads"
    for i in range(5):
        (d / f"f{i}.txt").write_text("x")
    (d / "link.txt").symlink_to(d / "f0.txt")
    files, truncated = scanner.list_files([d], max_files=100)
    assert len(files) == 5 and not truncated
    files, truncated = scanner.list_files([d], max_files=3)
    assert len(files) == 3 and truncated


# ---- model -----------------------------------------------------------------------------------

def test_model_known_bad_and_ordering(home):
    m = RiskModel()
    suspicious = {k: 0.0 for k in m.metrics["features"]}
    suspicious.update(ext_executable=1, double_ext=1, entropy=7.6, in_risky_location=1, is_pe=1,
                      wx_section=1, susp_imports=5, max_section_entropy=7.4, size_log=5)
    plain = {k: 0.0 for k in m.metrics["features"]}
    plain.update(entropy=4.5, size_log=4)
    out = m.predict([suspicious, plain, plain], ["a" * 64, None,
                                                 "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"])
    assert out[0]["score"] > out[1]["score"]
    assert out[1]["level"] == "Low"
    assert out[2]["score"] == 100 and out[2]["factors"][0]["feature"] == "known_bad_hash"
    assert all(f["effect"] is not None for f in out[0]["factors"])


# ---- health ----------------------------------------------------------------------------------

def _finding(level):
    return {"level": level, "quarantined": False}


def test_health_math_and_whatif_are_exact():
    findings = [_finding("High")] * 3 + [_finding("Medium")] * 2
    ports = [{"level": "High"}, {"level": "Low"}]
    checks = [{"id": "firewall", "status": "risk"}, {"id": "defender", "status": "ok"},
              {"id": "encryption", "status": "unknown"}]
    h = health.build(findings, ports, checks, {"low": True}, {"large": False})
    # high 30 (capped), medium 8, ports 5, firewall 15, disk 5 = 63
    assert h["score"] == 37 and h["level"] == "Poor"
    ids = [r["id"] for r in h["recommendations"]]
    assert "defender" not in ids and "encryption" not in ids
    ratios = [r["ratio"] for r in h["recommendations"]]
    assert ratios == sorted(ratios, reverse=True)
    w = health.what_if(h, ids)
    assert w["projected"] == 100
    w = health.what_if(h, ["firewall"])
    assert w["projected"] == 52


def test_quarantined_findings_stop_counting():
    f = [{"level": "High", "quarantined": True}]
    assert health.build(f, [], [], {"low": False}, {"large": False})["score"] == 100


# ---- system ----------------------------------------------------------------------------------

def test_parse_firewall_output():
    sample = """Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF
"""
    assert system_info.parse_firewall_states(sample) == ["ON", "OFF"]
    assert system_info.parse_firewall_states("nothing here") == []


# ---- quarantine ------------------------------------------------------------------------------

def test_quarantine_roundtrip_and_protection(home, tmp_path):
    f = home / "Downloads" / "bad.exe"
    f.write_bytes(b"evil")
    item = quarantine.quarantine(str(f), "abc", 90, "test")
    assert not f.exists()
    assert len(quarantine.list_items()) == 1
    quarantine.restore(item["id"])
    assert f.read_bytes() == b"evil" and quarantine.list_items() == []

    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    with pytest.raises(quarantine.QuarantineError):
        quarantine.quarantine(str(outside), None, 90, "test")


def test_restore_does_not_overwrite(home):
    f = home / "Downloads" / "a.exe"
    f.write_bytes(b"one")
    item = quarantine.quarantine(str(f), None, 80, "t")
    f.write_bytes(b"two")  # a new file now sits at the original path
    res = quarantine.restore(item["id"])
    assert f.read_bytes() == b"two" and Path(res["restored_to"]).read_bytes() == b"one"


# ---- API -------------------------------------------------------------------------------------

@pytest.fixture()
def client(home, monkeypatch):
    monkeypatch.setattr(agent_main, "TOKEN", TOKEN)
    agent_main.STATE["latest"] = None
    agent_main.STATE["job"] = {"state": "idle", "phase": "", "done": 0, "total": 0, "error": None}
    c = TestClient(agent_main.app, base_url=f"http://127.0.0.1:{config.PORT}")
    c.headers.update({"x-cira-token": TOKEN})
    return c


def wait_done(c):
    for _ in range(100):
        s = c.get("/api/scan/status").json()
        if s["state"] in ("done", "error"):
            return s
        time.sleep(0.1)
    raise AssertionError("scan did not finish")


def test_security_guards(client):
    assert TestClient(agent_main.app, base_url="http://evil.example").get("/").status_code == 403
    no_token = TestClient(agent_main.app, base_url=f"http://127.0.0.1:{config.PORT}")
    assert no_token.get("/api/info").status_code == 401
    page = no_token.get("/")
    assert page.status_code == 200 and TOKEN in page.text
    assert "access-control-allow-origin" not in page.headers


def test_scan_quarantine_restore_flow(client, home):
    d = home / "Downloads"
    (d / "eicar.com.txt").write_bytes(EICAR)
    (d / "invoice.pdf.exe").write_bytes(random_bytes(80_000, seed=3))
    (d / "notes.txt").write_text("shopping list: milk, eggs")

    assert client.post("/api/scan", json={"folders": ["/etc"], "include_system": False}).status_code == 400
    assert client.post("/api/scan", json={"folders": [str(d)], "include_system": False}).status_code == 200
    assert wait_done(client)["state"] == "done"

    res = client.get("/api/scan/result").json()["result"]
    names = {f["name"]: f for f in res["findings"]}
    assert res["files_scanned"] == 3
    assert names["eicar.com.txt"]["score"] == 100
    assert "notes.txt" not in names
    assert names["invoice.pdf.exe"]["score"] >= 40
    before = res["health"]["score"]
    assert before < 100

    fid = names["eicar.com.txt"]["id"]
    q = client.post("/api/quarantine", json={"finding_id": fid})
    assert q.status_code == 200
    assert not (d / "eicar.com.txt").exists()
    assert q.json()["result"]["health"]["score"] > before

    assert client.post("/api/quarantine", json={"finding_id": "nope"}).status_code == 404
    item_id = client.get("/api/quarantine").json()["items"][0]["id"]
    r = client.post("/api/restore", json={"item_id": item_id})
    assert r.status_code == 200 and (d / "eicar.com.txt").exists()
    assert r.json()["result"]["health"]["score"] == before

    w = client.post("/api/whatif", json={"ids": ["quarantine_high"]}).json()
    assert w["projected"] > w["current"]
    rep = client.get("/api/report")
    assert rep.status_code == 200 and "CIRA device report" in rep.text
