"""The local CIRA agent: a small web server that only listens on this computer.

Protections for a local server that can move files:
  * binds to 127.0.0.1 only
  * rejects requests whose Host header is not 127.0.0.1 or localhost (blocks DNS rebinding)
  * every /api call needs a per-launch token that is only embedded in the page the agent serves
  * quarantine accepts only IDs of findings from the last scan, never a path typed by a client
  * no CORS headers, so other websites cannot read responses
"""
from __future__ import annotations

import html
import os
import secrets
import threading
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config, engine, health, quarantine

TOKEN = os.environ.get("CIRA_TOKEN") or secrets.token_urlsafe(24)
ALLOWED_HOSTS = {f"127.0.0.1:{config.PORT}", f"localhost:{config.PORT}"}

app = FastAPI(title="CIRA agent", docs_url=None, redoc_url=None, openapi_url=None)

STATE: dict = {
    "job": {"state": "idle", "phase": "", "done": 0, "total": 0, "error": None},
    "latest": None,
}
LOCK = threading.Lock()


@app.middleware("http")
async def guard(request: Request, call_next):
    if request.headers.get("host", "") not in ALLOWED_HOSTS:
        return JSONResponse({"detail": "Host not allowed"}, status_code=403)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    return response


def require_token(x_cira_token: str = Header(default="")) -> None:
    if not secrets.compare_digest(x_cira_token, TOKEN):
        raise HTTPException(status_code=401, detail="Missing or wrong token")


# ---- pages -----------------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index() -> str:
    page = (config.FRONTEND_DIR / "index.html").read_text(encoding="utf-8")
    return page.replace("__CIRA_TOKEN__", TOKEN)


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


app.mount("/static", StaticFiles(directory=str(config.FRONTEND_DIR)), name="static")


# ---- API -------------------------------------------------------------------------------------

def default_folders() -> list[dict]:
    out = []
    for name in ("Downloads", "Desktop", "Documents"):
        p = config.HOME / name
        if p.is_dir():
            out.append({"name": name, "path": str(p)})
    return out


@app.get("/api/info", dependencies=[Depends(require_token)])
def info() -> dict:
    m = engine.get_model()
    return {"home": str(config.HOME), "folders": default_folders(), "metrics": m.metrics,
            "known_bad_count": len(m.known_bad)}


class ScanRequest(BaseModel):
    folders: list[str]
    include_system: bool = True


def _under_home(p: str) -> Path | None:
    try:
        rp = Path(p).resolve()
        home = config.HOME.resolve()
    except OSError:
        return None
    if rp.is_dir() and (rp == home or home in rp.parents):
        return rp
    return None


def _worker(folders: list[Path], include_system: bool) -> None:
    def progress(phase: str, done: int, total: int) -> None:
        STATE["job"].update(phase=phase, done=done, total=total)

    try:
        result = engine.run_scan(folders, include_system, progress)
        engine.save_result(result)
        with LOCK:
            STATE["latest"] = result
            STATE["job"].update(state="done", error=None)
    except Exception as e:  # report the failure to the UI instead of dying silently
        STATE["job"].update(state="error", error=f"{type(e).__name__}: {e}")


@app.post("/api/scan", dependencies=[Depends(require_token)])
def start_scan(req: ScanRequest) -> dict:
    folders = [_under_home(f) for f in req.folders]
    if not folders or any(f is None for f in folders):
        raise HTTPException(400, "Choose at least one folder inside your user folder.")
    with LOCK:
        if STATE["job"]["state"] == "running":
            raise HTTPException(409, "A scan is already running.")
        STATE["job"] = {"state": "running", "phase": "listing", "done": 0, "total": 0, "error": None}
    threading.Thread(target=_worker, args=(folders, req.include_system), daemon=True).start()
    return {"started": True}


@app.get("/api/scan/status", dependencies=[Depends(require_token)])
def scan_status() -> dict:
    return STATE["job"]


@app.get("/api/scan/result", dependencies=[Depends(require_token)])
def scan_result() -> dict:
    if STATE["latest"] is None:
        STATE["latest"] = engine.load_last()
    return {"result": STATE["latest"], "history": engine.load_history()}


class FindingRef(BaseModel):
    finding_id: str


@app.post("/api/quarantine", dependencies=[Depends(require_token)])
def do_quarantine(ref: FindingRef) -> dict:
    latest = STATE["latest"]
    finding = next((f for f in (latest or {}).get("findings", []) if f["id"] == ref.finding_id), None)
    if not finding:
        raise HTTPException(404, "That finding is not in the last scan.")
    if not finding["quarantinable"]:
        raise HTTPException(400, "End the running program first, then quarantine its file from the file scan.")
    if finding["quarantined"]:
        raise HTTPException(400, "Already quarantined.")
    reason = "; ".join(f["label"] for f in finding["factors"][:2]) or "High risk score"
    try:
        item = quarantine.quarantine(finding["path"], finding["sha256"], finding["score"], reason)
    except quarantine.QuarantineError as e:
        raise HTTPException(400, str(e))
    with LOCK:
        finding["quarantined"] = True
        finding["quarantine_id"] = item["id"]
        engine.recompute(latest)
        engine.save_last(latest)
    return {"item": item, "result": latest}


class RestoreRef(BaseModel):
    item_id: str


@app.get("/api/quarantine", dependencies=[Depends(require_token)])
def list_quarantine() -> dict:
    return {"items": quarantine.list_items()}


@app.post("/api/restore", dependencies=[Depends(require_token)])
def do_restore(ref: RestoreRef) -> dict:
    try:
        item = quarantine.restore(ref.item_id)
    except quarantine.QuarantineError as e:
        raise HTTPException(400, str(e))
    latest = STATE["latest"]
    if latest:
        with LOCK:
            for f in latest["findings"]:
                if f.get("quarantine_id") == ref.item_id:
                    f["quarantined"] = False
                    f.pop("quarantine_id", None)
            engine.recompute(latest)
            engine.save_last(latest)
    return {"item": item, "result": latest}


class WhatIf(BaseModel):
    ids: list[str]


@app.post("/api/whatif", dependencies=[Depends(require_token)])
def whatif(req: WhatIf) -> dict:
    latest = STATE["latest"]
    if not latest:
        raise HTTPException(404, "Run a scan first.")
    return health.what_if(latest["health"], req.ids)


@app.get("/api/report", dependencies=[Depends(require_token)])
def report() -> Response:
    latest = STATE["latest"]
    if not latest:
        raise HTTPException(404, "Run a scan first.")
    e = html.escape
    h = latest["health"]
    rows = "".join(
        f"<tr><td>{f['score']}</td><td>{e(f['level'])}</td><td>{e(f['name'])}</td><td>{e(f['path'])}</td>"
        f"<td>{'Quarantined' if f['quarantined'] else 'Open'}</td></tr>" for f in latest["findings"])
    recs = "".join(f"<li><b>{e(r['title'])}</b> (+{r['gain']} points, effort {r['effort']}/5)</li>"
                   for r in h["recommendations"])
    m = engine.get_model().metrics
    body = f"""<!doctype html><meta charset="utf-8"><title>CIRA report</title>
<style>body{{font:15px/1.5 sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px;text-align:left}}</style>
<h1>CIRA device report</h1>
<p>Scan finished {e(latest['finished_at'])}. {latest['files_scanned']} files checked in {e(', '.join(latest['folders']))}.</p>
<h2>Health score: {h['score']} ({e(h['level'])})</h2>
<h2>Findings</h2><table><tr><th>Risk</th><th>Level</th><th>Name</th><th>Path</th><th>Status</th></tr>{rows or '<tr><td colspan=5>None</td></tr>'}</table>
<h2>Recommended fixes, best value first</h2><ol>{recs or '<li>Nothing to fix.</li>'}</ol>
<p><i>The risk model was trained on {e(str(m.get('data_source', 'unknown')))} data. Scores indicate suspicious
traits, not confirmed malware.</i></p>"""
    return Response(body, media_type="text/html",
                    headers={"Content-Disposition": 'attachment; filename="cira-report.html"'})
