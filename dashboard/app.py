"""PatchProof Dashboard — thin live-status UI.

Read-only event viewer for harness runs: scenario statuses, verdicts,
test gates, sandbox activity, and an approval panel for staging deploys.

Usage:
    cd dashboard && pip install -r requirements.txt
    uvicorn app:app --port 8080
"""

import asyncio
import json
import os
import time
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="patchproof-dashboard")

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS_DIR = ROOT / "scenarios"
EVENT_LOG: list[dict] = []
_SCANNED_KEYS: set[str] = set()  # persists across _scan_events_from_files calls


def _record_event(event_type: str, message: str) -> None:
    """Append an event to the in-memory log (called by producers)."""
    EVENT_LOG.append({
        "type": event_type,
        "message": message,
        "ts": time.strftime("%H:%M:%S"),
    })
    if len(EVENT_LOG) > 200:
        del EVENT_LOG[: len(EVENT_LOG) - 100]


def _scan_events_from_files() -> None:
    """Populate EVENT_LOG by reading scenario verdict/gate files."""
    for d in sorted(SCENARIOS_DIR.iterdir()):
        if not d.is_dir() or d.name.startswith("_"):
            continue
        gate_path = d / "test_gate.json"
        verdict_path = d / "verdict.json"

        gate = {}
        if gate_path.exists():
            try:
                gate = json.loads(gate_path.read_text())
            except Exception:
                pass

        verdict = {}
        if verdict_path.exists():
            try:
                verdict = json.loads(verdict_path.read_text())
            except Exception:
                pass

        key = f"{d.name}:{json.dumps(gate, sort_keys=True)}:{json.dumps(verdict, sort_keys=True)}"
        if key in _SCANNED_KEYS:
            continue
        _SCANNED_KEYS.add(key)

        if gate.get("passed"):
            if verdict.get("exploitable"):
                _record_event("exploit", f"{d.name}: EXPLOITABLE — {verdict.get('evidence', '')[:80]}")
            elif verdict.get("exploitable") is False:
                _record_event("pass", f"{d.name}: NOT AFFECTED")
            else:
                _record_event("pass", f"{d.name}: tests pass")
        elif gate:
            _record_event("fail", f"{d.name}: tests FAIL — {gate.get('summary', '')[:60]}")


def _scan_scenarios() -> list[dict]:
    _scan_events_from_files()
    scenarios = []
    for d in sorted(SCENARIOS_DIR.iterdir()):
        if not d.is_dir() or d.name.startswith("_"):
            continue
        meta_path = d / "cve-meta.json"
        gate_path = d / "test_gate.json"
        verdict_path = d / "verdict.json"
        assessment_path = d / "assessment.json"

        meta = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
            except Exception:
                pass

        gate = {}
        if gate_path.exists():
            try:
                gate = json.loads(gate_path.read_text())
            except Exception:
                pass

        verdict = {}
        if verdict_path.exists():
            try:
                verdict = json.loads(verdict_path.read_text())
            except Exception:
                pass

        assessment = {}
        if assessment_path.exists():
            try:
                assessment = json.loads(assessment_path.read_text())
            except Exception:
                pass

        status = "unknown"
        if gate.get("passed"):
            if verdict.get("exploitable"):
                status = "exploitable"
            elif verdict.get("exploitable") is False:
                status = "not_affected"
            else:
                status = "tests_pass"
        elif gate:
            status = "tests_fail"

        scenarios.append({
            "id": d.name,
            "cve_id": meta.get("cve_id", "unknown"),
            "dependency": meta.get("dependency", {}),
            "expected": meta.get("expected", "unknown"),
            "status": status,
            "gate": gate,
            "verdict": verdict,
            "assessment": assessment,
        })
    return scenarios


def _scan_approvals() -> list[dict]:
    approvals = []
    state_path = SCENARIOS_DIR / ".approvals.json"
    if state_path.exists():
        try:
            approvals = json.loads(state_path.read_text())
        except Exception:
            pass
    return approvals


@app.get("/", response_class=HTMLResponse)
async def index():
    return (Path(__file__).parent / "static" / "index.html").read_text()


@app.get("/api/scenarios")
async def api_scenarios():
    return _scan_scenarios()


@app.get("/api/events")
async def api_events():
    return EVENT_LOG[-100:]


@app.get("/api/approvals")
async def api_approvals():
    return _scan_approvals()


async def event_stream() -> AsyncGenerator[str, None]:
    last_len = 0
    while True:
        scenarios = _scan_scenarios()
        events = EVENT_LOG[-100:]
        payload = json.dumps({"scenarios": scenarios, "events": events})
        yield f"data: {payload}\n\n"
        await asyncio.sleep(2)


@app.get("/api/stream")
async def stream():
    from fastapi.responses import StreamingResponse
    return StreamingResponse(event_stream(), media_type="text/event-stream")


app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
