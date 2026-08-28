"""Tests for the PatchProof dashboard backend.

Run from the dashboard/ directory:
    python -m pytest test_dashboard.py -q

The tests are hermetic: SCENARIOS_DIR is monkeypatched to an empty temp dir
so the app owns no real scenario state, and the module-level EVENT_LOG /
_SCANNED_KEYS are reset between tests.
"""

import asyncio
import json
import os

import pytest
from fastapi.testclient import TestClient

import app as dashboard_app
from app import app


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


@pytest.fixture()
def ctx(tmp_path, monkeypatch):
    d = tmp_path / "scenarios"
    d.mkdir()
    monkeypatch.setattr(dashboard_app, "SCENARIOS_DIR", d)
    dashboard_app.EVENT_LOG.clear()
    dashboard_app._SCANNED_KEYS.clear()
    with TestClient(app) as c:
        c.scenarios_dir = d
        yield c
    dashboard_app.EVENT_LOG.clear()
    dashboard_app._SCANNED_KEYS.clear()


def test_index_serves_ui(ctx):
    resp = ctx.get("/")
    assert resp.status_code == 200
    assert "PatchProof" in resp.text


def test_scenarios_empty(ctx):
    assert ctx.get("/api/scenarios").json() == []


def test_events_empty(ctx):
    assert ctx.get("/api/events").json() == []


def test_approvals_empty(ctx):
    assert ctx.get("/api/approvals").json() == []


def test_push_event_records_and_returns(ctx):
    resp = ctx.post("/api/events", json={"type": "exploit", "message": "boom"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    events = ctx.get("/api/events").json()
    assert any(e["type"] == "exploit" and e["message"] == "boom" for e in events)


def test_scenario_exploitable(ctx):
    _write(ctx.scenarios_dir / "s1" / "cve-meta.json", {
        "cve_id": "CVE-2020-14343",
        "dependency": {"name": "pyyaml", "pinned_version": "3.13"},
        "expected": "exploitable",
    })
    _write(ctx.scenarios_dir / "s1" / "test_gate.json",
           {"passed": True, "summary": "ok"})
    _write(ctx.scenarios_dir / "s1" / "verdict.json",
           {"exploitable": True, "evidence": "yaml.load executed"})
    data = ctx.get("/api/scenarios").json()
    assert len(data) == 1
    assert data[0]["id"] == "s1"
    assert data[0]["cve_id"] == "CVE-2020-14343"
    assert data[0]["status"] == "exploitable"
    # a matching exploit event is recorded from the scanned files
    assert any(e["type"] == "exploit" for e in ctx.get("/api/events").json())


def test_scenario_not_affected(ctx):
    _write(ctx.scenarios_dir / "s5" / "cve-meta.json",
           {"cve_id": "CVE-x", "expected": "not_affected"})
    _write(ctx.scenarios_dir / "s5" / "test_gate.json", {"passed": True})
    _write(ctx.scenarios_dir / "s5" / "verdict.json", {"exploitable": False})
    data = ctx.get("/api/scenarios").json()
    assert data[0]["status"] == "not_affected"


def test_stream_is_event_source(ctx):
    # The SSE endpoint never ends, so assert on the route table rather than
    # consuming the infinite body over HTTP. This verifies /api/stream is
    # actually registered as a GET endpoint returning text/event-stream.
    from starlette.responses import StreamingResponse
    route = next(
        r for r in dashboard_app.app.routes
        if getattr(r, "path", None) == "/api/stream"
    )
    assert "GET" in route.methods
    resp = asyncio.run(route.endpoint())
    assert isinstance(resp, StreamingResponse)
    assert resp.media_type == "text/event-stream"
