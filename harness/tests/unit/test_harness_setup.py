"""Unit tests for scripts/harness_setup.py.

No live TrueForge needed: the _http helper is monkeypatched.
"""

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
sys.path.insert(0, "scripts")

from unittest.mock import patch, MagicMock
import pytest

import harness_setup as hs


def fake_http(method, path, body=None):
    fake_db[path] = (method, body)
    if path == "/health":
        return 200, {"ok": True}
    if path == "/api/v1/skills":
        return 200, {"data": [{"name": s} for s in fake_db.get("_skills", [])]}
    if path == "/api/v1/mcp-servers":
        return 200, {"data": [{"name": m} for m in fake_db.get("_mcps", [])]}
    if path == "/api/v1/agents":
        return 200, {"data": [{"name": a} for a in fake_db.get("_agents", [])]}
    if path.startswith("/api/v1/mcp-servers") and method == "POST":
        m = (body or {}).get("manifest", {})
        fake_db["_mcps"] = fake_db.get("_mcps", []) + [m.get("name")]
        return 201, {"name": m.get("name")}
    if path.startswith("/api/v1/skills") and method == "POST":
        s = (body or {}).get("name")
        fake_db["_skills"] = fake_db.get("_skills", []) + [s]
        return 201, {"name": s}
    if path.startswith("/api/v1/agents/") and method == "PUT":
        a = path.split("/")[-1]
        fake_db["_agents"] = fake_db.get("_agents", []) + [a]
        return 200, {"name": a}
    return 404, {}


fake_db = {}


@pytest.fixture(autouse=True)
def reset_fake():
    global fake_db
    fake_db = {}


@pytest.fixture
def patch_http(monkeypatch):
    monkeypatch.setattr(hs, "_http", fake_http)


def test_current_head_sha():
    sha = hs.current_head_sha()
    assert len(sha) == 40


def test_build_agent_manifest():
    sha = "a" * 40
    m = hs.build_agent_manifest(sha)
    assert m["mode"] == "SingleAgent"
    assert m["name"] == "patchproof-v2"
    assert m["sandbox"]["enabled"] is False
    assert m["file_downloads"] is True
    assert len(m["skills"]) == 7
    assert {s["name"] for s in m["skills"]} == set(hs.SKILL_PATHS.keys())
    assert {s["type"] for s in m["skills"]} == {"git"}
    assert all(s["repo"] == hs.SKILL_REPO for s in m["skills"])
    assert m["mcp_servers"] == ["local-sandbox", "cve-feed"]


def test_skill_paths_cover_7(monkeypatch):
    assert len(hs.SKILL_PATHS) == 7
    assert set(hs.SKILL_PATHS.keys()) == {
        "analyzer", "orchestrator", "reproducer", "judge",
        "patcher", "verifier", "test-runner"}


def test_mcps_cover_local_sandbox_and_cve_feed():
    names = {m["name"] for m in hs.MCPS}
    assert "local-sandbox" in names
    assert "cve-feed" in names


def test_register_mcp_idempotent(patch_http):
    ok = hs.register_mcp({"name": "local-sandbox", "url": "http://x/mcp", "description": "x"})
    assert ok
    ok2 = hs.register_mcp({"name": "local-sandbox", "url": "http://x/mcp", "description": "x"})
    assert ok2


def test_register_skill_idempotent(patch_http):
    ok = hs.register_skill("analyzer", "agent/skills/analyzer", "a" * 40)
    assert ok
    ok2 = hs.register_skill("analyzer", "agent/skills/analyzer", "b" * 40)
    assert ok2


def test_upsert_agent_creates(patch_http):
    ok = hs.upsert_agent("patchproof-v2", {"mode": "SingleAgent"})
    assert ok
    assert "patchproof-v2" in fake_db.get("_agents", [])


def test_main_skips_existing(patch_http, monkeypatch):
    fake_db["_mcps"] = ["local-sandbox"]
    fake_db["_skills"] = list(hs.SKILL_PATHS.keys())
    fake_db["_agents"] = ["patchproof-v2"]
    monkeypatch.setattr(hs, "current_head_sha", lambda: "a" * 40)
    code = hs.main()
    assert code == 0


def test_main_fails_when_server_unreachable(monkeypatch):
    monkeypatch.setattr(hs, "_http", lambda *a, **kw: (0, {}))
    code = hs.main()
    assert code == 2
