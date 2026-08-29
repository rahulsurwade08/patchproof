"""Unit tests for scripts/harness_setup.py.

No live TrueForge needed: the _http helper is monkeypatched.
"""

import sys
import os
sys.path.insert(0, "scripts")

import harness_setup as hs


def make_db():
    """An in-memory store of TrueForge resources keyed by name → (id, body)."""
    db = {
        "skills": {},   # name -> {id, ref, url, path, ...}
        "mcps": {},     # name -> {id, url, manifest, ...}
        "agents": {},   # name -> {id, manifest, ...}
        "next_id": 100,
    }
    return db


def fake_http_factory(db, ok_endpoints=True):
    def fake_http(method, path, body=None):
        if not ok_endpoints:
            return 404, {}
        if path == "/api/v1/settings/mcp-servers" and method == "GET":
            return 200, {"data": list(db["mcps"].values())}
        if path == "/api/v1/settings/skills" and method == "GET":
            return 200, {"data": list(db["skills"].values())}
        if path == "/api/v1/agents" and method == "GET":
            return 200, {"data": list(db["agents"].values())}
        if path == "/api/v1/settings/mcp-servers" and method == "PUT":
            m = (body or {}).get("manifest", {})
            name = m.get("name", "")
            db["mcps"][name] = m
            return 200, {"name": name}
        if path == "/api/v1/settings/skills" and method == "PUT":
            manifest = (body or {}).get("manifest", {})
            name = manifest.get("name", "")
            db["skills"][name] = manifest
            return 200, {"name": name}
        if path.endswith("/api/v1/agents") and method == "POST":
            n = (body or {}).get("name")
            aid = db["next_id"]
            db["agents"][n] = {"id": aid, "name": n, **(body or {}).get("manifest", {})}
            db["next_id"] += 1
            return 201, {"id": aid, "name": n}
        if "/api/v1/agents/" in path and method == "PUT":
            aid = int(path.rsplit("/", 1)[-1])
            for name, rec in db["agents"].items():
                if rec.get("id") == aid:
                    rec.update((body or {}).get("manifest", {}))
                    return 200, rec
            return 404, {}
        return 404, {}
    return fake_http


def test_current_head_sha():
    sha = hs.current_head_sha()
    assert len(sha) == 40


def test_build_agent_manifest():
    sha = "a" * 40
    m = hs.build_agent_manifest(sha)
    # TrueForge AgentSpec schema: model is required; skills are name-only;
    # mcp_servers is a list of MCPServer objects; config.sandbox.enabled.
    assert m["model"]["name"]
    # MCP attachments: 2 API-registered + 1 catalog (github).
    # local-sandbox gates the 4 exploit/build/write/read tools but NOT
    # sandbox_stop (mandatory teardown per ADR-012 must run on all paths).
    # cve-feed uses default ["@write","@destructive"]; tools declare
    # readOnlyHint:true so triage runs autonomously.
    assert m["mcp_servers"] == [
        {"name": "local-sandbox",
         "require_approval_for_tools": ["sandbox_build", "sandbox_exec", "sandbox_write", "sandbox_read"]},
        {"name": "cve-feed",      "require_approval_for_tools": ["@write", "@destructive"]},
        {"name": "github"},
    ]
    assert {s["name"] for s in m["skills"]} == set(hs.SKILL_PATHS.keys())
    assert all(set(s.keys()) == {"name"} for s in m["skills"]), \
        "agent-manifest skills are name-only references (no type/repo/path/pin)"
    assert m["config"]["sandbox"]["enabled"] is True
    assert m["config"]["sandbox"]["file_downloads"] is True


def test_skill_paths_cover_7():
    assert len(hs.SKILL_PATHS) == 7
    assert set(hs.SKILL_PATHS.keys()) == {
        "analyzer", "orchestrator", "reproducer", "judge",
        "patcher", "verifier", "test-runner"}


def test_mcps_cover_local_sandbox_and_cve_feed():
    names = {m["name"] for m in hs._MCP_REGS}
    assert "local-sandbox" in names
    assert "cve-feed" in names


def test_register_mcp_idempotent(monkeypatch):
    db = make_db()
    monkeypatch.setattr(hs, "_http", fake_http_factory(db))
    assert hs.register_mcp(hs._MCP_REGS[0])
    assert hs.register_mcp(hs._MCP_REGS[0])


def test_register_skill_idempotent(monkeypatch):
    db = make_db()
    monkeypatch.setattr(hs, "_http", fake_http_factory(db))
    assert hs.register_skill("analyzer", "agent/skills/analyzer", "a" * 40)
    assert hs.register_skill("analyzer", "agent/skills/analyzer", "a" * 40)


def test_upsert_agent_creates(monkeypatch):
    db = make_db()
    monkeypatch.setattr(hs, "_http", fake_http_factory(db))
    assert hs.upsert_agent("patchproof-v2", {"mode": "SingleAgent"})
    assert "patchproof-v2" in db["agents"]


def test_upsert_agent_updates_existing(monkeypatch):
    db = make_db()
    monkeypatch.setattr(hs, "_http", fake_http_factory(db))
    assert hs.upsert_agent("patchproof-v2", {"model": {"name": "test"}})
    assert hs.upsert_agent("patchproof-v2", {"model": {"name": "test2"}})


def test_main_skips_existing_no_failures(monkeypatch):
    db = make_db()
    monkeypatch.setattr(hs, "_http", fake_http_factory(db))
    monkeypatch.setattr(hs, "current_head_sha", lambda: "a" * 40)
    # Pre-populate so the "already exists" path is exercised
    db["mcps"] = {m["name"]: {**m, "url": m["url"]} for m in hs._MCP_REGS}
    db["skills"] = {n: {"name": n, "ref": "a" * 40, "url": hs.SKILL_REPO + ".git", "path": p,
                        "type": "git", "description": f"PatchProof {n} skill"}
                    for n, p in hs.SKILL_PATHS.items()}
    db["agents"] = {"patchproof-v2": {"id": 1, "name": "patchproof-v2"}}
    monkeypatch.setattr(hs, "check_endpoints", lambda: True)
    code = hs.main()
    assert code == 0


def test_main_propagates_failure(monkeypatch):
    """A failed registration must yield non-zero exit (Rule 7)."""
    db = make_db()
    monkeypatch.setattr(hs, "_http", fake_http_factory(db, ok_endpoints=False))
    monkeypatch.setattr(hs, "current_head_sha", lambda: "a" * 40)
    monkeypatch.setattr(hs, "check_endpoints", lambda: True)
    code = hs.main()
    assert code == 1


def test_check_endpoints_fails_fast(monkeypatch):
    monkeypatch.setattr(hs, "_external_health", lambda u: (False, "unreachable"))
    assert hs.check_endpoints() is False


def test_check_endpoints_passes(monkeypatch):
    monkeypatch.setattr(hs, "_external_health", lambda u: (True, "HTTP 200"))
    assert hs.check_endpoints() is True
