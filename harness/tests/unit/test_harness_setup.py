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
        "skills": {},   # name -> {id, pin, repo, path, ...}
        "mcps": {},     # name -> {id, url, manifest, ...}
        "agents": {},   # name -> {id, manifest, ...}
        "next_id": 100,
    }
    return db


def fake_http_factory(db, ok_endpoints=True):
    def fake_http(method, path, body=None):
        if ok_endpoints and "/mcp-servers" in path and method == "POST":
            m = (body or {}).get("manifest", {})
            db["mcps"][m.get("name")] = {"id": db["next_id"], **m}
            db["next_id"] += 1
            return 201, {"id": db["next_id"] - 1, "name": m.get("name")}
        if ok_endpoints and "/mcp-servers" in path and method == "PUT":
            mid = int(path.rsplit("/", 1)[-1])
            for name, rec in db["mcps"].items():
                if rec.get("id") == mid:
                    rec.update((body or {}).get("manifest", {}))
                    return 200, rec
            return 404, {}
        if path.endswith("/api/v1/skills") and method == "GET":
            return 200, {"data": list(db["skills"].values())}
        if path.endswith("/api/v1/mcp-servers") and method == "GET":
            return 200, {"data": list(db["mcps"].values())}
        if path.endswith("/api/v1/agents") and method == "GET":
            return 200, {"data": list(db["agents"].values())}
        if path.endswith("/api/v1/skills") and method == "POST":
            s = body or {}
            db["skills"][s.get("name")] = {"id": db["next_id"], **s}
            db["next_id"] += 1
            return 201, {"id": db["next_id"] - 1, "name": s.get("name")}
        if "/api/v1/skills/" in path and method == "PUT":
            sid = int(path.rsplit("/", 1)[-1])
            for name, rec in db["skills"].items():
                if rec.get("id") == sid:
                    rec.update(body or {})
                    return 200, rec
            return 404, {}
        if path.endswith("/api/v1/agents") and method == "POST":
            n = (body or {}).get("name")
            db["agents"][n] = {"id": db["next_id"], **(body or {}).get("manifest", {})}
            db["next_id"] += 1
            return 201, {"id": db["next_id"] - 1, "name": n}
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
    assert m["mode"] == "SingleAgent"
    assert m["name"] == "patchproof-v2"
    # TrueForge requires config.sandbox.enabled: true to materialize attached
    # skills and provide file_downloads. Exploit execution stays on the
    # local-sandbox MCP regardless (ADR-008/016).
    assert m["sandbox"]["enabled"] is True
    assert m["file_downloads"] is True
    assert len(m["skills"]) == 7
    assert {s["name"] for s in m["skills"]} == set(hs.SKILL_PATHS.keys())
    assert {s["type"] for s in m["skills"]} == {"git"}
    assert all(s["repo"] == hs.SKILL_REPO for s in m["skills"])
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
    assert hs.upsert_agent("patchproof-v2", {"mode": "SingleAgent"})
    assert hs.upsert_agent("patchproof-v2", {"mode": "SingleAgent", "new": True})


def test_main_skips_existing_no_failures(monkeypatch):
    db = make_db()
    monkeypatch.setattr(hs, "_http", fake_http_factory(db))
    monkeypatch.setattr(hs, "current_head_sha", lambda: "a" * 40)
    # Pre-populate so the "already exists" path is exercised
    db["mcps"] = {m["name"]: {"id": 1, **m} for m in hs._MCP_REGS}
    db["skills"] = {n: {"id": 1, "name": n, "pin": "a" * 40, "repo": hs.SKILL_REPO, "path": p}
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
