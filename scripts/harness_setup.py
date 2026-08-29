#!/usr/bin/env python3
"""TrueForge harness setup — register MCPs, skills, and the patchproof-v2 agent.

Runs against a running TrueForge server (default http://[::1]:8790) and ensures
the harness wiring is in place per docs/custom-harness-build-plan.md step 3:
  - MCPs: local-sandbox (127.0.0.1:8081) and cve-feed (127.0.0.1:8091)
  - Skills: 7 PatchProof skills (analyzer, orchestrator, reproducer, judge,
    patcher, verifier, test-runner) as git-source skills, pinned to current HEAD
  - Agent: patchproof-v2 (SingleAgent mode) manifest with sandbox.enabled=false
    and attached skills/MCPs

Idempotent: re-running only registers missing items; existing skills/MCPs/agents
are left alone. Safe to re-run after server restart or schema evolution.

Requires: requests (already in harness/frontend/dev deps). Stdlib urllib works
but requests reads more naturally for an operator script; we fall back to
urllib if requests is not installed.
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("TRUEFORGE_URL", "http://[::1]:8790")
SKILL_REPO = "https://github.com/rahulsurwade08/patchproof"
SKILL_PATHS = {
    "analyzer":      "agent/skills/analyzer",
    "orchestrator":  "agent/skills/orchestrator",
    "reproducer":    "agent/skills/reproducer",
    "judge":         "agent/skills/judge",
    "patcher":       "agent/skills/patcher",
    "verifier":      "agent/skills/verifier",
    "test-runner":   "agent/skills/test-runner",
}
MCPS = [
    {"name": "local-sandbox",
     "description": "Keyless local Docker sandbox",
     "url": os.environ.get("LOCAL_SANDBOX_URL", "http://127.0.0.1:8081/mcp")},
    {"name": "cve-feed",
     "description": "Dual-source CVE legitimacy (CVE.org + OSV.dev)",
     "url": os.environ.get("CVE_FEED_URL", "http://127.0.0.1:8091/mcp")},
]


def _http(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{BASE_URL}{path}", data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": exc.read().decode()[:300]}
    except urllib.error.URLError as exc:
        print(f"connection failed: {exc.reason}", file=sys.stderr)
        return 0, {"error": str(exc.reason)}


def _get(path):
    return _http("GET", path)


def _post(path, body):
    return _http("POST", path, body)


def _put(path, body):
    return _http("PUT", path, body)


def current_head_sha():
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True).strip()


def list_skills():
    code, data = _get("/api/v1/skills")
    if code != 200:
        return []
    return [s.get("name") for s in data.get("data", [])]


def list_mcps():
    code, data = _get("/api/v1/mcp-servers")
    if code != 200:
        return []
    return [m.get("name") for m in data.get("data", [])]


def list_agents():
    code, data = _get("/api/v1/agents")
    if code != 200:
        return []
    return [a.get("name") for a in data.get("data", [])]


def register_mcp(mcp):
    manifest = {"type": "remote", **mcp}
    code, data = _post("/api/v1/mcp-servers", {"manifest": manifest})
    if code in (200, 201):
        print(f"  registered MCP: {mcp['name']}")
        return True
    if code == 409 or "exists" in str(data).lower():
        print(f"  already exists: {mcp['name']}")
        return True
    print(f"  FAIL register {mcp['name']}: {code} {data}",
          file=sys.stderr)
    return False


def register_skill(name, path, sha):
    body = {
        "type": "git",
        "name": name,
        "repo": SKILL_REPO,
        "path": path,
        "pin": sha,
    }
    code, data = _post("/api/v1/skills", body)
    if code in (200, 201):
        print(f"  registered skill: {name} @ {sha[:8]}")
        return True
    if code == 409 or "exists" in str(data).lower():
        print(f"  already exists: {name}")
        return True
    print(f"  FAIL register {name}: {code} {data}", file=sys.stderr)
    return False


def upsert_agent(name, manifest):
    code, data = _put(f"/api/v1/agents/{name}", {"manifest": manifest})
    if code in (200, 201):
        print(f"  agent updated: {name}")
        return True
    if code == 404:
        code, data = _post("/api/v1/agents", {"name": name, "manifest": manifest})
        if code in (200, 201):
            print(f"  agent created: {name}")
            return True
    print(f"  FAIL upsert {name}: {code} {data}", file=sys.stderr)
    return False


def build_agent_manifest(sha):
    return {
        "mode": "SingleAgent",
        "name": "patchproof-v2",
        "sandbox": {"enabled": False},
        "file_downloads": True,
        "skills": [{"type": "git", "name": n, "repo": SKILL_REPO,
                    "path": p, "pin": sha} for n, p in SKILL_PATHS.items()],
        "mcp_servers": [m["name"] for m in MCPS],
    }


def main():
    print(f"TrueForge harness setup — {BASE_URL}")
    code, data = _get("/health")
    if code != 200:
        print(f"server not reachable at {BASE_URL} (got {code})",
              file=sys.stderr)
        return 2

    sha = current_head_sha()
    print(f"Pinning skills to current HEAD: {sha}\n")

    print("MCPs:")
    existing_mcps = list_mcps()
    for mcp in MCPS:
        if mcp["name"] in existing_mcps:
            print(f"  already exists: {mcp['name']}")
            continue
        register_mcp(mcp)

    print("\nSkills:")
    existing_skills = list_skills()
    for name, path in SKILL_PATHS.items():
        if name in existing_skills:
            print(f"  already exists: {name}")
            continue
        register_skill(name, path, sha)

    print("\nAgent:")
    manifest = build_agent_manifest(sha)
    existing_agents = list_agents()
    if "patchproof-v2" in existing_agents:
        print("  already exists: patchproof-v2 — updating")
    upsert_agent("patchproof-v2", manifest)

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
