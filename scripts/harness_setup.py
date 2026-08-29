#!/usr/bin/env python3
"""TrueForge harness setup — register MCPs, skills, and the patchproof-v2 agent.

Runs against a running TrueForge server (default http://[::1]:8790) and ensures
the harness wiring is in place per docs/custom-harness-build-plan.md step 3:
  - MCPs: local-sandbox (127.0.0.1:8081) and cve-feed (127.0.0.1:8091)
  - Skills: 7 PatchProof skills (analyzer, orchestrator, reproducer, judge,
    patcher, verifier, test-runner) as git-source skills, pinned to current HEAD
  - Agent: patchproof-v2 (SingleAgent mode) manifest with attached skills/MCPs

Idempotent: re-running reconciles existing skills/MCPs/agents to match the
expected configuration (updates drift in pin/repo/path/url). Safe to re-run
after server restart, schema evolution, or a new commit.

Pre-run checks: TrueForge, local-sandbox, and cve-feed must all be reachable
or the script exits non-zero (PR Compliance ID 2917052).
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
# Connectors the agent attaches but that are NOT created by this script
# (configured separately via catalog UI / OAuth, see docs/trueforge-setup.md).
ATTACHED_NOT_REGISTERED = ["github"]


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
        return 0, {"error": str(exc.reason)}


def _external_health(url):
    """Probe a non-TrueForge URL (MCP /health). Returns (ok, detail)."""
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status == 200, f"HTTP {resp.status}"
    except urllib.error.URLError as exc:
        return False, str(exc.reason)
    except Exception as exc:
        return False, str(exc)


def current_head_sha():
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True).strip()


def list_skills():
    code, data = _http("GET", "/api/v1/skills")
    if code != 200:
        return []
    return data.get("data", [])


def list_mcps():
    code, data = _http("GET", "/api/v1/mcp-servers")
    if code != 200:
        return []
    return data.get("data", [])


def list_agents():
    code, data = _http("GET", "/api/v1/agents")
    if code != 200:
        return []
    return data.get("data", [])


def find_skill(skills, name):
    for s in skills:
        if s.get("name") == name:
            return s
    return None


def find_mcp(mcps, name):
    for m in mcps:
        if m.get("name") == name:
            return m
    return None


def find_agent(agents, name):
    for a in agents:
        if a.get("name") == name:
            return a
    return None


def register_mcp(mcp):
    """Register or update an MCP. Returns True on success (including 409 exists)."""
    manifest = {"type": "remote", **mcp}
    name = mcp["name"]
    existing = find_mcp(list_mcps(), name)
    if existing:
        if existing.get("url") == mcp["url"]:
            print(f"  already exists: {name}")
            return True
        # URL drift: update via PUT on the existing record's id
        mid = existing.get("id")
        if not mid:
            print(f"  FAIL {name}: existing record has no id", file=sys.stderr)
            return False
        code, data = _http("PUT", f"/api/v1/mcp-servers/{mid}", {"manifest": manifest})
        if code in (200, 201):
            print(f"  updated MCP: {name}")
            return True
        print(f"  FAIL update {name}: {code} {data}", file=sys.stderr)
        return False
    code, data = _http("POST", "/api/v1/mcp-servers", {"manifest": manifest})
    if code in (200, 201):
        print(f"  registered MCP: {name}")
        return True
    print(f"  FAIL register {name}: {code} {data}", file=sys.stderr)
    return False


def register_skill(name, path, sha):
    """Register or update a skill (reconciles pin/repo/path). Returns True on success."""
    body = {
        "type": "git",
        "name": name,
        "repo": SKILL_REPO,
        "path": path,
        "pin": sha,
    }
    existing = find_skill(list_skills(), name)
    if existing:
        if (existing.get("pin") == sha
                and existing.get("repo") == SKILL_REPO
                and existing.get("path") == path):
            print(f"  already exists: {name}")
            return True
        sid = existing.get("id")
        if not sid:
            print(f"  FAIL {name}: existing record has no id", file=sys.stderr)
            return False
        code, data = _http("PUT", f"/api/v1/skills/{sid}", body)
        if code in (200, 201):
            print(f"  updated skill: {name} @ {sha[:8]}")
            return True
        print(f"  FAIL update {name}: {code} {data}", file=sys.stderr)
        return False
    code, data = _http("POST", "/api/v1/skills", body)
    if code in (200, 201):
        print(f"  registered skill: {name} @ {sha[:8]}")
        return True
    print(f"  FAIL register {name}: {code} {data}", file=sys.stderr)
    return False


def upsert_agent(name, manifest):
    """Create or update the agent via the immutable-ID PUT endpoint."""
    existing = find_agent(list_agents(), name)
    if existing:
        aid = existing.get("id")
        if not aid:
            print(f"  FAIL {name}: existing record has no id", file=sys.stderr)
            return False
        code, data = _http("PUT", f"/api/v1/agents/{aid}", {"manifest": manifest})
        if code in (200, 201):
            print(f"  agent updated: {name}")
            return True
        print(f"  FAIL update {name}: {code} {data}", file=sys.stderr)
        return False
    code, data = _http("POST", "/api/v1/agents", {"name": name, "manifest": manifest})
    if code in (200, 201):
        print(f"  agent created: {name}")
        return True
    print(f"  FAIL create {name}: {code} {data}", file=sys.stderr)
    return False


def build_agent_manifest(sha):
    # sandbox.enabled: true activates TrueForge's built-in sandbox provider
    # for skill materialization and file_downloads (artifacts). Exploit
    # execution stays on the local-sandbox MCP (--network none), so the
    # built-in provider is only used to materialize skills and download
    # `verdict.json` / `reachability.json` / `assessment.json` artifacts.
    return {
        "mode": "SingleAgent",
        "name": "patchproof-v2",
        "sandbox": {"enabled": True, "file_downloads": True},
        "file_downloads": True,
        "skills": [{"type": "git", "name": n, "repo": SKILL_REPO,
                    "path": p, "pin": sha} for n, p in SKILL_PATHS.items()],
        "mcp_servers": [{"name": m["name"]} for m in MCPS]
                        + [{"name": n} for n in ATTACHED_NOT_REGISTERED],
    }


def check_endpoints():
    """PR Compliance ID 2917052: validate all three endpoints before continuing."""
    ok, detail = _external_health(f"{BASE_URL}/health")
    if not ok:
        print(f"TrueForge unreachable at {BASE_URL}: {detail}", file=sys.stderr)
        return False
    print(f"TrueForge OK: {BASE_URL}/health")
    for mcp in MCPS:
        ok, detail = _external_health(f"{mcp['url'].rsplit('/', 1)[0]}/health")
        if not ok:
            print(f"MCP unreachable: {mcp['name']} at {mcp['url']}: {detail}",
                  file=sys.stderr)
            return False
        print(f"MCP OK: {mcp['name']} at {mcp['url']}")
    return True


def main():
    print(f"TrueForge harness setup — {BASE_URL}")
    if not check_endpoints():
        return 2

    sha = current_head_sha()
    print(f"Pinning skills to current HEAD: {sha}\n")

    failures = 0

    print("MCPs:")
    for mcp in MCPS:
        if not register_mcp(mcp):
            failures += 1

    print("\nSkills:")
    for name, path in SKILL_PATHS.items():
        if not register_skill(name, path, sha):
            failures += 1

    print("\nAgent:")
    manifest = build_agent_manifest(sha)
    if not upsert_agent("patchproof-v2", manifest):
        failures += 1

    if failures:
        print(f"\nDone with {failures} failure(s).", file=sys.stderr)
        return 1
    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
