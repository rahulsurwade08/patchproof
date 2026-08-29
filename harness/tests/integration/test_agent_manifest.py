"""Integration test for the patchproof-v2 agent manifest.

Exercises the live TrueForge server: GET /api/v1/agents lists the
patchproof-v2 manifest; the manifest's mcp_servers, skills, and approval
policy match the spec in docs/custom-harness-build-plan.md §4 and §5.

All three required services (TrueForge + local-sandbox + cve-feed) must be
reachable. If any is missing the suite is skipped (with reason).  If the
agent is absent or the manifest deviates, the suite fails (not skips).
"""
import json
import os
import urllib.error
import urllib.request

import pytest

BASE_URL = os.environ.get("TRUEFORGE_URL", "http://[::1]:8790")
EXPECTED_SKILLS = {
    "analyzer", "orchestrator", "reproducer", "judge",
    "patcher", "verifier", "test-runner",
}


def _http_get(path):
    req = urllib.request.Request(f"{BASE_URL}{path}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.URLError:
        return 0, {}


def _trueforge_reachable():
    code, _ = _http_get("/api/v1/capabilities")
    return code == 200


def _service_reachable(url):
    data = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1}).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _check_prerequisites():
    """Verify all required services are reachable before running tests."""
    failures = []
    if not _trueforge_reachable():
        failures.append(f"TrueForge not reachable at {BASE_URL}")
    if not _service_reachable("http://127.0.0.1:8081/mcp"):
        failures.append("local-sandbox not reachable at http://127.0.0.1:8081/mcp")
    if not _service_reachable("http://127.0.0.1:8091/mcp"):
        failures.append("cve-feed not reachable at http://127.0.0.1:8091/mcp")
    return failures


def _get_patchproof_v2_manifest():
    code, data = _http_get("/api/v1/agents")
    if code != 200:
        pytest.fail(f"GET /api/v1/agents returned {code}")
    for agent in data.get("data", []):
        if agent.get("name") == "patchproof-v2":
            return agent.get("manifest", {})
    pytest.fail("patchproof-v2 agent not registered; run scripts/harness_setup.py")


pytestmark = pytest.mark.skipif(
    _check_prerequisites() != [],
    reason="required services unreachable (TrueForge + local-sandbox + cve-feed)",
)


def test_agent_model_required():
    m = _get_patchproof_v2_manifest()
    assert m.get("model", {}).get("name"), "agent manifest must declare model.name"


def test_sandbox_enabled_with_file_downloads():
    m = _get_patchproof_v2_manifest()
    sandbox = m.get("config", {}).get("sandbox", {})
    assert sandbox.get("enabled") is False, (
        "config.sandbox.enabled must be False — TrueForge's built-in provider is "
        "paid and unconfigured; all execution routes through local-sandbox MCP"
    )
    assert sandbox.get("file_downloads") is True


def test_skills_attach_all_seven():
    m = _get_patchproof_v2_manifest()
    skills = m.get("skills", [])
    names = {s.get("name") for s in skills}
    assert names == EXPECTED_SKILLS, f"expected all 7 skills; got {names}"


def test_mcp_attachments_local_sandbox_gates_exploit_tools():
    m = _get_patchproof_v2_manifest()
    by_name = {s.get("name"): s for s in m.get("mcp_servers", [])}
    assert "local-sandbox" in by_name
    approval = by_name["local-sandbox"].get("require_approval_for_tools", [])
    assert set(approval) == {
        "sandbox_build", "sandbox_exec",
        "sandbox_write", "sandbox_read", "sandbox_pull",
    }
    assert "sandbox_stop" not in approval


def test_mcp_attachments_cve_feed_default_policy():
    m = _get_patchproof_v2_manifest()
    by_name = {s.get("name"): s for s in m.get("mcp_servers", [])}
    assert "cve-feed" in by_name
    approval = by_name["cve-feed"].get("require_approval_for_tools", [])
    assert approval == ["@write", "@destructive"]


def test_mcp_attachments_github_included():
    m = _get_patchproof_v2_manifest()
    names = {s.get("name") for s in m.get("mcp_servers", [])}
    assert "github" in names


def test_mcp_attachments_have_no_preload():
    m = _get_patchproof_v2_manifest()
    for s in m.get("mcp_servers", []):
        assert s.get("preload", False) is False, s.get("name")
