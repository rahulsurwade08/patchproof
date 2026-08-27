"""Offline unit tests for the Python cve-feed MCP server port.

Network calls are never made: handlers are exercised through fakes, and the
JSON-RPC framing through pipes.
"""

import json
import os
import subprocess
import sys

import pytest

from agent.mcp import cve_feed_server as srv


# ---------------------------------------------------------------- summaries

def test_summarize_cve_prefers_cna_english_description():
    rec = {
        "cveMetadata": {"cveId": "CVE-1", "state": "PUBLISHED",
                        "datePublished": "2026-01-01T00:00:00Z"},
        "containers": {"cna": {"descriptions": [
            {"lang": "de", "value": "x"},
            {"lang": "en", "value": "english " * 100},
        ]}},
    }
    out = srv.summarize_cve(rec)
    assert out["id"] == "CVE-1" and out["state"] == "PUBLISHED"
    assert out["description"].startswith("english") and len(out["description"]) == 400


def test_summarize_cve_falls_back_to_adp():
    rec = {
        "cveMetadata": {"cveId": "CVE-2", "state": "REJECTED"},
        "containers": {"adp": [{"descriptions": [{"lang": "en", "value": "adp"}]}]},
    }
    assert srv.summarize_cve(rec)["description"] == "adp"


def test_summarize_osv_list_caps_at_ten():
    vulns = [{"id": f"OSV-{i}", "aliases": ["CVE-1"], "summary": "s" * 300}
             for i in range(15)]
    out = srv.summarize_osv_list(vulns)
    assert len(out) == 10
    assert out[0]["summary"] == "s" * 200
    assert out[0]["aliases"] == ["CVE-1"]


# ------------------------------------------------- handlers with fake HTTP

def test_cve_get_404(monkeypatch):
    monkeypatch.setattr(srv, "_http_json", lambda url, **kw: (404, None))
    assert srv.cve_get({"cveId": "CVE-X"}) == {"found": False}


def test_cve_get_server_error_raises(monkeypatch):
    monkeypatch.setattr(srv, "_http_json", lambda url, **kw: (500, None))
    with pytest.raises(RuntimeError):
        srv.cve_get({"cveId": "CVE-X"})


def test_cross_check_confirmed(monkeypatch):
    monkeypatch.setattr(srv, "cve_get", lambda a: {"found": True, "state": "PUBLISHED"})
    monkeypatch.setattr(srv, "osv_query_all", lambda a, max_pages=5: (
        [{"id": "GHSA-1", "aliases": ["CVE-1"], "summary": "y"},
         {"id": "GHSA-2", "aliases": [], "summary": "n"}], False))
    out = srv.cross_check({"cveId": "CVE-1", "ecosystem": "PyPI", "name": "pyyaml"})
    assert out["verdict"] == "CONFIRMED"
    assert out["osv_entry"]["id"] == "GHSA-1"


def test_cross_check_unknown_when_cve_missing(monkeypatch):
    monkeypatch.setattr(srv, "cve_get", lambda a: {"found": False})
    out = srv.cross_check({"cveId": "CVE-1", "ecosystem": "PyPI", "name": "x"})
    assert out["verdict"] == "UNKNOWN"


def test_cross_check_not_in_scope_when_osv_empty(monkeypatch):
    monkeypatch.setattr(srv, "cve_get", lambda a: {"found": True, "state": "PUBLISHED"})
    monkeypatch.setattr(srv, "osv_query_all", lambda a, max_pages=5: ([], False))
    out = srv.cross_check({"cveId": "CVE-1", "ecosystem": "PyPI", "name": "x"})
    assert out["verdict"] == "NOT_IN_SCOPE"
    assert out["osv_entries_checked"] == 0


def test_cross_check_unknown_when_osv_truncated(monkeypatch):
    monkeypatch.setattr(srv, "cve_get", lambda a: {"found": True, "state": "PUBLISHED"})

    def fake_page(query, page_token=None):
        return {"vulns": [{"id": "GHSA-x", "aliases": []}],
                "next_page_token": "still-more"}

    monkeypatch.setattr(srv, "osv_query_page", fake_page)
    out = srv.cross_check({"cveId": "CVE-1", "ecosystem": "PyPI", "name": "x"})
    assert out["verdict"] == "UNKNOWN"
    assert "truncated" in out["reason"]
    assert out["osv_entries_checked"] > 0


def test_identifiers_are_url_quoted(monkeypatch):
    captured = {}

    def fake_http(url, method="GET", body=None):
        captured["url"] = url
        return 200, {"cveMetadata": {"cveId": "CVE-1", "state": "PUBLISHED"},
                     "containers": {}}

    monkeypatch.setattr(srv, "_http_json", fake_http)
    srv.cve_get({"cveId": "CVE-2020../etc#fragment"})
    assert "#fragment" not in captured["url"]
    assert "CVE-2020..%2Fetc%23fragment" in captured["url"]


def test_osv_get_quotes_vuln_id(monkeypatch):
    captured = {}

    def fake_http(url, method="GET", body=None):
        captured["url"] = url
        return 200, {"id": "GHSA-1", "aliases": [], "summary": "", "affected": []}

    monkeypatch.setattr(srv, "_http_json", fake_http)
    srv.osv_get({"vulnId": "GHSA?a=b"})
    assert "GHSA%3Fa%3Db" in captured["url"]


def test_stdio_server_ignores_non_object_json():
    reqs = [
        json.dumps([1, 2, 3]) + "\n",      # valid JSON array: ignored
        '"just a string"\n',                # valid JSON string: ignored
        "42\n",                             # valid JSON number: ignored
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {}}) + "\n",
    ]
    proc = _spawn(reqs)
    assert proc.returncode == 0, proc.stderr[-300:]
    replies = [json.loads(l) for l in proc.stdout.strip().splitlines()]
    assert len(replies) == 1 and replies[0]["id"] == 1


def test_osv_query_all_follows_pagination(monkeypatch):
    pages = [
        {"vulns": [{"id": "A"}], "next_page_token": "t1"},
        {"vulns": [{"id": "B"}], "next_page_token": "t2"},
        {"vulns": [{"id": "C"}]},
    ]
    seen = []

    def fake(query, page_token=None):
        seen.append(page_token)
        return pages[len(seen) - 1]

    monkeypatch.setattr(srv, "osv_query_page", fake)
    vulns, truncated = srv.osv_query_all({"ecosystem": "PyPI", "name": "x"})
    assert [v["id"] for v in vulns] == ["A", "B", "C"]
    assert truncated is False
    assert seen == [None, "t1", "t2"]


# ------------------------------------------------------------ JSON-RPC wire

def test_dispatch_initialize_and_tools_list():
    init = srv.dispatch("initialize", {})
    assert init["protocolVersion"] == "2024-11-05"
    assert init["serverInfo"]["name"] == "patchproof-cve-feed"
    tools = srv.dispatch("tools/list", {})["tools"]
    assert {t["name"] for t in tools} == {
        "cve_get_cve", "osv_query_package", "osv_get_vuln", "cve_cross_check"}


def test_dispatch_unknown_tool_is_jsonrpc_error():
    with pytest.raises(RuntimeError) as exc:
        srv.dispatch("tools/call", {"name": "nope", "arguments": {}})
    assert exc.value.mcp_code == -32602


def test_dispatch_unknown_method():
    with pytest.raises(RuntimeError) as exc:
        srv.dispatch("resources/list", {})
    assert exc.value.mcp_code == -32601


def test_dispatch_tool_error_returns_is_error(monkeypatch):
    monkeypatch.setattr(srv, "cve_get",
                        lambda a: (_ for _ in ()).throw(RuntimeError("boom")))
    out = srv.dispatch("tools/call", {"name": "cve_get_cve",
                                      "arguments": {"cveId": "CVE-X"}})
    assert out["isError"] is True
    assert "boom" in out["content"][0]["text"]


def _spawn(proc_lines):
    env = dict(os.environ)
    proc = subprocess.run(
        [sys.executable, "agent/mcp/cve_feed_server.py"],
        input="".join(proc_lines), capture_output=True, text=True,
        timeout=30, env=env)
    return proc


def test_stdio_server_framing_end_to_end():
    """Offline end-to-end: initialize + tools/list + bad method over stdio."""
    reqs = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                    "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "bogus/x",
                    "params": {}}),
        "not json at all",              # must be ignored silently
        json.dumps({"jsonrpc": "2.0", "method": "notifications/none"}),  # no id
        "",
    ]
    proc = _spawn([r + "\n" for r in reqs])
    assert proc.returncode == 0
    replies = [json.loads(l) for l in proc.stdout.strip().splitlines()]
    assert [r["id"] for r in replies] == [1, 2, 3]
    assert replies[0]["result"]["protocolVersion"] == "2024-11-05"
    assert len(replies[1]["result"]["tools"]) == 4
    assert replies[2]["error"]["code"] == -32601
