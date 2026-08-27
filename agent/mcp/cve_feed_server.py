#!/usr/bin/env python3
"""Dual-source CVE legitimacy server: CVE.org (canonical record) + OSV.dev
(affected package/version ranges). Both APIs are public and keyless.

Tools:
  cve_get_cve       -- canonical record for one CVE id (cveawg.mitre.org)
  osv_query_package -- vulns matching ecosystem/package[/version] (api.osv.dev)
  osv_get_vuln      -- full OSV record for one OSV/CVE id
  cve_cross_check   -- confirm a CVE in BOTH sources in one call

Speaks newline-delimited JSON-RPC 2.0 on stdio (MCP stdio transport).
No dependencies; Python >= 3.9 (stdlib urllib).

This is the Python port of agent/mcp/cve-feed-server/index.mjs (ADR-011):
identical tool contracts, responses, and error semantics.
"""

import json
import sys
import urllib.request

CVE_API = "https://cveawg.mitre.org/api/cve"
OSV_API = "https://api.osv.dev/v1"

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "patchproof-cve-feed", "version": "0.1.0"}

TOOLS = [
    {
        "name": "cve_get_cve",
        "description": (
            "Fetch the canonical CVE.org record for one CVE id: confirms it "
            "exists, its state (PUBLISHED/REJECTED), description, and "
            "published date."),
        "inputSchema": {
            "type": "object",
            "properties": {"cveId": {"type": "string"}},
            "required": ["cveId"],
        },
    },
    {
        "name": "osv_query_package",
        "description": (
            "Query OSV.dev for vulnerabilities affecting an ecosystem "
            "package, optionally at one version. Returns compact summaries "
            "with affected ranges."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ecosystem": {"type": "string", "description": "e.g. PyPI, npm"},
                "name": {"type": "string", "description": "package name, e.g. pyyaml"},
                "version": {"type": "string", "description": "optional version, e.g. 5.3.1"},
            },
            "required": ["ecosystem", "name"],
        },
    },
    {
        "name": "osv_get_vuln",
        "description": (
            "Fetch the full OSV.dev record for one vulnerability id "
            "(OSV id or CVE id)."),
        "inputSchema": {
            "type": "object",
            "properties": {"vulnId": {"type": "string"}},
            "required": ["vulnId"],
        },
    },
    {
        "name": "cve_cross_check",
        "description": (
            "Legitimacy check across both sources for one CVE against an "
            "ecosystem package. Verdict CONFIRMED: CVE.org has it PUBLISHED "
            "and OSV lists it for that package. Verdict NOT_IN_SCOPE: CVE is "
            "real but OSV has no entry for that package/version. Verdict "
            "UNKNOWN: CVE.org has no such id."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cveId": {"type": "string"},
                "ecosystem": {"type": "string"},
                "name": {"type": "string"},
                "version": {"type": "string"},
            },
            "required": ["cveId", "ecosystem", "name"],
        },
    },
]


def _http_json(url, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, None


def summarize_cve(rec):
    """Compact CVE record: id, state, published, first English description."""
    desc = ""
    cna = ((rec.get("containers") or {}).get("cna") or {})
    for d in cna.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value") or ""
            break
    if not desc:
        adp = (rec.get("containers") or {}).get("adp") or []
        for c in adp:
            for d in c.get("descriptions") or []:
                if d.get("lang") == "en":
                    desc = d.get("value") or ""
                    break
            if desc:
                break
    meta = rec.get("cveMetadata") or {}
    return {
        "id": meta.get("cveId"),
        "state": meta.get("state"),
        "published": meta.get("datePublished"),
        "description": desc[:400],
    }


def cve_get(args):
    status, body = _http_json(f"{CVE_API}/{args['cveId']}")
    if status == 404:
        return {"found": False}
    if status != 200:
        raise RuntimeError(f"CVE.org API {status}")
    return {"found": True, **summarize_cve(body)}


def osv_query_page(query, page_token=None):
    body = {**query, "page_token": page_token} if page_token else query
    status, resp = _http_json(f"{OSV_API}/query", method="POST", body=body)
    if status != 200:
        raise RuntimeError(f"OSV API {status}")
    return resp or {}


def summarize_osv_list(vulns):
    """Display helper: compact, capped list for osv_query_package."""
    return [
        {"id": v.get("id"), "aliases": v.get("aliases") or [],
         "summary": (v.get("summary") or "")[:200]}
        for v in vulns[:10]
    ]


def osv_query(args):
    query = {"package": {"ecosystem": args["ecosystem"], "name": args["name"]}}
    if args.get("version"):
        query["version"] = args["version"]
    return summarize_osv_list(osv_query_page(query).get("vulns") or [])


def osv_query_all(args, max_pages=5):
    """Full traversal for legitimacy decisions: follow pagination up to a
    sane cap so a truncated result can never produce a false NOT_IN_SCOPE."""
    query = {"package": {"ecosystem": args["ecosystem"], "name": args["name"]}}
    if args.get("version"):
        query["version"] = args["version"]
    all_vulns = []
    page_token = None
    for _ in range(max_pages):
        body = osv_query_page(query, page_token)
        all_vulns.extend(body.get("vulns") or [])
        page_token = body.get("next_page_token")
        if not page_token:
            break
    return all_vulns


def osv_get(args):
    status, v = _http_json(f"{OSV_API}/vulns/{args['vulnId']}")
    if status == 404:
        return {"found": False}
    if status != 200:
        raise RuntimeError(f"OSV API {status}")
    return {
        "id": v.get("id"),
        "aliases": v.get("aliases") or [],
        "summary": (v.get("summary") or "")[:300],
        "affected": [
            {"package": a.get("package"), "ranges": a.get("ranges") or []}
            for a in v.get("affected") or []
        ],
    }


def cross_check(args):
    cve = cve_get({"cveId": args["cveId"]})
    if not cve.get("found") or cve.get("state") != "PUBLISHED":
        return {"verdict": "UNKNOWN", "cve": cve}
    osv = osv_query_all({
        "ecosystem": args["ecosystem"],
        "name": args["name"],
        "version": args.get("version"),
    })
    for v in osv:
        if args["cveId"] in [v.get("id"), *(v.get("aliases") or [])]:
            return {
                "verdict": "CONFIRMED",
                "cve": cve,
                "osv_entry": {
                    "id": v.get("id"),
                    "aliases": v.get("aliases") or [],
                    "summary": (v.get("summary") or "")[:200],
                },
            }
    return {"verdict": "NOT_IN_SCOPE", "cve": cve, "osv_entries_checked": len(osv)}


def dispatch(method, params):
    if method == "initialize":
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = (params or {}).get("name")
        args = (params or {}).get("arguments") or {}
        if not any(t["name"] == name for t in TOOLS):
            error = RuntimeError(f"unknown tool: {name}")
            error.mcp_code = -32602
            raise error
        try:
            if name == "cve_get_cve":
                result = cve_get(args)
            elif name == "osv_query_package":
                result = osv_query(args)
            elif name == "osv_get_vuln":
                result = osv_get(args)
            else:
                result = cross_check(args)
        except Exception as exc:  # tool execution failure: flag as isError
            return {
                "content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True,
            }
        return {"content": [{"type": "text",
                             "text": json.dumps(result, indent=2)}]}
    error = RuntimeError(f"method not supported: {method}")
    error.mcp_code = -32601
    raise error


def _send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") is None:
            continue  # notifications: ignore
        try:
            result = dispatch(msg.get("method"), msg.get("params") or {})
            _send({"jsonrpc": "2.0", "id": msg["id"], "result": result})
        except Exception as exc:
            _send({
                "jsonrpc": "2.0",
                "id": msg["id"],
                "error": {"code": getattr(exc, "mcp_code", -32603),
                          "message": str(exc)},
            })


if __name__ == "__main__":
    main()
