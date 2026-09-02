#!/usr/bin/env python3
"""Dual-source CVE legitimacy server: CVE.org (canonical record) + OSV.dev
(affected package/version ranges). Both APIs are public and keyless.

Tools:
  cve_get_cve       -- canonical record for one CVE id (cveawg.mitre.org)
  osv_query_package -- vulns matching ecosystem/package[/version] (api.osv.dev)
  osv_get_vuln      -- full OSV record for one OSV/CVE id
  cve_cross_check   -- confirm a CVE in BOTH sources in one call

Transport: MCP Streamable HTTP (POST JSON-RPC at /mcp, JSON responses).
No dependencies; Python >= 3.9. Register as a remote-URL MCP server with your
harness (e.g. OpenCode MCP config).
"""

import json
import os
import sys
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CVE_API = "https://cveawg.mitre.org/api/cve"
OSV_API = "https://api.osv.dev/v1"

PORT = int(os.environ.get("CVE_FEED_PORT", "8091"))
MAX_BODY_BYTES = 1024 * 1024
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
        "annotations": {"readOnlyHint": True},
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
        "annotations": {"readOnlyHint": True},
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
        "annotations": {"readOnlyHint": True},
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
        "annotations": {"readOnlyHint": True},
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
    cve_id = urllib.parse.quote(args["cveId"], safe="")
    status, body = _http_json(f"{CVE_API}/{cve_id}")
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
    """Display helper: full list for osv_query_package (no silent truncation).

    Returns all vulns, each trimmed to a compact display shape. The 10-item
    cap was removed because PatchProof triage needs the COMPLETE CVE list —
    a silent cap at 10 hid real vulnerabilities (e.g. jinja2 had 12 CVEs,
    aiohttp had 89 — the user only saw 6 and 10).
    """
    return [
        {"id": v.get("id"), "aliases": v.get("aliases") or [],
         "summary": (v.get("summary") or "")[:200]}
        for v in vulns
    ]


def osv_query(args):
    query = {"package": {"ecosystem": args["ecosystem"], "name": args["name"]}}
    if args.get("version"):
        query["version"] = args["version"]
    # Use osv_query_all so the result is the full set across pages, not just
    # the first page (OSV paginates large result sets; the first page has
    # ~10 entries by default).
    vulns, truncated = osv_query_all(args, max_pages=10)
    result = summarize_osv_list(vulns)
    if truncated:
        result = {"vulns": result,
                  "truncated": True,
                  "note": ("OSV result set exceeds 10 pages; some CVEs may "
                           "not be listed. Use osv_get_vuln to check a "
                           "specific CVE id.")}
    return result


def osv_query_all(args, max_pages=5):
    """Full traversal for legitimacy decisions. Returns (vulns, truncated):
    truncated is True when pages remain beyond the cap, so a match on a
    later page can never be misclassified as NOT_IN_SCOPE."""
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
            return all_vulns, False
    return all_vulns, True


def osv_get(args):
    vuln_id = urllib.parse.quote(args["vulnId"], safe="")
    status, v = _http_json(f"{OSV_API}/vulns/{vuln_id}")
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
    vulns, truncated = osv_query_all({
        "ecosystem": args["ecosystem"],
        "name": args["name"],
        "version": args.get("version"),
    }, max_pages=10)
    for v in vulns:
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
    if truncated:
        return {"verdict": "UNKNOWN",
                "reason": (f"osv results truncated at the page cap with "
                           f"{len(vulns)} entries checked; a match on a later "
                           f"page cannot be ruled out"),
                "cve": cve, "osv_entries_checked": len(vulns)}
    return {"verdict": "NOT_IN_SCOPE", "cve": cve, "osv_entries_checked": len(vulns)}


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
        except Exception as exc:
            return {
                "content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True,
            }
        return {"content": [{"type": "text",
                             "text": json.dumps(result, indent=2)}]}
    error = RuntimeError(f"method not supported: {method}")
    error.mcp_code = -32601
    raise error


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, obj=None, close=False):
        if obj is None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            if close:
                self.close_connection = True
                self.send_header("Connection", "close")
            self.end_headers()
            return
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.close_connection = True
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urllib.parse.urlparse(self.path).path == "/health":
            return self._send(200, {"ok": True})
        # Close the keep-alive connection: a bare 404 leaves no framing
        # delimiter, so a persistent client can hang waiting for the
        # response to end.
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()

    def do_POST(self):
        if not urllib.parse.urlparse(self.path).path.startswith("/mcp"):
            # Close the keep-alive connection: a 405 with no body
            # delimiter can leave the request body unread on the next
            # request, desynchronizing the stream.
            self.send_response(405)
            self.send_header("Allow", "POST")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length < 0 or length > MAX_BODY_BYTES:
                # Reject without reading the body and close the connection:
                # leaving the bytes unread on a keep-alive socket would be
                # parsed as the next request (protocol desync).
                self.close_connection = True
                return self._send(413, {"jsonrpc": "2.0", "id": None,
                                        "error": {"code": -32700,
                                                  "message": "request body exceeds 1 MiB"}},
                                  close=True)
            body = self.rfile.read(length)
            msg = json.loads(body.decode())
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            # Close the connection on parse error: the next request on a
            # keep-alive socket would otherwise consume trailing bytes.
            self.close_connection = True
            return self._send(400, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700,
                                              "message": "parse error"}},
                              close=True)
        if not isinstance(msg, dict):
            self.close_connection = True
            return self._send(400, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700,
                                              "message": "parse error"}},
                              close=True)
        req_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        try:
            if method == "initialize":
                return self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO}})
            if method == "notifications/initialized":
                return self._send(202)
            if method == "ping":
                return self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": {}})
            if method == "tools/list":
                return self._send(200, {"jsonrpc": "2.0", "id": req_id,
                                        "result": {"tools": TOOLS}})
            if method == "tools/call":
                name = (params or {}).get("name")
                args = (params or {}).get("arguments") or {}
                if not any(t["name"] == name for t in TOOLS):
                    return self._send(200, {"jsonrpc": "2.0", "id": req_id,
                                            "error": {"code": -32602,
                                                      "message": f"unknown tool: {name}"}})
                try:
                    result = dispatch(method, {"name": name, "arguments": args})
                except Exception as tool_err:
                    return self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": {
                        "content": [{"type": "text",
                                     "text": f"error: {tool_err}"}],
                        "isError": True}})
                return self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": result})
            return self._send(200, {"jsonrpc": "2.0", "id": req_id,
                                    "error": {"code": -32601,
                                              "message": f"method not supported: {method}"}})
        except Exception as err:
            return self._send(200, {"jsonrpc": "2.0", "id": req_id,
                                    "error": {"code": -32603,
                                              "message": str(err)}})

    def log_message(self, fmt, *args):
        pass


def main():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"cve-feed MCP listening on http://127.0.0.1:{PORT}/mcp "
          f"(request-id: {uuid.uuid4().hex[:8]})", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
