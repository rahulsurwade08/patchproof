"""MCP JSON-RPC client — minimal Streamable HTTP transport."""
import json
import urllib.request

_initialized_urls = set()


def _post(url, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"},
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read()


def _unwrap_content(result):
    if isinstance(result, dict) and "content" in result:
        for item in result["content"]:
            if item.get("type") == "text":
                try:
                    return json.loads(item["text"])
                except (json.JSONDecodeError, TypeError):
                    return item["text"]
    return result


def _extract_result(raw):
    # Plain JSON (most MCP responses)
    try:
        d = json.loads(raw)
        if "error" in d:
            raise RuntimeError(f"MCP error: {d['error']}")
        return _unwrap_content(d.get("result"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    # SSE: data: lines
    result = None
    for line in raw.decode(errors="replace").split("\n"):
        if line.startswith("data: "):
            d = json.loads(line[6:])
            if "error" in d:
                raise RuntimeError(f"MCP error: {d['error']}")
            if "result" in d:
                result = _unwrap_content(d["result"])
    return result


def mcp_init(url):
    if url in _initialized_urls:
        return
    _extract_result(_post(url, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05",
                   "capabilities": {},
                   "clientInfo": {"name": "checkexploit-client", "version": "0.1"}}},
    ))
    _initialized_urls.add(url)


def mcp_call(url, method, params):
    if method != "initialize":
        mcp_init(url)
    return _extract_result(_post(url, {
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    }))
