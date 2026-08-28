"""Offline unit tests for the Python local-sandbox MCP server port.

No Docker daemon and no network bind required: the HTTP surface is exercised
through a real server on an ephemeral port with the docker layer monkeypatched,
and redaction/hashing through direct calls.
"""

import json
import threading
import urllib.error
import urllib.request

import pytest

from agent.mcp import local_sandbox_server as srv


# ---------------------------------------------------------------- redaction

def test_redact_strips_known_credential_shapes():
    text = ("sk-or-v1-abcdef1234567890 ghp_" + "a" * 25
            + " github_pat_" + "b" * 25 + " dtn_abc12345678 "
            + "Authorization: Bearer abcdefghijklmnop"
            + " api_key='supersecretvalue123'")
    out = srv.redact(text)
    assert "sk-or-v1-abcdef" not in out
    assert "ghp_" + "a" * 25 not in out
    assert "github_pat_" + "b" * 25 not in out
    assert "dtn_abc12345678" not in out
    assert "abcdefghijklmnop" not in out
    assert "supersecretvalue123" not in out
    assert "<redacted>" in out


def test_container_name_hashes_raw_label():
    a = srv.container_name("s01")
    b = srv.container_name("s01 ")
    c = srv.container_name("s01")
    assert a == c and a != b
    assert a.startswith("patchproof-sbx-")


def test_tool_registry():
    names = {t["name"] for t in srv.TOOLS}
    assert names == {"sandbox_build", "sandbox_exec", "sandbox_write",
                     "sandbox_read", "sandbox_stop"}


def test_unknown_tool_raises():
    with pytest.raises(RuntimeError):
        srv.tool_call("nope", {})


def test_sandbox_write_passes_path_as_argv(monkeypatch):
    """Write must not interpolate the path into a shell string."""
    captured = {}

    def fake_docker(args, timeout_ms=120000, input_text=None):
        captured["args"] = args
        captured["input"] = input_text
        if "Running" in " ".join(args):
            return {"code": 0, "stdout": "true\n", "stderr": ""}
        return {"code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(srv, "docker", fake_docker)
    out = srv.tool_call("sandbox_write", {"session": "s", "path": "/srv/p'x",
                                          "content": "hi"})
    assert out["written"] == "/srv/p'x" and out["bytes"] == 2
    # the path travels as an argv element, not inside the sh -c string
    assert "/srv/p'x" not in captured["args"][5]
    assert captured["args"][-1] == "/srv/p'x"
    assert captured["input"] == "hi"


def test_sandbox_write_failure_raises(monkeypatch):
    monkeypatch.setattr(srv, "docker", lambda *a, **k: {
        "code": 1, "stdout": "", "stderr": "no space"})
    with pytest.raises(RuntimeError):
        srv.tool_call("sandbox_write", {"session": "s", "path": "/x",
                                        "content": ""})


def test_ensure_container_recreates_on_image_mismatch(monkeypatch):
    calls = []

    def fake_docker(args, timeout_ms=120000, input_text=None):
        calls.append(args)
        joined = " ".join(args)
        if joined.startswith("inspect"):
            if "Running" in joined:
                return {"code": 0, "stdout": "true\n", "stderr": ""}
            return {"code": 0,
                    "stdout": "patchproof-old|\n", "stderr": ""}  # wrong image
        return {"code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(srv, "docker", fake_docker)
    name = srv.ensure_container("s", "none", "patchproof-new")
    assert name == srv.container_name("s")
    assert any(a[:2] == ["rm", "-f"] for a in calls)
    assert any(a[:3] == ["run", "--rm", "-d"] and "patchproof-new" in a
               and "while :; do sleep 3600; done" in a for a in calls)


def test_ensure_container_reuses_matching(monkeypatch):
    calls = []

    def fake_docker(args, timeout_ms=120000, input_text=None):
        calls.append(args)
        joined = " ".join(args)
        if "Running" in joined:
            return {"code": 0, "stdout": "true\n", "stderr": ""}
        if "Config.Image" in joined:
            return {"code": 0, "stdout": "patchproof-ok|\n", "stderr": ""}
        return {"code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(srv, "docker", fake_docker)
    srv.ensure_container("s", "none", "patchproof-ok")
    assert not any(a[:2] == ["rm", "-f"] for a in calls)


def test_runtime_container_rejects_named_network(monkeypatch):
    monkeypatch.setattr(srv, "docker",
                        lambda *a, **k: {"code": 0, "stdout": "", "stderr": ""})
    with pytest.raises(RuntimeError):
        srv.tool_call("sandbox_exec", {"session": "s", "command": "ls",
                                       "network": "infra_default"})


def test_named_network_rejected_even_on_reuse(monkeypatch):
    """A leftover network-connected container must never be reused."""
    called = {"inspect": False}

    def fake_docker(args, timeout_ms=120000, input_text=None):
        called["inspect"] = True
        return {"code": 0, "stdout": "true\\n", "stderr": ""}

    monkeypatch.setattr(srv, "docker", fake_docker)
    with pytest.raises(RuntimeError):
        srv.ensure_container("s", "infra_default", srv.IMAGE)
    assert not called["inspect"]  # rejected before any reuse check


def test_build_allows_dot_prefixed_filenames(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.11-slim\n")
    captured = {}

    def fake_docker(args, timeout_ms=120000, input_text=None):
        ctx = args[-1]
        captured["env"] = open(ctx + "/..env").read()
        return {"code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(srv, "docker", fake_docker)
    srv.tool_call("sandbox_build", {
        "tag": "t", "context_path": str(tmp_path), "files": {"..env": "A=1"}})
    assert captured["env"] == "A=1"


def test_runtime_container_defaults_apply(monkeypatch):
    seen = {}

    def fake_ensure(session, network, image):
        seen["network"], seen["image"] = network, image
        return srv.container_name(session)

    monkeypatch.setattr(srv, "ensure_container", fake_ensure)
    monkeypatch.setattr(srv, "docker",
                        lambda *a, **k: {"code": 0, "stdout": "", "stderr": ""})
    srv.tool_call("sandbox_exec", {"session": "s", "command": "ls"})
    assert seen["network"] == "none" and seen["image"] == srv.IMAGE


def test_build_rejects_path_traversal_overrides(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.11-slim\n")
    monkeypatch.setattr(srv, "docker",
                        lambda *a, **k: {"code": 0, "stdout": "", "stderr": ""})
    for rel in ("../evil.txt", "/etc/cron.d/evil", "a/../../evil"):
        with pytest.raises(RuntimeError):
            srv.tool_call("sandbox_build", {
                "tag": "t", "context_path": str(tmp_path), "files": {rel: "x"}})
    assert not (tmp_path.parent / "evil.txt").exists()


def test_timeout_returns_124_not_crash(monkeypatch):
    import subprocess as sp

    def fake_run(*a, **k):
        raise sp.TimeoutExpired(cmd=a[0], timeout=1,
                                output=b"partial-out", stderr=b"partial-err")

    monkeypatch.setattr(srv.subprocess, "run", fake_run)
    out = srv.docker(["exec", "x"])
    assert out["code"] == 124
    assert out["stdout"] == "partial-out"
    assert "timed out" in out["stderr"]


def test_build_applies_files_overrides_to_temp_copy(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.11-slim\n")
    (tmp_path / "requirements.lock").write_text("pyyaml==3.13\n")
    captured = {}

    def fake_docker(args, timeout_ms=120000, input_text=None):
        captured["args"] = args
        ctx = args[-1]
        captured["lock"] = open(ctx + "/requirements.lock").read()
        captured["dockerfile"] = open(ctx + "/Dockerfile").read()
        return {"code": 0, "stdout": "built\n", "stderr": ""}

    monkeypatch.setattr(srv, "docker", fake_docker)
    out = srv.tool_call("sandbox_build", {
        "tag": "t1", "context_path": str(tmp_path),
        "files": {"requirements.lock": "pyyaml==5.4\n"}})
    assert out["exit_code"] == 0
    build_ctx = captured["args"][-1]
    assert build_ctx != str(tmp_path)  # temp copy
    # the override was readable by the build (captured before cleanup)
    assert captured["lock"] == "pyyaml==5.4\n"
    assert captured["dockerfile"].startswith("FROM")


def test_build_passes_dockerfile_flag(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile.app").write_text("FROM python:3.9-slim\n")
    captured = {}

    def fake_docker(args, timeout_ms=120000, input_text=None):
        captured["args"] = args
        return {"code": 0, "stdout": "built\n", "stderr": ""}

    monkeypatch.setattr(srv, "docker", fake_docker)
    srv.tool_call("sandbox_build", {"tag": "t", "context_path": str(tmp_path),
                                    "dockerfile": "Dockerfile.app"})
    a = captured["args"]
    assert a[a.index("-f") + 1] == "Dockerfile.app"


def test_build_rejects_escaping_dockerfile(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.9-slim\n")
    monkeypatch.setattr(srv, "docker",
                        lambda *a, **k: {"code": 0, "stdout": "", "stderr": ""})
    with pytest.raises(RuntimeError):
        srv.tool_call("sandbox_build", {"tag": "t", "context_path": str(tmp_path),
                                        "dockerfile": "../evil/Dockerfile"})
    with pytest.raises(RuntimeError):
        srv.tool_call("sandbox_build", {"tag": "t", "context_path": str(tmp_path),
                                        "dockerfile": "/etc/Dockerfile"})
    # in-context symlink resolving OUTSIDE the context is rejected
    os.symlink("/etc/passwd", tmp_path / "Dockerfile.link")
    with pytest.raises(RuntimeError):
        srv.tool_call("sandbox_build", {"tag": "t", "context_path": str(tmp_path),
                                        "dockerfile": "Dockerfile.link"})


def test_build_rejects_missing_dockerfile(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.9-slim\n")
    monkeypatch.setattr(srv, "docker",
                        lambda *a, **k: {"code": 0, "stdout": "", "stderr": ""})
    with pytest.raises(RuntimeError):
        srv.tool_call("sandbox_build", {"tag": "t", "context_path": str(tmp_path),
                                        "dockerfile": "Dockerfile.app"})


# --------------------------------------------------------- HTTP via server

@pytest.fixture(scope="module")
def http_server():
    _orig_docker, _orig_tool_call = srv.docker, srv.tool_call
    srv.docker = lambda *a, **k: {"code": 0, "stdout": "", "stderr": ""}
    srv.register_shutdown_cleanup()
    assert srv.cleanup_all_containers() == 0
    server = srv.ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    srv.docker, srv.tool_call = _orig_docker, _orig_tool_call


def _post(base, payload, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode()
    req = urllib.request.Request(base + "/mcp", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def test_http_health(http_server):
    with urllib.request.urlopen(http_server + "/health", timeout=5) as resp:
        assert json.loads(resp.read().decode()) == {"ok": True}


def test_http_initialize_and_tools_list(http_server):
    status, body = _post(http_server, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26"}})
    assert status == 200
    assert body["result"]["serverInfo"]["name"] == "patchproof-local-sandbox"
    status, body = _post(http_server, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert len(body["result"]["tools"]) == 5


def test_http_unknown_tool_is_jsonrpc_error(http_server):
    status, body = _post(http_server, {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "nope", "arguments": {}}})
    assert body["error"]["code"] == -32602


def test_http_unknown_method(http_server):
    status, body = _post(http_server, {
        "jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}})
    assert body["error"]["code"] == -32601


def test_http_parse_error(http_server):
    status, body = _post(http_server, None, raw=b"{not json")
    assert status == 400 and body["error"]["code"] == -32700


def test_http_non_object_payload_returns_parse_error(http_server):
    status, body = _post(http_server, None, raw=b"[1, 2, 3]")
    assert status == 400 and body["error"]["code"] == -32700


def test_http_oversize_body_gets_413_and_close(http_server):
    # Raw socket: the server rejects on Content-Length without reading the
    # body, so a urllib upload would race the server's early response.
    import socket
    host, port = urllib.parse.urlparse(http_server).netloc.split(":")
    sock = socket.create_connection((host, int(port)), timeout=10)
    try:
        sock.sendall((
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\n"
            f"Content-Length: {srv.MAX_BODY_BYTES + 1}\r\n"
            "Content-Type: application/json\r\n\r\n").encode())
        sock.sendall(b"x" * 16)  # a slice of the body; server never reads it
        # The server answers 413 with Connection: close — read to EOF so the
        # full response (headers + body) is deterministic, never a split read.
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    assert data.split(b"\r\n")[0].startswith(b"HTTP/1.1 413")
    assert b"Connection: close" in data
    assert b"-32700" in data


def test_http_tool_failure_is_error_result(http_server):
    orig = srv.tool_call
    srv.tool_call = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("docker exploded"))
    try:
        status, body = _post(http_server, {
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "sandbox_stop", "arguments": {"session": "x"}}})
    finally:
        srv.tool_call = orig
    assert body["result"]["isError"] is True
    assert "docker exploded" in body["result"]["content"][0]["text"]
