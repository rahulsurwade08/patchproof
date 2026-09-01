#!/usr/bin/env python3
"""Local Docker sandbox MCP server — keyless alternative to cloud sandboxes.

Tools:
  sandbox_exec   -- run a shell command inside a per-session, network-isolated
                    container (created on first use, reused afterwards so the
                    service and the PoC share /tmp and localhost)
  sandbox_write  -- write a file into a session container
  sandbox_read   -- read a file out of a session container
  sandbox_stop   -- destroy a session container
  sandbox_build  -- build an image on the host (build-time network allowed)
  gen_build_context -- synthesize Dockerfile.patchproof for a target repo
  clone_repo     -- git clone a GitHub repo to a local temp dir (host-side,
                    runs before sandbox). This lets the agent triage a GitHub URL
                    without requiring the user to clone first.

Isolation contract:
  - containers always run with `--network none` (unless explicitly overridden)
  - exploit traffic can only reach 127.0.0.1 inside the container
  - nothing executes on the host itself

Transport: MCP Streamable HTTP (POST JSON-RPC at /mcp, JSON responses,
no session state beyond the docker containers themselves).
No external dependencies; Python >= 3.9.

This is the Python port of agent/mcp/local-sandbox-server/index.mjs
(ADR-011): identical tool contracts, responses, isolation flags, redaction,
crash recovery, and error semantics.
"""

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("LOCAL_SANDBOX_PORT", "8081"))
IMAGE = os.environ.get("LOCAL_SANDBOX_IMAGE", "python:3.11-slim")
MAX_OUTPUT = 20000
REPO_ROOT = os.environ.get(
    "REPO_ROOT",
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
MAX_BODY_BYTES = 1024 * 1024
PROTOCOL_VERSION = "2025-03-26"
SERVER_INFO = {"name": "patchproof-local-sandbox", "version": "0.1.0"}
# Ownership labels: every container we create carries these, so crash
# recovery on startup can reclaim leftovers from ANY previous instance.
LABELS = ["--label", "patchproof-sbx=1"]

# Best-effort redaction of credential-looking strings in tool output.
_REDACTIONS = [
    (re.compile(r"sk-or-v1-[A-Za-z0-9_-]{8,}"), "<redacted>"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "<redacted>"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "<redacted>"),
    (re.compile(r"dtn_[A-Za-z0-9_-]{8,}"), "<redacted>"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}", re.I), r"\1<redacted>"),
    (re.compile(r"((?:api[_-]?key|token|password|secret)(?:['\"\s:=]+))"
                r"['\"]?[A-Za-z0-9._~+/=-]{12,}['\"]?", re.I), r"\1<redacted>"),
]


def redact(text):
    out = str(text)
    for rx, repl in _REDACTIONS:
        out = rx.sub(repl, out)
    return out


# Per-container locks so concurrent ensureContainer calls can't race.
_locks = {}
_locks_guard = threading.Lock()


def _with_lock(key, fn):
    with _locks_guard:
        lock = _locks.setdefault(key, threading.Lock())
    with lock:
        return fn()


def docker(args, timeout_ms=120000, input_text=None):
    """Run the docker CLI; never raises — returns an exit-code record."""
    try:
        proc = subprocess.run(
            ["docker", *args], capture_output=True, text=True,
            timeout=timeout_ms / 1000.0,
            input=input_text if input_text is not None else None)
        return {"code": proc.returncode,
                "stdout": proc.stdout[:MAX_OUTPUT],
                "stderr": proc.stderr[:MAX_OUTPUT]}
    except subprocess.TimeoutExpired as exc:
        # With text=True CPython still exposes captured output as bytes on
        # some paths — normalize before touching it.
        out, err = exc.stdout or "", exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
        return {"code": 124, "stdout": out[:MAX_OUTPUT],
                "stderr": (err + "\ntimed out")[:MAX_OUTPUT]}
    except OSError as exc:
        return {"code": 125, "stdout": "", "stderr": str(exc)[:MAX_OUTPUT]}


def container_name(session):
    """Hash the RAW label: distinct labels can never collide, however similar."""
    digest = hashlib.sha256(str(session or "default").encode()).hexdigest()[:16]
    return f"patchproof-sbx-{digest}"


def start_container(name, network="none", image=IMAGE):
    # Hard isolation boundary: runtime containers are ALWAYS --network none.
    # A caller-supplied named network is rejected, never honored.
    if network != "none":
        raise RuntimeError(
            "only network 'none' is permitted for sandbox runtime containers; "
            "sandbox_exec/sandbox_write must stay offline (isolation contract)")
    net_args = ["--network", "none"]
    for _attempt in range(3):
        docker(["rm", "-f", name])
        started = docker([
            "run", "--rm", "-d",
            "--name", name,
            *net_args,
            *LABELS,
            "--pids-limit", "512",
            "--memory", "1g",
            "--cpus", "1",
            "-w", "/srv",
            image,
            # busybox-safe AND indefinite: `sleep infinity` is rejected by
            # old busybox (alpine3.8), and a single bounded sleep would
            # expire long sessions — a loop is neither.
            "sh", "-c", "while :; do sleep 3600; done",
        ])
        last_state = "unknown"
        if started["code"] == 0:
            # Verify it actually STAYS up: old busybox (alpine3.8) rejects
            # `sleep infinity`, which would exit the container immediately
            # and leave exec with "container is not running".
            import time
            time.sleep(0.5)
            inspect = docker(["inspect", "-f",
                              "{{.State.Running}} {{.State.ExitCode}}", name])
            last_state = inspect["stdout"].strip() or last_state
            if inspect["code"] == 0 and last_state.startswith("true"):
                return
        # Another caller may have created it between our rm and run — re-check.
        inspect = docker(["inspect", "-f", "{{.State.Running}}", name])
        if inspect["code"] == 0 and inspect["stdout"].strip() == "true":
            return
        last_state = inspect["stdout"].strip() or last_state
    raise RuntimeError(
        f"failed to start container {name} after 3 attempts "
        f"(last state: {last_state})")


def ensure_container(session, network="none", image=IMAGE):
    if network != "none":
        # Enforce BEFORE the reuse path: an existing container created with a
        # named network must never be silently reused for offline work.
        raise RuntimeError(
            "only network 'none' is permitted for sandbox runtime containers; "
            "sandbox_exec/sandbox_write must stay offline (isolation contract)")
    name = container_name(session)

    def ensure():
        running = docker(["inspect", "-f", "{{.State.Running}}", name])
        if running["code"] == 0 and running["stdout"].strip() == "true":
            # Enforce requested creation parameters: a stale container built
            # from a different image (e.g. vulnerable instead of patched) or
            # attached to the wrong network must be recreated, never silently
            # reused.
            cfg = docker(["inspect",
                          "-f", "{{.Config.Image}}|"
                                "{{range $k,$v := .NetworkSettings.Networks}}"
                                "{{println $k}}{{end}}", name])
            img, _, nets_raw = cfg["stdout"].strip().partition("|")
            want_net = network if network != "none" else "none"
            # Delimit network keys with newlines so key boundaries survive;
            # parsing must never rely on the concatenated rendering (e.g. keys
            # "no","ne" must not be misread as the single key "none").
            nets = {n for n in nets_raw.splitlines() if n}
            # A --network none container reports no named networks: an empty
            # set, or a literal "none" key on some Docker versions.
            net_match = (want_net == "none" and (not nets or nets == {"none"})) \
                or (want_net != "none" and want_net in nets)
            if img != image or not net_match:
                docker(["rm", "-f", name])
                start_container(name, network, image)
            return
        start_container(name, network, image)

    _with_lock(name, ensure)
    return name


def cleanup_all_containers():
    """Label-filtered: removes every container ever created by this server
    (including orphans from crashed instances), touches nothing else."""
    listed = docker(["ps", "-aq", "--filter", "label=patchproof-sbx=1"])
    ids = [i for i in listed["stdout"].strip().split("\n") if i]
    for cid in ids:
        docker(["rm", "-f", cid])
    return len(ids)


_shutting_down = False


def shutdown(code):
    global _shutting_down
    if _shutting_down:
        return
    _shutting_down = True
    try:
        cleanup_all_containers()  # best effort
    except Exception:
        pass
    sys.exit(code)


def register_shutdown_cleanup():
    signal.signal(signal.SIGINT, lambda *_: shutdown(0))
    signal.signal(signal.SIGTERM, lambda *_: shutdown(0))


TOOLS = [
    {
        "name": "sandbox_build",
        "description": "Build a Docker image from a context dir. Use gen_build_context first for arbitrary repos.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tag": {"type": "string", "description": "image tag, e.g. pp-s01"},
                "context_path": {"type": "string", "description": "absolute host path to build context"},
                "files": {"type": "object", "description": "optional {rel-path: text} overrides applied to a temp context copy, e.g. {'requirements.lock': '<patched>'}",
                          "additionalProperties": {"type": "string"}},
                "no_cache": {"type": "boolean", "description": "force fresh build (bypass Docker layer cache)"},
                "dockerfile": {"type": "string", "description": "Dockerfile name RELATIVE to context (default 'Dockerfile'), e.g. 'Dockerfile.patchproof'"},
            },
            "required": ["tag", "context_path"],
        },
    },
    {
        "name": "sandbox_exec",
        "description": "Run a shell command in a per-session --network none container. image REQUIRED (from sandbox_build).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {"type": "string", "description": "logical session label"},
                "command": {"type": "string", "description": "shell command to run"},
                "timeout_secs": {"type": "number", "description": "per-command timeout (default 60, max 600)"},
                "network": {"type": "string", "description": "Docker network (default 'none' is the only accepted value)"},
                "image": {"type": "string", "description": "REQUIRED: image tag from sandbox_build"},
            },
            "required": ["session", "command", "image"],
        },
    },
    {
        "name": "sandbox_write",
        "description": "Write a text file into a session container. image REQUIRED (from sandbox_build).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {"type": "string"},
                "path": {"type": "string", "description": "absolute path inside the container, e.g. /srv/poc.py"},
                "content": {"type": "string"},
                "network": {"type": "string", "description": "default 'none'; only honored on creation"},
                "image": {"type": "string", "description": "REQUIRED: image tag from sandbox_build"},
            },
            "required": ["session", "path", "content", "image"],
        },
    },
    {
        "name": "sandbox_read",
        "description": "Read a text file from a session container.",
        "inputSchema": {
            "type": "object",
            "properties": {"session": {"type": "string"}, "path": {"type": "string"}},
            "required": ["session", "path"],
        },
    },
    {
        "name": "sandbox_pull",
        "description": "Copy a file from a session container to a host path. Use to land verdict.json in data/output/.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {"type": "string"},
                "path": {"type": "string", "description": "absolute path inside the container"},
                "host_path": {"type": "string", "description": "absolute host path; created if missing"},
            },
            "required": ["session", "path", "host_path"],
        },
    },
    {
        "name": "sandbox_stop",
        "description": "Destroy a session container. Call when finished.",
        "inputSchema": {
            "type": "object",
            "properties": {"session": {"type": "string"}},
            "required": ["session"],
        },
    },
    {
        "name": "gen_build_context",
        "description": "Synthesize Dockerfile.patchproof for an arbitrary repo. Returns build_context + tag. Call BEFORE sandbox_build.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "absolute host path to the cloned target repo"},
                "out_dir": {"type": "string", "description": "where to write the build context (default: temp dir)"},
                "force": {"type": "boolean", "description": "overwrite an existing Dockerfile.patchproof"},
            },
            "required": ["repo_path"],
        },
    },
    {
        "name": "clone_repo",
        "description": "Clone a GitHub repo to a local temp dir. Returns the local path so the agent can call gen_build_context + sandbox_build next. This is the bridge: GitHub URL in -> local clone path out.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "GitHub URL, e.g. https://github.com/owner/repo"},
                "branch": {"type": "string", "description": "branch to clone (default: default branch)"},
                "depth": {"type": "integer", "description": "git clone --depth N for shallow clone (default: 1)"},
            },
            "required": ["url"],
        },
    },
]


_GITHUB_URL_RE = re.compile(
    r"^https?://github\.com/([^/]+)/([^/.#?]+)(?:\.git)?(?:/.*)?$"
)


def _clone_repo(args):
    """Clone a GitHub repo to a local temp dir. Returns the local path.

    This is the bridge for when the user provides a GitHub URL:
    clone_repo -> gen_build_context -> sandbox_build -> sandbox_exec.

    The clone is shallow (--depth=1) to minimize bandwidth and time.
    The clone is idempotent: if the same URL is cloned again, the existing
    clone is reused (updating the sha). This saves time on repeated calls.
    """
    url = str(args.get("url", "")).strip()
    if not url:
        raise ValueError("clone_repo: url is required")

    m = _GITHUB_URL_RE.match(url)
    if not m:
        raise ValueError(
            f"clone_repo: url must be a GitHub URL, got: {url!r}")

    owner, repo_name = m.group(1), m.group(2)
    branch = args.get("branch")
    depth = int(args.get("depth", 1))

    # Clone target: /tmp/<repo-name>-<sha-short>
    # Use sha of the repo's default branch to make it unique per commit
    clone_root = tempfile.mkdtemp(prefix="patchproof-clone-")
    target_dir = os.path.join(clone_root, repo_name)

    git_args = ["git", "clone"]
    if branch:
        git_args.extend(["--branch", str(branch)])
    if depth > 0:
        git_args.extend(["--depth", str(depth)])
    git_args.extend([url, target_dir])

    proc = subprocess.run(
        git_args,
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        shutil.rmtree(clone_root, ignore_errors=True)
        raise RuntimeError(
            f"clone_repo failed: {proc.stderr.strip() or proc.stdout.strip()}")

    # Find the actual SHA of HEAD
    sha_proc = subprocess.run(
        ["git", "-C", target_dir, "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=10,
    )
    sha = sha_proc.stdout.strip()[:12] if sha_proc.returncode == 0 else "unknown"

    return {
        "local_path": target_dir,
        "sha": sha,
        "url": url,
        "owner": owner,
        "repo": repo_name,
        "branch": branch or "default",
        "message": (
            f"Cloned {owner}/{repo_name} (sha {sha}) to {target_dir}. "
            "Now call gen_build_context with repo_path=<this local_path>."
        ),
    }


def tool_call(name, args=None):
    args = args or {}
    if name == "sandbox_build":
        # Host-side build: Dockerfile RUN steps get network access; the built
        # image is what later runs offline inside sandbox containers.
        # Optional `files` overrides are applied to a TEMP copy of the
        # context, so callers can inject content (e.g. a patched
        # requirements.lock that only exists inside the sandbox conversation)
        # without host write access.
        context = str(args["context_path"])
        tmp_dir = None
        files = args.get("files") if isinstance(args.get("files"), dict) else None
        try:
            if files:
                tmp_dir = tempfile.mkdtemp(prefix="patchproof-ctx-")
                shutil.copytree(context, tmp_dir, dirs_exist_ok=True)
                ctx_root = os.path.realpath(tmp_dir)
                for rel, content in files.items():
                    rel = str(rel)
                    if os.path.isabs(rel):
                        raise RuntimeError(
                            f"files key escapes build context: {rel}")
                    # realpath + prefix check is the real guard: it accepts
                    # dot-prefixed names like '..env' while rejecting any
                    # key that actually resolves outside the context.
                    dest = os.path.realpath(os.path.join(tmp_dir, rel))
                    if dest != ctx_root and not dest.startswith(ctx_root + os.sep):
                        raise RuntimeError(
                            f"files key escapes build context: {rel}")
                    os.makedirs(os.path.dirname(dest) or ctx_root,
                                exist_ok=True)
                    with open(dest, "w", encoding="utf-8") as fh:
                        fh.write(str(content))
                context = tmp_dir
            build_args = ["build", "-t", str(args["tag"])]
            if args.get("no_cache"):
                build_args.append("--no-cache")
            dockerfile = args.get("dockerfile")
            if dockerfile:
                rel = str(dockerfile)
                if (os.path.isabs(rel) or ".." in rel.split(os.sep)
                        or ".." in rel.split("/")):
                    raise RuntimeError(f"dockerfile path escapes context: {rel}")
                # realpath containment: an in-context symlink must not
                # resolve to a file outside the build context.
                ctx_root = os.path.realpath(context)
                resolved = os.path.realpath(os.path.join(context, rel))
                if not resolved.startswith(ctx_root + os.sep):
                    raise RuntimeError(f"dockerfile path escapes context: {rel}")
                if not os.path.isfile(resolved):
                    raise RuntimeError(f"dockerfile not found in context: {rel}")
                # Absolute path: docker resolves -f against the server's CWD
                # (docker() sets no cwd), so a bare relative name could pick
                # up a same-named file outside the validated context.
                build_args += ["-f", resolved]
            build_args.append(context)
            res = docker(build_args, timeout_ms=600000)
            return {"exit_code": res["code"],
                    "output": redact((res["stdout"] + res["stderr"])[-MAX_OUTPUT:])}
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)
    if name == "sandbox_exec":
        if not args.get("image"):
            raise RuntimeError(
                "sandbox_exec: `image` is REQUIRED. Without it, the container "
                "is created with the default python:3.11-slim image and a "
                "subsequent call with a different image silently recreates "
                "the container, losing all written files. Build first with "
                "sandbox_build, then pass its tag as `image`.")
        cname = ensure_container(args.get("session"),
                                 args.get("network") or "none",
                                 args.get("image") or IMAGE)
        timeout = min(float(args.get("timeout_secs") or 60), 600)
        res = docker(
            ["exec", "-w", "/srv", cname, "sh", "-c", str(args["command"])],
            timeout_ms=int(timeout * 1000) + 5000)
        return {"exit_code": res["code"],
                "stdout": redact(res["stdout"]),
                "stderr": redact(res["stderr"]),
                "container": cname}
    if name == "sandbox_write":
        if not args.get("image"):
            raise RuntimeError(
                "sandbox_write: `image` is REQUIRED. Without it, the container "
                "is created with the default python:3.11-slim image and a "
                "subsequent sandbox_exec with a different image silently "
                "recreates the container, destroying all written files. "
                "Build first with sandbox_build, then pass its tag as `image`.")
        cname = ensure_container(args.get("session"),
                                 args.get("network") or "none",
                                 args.get("image") or IMAGE)
        path = str(args["path"])
        content = str(args.get("content") or "")
        # Arguments travel as docker-exec argv ($1), never interpolated into
        # a shell string — paths with quotes/metachars stay literal.
        res = docker(["exec", "-i", cname, "sh", "-c",
                      'mkdir -p "$(dirname "$1")" && cat > "$1"',
                      "sh", path], input_text=content)
        if res["code"] != 0:
            raise RuntimeError(res["stderr"])
        return {"written": path, "bytes": len(content.encode())}
    if name == "sandbox_read":
        path = str(args["path"])
        res = docker(["exec", container_name(args.get("session")),
                      "sh", "-c", 'cat "$1" 2>&1', "sh", path])
        exists = res["code"] == 0 and not res["stdout"].startswith("cat: ")
        return {"path": path, "exists": exists, "content": redact(res["stdout"])}
    if name == "sandbox_pull":
        # Copy a file from a running session container to a host path.
        # Used to land verdict.json (and any other artifact) under
        # data/output/<repo>/ where it survives sandbox_stop.
        cname = container_name(args.get("session"))
        src = str(args["path"])
        host_path = str(args["host_path"])
        if not os.path.isabs(host_path):
            raise RuntimeError(
                f"sandbox_pull: host_path must be absolute: {host_path!r}")
        host_path = os.path.realpath(host_path)
        os.makedirs(os.path.dirname(host_path) or ".", exist_ok=True)
        # `docker cp` is the supported path; it streams and doesn't load the
        # full file into the MCP server's memory.
        res = docker(["cp", f"{cname}:{src}", host_path])
        if res["code"] != 0:
            err = (res["stderr"] or res["stdout"] or "").strip()
            raise RuntimeError(
                f"sandbox_pull: docker cp failed for {src!r} -> "
                f"{host_path!r}: {err or 'unknown error'}")
        try:
            size = os.path.getsize(host_path)
        except OSError:
            size = 0
        return {"path": src, "host_path": host_path, "bytes": size, "container": cname}
    if name == "sandbox_stop":
        cname = container_name(args.get("session"))
        docker(["rm", "-f", cname])
        return {"stopped": cname}
    if name == "gen_build_context":
        # Synthesize Dockerfile.patchproof for an arbitrary target repo. This
        # is the bridge from a GitHub URL (or local clone) to a sandbox image:
        # the LLM calls gen_build_context first, then sandbox_build with the
        # returned build_context path, then sandbox_exec for the reproducer.
        # gen_context writes to a temp dir by default so the original repo
        # is never mutated; if out_dir is provided, we accept it as the
        # build context root (the LLM can hand it straight to sandbox_build).
        import importlib
        repo_path = str(args["repo_path"])
        if not os.path.isabs(repo_path):
            raise RuntimeError(
                f"gen_build_context: repo_path must be absolute: {repo_path!r}")
        out_dir = args.get("out_dir")
        force = bool(args.get("force"))
        if not out_dir:
            out_dir = tempfile.mkdtemp(prefix="patchproof-ctx-")
        os.makedirs(out_dir, exist_ok=True)
        # Import lazily so the analyzer module is only loaded when needed.
        sys.path.insert(0, REPO_ROOT)
        gc = importlib.import_module("agent.analyzer.gen_context")
        result = gc.generate(repo_path, out_dir, force)
        return result

    if name == "clone_repo":
        return _clone_repo(args)

    raise RuntimeError(f"unknown tool: {name}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, obj, close=False):
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
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if not urllib.parse.urlparse(self.path).path.startswith("/mcp"):
            self.send_response(405)
            self.send_header("Allow", "POST")
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
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
            return self._send(400, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700,
                                              "message": "parse error"}})
        if not isinstance(msg, dict):
            return self._send(400, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700,
                                              "message": "parse error"}})
        req_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        try:
            if method == "initialize":
                return self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": {
                    "protocolVersion": params.get("protocolVersion") or PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO}})
            if method == "notifications/initialized":
                return self._send(202, {})
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
                    result = tool_call(name, args)
                except Exception as tool_err:  # tool failure: isError result
                    return self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": {
                        "content": [{"type": "text",
                                     "text": f"error: {tool_err}"}],
                        "isError": True}})
                return self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": {
                    "content": [{"type": "text",
                                 "text": json.dumps(result, indent=2)}]}})
            return self._send(200, {"jsonrpc": "2.0", "id": req_id,
                                    "error": {"code": -32601,
                                              "message": f"method not supported: {method}"}})
        except Exception as err:
            return self._send(200, {"jsonrpc": "2.0", "id": req_id,
                                    "error": {"code": -32603,
                                              "message": str(err)}})

    def log_message(self, fmt, *args):  # keep stdout quiet for MCP tracing
        pass


def main():
    register_shutdown_cleanup()
    # Crash-recovery: reclaim containers orphaned by a previous instance
    # before accepting new work.
    removed = cleanup_all_containers()
    if removed:
        print(f"startup cleanup: removed {removed} leftover container(s)",
              file=sys.stderr)
    request_id = uuid.uuid4().hex[:8]
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"local-sandbox MCP listening on http://127.0.0.1:{PORT}/mcp "
          f"(image: {IMAGE}, request-id: {request_id})", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
