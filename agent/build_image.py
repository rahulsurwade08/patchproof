"""Build a sandbox image for any Python or Node.js repo.

Caches by repo git SHA. Skips rebuild if image:<sha> already exists.

ponytail: two runtimes only (Python, Node). A third runtime justifies
extracting a Runtime class; not before.
"""
import hashlib
import shutil
import subprocess
from pathlib import Path

IMAGE_PREFIX = "ce-sandbox"


def repo_sha(repo: Path) -> str:
    """Stable identifier for the repo state. Uses git if available, else file hash."""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip()[:12]
    except Exception:
        # ponytail: file-hash fallback is O(repo size); upgrade to git index hash
        # for large repos
        h = hashlib.sha256()
        for p in sorted(repo.rglob("*"))[:5000]:
            if p.is_file():
                h.update(p.read_bytes()[:1024])
        return h.hexdigest()[:12]


def image_exists(tag: str) -> bool:
    r = subprocess.run(
        ["docker", "images", "-q", tag], capture_output=True, text=True
    )
    return bool(r.stdout.strip())


_SUBDIR_CANDIDATES = (
    "src", "server", "app", "web", "webapp", "www", "client",
    "frontend", "backend",
)


def _find_in_subdirs(repo: Path, targets: list[str]) -> Path | None:
    """Walk depth-1 subdirs looking for any of targets.

    ponytail: shallow walk only (depth 1). Deeper walks are a research
    project. Add subdirs to _SUBDIR_CANDIDATES as real repos surface new ones.
    """
    for sub in _SUBDIR_CANDIDATES:
        subpath = repo / sub
        if subpath.is_dir():
            for t in targets:
                found = subpath / t
                if found.is_file():
                    return subpath
    return None


def _fallback_for(runtime: str, repo: Path) -> tuple[str, int]:
    """Pick a server entrypoint for a forced runtime, or sleep-hold.

    Used by build_image_for_repo when runtime is forced but detect_runtime
    found nothing (e.g. caller asks for node on a CLI repo). Same sleep-hold
    as the auto-detect fallback.
    """
    if runtime == "python":
        return "python3 -c 'import time; time.sleep(3600)'", 8080
    return "node -e 'setInterval(()=>{},1<<30)'", 3000


def detect_runtime(repo: Path) -> tuple[str, str, int] | None:
    """Detect runtime, entry command, and port for a repo.

    Returns (runtime, cmd, port). runtime is "python" or "node".
    port is the TCP port the server will bind to.

    Detection order:
      1. package.json at root or depth-1 subdir with start script -> node
      2. server.js / app.js / index.js / main.js at root or subdir  -> node
      3. manage.py / run.py / app.py / main.py at root or subdir    -> python
      4. None (falls back to a sleep-hold for non-server repos)

    ponytail: no TypeScript build, no monorepo/workspace walk.
    Node port is always 3000 (Express convention); the app must read
    CE_PORT env or bind to 0.0.0.0.
    """
    # Check root first
    result = _detect_at(repo)
    if result:
        return result
    # Shallow subdir walk: find first package.json or py entrypoint
    sub = _find_in_subdirs(repo, ["package.json", "manage.py", "run.py", "app.py", "main.py"])
    if sub:
        result = _detect_at(sub)
        if result:
            rel = sub.relative_to(repo)
            return result[0], f"cd {rel} && {result[1]}", result[2]
    return None


def _detect_at(base: Path) -> tuple[str, str, int] | None:
    """Detect runtime at a specific directory (root or subdir)."""
    pkg_json = base / "package.json"
    if pkg_json.exists():
        try:
            import json
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
            scripts = (data.get("scripts") or {})
            start = scripts.get("start") or scripts.get("dev")
            if start:
                cmd = start
                if cmd.startswith("node "):
                    cmd = cmd[5:].strip()
                return "node", f"node {cmd}", 3000
        except (OSError, ValueError):
            pass
        for fname in ("server.js", "app.js", "index.js", "main.js"):
            if (base / fname).exists():
                return "node", f"node {fname}", 3000

    for fname, cmd, port in (
        ("manage.py", "python3 manage.py runserver 0.0.0.0:8080", 8080),
        ("run.py",     "python3 run.py",                                8080),
        ("app.py",     "python3 app.py",                                5000),
        ("main.py",    "python3 main.py",                               8000),
    ):
        if (base / fname).exists():
            return "python", cmd, port
    return None


def build_image_for_repo(repo: Path, runtime: str | None = None) -> str:
    """Build and return a sandbox image tag for this repo.

    Args:
        repo: repo path
        runtime: force a runtime ("python" or "node"). If None, auto-detect
                 via detect_runtime. Exists so callers can build a specific
                 runtime regardless of server entrypoint detection.
    """
    sha = repo_sha(repo)
    if runtime:
        tag = f"{IMAGE_PREFIX}:{repo.name}-{sha}-{runtime}"
    else:
        tag = f"{IMAGE_PREFIX}:{repo.name}-{sha}"

    if image_exists(tag):
        return tag

    if runtime is None:
        runtime_info = detect_runtime(repo)
        if runtime_info:
            runtime, entrypoint, port = runtime_info
        else:
            runtime, entrypoint, port = "python", "python3 -c 'import time; time.sleep(3600)'", 8080
    else:
        entrypoint, port = _fallback_for(runtime, repo)

    # ponytail: each sandbox_exec starts a fresh container, so the kill loop
    # was dead code (and a footgun: pgrep -f "main.py" would match anything on
    # the line). Drop it. Upgrade path: add targeted pkill -f "$ENTRYPOINT"
    # only if/when sandbox_exec supports in-place restart.
    start_sh = f"""#!/bin/bash
set +e
CE_PORT={port} bash -c "{entrypoint.strip()}" >> /tmp/srv.log 2>&1 &
for i in $(seq 1 20); do
    (echo > /dev/tcp/127.0.0.1/{port}) 2>/dev/null && {{
        echo READY
        exit 0
    }}
    sleep 0.5
done
echo FAILED
exit 1
"""
    # ponytail: Dockerfile assembled as a list of lines for readability;
    # extracted template class if a 3rd runtime is added.
    dockerfile_lines = []
    if runtime == "python":
        dockerfile_lines = [
            "FROM python:3.11-slim",
            "WORKDIR /srv",
            "COPY . /srv/",
            "RUN chmod +x start.sh",
        ]
        if (repo / "requirements.txt").exists():
            dockerfile_lines.append("RUN pip install --no-cache-dir -r requirements.txt")
    else:  # node
        dockerfile_lines = [
            "FROM node:20-slim",
            "WORKDIR /srv",
            "COPY . /srv/",
            "RUN chmod +x start.sh",
        ]
        # ponytail: --omit=dev skips devDeps; --no-fund --no-audit keeps the layer small.
        # No npm ci (lockfile not guaranteed). Lockfile handling when a real caller needs it.
        if (repo / "package.json").exists():
            dockerfile_lines.append(
                "RUN npm install --omit=dev --no-fund --no-audit 2>/dev/null || true"
            )
    dockerfile_lines.extend([f"EXPOSE {port}", f"ENV CE_PORT={port}", 'CMD ["/srv/start.sh"]'])
    dockerfile = "\n".join(dockerfile_lines) + "\n"

    # Build with a temp context dir to avoid embedding secrets.
    # Copy repo contents first, then overwrite with our generated files
    # (so any Dockerfile in the repo doesn't replace ours).
    ctx = Path(f"/tmp/ce-build-{sha}")
    ctx.mkdir(exist_ok=True)
    (ctx / "start.sh").write_text(start_sh)
    skip_names = {".git", ".venv", "venv", "__pycache__", "node_modules"}
    for item in repo.iterdir():
        if item.name in skip_names or item.name.startswith("."):
            continue
        target = ctx / item.name
        if item.is_symlink():
            continue
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns(".env*", "__pycache__", "node_modules"))
        else:
            target.write_bytes(item.read_bytes())
    # Must write AFTER copying so we overwrite any Dockerfile from the repo
    (ctx / "Dockerfile").write_text(dockerfile)

    subprocess.run(
        ["docker", "build", "-t", tag, str(ctx)],
        check=True, capture_output=True,
    )
    shutil.rmtree(ctx, ignore_errors=True)
    return tag
