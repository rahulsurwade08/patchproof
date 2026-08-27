"""Build-context generator for arbitrary repos.

Arbitrary-repo triage needs a valid Docker build context for the local
sandbox. Many repos (e.g. dvpwa) ship only `Dockerfile.app`/`Dockerfile.db`
or none at all. This script derives a minimal `Dockerfile` (+ `.dockerignore`)
from the repo layout so `sandbox_build` can operate on any repo.

Behavior:
  - Default output directory is the repo itself (Docker context = repo).
  - ``--out DIR`` builds a COMPLETE context: the repo tree is copied into DIR
    (excluding VCS/venv/build dirs) and the Dockerfile is generated there, so
    COPY sources never escape the context.
  - Existing `Dockerfile`/`.dockerignore` are never silently overwritten;
    pass ``--force`` to replace them explicitly.
  - Raises ValueError when no runnable entry can be derived — a Dockerfile
    referencing a nonexistent entry would start-fail in the sandbox.

Never runs exploit code; this only generates build context.
"""

import argparse
import json
import os
import re
import shlex
import shutil
import sys

if __package__ in (None, ""):  # direct-file execution: make the package importable
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    from agent.analyzer import deps
else:
    from . import deps

_ENTRY_CANDIDATES = ("main.py", "app.py", "run.py", "server.py", "wsgi.py",
                     "manage.py", "index.js", "server.js", "app.js", "main.js")
_SKIP = deps._SKIP_PARTS + ("tests", "test", ".github", "dist", "build",
                            "static", "assets", "vendor", "public")


def _find_entry(repo_path):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP]
        for fname in files:
            if fname in _ENTRY_CANDIDATES:
                return os.path.relpath(os.path.join(root, fname), repo_path)
    return None


def _detect_manifest(repo_path):
    found = deps.scan_repo(repo_path)
    for kind in ("requirements", "pyproject.toml", "package.json"):
        entry = next((e for entries in found.values() for e in entries
                      if e["manifest"] == kind), None)
        if entry:
            return kind, entry["path"]
    return None, None


def _copy(src, dst=None):
    """Dockerfile JSON-array COPY — safe for paths with spaces/metachars."""
    dst = dst or src
    return "COPY " + json.dumps([src, dst])


def _install_block(manifest_name, manifest_rel, ctx_root):
    if manifest_name == "requirements":
        return [_copy(manifest_rel),
                f"RUN pip install --no-cache-dir -r {shlex.quote(manifest_rel)}"]
    if manifest_name == "package.json":
        manifest_dir = os.path.dirname(manifest_rel)
        lockfiles = [f for f in ("package-lock.json", "npm-shrinkwrap.json",
                                 "yarn.lock", "pnpm-lock.yaml")
                     if os.path.isfile(os.path.join(ctx_root, manifest_dir, f))]
        lines = [_copy(manifest_rel)]
        lines += [_copy(os.path.join(manifest_dir, f) if manifest_dir else f)
                  for f in lockfiles]
        install = "npm ci --omit=dev" if lockfiles else "npm install --omit=dev"
        # Manifest scanning is recursive: the Node project root is the
        # manifest's directory, not necessarily the context root.
        lines.append(f"RUN cd {shlex.quote(manifest_dir)} && {install}" if manifest_dir
                     else f"RUN {install}")
        return lines
    if manifest_name == "pyproject.toml":
        # A pyproject manifest alone is not installable: source first.
        return None
    return None


_COPY_IGNORE = (".git", "venv", ".venv", "__pycache__", "node_modules",
                "data", "output")

# Evidence the entry starts its own server loop (safe to exec directly).
_SELF_SERVING_RE = re.compile(
    r"uvicorn\.run\(|run_app\(|app\.run\(|\.listen\(|serve_forever\(|"
    r"create_server\(")
# Evidence the entry exposes an ASGI/WSGI application object (needs a server
# launcher — `python entry.py` would define the app and exit).
_APP_OBJECT_RE = re.compile(
    r"^\s*(\w+)\s*=\s*("
    r"FastAPI|Flask|Starlette|Quart|Sanic|Bottle|"
    r"web\.Application|aiohttp\.web\.Application)\(", re.M)


def _derive_start_command(entry, repo_path):
    """Return a runtime command that actually SERVES the app, or raise.

    A bare `[python, entry]` only works when the entry starts its own server
    loop; an entry that merely defines an ASGI/WSGI app object exits without
    serving, so it gets a uvicorn command; anything else is a hard failure
    rather than a start command we cannot prove works.
    """
    runner, ext = ("python", ".py") if entry.endswith(".py") else ("node", ".js")
    if runner == "node":
        # Node servers listen directly; no module indirection to resolve.
        return [runner, entry]
    try:
        with open(os.path.join(repo_path, entry), encoding="utf-8",
                  errors="replace") as fh:
            text = fh.read()
    except OSError:
        text = ""
    if _SELF_SERVING_RE.search(text):
        return [runner, entry]
    m = _APP_OBJECT_RE.search(text)
    if m:
        module = entry[:-len(ext)].replace(os.sep, ".").replace("/", ".")
        module = re.sub(r"\.__init__$", "", module)
        return ["uvicorn", f"{module}:{m.group(1)}",
                "--host", "127.0.0.1", "--port", "8000"]
    raise ValueError(
        f"cannot prove a serving command for {entry}: it neither starts a "
        f"server loop nor exposes a recognized ASGI/WSGI app object; supply "
        f"the startup command explicitly instead of a start that exits")


def _write_file(path, content, force):
    if os.path.exists(path) and not force:
        raise FileExistsError(
            f"{path} already exists; refusing to overwrite target files "
            f"(pass --force to replace explicitly)")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def generate(repo_path, out_dir=None, force=False):
    repo_path = os.path.abspath(repo_path)
    out_dir = os.path.abspath(out_dir) if out_dir else repo_path

    if out_dir != repo_path:
        if os.path.exists(out_dir) and os.listdir(out_dir):
            raise FileExistsError(f"{out_dir} is not empty; refusing to mix contexts")
        shutil.copytree(repo_path, out_dir,
                        ignore=shutil.ignore_patterns(*_COPY_IGNORE),
                        dirs_exist_ok=True)

    entry = _find_entry(repo_path)
    if not entry:
        raise ValueError(
            f"no runnable application entry detected in {repo_path} "
            f"(looked for {', '.join(_ENTRY_CANDIDATES)}); supply the entry "
            f"explicitly instead of generating a Dockerfile that cannot start")
    manifest_name, manifest_path = _detect_manifest(repo_path)
    is_py = entry.endswith(".py")
    base = "python:3.11-slim" if is_py else "node:20-slim"
    runner = "python" if is_py else "node"
    start_command = _derive_start_command(entry, repo_path)

    if manifest_path and manifest_name == "pyproject.toml":
        install_lines = ["COPY . /srv", "RUN pip install --no-cache-dir ."]
        copy_rest = []
    else:
        install_lines = _install_block(manifest_name, manifest_path, out_dir) if manifest_path else []
        copy_rest = ["COPY . /srv"]

    lines = [f"FROM {base}", "WORKDIR /srv"]
    lines += install_lines + copy_rest
    lines.append("CMD [" + ", ".join(f'"{p}"' for p in start_command) + "]")

    _write_file(os.path.join(out_dir, "Dockerfile"), "\n".join(lines) + "\n", force)
    _write_file(os.path.join(out_dir, ".dockerignore"),
                "\n".join((".git", ".env", ".env.*", "*.pem", "*.key", "*.p12",
                           "*.pfx", "id_rsa*", ".aws", ".ssh", ".npmrc",
                           ".pypirc", "credentials*", "*.credentials",
                           "venv", ".venv", "__pycache__", "node_modules",
                           "data", "output")) + "\n", force)

    # The sandbox start command overrides the Dockerfile CMD, so persist the
    # validated startup command for the reproducer to consume (it cannot
    # assume `uvicorn main:app` for arbitrary repos).
    context_record = {
        "dockerfile": os.path.join(out_dir, "Dockerfile"),
        "base_image": base,
        "entry": entry,
        "start_command": start_command,
        "dependency_manifest": manifest_path,
        "build_context": out_dir,
        "generated": True,
    }
    _write_file(os.path.join(out_dir, "patchproof-build-context.json"),
                json.dumps(context_record, indent=2, ensure_ascii=False) + "\n", force)

    return context_record


def main(argv=None):
    parser = argparse.ArgumentParser(description="PatchProof build-context generator")
    parser.add_argument("repo_path", help="path to the target repository")
    parser.add_argument("--out", help="write a complete build context here (default: repo path)")
    parser.add_argument("--force", action="store_true",
                        help="replace an existing generated Dockerfile/.dockerignore")
    args = parser.parse_args(argv)

    result = generate(args.repo_path, args.out, args.force)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
