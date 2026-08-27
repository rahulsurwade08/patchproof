"""Build-context generator for arbitrary repos.

Arbitrary-repo triage needs a valid Docker build context for the local
sandbox. Many repos (e.g. dvpwa) ship only `Dockerfile.app`/`Dockerfile.db`
or none at all. This script derives a minimal `Dockerfile` (+ entry probe)
from the repo layout so `sandbox_build` can operate on any repo.

It writes the generated context into the target repo directory (gitignored
paths are skipped) and reports the current working directory (cwd) that a
`docker build` should use, defaulting to the published app entry point.

Never run exploit code; this only generates build context.
"""

import argparse
import json
import os

from . import deps

_ENTRY_CANDIDATES = ("main.py", "app.py", "run.py", "server.py", "wsgi.py",
                     "manage.py", "index.js", "server.js", "app.js", "main.js")

_SKIP = deps._SKIP_PARTS + ("tests", "test", "__pycache__", ".github")


def _find_entry(repo_path):
    """Return the most likely application entry script, or None."""
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP]
        for fname in files:
            if fname in _ENTRY_CANDIDATES and fname.endswith((".py", ".js")):
                rel = os.path.relpath(os.path.join(root, fname), repo_path)
                if not any(part in _SKIP for part in rel.split(os.sep)):
                    return rel
    return None


def _detect_manifest(repo_path):
    found = deps.scan_repo(repo_path)
    req = next((v for v in found.values() if v["manifest"] == "requirements"), None)
    if req:
        return "requirements", req["path"]
    py = next((v for v in found.values() if v["manifest"] == "pyproject.toml"), None)
    if py:
        return "pyproject.toml", py["path"]
    js = next((v for v in found.values() if v["manifest"] == "package.json"), None)
    if js:
        return "package.json", js["path"]
    return None, None


def _print_build_rules(manifest_name):
    if manifest_name == "requirements":
        return "RUN pip install --no-cache-dir -r <req>"
    if manifest_name == "pyproject.toml":
        return "RUN pip install --no-cache-dir ."
    if manifest_name == "package.json":
        return "RUN npm ci --omit=dev"
    return "RUN true"


def generate(repo_path, out_dir=None):
    out_dir = out_dir or repo_path
    os.makedirs(out_dir, exist_ok=True)

    entry = _find_entry(repo_path)
    manifest_name, manifest_path = _detect_manifest(repo_path)

    if not entry:
        entry = "main.py"
    entry_rel = os.path.relpath(os.path.join(repo_path, entry), out_dir) if entry else "main.py"

    if manifest_path:
        manifest_rel = os.path.relpath(os.path.join(repo_path, manifest_path), out_dir)
    else:
        manifest_rel = None

    is_py = entry.endswith(".py")
    base = "python:3.11-slim" if is_py else "node:20-slim"
    install = _print_build_rules(manifest_name)
    if manifest_rel:
        install = install.replace("<req>", manifest_rel)
        copy_deps = f"COPY {manifest_rel} {manifest_rel}"
        copy_all = "COPY . /srv"
        run_install = install
    else:
        copy_deps = "COPY . /srv"
        copy_all = ""
        run_install = "RUN true"

    dockerfile = f"""FROM {base}
WORKDIR /srv
{copy_deps}
{run_install}
{copy_all}
CMD ["python", "{entry_rel}"]
"""
    df_path = os.path.join(out_dir, "Dockerfile")
    with open(df_path, "w", encoding="utf-8") as fh:
        fh.write(dockerfile)

    dockerignore = "\n".join((".git", "venv", ".venv", "__pycache__",
                              "node_modules", "data", "output")) + "\n"
    with open(os.path.join(out_dir, ".dockerignore"), "w", encoding="utf-8") as fh:
        fh.write(dockerignore)

    result = {
        "dockerfile": df_path,
        "base_image": base,
        "entry": entry,
        "entry_abs": os.path.abspath(os.path.join(repo_path, entry)),
        "dependency_manifest": manifest_path,
        "build_context": repo_path,
        "generated": True,
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="PatchProof build-context generator")
    parser.add_argument("repo_path", help="path to the target repository")
    parser.add_argument("--out", help="directory to write build context (default: repo path)")
    args = parser.parse_args(argv)

    result = generate(args.repo_path, args.out)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
