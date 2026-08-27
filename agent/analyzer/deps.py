"""Dependency-manifest parsing for the dep-pin short-circuit.

Find a package's declared version in a repo's manifests/lockfiles: supports
requirements*.txt, pyproject.toml (PEP 621 and Poetry), and package.json.
Names are normalized to lowercase.

A dependency is only "pinned" when the spec is an exact version (``==`` /
bare Poetry version / bare npm version). Range or caret specs are recorded
with ``version=None`` — an unknown version must NOT be treated as absence.
"""

import json
import os
import re

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    tomllib = None

_SKIP_PARTS = (".git", "data", "output", "node_modules", "venv", ".venv", "__pycache__")
_REQ_LINE_RE = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|~=|>=|<=|>|<|!=)?\s*([^;]*?)\s*$")


def _normalize(name):
    """PEP 503 canonical form (Python manifests): [-_.]+ runs collapse to '-'."""
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def _npm_key(name):
    """npm identity: lowercase exact name — dots and @scope are significant."""
    return (name or "").strip().lower()


def _entry(kind, path, rel, spec):
    spec = (spec or "").strip()
    exact = None
    m = re.match(r"^==\s*(\d[0-9A-Za-z.\-]*)$", spec)
    if m:
        exact = m.group(1)
    elif kind in ("pyproject.toml", "package.json") and re.match(r"^\d[0-9A-Za-z.\-]*$", spec):
        exact = spec
    return {"manifest": kind, "path": rel, "version": exact,
            "spec": spec or None, "pinned": exact is not None}


def _iter_requirements(path, rel):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "[")):
                continue
            m = _REQ_LINE_RE.match(line)
            if not m:
                continue
            yield _normalize(m.group(1)), _entry("requirements", path, rel, (m.group(2) or "") + m.group(3))


def _parse_requirement_string(req, rel):
    m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(.*)$", req)
    if not m:
        return None
    return _normalize(m.group(1)), _entry("pyproject.toml", None, rel, m.group(2))


def _iter_pyproject(path, rel):
    if tomllib is None:
        return
    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    proj = data.get("project") or {}
    for req in proj.get("dependencies") or []:
        if isinstance(req, str):
            parsed = _parse_requirement_string(req, rel)
            if parsed:
                yield parsed

    poetry = (data.get("tool") or {}).get("poetry") or {}
    deps_table = poetry.get("dependencies") or {}
    groups = poetry.get("group") or {}
    for group in groups.values():
        if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
            deps_table = {**deps_table, **group["dependencies"]}
    for name, spec in deps_table.items():
        if isinstance(spec, str):
            yield _normalize(name), _entry("pyproject.toml", None, rel, spec)
        elif isinstance(spec, dict) and spec.get("version"):
            yield _normalize(name), _entry("pyproject.toml", None, rel, spec["version"])


def _iter_package_json(path, rel):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(key) or {}).items():
            spec = spec if isinstance(spec, str) else ""
            if "git" in spec or spec.startswith(("file:", "link:", "workspace:")):
                continue
            yield _npm_key(name), _entry("package.json", None, rel, spec)


def scan_repo(repo_path):
    """Return {normalized_name: [entries]} — every declaration, not just the first.

    Multiple manifests may pin the same package; reachability must consider
    each entry, so none is discarded (first-entry wins can hide an affected pin).
    """
    found = {}
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_PARTS]
        for fname in files:
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, repo_path)
            try:
                if fname.startswith("requirements") and fname.endswith((".txt", ".lock")):
                    it = _iter_requirements(full, rel)
                elif fname == "pyproject.toml":
                    it = _iter_pyproject(full, rel)
                elif fname == "package.json" and "node_modules" not in rel.split(os.sep):
                    it = _iter_package_json(full, rel)
                else:
                    continue
                for name, entry in it:
                    found.setdefault(name, []).append(entry)
            except (OSError, ValueError):
                continue
    return found


def find_package(found, name):
    """Look up declarations under both identity schemes.

    npm names are exact lowercase identity (dots/@scope significant); Python
    names use PEP 503. The advisory side may use either, so try both keys.
    """
    for key in (_npm_key(name), _normalize(name)):
        entries = found.get(key)
        if entries:
            return entries
    return None
