"""Dependency-manifest parsing for the dep-pin short-circuit.

Find the pinned version of a package in a repo's manifests/lockfiles.
Supports requirements*.txt, requirements*.lock, pyproject.toml (PEP 621 and
Poetry sections), and package.json. Names are normalized to lowercase.
"""

import json
import os
import re

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    tomllib = None

_REQ_FILES = ("requirements.txt", "requirements.lock", "requirements-dev.txt")
_SKIP_PARTS = (".git", "data", "output", "node_modules", "venv", ".venv", "__pycache__")


def _normalize(name):
    return (name or "").strip().lower().replace("_", "-")


def _iter_requirements(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "[")):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([0-9][0-9A-Za-z.\-]*)", line)
            if not m:
                continue
            name = m.group(1).split("[", 1)[0]
            yield _normalize(name), m.group(2)


def _iter_pyproject(path):
    if tomllib is None:
        return
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    tables = []
    proj = data.get("project") or {}
    if proj.get("dependencies"):
        tables.append(proj["dependencies"])
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for key in ("dependencies", "group"):
        if key in poetry:
            tables.append(poetry[key])
    for table in tables:
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if isinstance(spec, str):
                m = re.search(r"==\s*([0-9][0-9A-Za-z.\-]*)", spec)
            elif isinstance(spec, dict) and spec.get("version"):
                m = re.search(r"==\s*([0-9][0-9A-Za-z.\-]*)", spec["version"])
            else:
                m = None
            if m:
                yield _normalize(name), m.group(1)


def _iter_package_json(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(key) or {}).items():
            m = re.search(r"^[~^]?([0-9][0-9A-Za-z.\-]*)", spec)
            if m:
                yield _normalize(name), m.group(1)


def _is_manifest(fname):
    if fname in _REQ_FILES:
        return "requirements"
    if fname == "pyproject.toml":
        return "pyproject.toml"
    if fname == "package.json":
        return "package.json"
    if fname.endswith(".txt") and "require" in fname:
        return "requirements"
    if fname.startswith("requirements") and (fname.endswith(".lock")):
        return "requirements"
    return None


def find_package(found, name):
    return found.get(_normalize(name))


def scan_repo(repo_path):
    """Return {normalized_name: {manifest, path, version}} for the repo."""
    found = {}
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_PARTS]
        for fname in files:
            kind = _is_manifest(fname)
            if not kind:
                continue
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, repo_path)
            try:
                if kind == "requirements":
                    it = _iter_requirements(full)
                elif kind == "pyproject.toml":
                    it = _iter_pyproject(full)
                else:
                    it = _iter_package_json(full)
                for name, version in it:
                    found.setdefault(name, {"manifest": kind, "path": rel, "version": version})
            except (OSError, ValueError):
                continue
    return found
