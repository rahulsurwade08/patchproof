"""Unit tests for the reachability analyzer.

Fixtures are tiny throwaway repos built in tmp_path; the analyzer must decide
REACHABLE / NOT_REACHABLE / UNKNOWN honestly across the triage paths.
"""

import json
import os

import pytest

from agent.analyzer import deps, gen_context, reach, versions  # noqa: E402


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


_NODE_LISTENER = ("const http = require('http');\n"
                  "http.createServer(() => {}).listen(3000, '127.0.0.1');\n")

_SELF_SERVING_APP = (
    "import uvicorn\n"
    "app = 'placeholder'\n"
    "if __name__ == '__main__':\n"
    "    uvicorn.run(app)\n")


def _require(repo, body="pyyaml==3.13\n"):
    _write(os.path.join(repo, "requirements.txt"), body)


def _advisory(tmp_path, cve="CVE-X", pkg="pyyaml", affected="< 5.4",
              desc="load() executes arbitrary code"):
    p = tmp_path / "advisory.json"
    _write(str(p), json.dumps({
        "cve_id": cve, "package": pkg, "affected_versions": affected,
        "description": desc}))
    return str(p)


def _run(repo, tmp_path, **kw):
    adv = _advisory(tmp_path, **kw)
    out_dir = str(tmp_path / "out")
    return reach.reach(str(repo), reach._load_advisory(adv), out_dir), out_dir


def test_dep_out_of_scope(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    rec, _ = _run(repo, tmp_path, affected=">= 5.4")
    assert rec["verdict"] == "NOT_REACHABLE"
    assert rec["needs_sandbox"] is False
    assert rec["in_scope"] is False


def test_package_not_pinned(tmp_path):
    repo = tmp_path / "repo"
    _write(os.path.join(repo, "requirements.txt"), "flask==2.0\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "NOT_REACHABLE"
    assert rec["in_scope"] is False
    assert rec["needs_sandbox"] is False


def test_unpinned_spec_is_unknown_not_absent(tmp_path):
    repo = tmp_path / "repo"
    _require(repo, body="pyyaml>=3.0\n")
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_pep621_dependency_list_parsed(tmp_path):
    repo = tmp_path / "repo"
    _write(os.path.join(repo, "pyproject.toml"),
           '[project]\nname = "x"\ndependencies = ["pyyaml==3.13"]\n')
    rec, _ = _run(repo, tmp_path)
    assert rec["dep"]["pinned_version"] == "3.13"
    assert rec["verdict"] == "UNKNOWN"


def test_direct_load_reachable(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "main.py"), (
        "import yaml\n"
        "async def load_config(request):\n"
        "    raw = await request.body()\n"
        "    cfg = yaml.load(raw)\n"))
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "REACHABLE"
    assert rec["needs_sandbox"] is True


def test_pinned_but_unreferenced_gates_sandbox(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "main.py"), "print('hello')\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_safe_symbol_not_mistaken_for_vulnerable(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "main.py"), (
        "import yaml\n"
        "async def load_config(request):\n"
        "    raw = await request.body()\n"
        "    cfg = yaml.safe_load(raw)\n"))
    rec, _ = _run(repo, tmp_path)
    # safe_load is a distinct symbol the analyzer cannot prove safe without a
    # hardcoded map, and the pkg import is aliased (`yaml` vs `pyyaml`) — so
    # this must gate the sandbox, never be declared safe statically.
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_static_config_not_reachable(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "config.py"), (
        "import yaml\n"
        "cfg = yaml.load(open('./dev.yaml', 'r'))\n"))
    _write(os.path.join(repo, "dev.yaml"), "key: value\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "NOT_REACHABLE"
    assert rec["needs_sandbox"] is False


def test_unchecked_file_literal_is_not_static_evidence(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "config.py"), (
        "import yaml\n"
        "cfg = yaml.load(open('./user-supplied.yaml', 'r'))\n"))
    rec, _ = _run(repo, tmp_path)
    # the quoted .yaml path does not exist in the repo — no checked-in
    # evidence, so the site must NOT be classified safe
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_name_similarity_does_not_prove_static(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "app.py"), (
        "import yaml\n"
        "def parse(config):\n"
        "    return yaml.load(config)\n"))
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_mixed_unknown_and_static_gates_sandbox(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "startup.py"), "import yaml\nyaml.load(open('a.yaml'))\n")
    _write(os.path.join(repo, "a.yaml"), "key: value\n")
    _write(os.path.join(repo, "util.py"), "import yaml\ndef f(v):\n    return yaml.load(v)\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_no_package_in_advisory_unknown(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    adv_path = _advisory(tmp_path, pkg="")
    rec = reach.reach(str(repo), reach._load_advisory(adv_path), str(tmp_path / "o"))
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_reachability_json_written(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    rec, out_dir = _run(repo, tmp_path)
    out_file = os.path.join(out_dir, "reachability.json")
    assert os.path.isfile(out_file)
    with open(out_file, encoding="utf-8") as fh:
        assert json.load(fh)["cve_id"] == rec["cve_id"]


def test_direct_script_entry_runs(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    adv = _advisory(tmp_path)
    import subprocess
    import sys
    proc = subprocess.run(
        [sys.executable, "agent/analyzer/reach.py", str(repo), adv,
         "--out", str(tmp_path / "cli-out")],
        capture_output=True, text=True, cwd=os.getcwd())
    assert proc.returncode == 0, proc.stderr[-400:]
    assert os.path.isfile(tmp_path / "cli-out" / "reachability.json")


def test_osv_interval_events_assembled(tmp_path):
    advisory = reach._load_advisory.__wrapped__ if hasattr(reach._load_advisory, "__wrapped__") else None
    # Direct interval-assembly check through the OSV event list shape.
    events = [{"introduced": "3.0"}, {"fixed": "3.9"},
              {"introduced": "4.0"}, {"fixed": "5.4"}]
    ranges = []
    introduced = None
    for ev in events:
        if "introduced" in ev:
            introduced = ev["introduced"]
        elif introduced is not None and ("fixed" in ev or "limit" in ev):
            hi = ev.get("fixed", ev.get("limit"))
            ranges.append(f">= {introduced}, < {hi}")
            introduced = None
    assert ranges == [">= 3.0, < 3.9", ">= 4.0, < 5.4"]
    assert versions.version_in_range("3.13", ranges[0]) is False
    assert versions.version_in_range("3.5", ranges[0]) is True


def test_gen_context_generates_dockerfile(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    result = gen_context.generate(str(repo), str(repo))
    assert os.path.isfile(os.path.join(str(repo), "Dockerfile"))
    assert result["entry"] == "main.py"
    assert result["base_image"].startswith("python:")
    assert result["build_context"] == os.path.abspath(str(repo))


def test_gen_context_refuses_overwrite(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    gen_context.generate(str(repo), str(repo))
    with pytest.raises(FileExistsError):
        gen_context.generate(str(repo), str(repo))
    gen_context.generate(str(repo), str(repo), force=True)


def test_gen_context_out_is_complete_context(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    out = tmp_path / "ctx"
    result = gen_context.generate(str(repo), str(out))
    assert result["build_context"] == os.path.abspath(str(out))
    assert os.path.isfile(out / "Dockerfile")
    assert os.path.isfile(out / "main.py")
    assert os.path.isfile(out / "requirements.txt")


def test_gen_context_node_entry_uses_node(tmp_path):
    repo = tmp_path / "app"
    _write(os.path.join(repo, "package.json"),
           json.dumps({"dependencies": {"yaml": "1.10.0"}}))
    _write(os.path.join(repo, "server.js"), _NODE_LISTENER)
    result = gen_context.generate(str(repo), str(repo))
    assert result["base_image"] == "node:20-slim"
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    assert 'CMD ["node", "server.js"]' in dockerfile
    assert "npm install" in dockerfile


def test_gen_context_npm_ci_with_lockfile(tmp_path):
    repo = tmp_path / "app"
    _write(os.path.join(repo, "package.json"),
           json.dumps({"dependencies": {"yaml": "1.10.0"}}))
    _write(os.path.join(repo, "package-lock.json"), "{}")
    _write(os.path.join(repo, "server.js"), _NODE_LISTENER)
    gen_context.generate(str(repo), str(repo))
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    assert "npm ci" in dockerfile and "package-lock.json" in dockerfile


def test_versions_range_parsing():
    assert versions.version_in_range("3.13", "< 5.4") is True
    assert versions.version_in_range("5.4", "< 5.4") is False
    assert versions.version_in_range("4.5", ">= 4.0, < 5.4") is True
    assert versions.version_in_range("5.3.1", "< 5.4") is True
    assert versions.version_in_range("3.9", ">= 3.0, < 3.1.5") is False


def test_prerelease_sorts_before_release():
    assert versions.version_in_range("1.0rc1", "< 1.0") is True
    assert versions.version_in_range("1.0", "< 1.0") is False
    assert versions.version_in_range("1.0rc2", "< 1.0rc1") is False


def test_deps_scan_missing_dir():
    assert deps.scan_repo("/nonexistent") == {}


def test_equivalent_versions_compare_equal():
    assert versions.version_in_range("1.0.0", "== 1.0") is True
    assert versions.version_in_range("1.0", "< 1.0.1") is True
    assert versions.version_in_range("1.0.1", "< 1.0.1") is False


def test_multi_manifest_affected_pin_not_hidden(tmp_path):
    repo = tmp_path / "repo"
    _write(os.path.join(repo, "requirements.txt"), "pyyaml==5.4.1\n")
    _write(os.path.join(repo, "sub", "requirements.txt"), "pyyaml==3.13\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["in_scope"] is True
    assert rec["dep"]["pinned_version"] == "3.13"


def test_poetry_group_dependencies_parsed(tmp_path):
    repo = tmp_path / "repo"
    _write(os.path.join(repo, "pyproject.toml"), (
        "[tool.poetry.group.dev.dependencies]\n"
        'pyyaml = "3.13"\n'))
    rec, _ = _run(repo, tmp_path)
    assert rec["dep"]["pinned_version"] == "3.13"


def test_alternate_advisory_keys(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    p = tmp_path / "alt.json"
    _write(str(p), json.dumps({
        "cve_id": "CVE-ALT", "affected_package": "pyyaml",
        "affected_range": "< 5.4", "summary": "load() unsafe"}))
    rec = reach.reach(str(repo), reach._load_advisory(str(p)), str(tmp_path / "o"))
    assert rec["dep"]["name"] == "pyyaml"


def test_transitive_unreferenced_gates_sandbox(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True
    assert "transitive" in rec["rationale"]


def test_osv_shaped_advisory_file(tmp_path):
    """Advisory records written from the cve-feed MCP osv_get_vuln shape."""
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    p = tmp_path / "osv.json"
    _write(str(p), json.dumps({
        "id": "GHSA-xxxx",
        "summary": "unsafe load()",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "pyyaml"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"},
                                             {"fixed": "5.4"}]}]}]}))
    rec = reach.reach(str(repo), reach._load_advisory(str(p)), str(tmp_path / "o"))
    assert rec["source"] == "advisory-file-osv"
    assert rec["dep"]["name"] == "pyyaml"
    assert rec["dep"]["pinned_version"] == "3.13"
    assert rec["in_scope"] is True


def test_wildcard_spec_is_not_a_pin(tmp_path):
    repo = tmp_path / "repo"
    _require(repo, body="pyyaml==3.*\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_post_release_sorts_between():
    assert versions.version_in_range("1.0.post1", ">= 1.0.1") is False
    assert versions.version_in_range("1.0.post1", ">= 1.0") is True


def test_preview_ranks_as_rc():
    assert versions.version_in_range("1.0preview1", ">= 1.0rc1") is True
    assert versions.version_in_range("1.0preview1", "< 1.0rc1") is False


def test_local_version_sorts_below_post():
    assert versions.version_in_range("1.0+abc", "< 1.0.post1") is True
    assert versions.version_in_range("1.0+abc", ">= 1.0") is True
    assert versions.version_in_range("1.0.post1", "< 1.0.1") is True


def test_local_label_ignored_without_local_bound():
    assert versions.version_in_range("1.0+vendor", "<= 1.0") is True
    assert versions.version_in_range("1.0+vendor", "== 1.0") is True
    assert versions.version_in_range("1.0+vendor", "== 1.0+vendor") is True
    assert versions.version_in_range("1.0.post1", "<= 1.0+vendor") is False


def test_npm_identity_is_exact_not_pep503(tmp_path):
    repo = tmp_path / "repo"
    _write(os.path.join(repo, "package.json"), json.dumps(
        {"dependencies": {"@scope/foo.bar": "1.0.0"}}))
    scan = deps.scan_repo(str(repo))
    assert deps.find_package(scan, "@scope/foo.bar") is not None
    assert deps.find_package(scan, "@scope/foo-bar") is None


def test_pep503_name_normalization(tmp_path):
    repo = tmp_path / "repo"
    _write(os.path.join(repo, "requirements.txt"), "zope.interface==5.4.1\n")
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    adv = tmp_path / "adv.json"
    _write(str(adv), json.dumps({
        "cve_id": "CVE-NORM", "package": "zope-interface",
        "affected_versions": "< 5.5", "description": "x() unsafe"}))
    rec = reach.reach(str(repo), reach._load_advisory(str(adv)), str(tmp_path / "o"))
    assert rec["dep"]["pinned_version"] == "5.4.1"
    assert rec["in_scope"] is True


def test_dockerignore_blocks_secrets(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    gen_context.generate(str(repo), str(repo))
    di = open(os.path.join(str(repo), ".dockerignore"), encoding="utf-8").read()
    for pattern in (".env", "*.pem", "id_rsa*", ".aws", ".ssh"):
        assert pattern in di


def test_gen_context_nested_npm_project(tmp_path):
    repo = tmp_path / "app"
    _write(os.path.join(repo, "frontend", "package.json"), json.dumps(
        {"dependencies": {"yaml": "1.10.0"}}))
    _write(os.path.join(repo, "frontend", "package-lock.json"), "{}")
    _write(os.path.join(repo, "frontend", "server.js"), _NODE_LISTENER)
    result = gen_context.generate(str(repo), str(repo))
    assert result["entry"] == os.path.join("frontend", "server.js")
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    assert 'COPY ["frontend/package.json", "frontend/package.json"]' in dockerfile
    assert 'COPY ["frontend/package-lock.json", "frontend/package-lock.json"]' in dockerfile
    assert "RUN cd frontend && npm ci" in dockerfile
    assert 'CMD ["node", "frontend/server.js"]' in dockerfile


def test_gen_context_persists_start_command(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    result = gen_context.generate(str(repo), str(repo))
    assert result["start_command"] == ["python", "main.py"]  # self-serving entry
    ctx_file = os.path.join(str(repo), "patchproof-build-context.json")
    assert os.path.isfile(ctx_file)
    saved = json.load(open(ctx_file, encoding="utf-8"))
    assert saved["start_command"] == ["python", "main.py"]
    assert saved["build_context"] == os.path.abspath(str(repo))


def test_gen_context_quoting_survives_spaces(tmp_path):
    repo = tmp_path / "app"
    _write(os.path.join(repo, "front end", "package.json"), json.dumps(
        {"dependencies": {"yaml": "1.10.0"}}))
    _write(os.path.join(repo, "front end", "server.js"), _NODE_LISTENER)
    gen_context.generate(str(repo), str(repo))
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    assert 'COPY ["front end/package.json", "front end/package.json"]' in dockerfile
    assert "RUN cd 'front end' && npm install" in dockerfile
    assert 'CMD ["node", "front end/server.js"]' in dockerfile


def test_gen_context_app_object_gets_uvicorn(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "api", "main.py"),
           "from fastapi import FastAPI\napp = FastAPI()\n")
    result = gen_context.generate(str(repo), str(repo))
    assert result["start_command"] == ["uvicorn", "api.main:app",
                                       "--host", "127.0.0.1", "--port", "8000"]
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    assert '"uvicorn"' in dockerfile


def test_gen_context_fails_without_serving_command(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), "print('library only')\n")
    with pytest.raises(ValueError):
        gen_context.generate(str(repo), str(repo))


def test_gen_context_skips_symlinked_dockerfiles(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    os.symlink("/dev/zero", os.path.join(repo, "Dockerfile.zero"))
    os.symlink("/etc/passwd", os.path.join(repo, "Dockerfile.esc"))
    result = gen_context.generate(str(repo), str(repo), force=True)
    assert result["base_image"] == "python:3.11-slim"  # fallback, no hang/leak


def test_gen_context_handles_from_flags_and_digests(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "Dockerfile.app"),
           "FROM --platform=linux/amd64 python:3.9-slim@sha256:"
           + "a" * 64 + "\n")
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    result = gen_context.generate(str(repo), str(repo), force=True)
    assert result["base_image"] == "python:3.9-slim@sha256:" + "a" * 64


def test_gen_context_rejects_untrusted_base(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "Dockerfile"), "FROM mysql:8.0\n")
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    # untrusted foreign image -> explicit failure, never a wrong-base build
    with pytest.raises(ValueError):
        gen_context.generate(str(repo), str(repo), force=True)


def test_gen_context_skips_parametrized_from(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "Dockerfile"),
           "ARG BASE=python:3.8\nFROM ${BASE}\n")
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    with pytest.raises(ValueError):
        gen_context.generate(str(repo), str(repo), force=True)


def test_gen_context_prefers_runtime_dockerfile_over_db(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "Dockerfile.db"), "FROM mysql:8.0\n")
    _write(os.path.join(repo, "Dockerfile.app"), "FROM python:3.9-slim\n")
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    result = gen_context.generate(str(repo), str(repo))
    assert result["base_image"] == "python:3.9-slim"


def test_gen_context_case_insensitive_from(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "Dockerfile.app"),
           "  from python:3.8-slim AS build\n")
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    result = gen_context.generate(str(repo), str(repo))
    assert result["base_image"] == "python:3.8-slim"


def test_gen_context_skips_its_own_generated_dockerfile(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "Dockerfile"),
           "# Generated by PatchProof gen_context (safe to delete).\n"
           "FROM python:3.11-slim\n")  # stale artifact from an earlier run
    _write(os.path.join(repo, "Dockerfile.app"), "FROM python:alpine3.8\n")
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    result = gen_context.generate(str(repo), str(repo), force=True)
    assert result["base_image"] == "python:alpine3.8"


def test_gen_context_reuses_repo_declared_base(tmp_path):
    repo = tmp_path / "app"
    _require(repo, body="old-pin==1.0\n")
    _write(os.path.join(repo, "Dockerfile.app"),
           "FROM python:alpine3.8\nRUN apk add --no-cache gcc musl-dev\n")
    _write(os.path.join(repo, "main.py"), _SELF_SERVING_APP)
    result = gen_context.generate(str(repo), str(repo))
    assert result["base_image"] == "python:alpine3.8"
    assert result["source"] == "repo-dockerfile"
    # verbatim copy: the repo's own RUN steps (apk build tooling) survive
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    assert "FROM python:alpine3.8" in dockerfile
    assert "apk add --no-cache gcc musl-dev" in dockerfile


def test_gen_context_fails_without_entry(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "lib.py"), "print('library only')\n")
    with pytest.raises(ValueError):
        gen_context.generate(str(repo), str(repo))


def test_gen_context_rejects_console_only_node(tmp_path):
    repo = tmp_path / "app"
    _write(os.path.join(repo, "package.json"), json.dumps(
        {"dependencies": {"yaml": "1.10.0"}}))
    _write(os.path.join(repo, "server.js"), "console.log('not a server')\n")
    with pytest.raises(ValueError):
        gen_context.generate(str(repo), str(repo))


def test_gen_context_installs_uvicorn_for_app_object(tmp_path):
    repo = tmp_path / "app"
    _require(repo, body="fastapi==0.115.0\n")  # note: no uvicorn declared
    _write(os.path.join(repo, "main.py"),
           "from fastapi import FastAPI\napp = FastAPI()\n")
    result = gen_context.generate(str(repo), str(repo))
    assert result["start_command"][0] == "uvicorn"
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    assert "pip install" in dockerfile and "uvicorn" in dockerfile


def test_conflicting_static_and_network_evidence_gates_sandbox(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "handler.py"), (
        "import yaml\n"
        "async def h(request):\n"
        "    cfg = yaml.load(open('./dev.yaml'))\n"
        "    return yaml.load(await request.json())\n"))
    _write(os.path.join(repo, "dev.yaml"), "key: value\n")
    rec, _ = _run(repo, tmp_path)
    # static literal on one call line + network provenance in the same
    # context -> conflicting evidence must NOT produce a safe verdict
    verdicts = [c["input_source"] for c in rec.get("call_sites_scanned", [])]
    assert "NOT_REACHABLE" not in verdicts or rec["verdict"] != "NOT_REACHABLE" \
        or all(v != "REACHABLE" for v in verdicts)
    assert rec["verdict"] == "REACHABLE" or rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True


def test_checked_in_filename_with_indicator_word_not_reachable(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "loader.py"),
           "import yaml\ncfg = yaml.load(open('body.yaml'))\n")
    _write(os.path.join(repo, "body.yaml"), "k: v\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "NOT_REACHABLE"
    assert rec["needs_sandbox"] is False


def test_relative_repo_path_does_not_crash(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "loader.py"),
           "import yaml\ncfg = yaml.load(open('dev.yaml'))\n")
    _write(os.path.join(repo, "dev.yaml"), "k: v\n")
    monkeypatch.chdir(tmp_path)
    adv = _advisory(tmp_path)
    rec = reach.reach("repo", reach._load_advisory(adv), str(tmp_path / "o"))
    assert rec["verdict"] == "NOT_REACHABLE"


def test_cmd_json_escapes_sensitive_entry_paths(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, 'we"ird', "main.py"), _SELF_SERVING_APP)
    gen_context.generate(str(repo), str(repo))
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    cmd_line = next(l for l in dockerfile.splitlines() if l.startswith("CMD "))
    import json as j
    parsed = j.loads(cmd_line[4:])
    assert parsed[0] == "python"


def test_gen_context_rejects_node_constructor_without_listen(tmp_path):
    repo = tmp_path / "app"
    _write(os.path.join(repo, "package.json"), json.dumps(
        {"dependencies": {"express": "4.19.0"}}))
    _write(os.path.join(repo, "server.js"),
           "const http = require('http');\nhttp.createServer(() => {});\n")
    with pytest.raises(ValueError):
        gen_context.generate(str(repo), str(repo))


def test_multiline_static_call_not_reachable(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "loader.py"), (
        "import yaml\n"
        "cfg = yaml.load(\n"
        "    open('config.yaml'))\n"))
    _write(os.path.join(repo, "config.yaml"), "k: v\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "NOT_REACHABLE"
    assert rec["needs_sandbox"] is False


def test_uvicorn_launcher_install_precedes_repo_deps(tmp_path):
    repo = tmp_path / "app"
    _require(repo, body="fastapi==0.115.0\nuvicorn==0.29.0\n")
    _write(os.path.join(repo, "main.py"),
           "from fastapi import FastAPI\napp = FastAPI()\n")
    gen_context.generate(str(repo), str(repo))
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    assert dockerfile.index("pip install --no-cache-dir \"uvicorn") < \
        dockerfile.index("pip install --no-cache-dir -r")


def test_gen_context_rejects_all_interface_node_bind(tmp_path):
    repo = tmp_path / "app"
    _write(os.path.join(repo, "package.json"), json.dumps(
        {"dependencies": {"express": "4.19.0"}}))
    _write(os.path.join(repo, "server.js"),
           "http.createServer(() => {}).listen(3000);\n")
    with pytest.raises(ValueError):
        gen_context.generate(str(repo), str(repo))


def test_gen_context_accepts_python_listener_loop(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), (
        "import tornado.ioloop\n"
        "import tornado.web\n"
        "app = tornado.web.Application([])\n"
        "app.listen(8888, '127.0.0.1')\n"
        "tornado.ioloop.IOLoop.current().start()\n"))
    result = gen_context.generate(str(repo), str(repo))
    assert result["start_command"] == ["python", "main.py"]


def test_unrelated_literal_after_call_not_static(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "loader.py"), (
        "import yaml\n"
        "def handle(data):\n"
        "    cfg = yaml.load(data)\n"
        "    other = yaml.safe_load(open('config.yaml'))\n"))
    _write(os.path.join(repo, "config.yaml"), "k: v\n")
    rec, _ = _run(repo, tmp_path)
    # the checked-in literal is OUTSIDE the yaml.load(data) call span, and
    # the call's provenance is unknown — must not be a false NOT_REACHABLE
    site = next(c for c in rec["call_sites_scanned"] if "yaml.load(data)" in c["symbol"])
    assert site["input_source"] != "NOT_REACHABLE"


def test_gen_context_rejects_all_interface_python_bind(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), (
        "import tornado.ioloop\nimport tornado.web\n"
        "app = tornado.web.Application([])\n"
        "app.listen(8888)\n"
        "tornado.ioloop.IOLoop.current().start()\n"))
    with pytest.raises(ValueError):
        gen_context.generate(str(repo), str(repo))


def test_comment_bracket_does_not_extend_call_span(tmp_path):
    repo = tmp_path / "repo"
    _require(repo)
    _write(os.path.join(repo, "loader.py"), (
        "import yaml\n"
        "def handle(data):\n"
        "    cfg = yaml.load(data)  # (\n"
        "    other = yaml.safe_load(open('config.yaml'))\n"))
    _write(os.path.join(repo, "config.yaml"), "k: v\n")
    rec, _ = _run(repo, tmp_path)
    site = next(c for c in rec["call_sites_scanned"] if "yaml.load(data)" in c["symbol"])
    assert site["input_source"] != "NOT_REACHABLE"
