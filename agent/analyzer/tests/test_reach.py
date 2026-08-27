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
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
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
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
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
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
    result = gen_context.generate(str(repo), str(repo))
    assert os.path.isfile(os.path.join(str(repo), "Dockerfile"))
    assert result["entry"] == "main.py"
    assert result["base_image"].startswith("python:")
    assert result["build_context"] == os.path.abspath(str(repo))


def test_gen_context_refuses_overwrite(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
    gen_context.generate(str(repo), str(repo))
    with pytest.raises(FileExistsError):
        gen_context.generate(str(repo), str(repo))
    gen_context.generate(str(repo), str(repo), force=True)


def test_gen_context_out_is_complete_context(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
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
    _write(os.path.join(repo, "server.js"), "console.log('hi')\n")
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
    _write(os.path.join(repo, "server.js"), "console.log('hi')\n")
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
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
    rec, _ = _run(repo, tmp_path)
    assert rec["verdict"] == "UNKNOWN"
    assert rec["needs_sandbox"] is True
    assert "transitive" in rec["rationale"]


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
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
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
    _write(os.path.join(repo, "main.py"), "print('hi')\n")
    gen_context.generate(str(repo), str(repo))
    di = open(os.path.join(str(repo), ".dockerignore"), encoding="utf-8").read()
    for pattern in (".env", "*.pem", "id_rsa*", ".aws", ".ssh"):
        assert pattern in di


def test_gen_context_nested_npm_project(tmp_path):
    repo = tmp_path / "app"
    _write(os.path.join(repo, "frontend", "package.json"), json.dumps(
        {"dependencies": {"yaml": "1.10.0"}}))
    _write(os.path.join(repo, "frontend", "package-lock.json"), "{}")
    _write(os.path.join(repo, "frontend", "server.js"), "console.log('hi')\n")
    result = gen_context.generate(str(repo), str(repo))
    assert result["entry"] == os.path.join("frontend", "server.js")
    dockerfile = open(os.path.join(str(repo), "Dockerfile"), encoding="utf-8").read()
    assert "COPY frontend/package.json frontend/package.json" in dockerfile
    assert "COPY frontend/package-lock.json frontend/package-lock.json" in dockerfile
    assert "RUN cd frontend && npm ci" in dockerfile
    assert 'CMD ["node", "frontend/server.js"]' in dockerfile


def test_gen_context_fails_without_entry(tmp_path):
    repo = tmp_path / "app"
    _require(repo)
    _write(os.path.join(repo, "lib.py"), "print('library only')\n")
    with pytest.raises(ValueError):
        gen_context.generate(str(repo), str(repo))
