"""Reachability triage entry point.

Usage (dev/CI; the product path drives this via the harness skill with
sandbox_exec):
    python agent/analyzer/reach.py <repo-path> <cve-or-advisory> [--out <dir>]
    python -m agent.analyzer.reach <repo-path> <cve-or-advisory> [--out <dir>]

    # Auto-discovery mode: find all CVEs affecting repo packages
    python agent/analyzer/reach.py --discover <repo-path> [--out <dir>]

Writes reachability.json into --out (default data/output/<repo-basename>/).
For --discover, writes discovered_cves.json instead.

Triage pipeline: dep-pin short-circuit -> call-site scan -> input-source trace.

Honesty rules (ADR-010):
  - All symbol/range knowledge comes from the advisory (file or OSV) at
    runtime; nothing is hardcoded into this tool.
  - NOT_REACHABLE requires identifying a non-attacker-controlled input source
    (e.g. a checked-in config file parsed at startup).
  - Ambiguous input sources are UNKNOWN, which gates sandbox time rather than
    assuming safe. The sandbox is the arbiter, never this heuristic.
"""

import argparse
import json
import os
import re
import sys
import urllib.request

if __package__ in (None, ""):  # direct-file execution: make the package importable
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    from agent.analyzer import deps, versions
else:
    from . import deps, versions

OSV_QUERY_URL = "https://api.osv.dev/v1/vulns/"
CVEORG_QUERY_URL = "https://cveawg.mitre.org/api/cve/"

_SKIP_DIRS = deps._SKIP_PARTS + ("static", "assets", "dist", "build", "public", "vendor")
_SKIP_FILES = (".min.js",)

# Candidate symbols derived from advisory prose, kept conservative.
_FN_HINT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{1,40})\s*\(")

# Input-source trace (heuristic; the sandbox arbitrates). NETWORK provenance
# must match a concrete source expression (_NETWORK_RES); STATIC evidence
# requires a quoted file-path literal whose file exists in the repo (see
# _checked_in_file_literal). Variable or function NAMES prove nothing.

_CODE_EXT = (".py", ".js", ".ts", ".jsx", ".tsx")
_SERIALIZATION_CAP = 40


def _osv_affected_packages(affected_list):
    """Normalize an OSV `affected` array into [{"name", "ranges": [...]}].

    Range events are ordered introduced/fixed pairs (one per event object),
    assembled into `>= x, < y` interval strings; an open-ended introduced
    becomes `""` (all versions) or `>= x`.
    """
    packages = []
    for aff in affected_list or []:
        name = (aff.get("package") or {}).get("name")
        if not name:
            continue
        ecosystem = (aff.get("package") or {}).get("ecosystem") or ""
        versions = [str(v) for v in (aff.get("versions") or [])]
        ranges = []
        for r in (aff.get("ranges") or []):
            introduced = None
            for ev in (r.get("events") or []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                elif introduced is not None and ("fixed" in ev or "limit" in ev
                                                 or "last_affected" in ev):
                    if "last_affected" in ev:
                        # OSV last_affected is an INCLUSIVE ceiling
                        ranges.append(f">= {introduced}, <= {ev['last_affected']}")
                    else:
                        hi = ev.get("fixed", ev.get("limit"))
                        ranges.append(f">= {introduced}, < {hi}")
                    introduced = None
            if introduced is not None:
                ranges.append("" if introduced == "0" else f">= {introduced}")
        packages.append({"name": name, "ranges": ranges,
                         "versions": versions,
                         "ecosystem": ecosystem})
    return packages


def _load_advisory(arg):
    """Load advisory from a JSON file path or a bare CVE id via OSV.

    Returns {"cve_id", "source", "description", "packages": [{"name",
    "ranges": [range-str, ...]}]}. Empty range string means "all versions".
    """
    if os.path.isfile(arg):
        with open(arg, encoding="utf-8") as fh:
            data = json.load(fh)
        cve_id = str(data.get("cve_id") or data.get("id") or os.path.basename(arg))
        raw_pkg = (data.get("package") or data.get("affected_package")
                   or data.get("dependency"))
        if isinstance(raw_pkg, dict):
            raw_pkg = raw_pkg.get("name")
        if isinstance(data.get("affected"), list):
            # OSV-shaped record, e.g. written from the cve-feed MCP tools
            # (osv_get_vuln): {"id", "summary", "affected": [{package, ranges}]}
            packages = _osv_affected_packages(data["affected"])
            return {"cve_id": cve_id, "source": "advisory-file-osv",
                    "description": data.get("summary")
                    or data.get("description") or "",
                    "packages": packages}
        affected = (data.get("affected_versions") or data.get("affected")
                    or data.get("affected_range") or "")
        if not isinstance(affected, str):
            affected = ""
        packages = [{"name": raw_pkg, "ranges": [affected]}] if raw_pkg else []
        desc = (data.get("description") or data.get("summary") or "")
        return {"cve_id": cve_id, "source": "advisory-file",
                "description": desc, "packages": packages}

    cve_id = arg
    source = "unknown"
    desc = ""
    cveorg_state = None
    # Dual-source legitimacy (ADR-010): a bare CVE id is only trusted when
    # CVE.org has a PUBLISHED record; otherwise fail closed to UNKNOWN.
    try:
        with urllib.request.urlopen(CVEORG_QUERY_URL + cve_id, timeout=15) as resp:
            cve_data = json.load(resp)
        cveorg_state = (cve_data.get("cveMetadata") or {}).get("state")
        if not desc:
            containers = cve_data.get("containers") or {}
            cna_desc = ((containers.get("cna") or {}).get("descriptions") or [{}])
            desc = cna_desc[0].get("value", "") if cna_desc else ""
    except Exception as exc:  # noqa: BLE001 - fail closed on CVE.org errors
        return {"cve_id": cve_id, "source": "unverified", "packages": [],
                "description": f"(CVE.org lookup failed: {exc})",
                "verified": {"cveorg": False, "osv": False}}
    if cveorg_state != "PUBLISHED":
        return {"cve_id": cve_id, "source": "unverified", "packages": [],
                "description": f"CVE.org record state={cveorg_state!r}; "
                               f"advisory not accepted without a PUBLISHED record",
                "verified": {"cveorg": False, "osv": False}}
    try:
        with urllib.request.urlopen(OSV_QUERY_URL + cve_id, timeout=15) as resp:
            data = json.load(resp)
        desc = data.get("details") or data.get("summary") or desc
        packages = _osv_affected_packages(data.get("affected"))
        source = "cveorg+osv"
    except Exception as exc:  # noqa: BLE001 - honest UNKNOWN on lookup failure
        return {"cve_id": cve_id, "source": source, "packages": [],
                "description": f"(OSV lookup failed: {exc})",
                "verified": {"cveorg": True, "osv": False}}
    return {"cve_id": cve_id, "source": source, "description": desc,
            "packages": packages, "verified": {"cveorg": True, "osv": True}}


def _derive_vuln_funcs(advisory, pkg):
    """Conservative function-name candidates from advisory prose (ADR-010)."""
    funcs = set()
    desc = advisory.get("description") or ""
    for m in _FN_HINT_RE.finditer(desc):
        fn = m.group(1)
        if fn not in ("function", "class", "if", "for", "while", "def",
                      "return", "and", "or", "not"):
            funcs.add(fn.lower())
    for token in re.findall(r"\b[a-z]+_[a-z0-9_]*\b", desc):
        funcs.add(token.lower())
    if pkg:
        plow = pkg.lower().split(".")[-1]
        funcs.add(plow)
        for meth in ("load", "loads", "from_string", "render", "dumps", "execute"):
            funcs.add(f"{plow}.{meth}")
    return sorted(funcs)


def _is_direct_call(line, funcs, pkg):
    """True if the line invokes one of the vulnerable functions or the package.

    Word-boundary matching keeps distinct identifiers like ``safe_load`` from
    matching the vulnerable ``load`` token. Recognizes Python import forms and
    CommonJS ``require()``/dynamic ``import()``.
    """
    low = line.lower()
    for fn in funcs:
        if fn in ("yaml", "pickle", "jinja2", "trafaret_config"):
            continue
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(fn)}\(", low) or \
           re.search(rf"\.{re.escape(fn)}\(", low):
            return True
    if pkg:
        plow = re.escape(pkg.lower().split(".")[-1])
        if re.search(rf"import {plow}\b", low) or re.search(rf"from {plow}\b", low) or \
           re.search(rf"""require\(['"]{plow}['"]\)""", low) or \
           re.search(rf"""import\(['"]{plow}['"]\)""", low):
            return True
    return False


def _is_pkg_reference(line, pkg):
    low = line.lower()
    plow = pkg.lower().split(".")[-1]
    return (f"import {plow}" in low or f"from {plow}" in low or f"{plow}." in low or
            f"require('{plow}')" in low or f'require("{plow}")' in low)


def _file_is_code(fname):
    return fname.endswith(_CODE_EXT) and not fname.endswith(_SKIP_FILES)


_CONTEXT_WINDOW = 8


def _call_span(lines, lineno, lang="py", max_lines=30):
    """Return the vulnerable call's actual expression text: the call line
    plus continuation lines until delimiters balance. String literals,
    escapes, and COMMENTS (py #..., js //... and /*...*/) are skipped while
    counting, so bracket characters in comments cannot extend the span."""
    span = [lines[lineno - 1]]
    state = {"quote": None, "block": False}

    def net_depth(text, depth):
        i = 0
        while i < len(text):
            ch = text[i]
            if state["block"]:
                if text[i:i + 2] == "*/":
                    state["block"] = False
                    i += 2
                    continue
                i += 1
                continue
            if state["quote"]:
                if ch == "\\":
                    i += 2
                    continue
                if ch == state["quote"]:
                    state["quote"] = None
                i += 1
                continue
            if lang == "js" and text[i:i + 2] in ("//", "/*"):
                if text[i:i + 2] == "/*":
                    state["block"] = True
                    i += 2
                    continue
                return depth  # // comment: rest of line ignored
            if lang == "py" and ch == "#":
                return depth  # comment: rest of line ignored
            if ch in "'\"":
                state["quote"] = ch
                i += 1
                continue
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            i += 1
        return depth

    depth = net_depth(span[0], 0)
    if depth > 0:
        for line in lines[lineno:lineno - 1 + max_lines]:
            span.append(line)
            depth = net_depth(line, depth)
            if depth <= 0:
                break
    return "".join(span)


def _collected_site(rel, lineno, line, context, call_span):
    return {"file": rel, "line": lineno, "symbol": line.strip()[:160],
            "context": (context or line).strip()[:600],
            "call_span": (call_span or line).strip()[:800]}


def _find_call_sites(repo_path, funcs, pkg):
    """Find candidate sites: direct vulnerable-fn/package calls.

    Every candidate is classified before any cap is applied; only the
    serialized report is truncated.
    """
    direct, pkg_sites = [], []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            if not _file_is_code(fname):
                continue
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, repo_path)
            try:
                with open(full, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            context = ""
            for lineno, line in enumerate(lines, 1):
                low = line.lower()
                if low.lstrip().startswith(("def ", "async def ", "@app.", "@router.", "@bp.")):
                    context = line
                window = "".join(lines[lineno:lineno + _CONTEXT_WINDOW])
                # Continuation lines: a multiline call's own arguments live
                # here, so checked-in literals on them count for the call.
                lang = "js" if fname.endswith((".js", ".ts", ".jsx", ".tsx")) else "py"
                span = _call_span(lines, lineno, lang)
                if _is_direct_call(line, funcs, pkg):
                    direct.append(_collected_site(rel, lineno, line, context + window, span))
                elif pkg and _is_pkg_reference(line, pkg):
                    pkg_sites.append(_collected_site(rel, lineno, line, context + window, span))
    return direct, pkg_sites


_STATIC_EXT_RE = re.compile(r"['\"]([^'\"]*?\.(?:yaml|yml|json))['\"]")

# Concrete source expressions for attacker-controlled provenance — matched as
# identifiers/attribute calls, never as bare substrings (a checked-in
# filename like body.yaml must not read as request provenance).
_NETWORK_RES = tuple(re.compile(p) for p in (
    r"@app\.(get|post|put|patch|delete)\b", r"@router\.", r"@bp\.",
    r"@\w*\.(get|post|put|patch|delete)\(",
    r"\bawait\s+request\b", r"\brequest\.(body|json|form|args|data|files|"
    r"values|stream|GET|POST|cookies|headers)\b",
    r":\s*Request\b", r"\(Request\)",
    r"\bdef\s+\w+\([^)]*\brequest\b[^)]*\)",
    r"\(\s*request\s*[,)]",
    r"\bsys\.argv\b", r"\bstdin\b", r"\bos\.environ\b", r"\bgetenv\(",
    r"\binput\(",
))


def _checked_in_file_literal(context, site_rel, repo_path):
    """True if the context quotes a relative file path with a static-data
    extension AND exactly that file exists inside the repo.

    Rejects absolute paths and parent traversal; resolves the quoted path
    against the site's directory and the repo root — no basename guessing —
    and requires the resolved file to stay inside the repository.
    """
    m = _STATIC_EXT_RE.search(context)
    if not m:
        return False
    quoted = m.group(1)
    if os.path.isabs(quoted) or ".." in quoted.split(os.sep) + quoted.split("/"):
        return False
    site_dir = os.path.dirname(os.path.join(repo_path, site_rel))
    for base in (site_dir, repo_path):
        resolved = os.path.realpath(os.path.join(base, quoted))
        if os.path.isfile(resolved) and \
                os.path.commonpath([resolved, repo_path]) == str(repo_path):
            return True
    return False


def _classify_site(site, repo_path):
    """Classify a call site's input source.

    Returns REACHABLE / NOT_REACHABLE / UNKNOWN. Static evidence is tied to
    the vulnerable call's own line (a quoted checked-in file literal in the
    call arguments); network provenance matches concrete source expressions
    anywhere in the context window. When both appear — or neither does — the
    site is UNKNOWN: conflicting or missing evidence never disables
    sandboxing.
    """
    call_line = site["symbol"]
    context = site.get("context") or call_line
    # Static evidence covers the vulnerable call's own expression span
    # (balanced delimiters), NOT the whole window.
    has_static = _checked_in_file_literal(
        site.get("call_span") or call_line, site["file"], repo_path)
    has_network = any(rx.search(context) for rx in _NETWORK_RES)
    if has_static and has_network:
        return "UNKNOWN"
    if has_static:
        return "NOT_REACHABLE"
    if has_network:
        return "REACHABLE"
    return "UNKNOWN"


def _trace_input_sources(sites, repo_path):
    """Classify all candidate sites; aggregate into a verdict.

    Any REACHABLE site dominates. Any UNKNOWN site gates sandbox time —
    ambiguous sites never collapse into a static NOT_REACHABLE.
    """
    classified = []
    for site in sites:
        classified.append({**site, "input_source": _classify_site(site, repo_path)})
    if not classified:
        return classified, ("UNKNOWN", "no candidate sites found in repo source")
    reachable = [c for c in classified if c["input_source"] == "REACHABLE"]
    unknown = [c for c in classified if c["input_source"] == "UNKNOWN"]
    notr = [c for c in classified if c["input_source"] == "NOT_REACHABLE"]

    def _loc(items):
        return "; ".join(f"{c['file']}:{c['line']}" for c in items[:5])

    if reachable:
        return classified, ("REACHABLE",
                            f"{len(reachable)} candidate site(s) fed by attacker-controlled/"
                            f"network input: {_loc(reachable)}")
    if unknown:
        return classified, ("UNKNOWN",
                            f"{len(unknown)} candidate site(s) with ambiguous input source "
                            f"(sandbox required): {_loc(unknown)}")
    return classified, ("NOT_REACHABLE",
                        f"only checked-in file inputs reach candidate site(s): {_loc(notr)}")


def _select_dep(repo_path, packages):
    """Pick the advisory package/manifest entry the repo actually pins.

    Returns (pkg_name, dep_entry, scan, ranges, status) using repository
    evidence rather than advisory order. Every manifest declaration of a
    package is considered (none discarded); a declaration without an exact
    pin is version-unknown, never absent.
    """
    scan = deps.scan_repo(repo_path)
    in_scope = out_scope = unknown = None
    for adv in packages:
        ranges = list(adv["ranges"] or [])
        versions_list = adv.get("versions") or []
        eco = (adv.get("ecosystem") or "").strip().lower()
        # Ecosystem-aware lookup: same-named package from another ecosystem
        # must not be evaluated against this advisory. Empty ecosystem is
        # unrestricted (advisory-file path); unsupported non-empty ecosystems
        # match nothing — they must not cross-match Python/npm manifests.
        if eco in ("pypi", "pip", "python"):
            # Python: collect Python-manifest entries via both identity keys,
            # not find_package's npm-first order which can hide the PEP 503
            # normalized entry behind an npm entry for the same raw name.
            seen = set()
            entries = []
            for key in {deps._normalize(adv["name"]), deps._npm_key(adv["name"])}:
                for e in scan.get(key, []) or []:
                    if e["manifest"] != "package.json" and id(e) not in seen:
                        seen.add(id(e))
                        entries.append(e)
        elif eco == "npm":
            entries = [e for e in (scan.get(deps._npm_key(adv["name"]), []) or [])
                       if e["manifest"] == "package.json"]
        elif eco == "":
            entries = deps.find_package(scan, adv["name"]) or []
        else:
            entries = []
        for entry in entries:
            if not entry["pinned"]:
                if unknown is None:
                    unknown = (adv["name"], entry, scan, ranges, "unknown")
                continue
            # OSV: version affected if enumerated OR in any listed range.
            # "" sentinel from _osv_affected_packages means all versions.
            by_versions = any(
                versions.version_in_range(entry["version"], f"== {v}")
                for v in versions_list) if versions_list else False
            if "" in ranges:
                by_ranges = True
            else:
                by_ranges = any(versions.version_in_range(entry["version"], r)
                                for r in ranges) if ranges else False
            if versions_list or ranges:
                affected = by_versions or by_ranges
            else:
                affected = True
            if affected and in_scope is None:
                in_scope = (adv["name"], entry, scan, ranges, "in-scope")
            elif not affected and out_scope is None:
                out_scope = (adv["name"], entry, scan, ranges, "out-of-scope")
    for state in (in_scope, unknown, out_scope):
        if state:
            return state
    return None, None, scan, [], "absent"


def reach(repo_path, advisory, out_dir):
    # Normalize once: realpath comparisons inside the trace require an
    # absolute root, and relative CLI args (".", "sub/../repo") must not
    # crash the containment check.
    repo_path = os.path.realpath(os.path.abspath(repo_path))
    packages = advisory.get("packages") or []
    record = {
        "cve_id": advisory["cve_id"],
        "source": advisory.get("source", "unknown"),
        "verified": advisory.get("verified"),
        "disclaimer": ("heuristic static verdict for scanned call sites only; symbol "
                       "knowledge derived from the advisory, no hardcoded map; "
                       "REACHABLE/UNKNOWN gate sandbox confirmation; import aliases "
                       "and transitive dependency-internal usage are not traced — "
                       "sandbox re-confirmation is available for any verdict"),
    }

    if not packages:
        record.update({"in_scope": None, "verdict": "UNKNOWN", "confidence": "low",
                       "rationale": "no package derivable from advisory",
                       "needs_sandbox": True})
        _write(record, out_dir)
        return record

    pkg, dep, _scan, ranges, status = _select_dep(repo_path, packages)
    record["advisory_packages"] = [p["name"] for p in packages]

    if status == "absent":
        names = ", ".join(p["name"] for p in packages)
        record.update({"dep": None, "in_scope": False, "verdict": "NOT_REACHABLE",
                       "confidence": "high",
                       "rationale": f"no affected package ({names}) pinned in repo manifests",
                       "needs_sandbox": False})
        _write(record, out_dir)
        return record

    record["dep"] = {"name": pkg, "manifest": dep["manifest"],
                     "manifest_path": dep["path"], "spec": dep["spec"]}
    if ranges:
        record["dep"]["affected_ranges"] = ranges

    if status == "unknown":
        record.update({"in_scope": None, "verdict": "UNKNOWN", "confidence": "low",
                       "rationale": (f"{pkg} declared with non-exact spec "
                                     f"'{dep['spec']}'; installed version unknown "
                                     f"(resolve lockfile or confirm in sandbox)"),
                       "needs_sandbox": True})
        _write(record, out_dir)
        return record

    if status == "out-of-scope":
        record.update({"in_scope": False, "verdict": "NOT_REACHABLE",
                       "confidence": "high",
                       "rationale": f"pinned {pkg}=={dep['version']} outside affected "
                                    f"range ({'; '.join(ranges)})",
                       "needs_sandbox": False})
        _write(record, out_dir)
        return record

    record["dep"]["pinned_version"] = dep["version"]
    record["in_scope"] = True

    funcs = _derive_vuln_funcs(advisory, pkg)
    direct, pkg_sites = _find_call_sites(repo_path, funcs, pkg)

    # Direct vulnerable calls first; package references as fallback. All sites
    # are classified before any cap; only the report is truncated.
    candidate = direct or pkg_sites
    record["call_sites"] = {"direct": direct[:_SERIALIZATION_CAP],
                            "pkg": pkg_sites[:_SERIALIZATION_CAP],
                            "totals": {"direct": len(direct), "pkg": len(pkg_sites)}}

    if not candidate:
        # The repo pins the package but its own source never references it.
        # Absence of a direct repo call is insufficient to disable sandboxing:
        # an installed dependency can invoke the vulnerable symbol internally
        # on application-controlled input. Fail open to the sandbox.
        record.update({
            "verdict": "UNKNOWN",
            "confidence": "low",
            "rationale": (f"pinned {pkg}=={dep['version']} not referenced in repo "
                          f"source; transitive dependency-internal usage is not "
                          f"traced by static analysis — sandbox confirmation "
                          f"required"),
            "needs_sandbox": True,
        })
        _write(record, out_dir)
        return record

    classified, (verdict, rationale) = _trace_input_sources(candidate, repo_path)
    record["call_sites_scanned"] = classified[:_SERIALIZATION_CAP]
    record.update({
        "verdict": verdict,
        "confidence": "high" if verdict == "NOT_REACHABLE" else (
            "medium" if verdict == "REACHABLE" else "low"),
        "rationale": rationale,
        "needs_sandbox": verdict in ("REACHABLE", "UNKNOWN"),
    })
    _write(record, out_dir)
    return record


def _write(record, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "reachability.json"), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, ensure_ascii=False)


def _default_outdir(repo_path):
    return os.path.join("data", "output", os.path.basename(os.path.abspath(repo_path)))


_OSV_API = "https://api.osv.dev/v1/query"
_ECOSYSTEM_MAP = {
    "pypi": "PyPI", "pip": "PyPI", "python": "PyPI",
    "npm": "npm", "yarn": "npm",
    "go": "Go", "cargo": "cargo",
}


def _ecosystem_for(pkg_name, scan):
    """Determine the OSV ecosystem name for a package based on its manifest entries.

    Python packages (from requirements.txt, pyproject.toml) map to PyPI.
    npm packages (from package.json) map to npm.
    """
    entries = scan.get(pkg_name, [])
    for e in entries:
        manifest = e.get("manifest", "")
        if manifest in ("requirements", "pyproject.toml"):
            return "PyPI"
        elif manifest == "package.json":
            return "npm"
    # Defaults: try Python first, then npm
    normalized = deps._normalize(pkg_name)
    if normalized in scan:
        return "PyPI"
    return "npm"


def discover_cves(repo_path):
    """Auto-discover CVEs in a repo by querying OSV for each declared package.

    Returns a sorted list of CVE dicts:
        [{"cve_id": "CVE-YYYY-NNNN", "package": "name", "version": "x.y.z",
          "summary": "...", "aliases": [...], "affected": true/false}]

    Fails closed: if OSV lookup returns an error, the package is skipped
    silently (no CVEs reported for it). Network errors are logged to stderr
    once per package, not per call.
    """
    found = deps.scan_repo(repo_path)
    if not found:
        return []

    discovered = {}
    seen_packages = set()
    for pkg_name, entries in found.items():
        # Pick the first pinned version if available; otherwise any version
        version = None
        for e in entries:
            if e.get("pinned") and e.get("version"):
                version = e["version"]
                break

        # Query once per package (not once per entry) to avoid N+1 calls
        if pkg_name in seen_packages:
            continue
        seen_packages.add(pkg_name)

        ecosystem = _ecosystem_for(pkg_name, found)
        vulns = _osv_query_package(ecosystem, pkg_name, version)
        for vuln in vulns:
            cve_id = _extract_cve_id(vuln)
            if cve_id is None:
                continue
            key = (cve_id, pkg_name)
            if key in discovered:
                continue
            # Determine if the pinned version is actually in the
            # affected range. If no version is pinned, mark as unknown.
            in_range = _version_in_affected_ranges(
                version, vuln.get("affected", []), pkg_name, ecosystem
            ) if version else None
            discovered[key] = {
                "cve_id": cve_id,
                "package": pkg_name,
                "version": version or "unknown",
                "summary": vuln.get("summary", ""),
                "aliases": vuln.get("aliases", []),
                "affected": in_range if in_range is not None else True,
            }

    return sorted(discovered.values(), key=lambda x: (x["cve_id"], x["package"]))


def _version_in_affected_ranges(version, affected_list, pkg_name, ecosystem):
    """Check if a version falls in any of the affected ranges for the package.

    Returns True/False, or None if the version can't be compared (e.g. the
    affected list has no ranges for this ecosystem/package).
    """
    for aff in affected_list or []:
        pkg = aff.get("package") or {}
        if pkg.get("name", "").lower() != pkg_name.lower():
            continue
        if pkg.get("ecosystem", "") and pkg["ecosystem"] != ecosystem:
            continue
        for r in aff.get("ranges") or []:
            events = r.get("events") or []
            introduced = None
            fixed = None
            for ev in events:
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
            if introduced is None and fixed is None:
                continue
            try:
                from agent.analyzer.versions import version_in_range
                range_spec = (f">={introduced}" if introduced else ">=0") + (
                    f",<{fixed}" if fixed else ""
                )
                if version_in_range(version, range_spec):
                    return True
            except Exception:
                continue
        return False
    return None


def _extract_cve_id(vuln):
    """Extract the primary CVE ID from an OSV vulnerability record.

    OSV IDs are like GHSA-xxx or PYSEC-yyy. We prefer the CVE alias.
    """
    aliases = vuln.get("aliases", [])
    for alias in aliases:
        if alias.startswith("CVE-"):
            return alias
    return None


def _osv_query_package(ecosystem, name, version=None):
    """Query OSV.dev for vulnerabilities affecting a package.

    Uses the standard OSV query API (same data source as the cve-feed MCP).
    Returns a list of vuln dicts with at least {"id", "aliases", "summary"}.
    Logs to stderr on network/parse errors; returns [] so the caller treats
    a failed lookup as "no CVEs found" (fail-closed for discover_cves).
    """
    if version:
        query = {
            "version": version,
            "package": {"name": name, "ecosystem": ecosystem},
        }
    else:
        query = {
            "package": {"name": name, "ecosystem": ecosystem},
        }

    try:
        req = urllib.request.Request(
            _OSV_API,
            data=json.dumps(query).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        vulns = data.get("vulns") or []
        if not isinstance(vulns, list):
            print(f"OSV query for {ecosystem}/{name}@{version or 'any'}: "
                  f"unexpected response type {type(vulns).__name__}; skipping",
                  file=sys.stderr)
            return []
        return vulns
    except Exception as exc:
        print(f"OSV query for {ecosystem}/{name}@{version or 'any'}: {exc}; "
              f"skipping (fail-closed)", file=sys.stderr)
        return []


def _osv_fetch_vuln(vuln_id):
    """Fetch a full OSV vulnerability record by ID."""
    try:
        with urllib.request.urlopen(
            OSV_QUERY_URL + vuln_id, timeout=15
        ) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _handle_discover(args):
    """Auto-discover CVEs from repo packages via OSV.dev.

    Scans every manifest in the repo for declared packages, then queries
    OSV.dev for each. Writes the deduplicated CVE list to
    <out>/discovered_cves.json. Print a short summary to stdout.
    """
    repo_path = args.repo_path
    if not repo_path or not os.path.isdir(repo_path):
        print(f"Error: {repo_path} is not a valid directory", file=sys.stderr)
        sys.exit(1)

    cves = discover_cves(repo_path)
    out_dir = args.out or _default_outdir(repo_path)
    os.makedirs(out_dir, exist_ok=True)

    print(f"Found {len(cves)} CVEs across {len(set(c['package'] for c in cves))} packages:")
    for cve in cves:
        print(f"  {cve['cve_id']} in {cve['package']} (v{cve['version']})")

    outfile = os.path.join(out_dir, "discovered_cves.json")
    with open(outfile, "w", encoding="utf-8") as fh:
        json.dump(cves, fh, indent=2, ensure_ascii=False)

    print(f"\nWrote {len(cves)} CVEs to {outfile}", file=sys.stderr)


def _handle_regular(args):
    """Original mode: analyze a specific CVE/advisory against the repo."""
    repo_path = args.repo_path
    advisory_path = args.cve_or_advisory
    if not repo_path or not advisory_path:
        print("Error: repo_path and cve_or_advisory required", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(repo_path):
        print(f"Error: {repo_path} is not a valid directory", file=sys.stderr)
        sys.exit(1)

    advisory = _load_advisory(advisory_path)
    out_dir = args.out or _default_outdir(repo_path)
    record = reach(repo_path, advisory, out_dir)
    print(json.dumps(record, indent=2, ensure_ascii=False))
    print(f"\nwrote {os.path.join(out_dir, 'reachability.json')}", file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description="PatchProof reachability analyzer")
    parser.add_argument("repo_path", nargs="?", default=None, help="path to the target repository")
    parser.add_argument("cve_or_advisory", nargs="?", default=None, help="advisory JSON path or a CVE id")
    parser.add_argument("--out", help="output directory (default data/output/<repo-basename>)")
    parser.add_argument("--discover", action="store_true", default=False,
                        help="auto-discover CVEs from repo packages via OSV.dev")
    args = parser.parse_args(argv)

    if args.discover:
        _handle_discover(args)
    else:
        _handle_regular(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
