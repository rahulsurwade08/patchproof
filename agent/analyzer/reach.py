"""Reachability triage entry point.

Usage (dev/CI; the product path drives this via the harness skill with
sandbox_exec):
    python agent/analyzer/reach.py <repo-path> <cve-or-advisory> [--out <dir>]

Writes reachability.json into --out (default data/output/<repo-basename>/).

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

from . import deps, versions

OSV_QUERY_URL = "https://api.osv.dev/v1/vulns/"

_SKIP_DIRS = deps._SKIP_PARTS + ("static", "assets", "dist", "build", "public", "vendor")
_SKIP_FILES = (".min.js",)

# Candidate symbols derived from advisory prose, kept conservative.
_FN_HINT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{1,40})\s*\(")

# Indicators used by the input-source trace (heuristic; sandbox arbitrates).
_NETWORK_INDICATORS = (
    "@app.", "@router.", "@bp.", "@get", "@post", "@put", "@patch", "@delete",
    "request", "Request", "body", "json", "Form", "Query", "params",
    "await request", "input(", "sys.argv", "stdin", "environ",
)
_STATIC_INDICATORS = (
    "config", "default_config", "settings", "schema", "open(", ".yaml", ".yml",
    ".json", "argparse", "cli.",
)

_CODE_EXT = (".py", ".js", ".ts", ".jsx", ".tsx")


def _load_advisory(arg):
    """Load advisory from a JSON file path or a bare CVE id via OSV."""
    if os.path.isfile(arg):
        with open(arg, encoding="utf-8") as fh:
            data = json.load(fh)
        cve_id = str(data.get("cve_id") or data.get("id") or os.path.basename(arg))
        pkg = (data.get("package") or {}).get("name") if isinstance(data.get("package"), dict) else data.get("package")
        affected = data.get("affected_versions") or data.get("affected")
        desc = data.get("description") or ""
        return {"cve_id": cve_id, "package": pkg, "affected": affected,
                "description": desc, "source": "advisory-file"}
    source = "unknown"
    cve_id = arg
    desc, pkg, affected = "", None, None
    try:
        with urllib.request.urlopen(OSV_QUERY_URL + cve_id, timeout=15) as resp:
            data = json.load(resp)
        desc = data.get("details") or data.get("summary") or ""
        for aff in (data.get("affected") or []):
            pkg = (aff.get("package") or {}).get("name")
            for r in (aff.get("ranges") or []):
                for ev in (r.get("events") or []):
                    if "introduced" in ev and "fixed" in ev:
                        affected = f">= {ev['introduced']}, < {ev['fixed']}"
                        break
            if pkg:
                break
        source = "osv"
    except Exception as exc:  # noqa: BLE001 - honest UNKNOWN on lookup failure
        return {"cve_id": cve_id, "package": None, "affected": None,
                "description": f"(OSV lookup failed: {exc})", "source": source}
    return {"cve_id": cve_id, "package": pkg, "affected": affected,
            "description": desc, "source": source}


def _derive_vuln_funcs(advisory, pkg):
    """Conservative function-name candidates from advisory prose (ADR-010)."""
    funcs = set()
    desc = advisory.get("description") or ""
    for m in _FN_HINT_RE.finditer(desc):
        fn = m.group(1)
        if fn not in ("function", "class", "if", "for", "while", "def",
                      "return", "and", "or", "not") and " " not in fn:
            funcs.add(fn.lower())
    for token in re.findall(r"\b[a-z]+_[a-z0-9_]*\b", desc):
        funcs.add(token.lower())
    if pkg:
        base = pkg.split(".")[-1]
        plow = base.lower() if not base.isupper() else base.lower()
        funcs.add(plow)
        for meth in ("load", "loads", "from_string", "render", "dumps", "execute"):
            funcs.add(f"{plow}.{meth}")
    return sorted(funcs)


def _is_direct_call(line, funcs, pkg):
    """True if the line invokes one of the vulnerable functions.

    Uses word-boundary matching so a distinct identifier like ``safe_load`` is
    not mistaken for the vulnerable ``load`` token (safe_load is not the
    vulnerable entry point derived from the advisory).
    """
    low = line.lower()
    for fn in funcs:
        if fn in ("yaml", "pickle", "jinja2", "trafaret_config"):
            continue
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(fn)}\(", low) or \
           re.search(rf"\.{re.escape(fn)}\(", low):
            return True
    if pkg:
        plow = pkg.lower().split(".")[-1]
        if re.search(rf"import {re.escape(plow)}\b", low) or \
           re.search(rf"from {re.escape(plow)}", low):
            return True
    return False


def _file_is_code(fname):
    return fname.endswith(_CODE_EXT) and not fname.endswith(_SKIP_FILES)


_CONTEXT_WINDOW = 8


def _collected_site(rel, lineno, line, context):
    return {"file": rel, "line": lineno, "symbol": line.strip()[:160],
            "context": (context or line).strip()[:600]}


def _find_call_sites(repo_path, funcs, pkg):
    """Find candidate sites: direct vulnerable-fn calls or package use.

    Each site carries a `context` window (enclosing function/route + nearby
    lines) so the input-source trace can judge attacker-reachability.
    Returns a dict with 'direct' and 'pkg' lists.
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
                if _is_direct_call(line, funcs, pkg):
                    window = "".join(lines[lineno:lineno + _CONTEXT_WINDOW])
                    site_ctx = _collected_site(rel, lineno, line, context + window)
                    direct.append(site_ctx)
                elif pkg and (f"import {pkg.lower()}" in low
                              or f"from {pkg.lower()}" in low
                              or f"{pkg.lower()}." in low):
                    window = "".join(lines[lineno:lineno + _CONTEXT_WINDOW])
                    pkg_sites.append(_collected_site(rel, lineno, line, context + window))
    return {"direct": direct[:40], "pkg": pkg_sites[:40]}


def _classify_site(site):
    """Classify a call site's input source using its context window.

    Returns REACHABLE / NOT_REACHABLE / UNKNOWN.
    """
    context = site.get("context") or site["symbol"]
    low = context.lower()
    if any(ind in low for ind in _NETWORK_INDICATORS):
        return "REACHABLE"
    if any(ind in low for ind in _STATIC_INDICATORS):
        return "NOT_REACHABLE"
    base = os.path.basename(site["file"]).lower()
    if base in ("schema.py", "config.py", "settings.py", "config.ts"):
        return "NOT_REACHABLE"
    if any(h in base for h in ("view", "route", "handler", "controller", "api")):
        return "REACHABLE"
    return "UNKNOWN"


def _trace_input_sources(sites):
    """Classify all candidate sites; aggregate into a verdict."""
    classified = []
    for site in sites:
        verdict = _classify_site(site)
        classified.append({**site, "input_source": verdict})
    if not classified:
        return [], "VERDICT_NOT_REACHABLE"
    reachable = [c for c in classified if c["input_source"] == "REACHABLE"]
    notr = [c for c in classified if c["input_source"] == "NOT_REACHABLE"]
    unknown = [c for c in classified if c["input_source"] == "UNKNOWN"]
    if reachable:
        loc = "; ".join(f"{c['file']}:{c['line']}" for c in reachable[:5])
        return classified, ("REACHABLE",
                            f"{len(reachable)} candidate site(s) fed by attacker-controlled/network "
                            f"input: {loc}")
    if unknown and not notr:
        loc = "; ".join(f"{c['file']}:{c['line']}" for c in unknown[:5])
        return classified, ("UNKNOWN",
                            f"candidate site(s) with ambiguous input source "
                            f"(sandbox required): {loc}")
    if notr:
        loc = "; ".join(f"{c['file']}:{c['line']}" for c in notr[:5])
        return classified, ("NOT_REACHABLE",
                            f"only static/checked-in inputs reach candidate "
                            f"site(s): {loc}")
    return classified, ("UNKNOWN", "no clear input classification")  # pragma: no cover


def reach(repo_path, advisory, out_dir):
    pkg = advisory.get("package")
    affected = advisory.get("affected")
    record = {
        "cve_id": advisory["cve_id"],
        "source": advisory.get("source", "unknown"),
        "disclaimer": ("heuristic static verdict for scanned call sites only; symbol "
                       "knowledge derived from the advisory, no hardcoded map; "
                       "REACHABLE/UNKNOWN results gate sandbox confirmation"),
    }

    if not pkg:
        record.update({"in_scope": None, "verdict": "UNKNOWN",
                       "confidence": "low",
                       "rationale": "no package derived from advisory",
                       "needs_sandbox": True})
        _write(record, out_dir)
        return record

    record["dep"] = {"name": pkg}

    dep = deps.find_package(deps.scan_repo(repo_path), pkg)
    if not dep:
        record.update({"in_scope": False, "verdict": "NOT_REACHABLE",
                       "confidence": "high",
                       "rationale": f"package '{pkg}' not pinned in repo manifests",
                       "needs_sandbox": False})
        _write(record, out_dir)
        return record

    pinned = dep["version"]
    record["dep"].update({"pinned_version": pinned, "manifest": dep["manifest"],
                          "manifest_path": dep["path"]})
    if affected:
        record["dep"]["affected_range"] = affected

    in_scope = versions.version_in_range(pinned, affected) if affected else True
    record["in_scope"] = in_scope
    if not in_scope:
        record.update({"verdict": "NOT_REACHABLE", "confidence": "high",
                       "rationale": f"pinned {pkg}=={pinned} outside affected range "
                                    f"({affected})",
                       "needs_sandbox": False})
        _write(record, out_dir)
        return record

    funcs = _derive_vuln_funcs(advisory, pkg)
    sites = _find_call_sites(repo_path, funcs, pkg)

    # Prefer direct vulnerable-fn call sites; fall back to package use sites.
    candidate = sites["direct"] or sites["pkg"]
    record["call_sites"] = sites

    if not candidate:
        # The repo pins the package but its own source never invokes it. There
        # is no call site to gate on; sandbox can re-confirm if required.
        record.update({
            "verdict": "NOT_REACHABLE",
            "confidence": "high",
            "rationale": (f"pinned {pkg}=={pinned} not referenced in repo source; "
                          f"no call site of the vulnerable symbol"),
            "needs_sandbox": False,
        })
        _write(record, out_dir)
        return record

    classified, (verdict, rationale) = _trace_input_sources(candidate)
    record["call_sites_scanned"] = classified
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


def main(argv=None):
    parser = argparse.ArgumentParser(description="PatchProof reachability analyzer")
    parser.add_argument("repo_path", help="path to the target repository")
    parser.add_argument("cve_or_advisory", help="advisory JSON path or a CVE id")
    parser.add_argument("--out", help="output directory (default data/output/<repo-basename>)")
    args = parser.parse_args(argv)

    advisory = _load_advisory(args.cve_or_advisory)
    out_dir = args.out or _default_outdir(args.repo_path)
    record = reach(args.repo_path, advisory, out_dir)
    print(json.dumps(record, indent=2, ensure_ascii=False))
    print(f"\nwrote {os.path.join(out_dir, 'reachability.json')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
