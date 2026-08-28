"""Jinja2 rendering — vulnerable fmt filter + safe fixed-template path."""

from pathlib import Path

from jinja2.sandbox import SandboxedEnvironment

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
MARKER = "/tmp/patchproof_pwned"


def format_filter(value, fmt="", **kwargs):
    """Custom filter that calls str.format() — the CVE-2024-56326 pattern.

    OSV: jinja2==3.1.5 GHSA-cpwx-vrp4-4pq7 — Fixed in 3.1.6. The sandbox's
    inspect_format_method blocks format() via call_method, but a filter that
    calls value.format() in native Python bypasses it — C-level format engine
    resolves {0.__class__...} without checks. Present in real apps.

    Patch requires BOTH: upgrade to >=3.1.6 AND rewrite filter to not call
    .format() on user input.
    """
    if fmt:
        if hasattr(value, "format"):
            return value.format(fmt, **kwargs)
        return str(value).format(fmt, **kwargs)
    return str(value)


def render_user_template(template_str: str, context: dict) -> str:
    """REACHABLE: template_str comes directly from JSON body (attacker-controlled).

    Analyzer must mark REACHABLE — this is the exploitable path.
    """
    env = SandboxedEnvironment()
    env.filters["fmt"] = format_filter
    tmpl = env.from_string(template_str)
    result = tmpl.render(**context)
    # Marker for PoC proof: if sandbox escape leaks class info, write marker
    if isinstance(result, str) and "<class" in result and "object" in result:
        nonce = context.get("nonce", "")
        try:
            with open(MARKER, "w") as fh:
                fh.write(f"sandbox_escape:{nonce}:{result}\n")
        except OSError:
            pass
    return result


def render_fixed_template(name: str, context: dict) -> str:
    """NOT_REACHABLE: template *file* is checked into git, not user-supplied.

    Even though it uses the same vulnerable fmt filter, the template source
    is static. Analyzer must mark NOT_REACHABLE (no sandbox for this site).
    Scanner still flags jinja2 pin, but PatchProof proves this site safe.
    """
    env = SandboxedEnvironment()
    env.filters["fmt"] = format_filter
    path = TEMPLATES_DIR / name
    tmpl = env.from_string(path.read_text())
    return tmpl.render(**context)
