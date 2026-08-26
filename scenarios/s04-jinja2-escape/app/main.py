"""Jinja2 sandbox escape scenario (CVE-2024-56326).

Vulnerable Jinja2 version (3.1.2) with a custom filter that calls str.format(),
allowing an attacker to bypass the sandbox and execute arbitrary code.

The filter calls value.format() in native Python — the sandbox only intercepts
format() calls made through Jinja2's call_method. Patching requires BOTH
upgrading jinja2 AND rewriting the filter to avoid direct .format() calls.
"""

import os

from fastapi import FastAPI, Request
from jinja2.sandbox import SandboxedEnvironment

app = FastAPI(title="patchproof-scenario")

MARKER = "/tmp/patchproof_pwned"


def format_filter(value, fmt="", **kwargs):
    """Custom filter that calls str.format() — common pattern in real apps.

    CVE-2024-56326: the sandbox only intercepts format() calls made through
    Jinja2's call_method.  When the filter invokes value.format() directly,
    Python's C-level format engine resolves ``{0.__class__…}`` without ever
    touching the sandbox, breaking out completely.

    Patch: must rewrite filter to NOT call .format() on user input, AND
    upgrade jinja2 to >=3.1.5 which adds inspect_format_method.
    """
    if fmt:
        if hasattr(value, "format"):
            return value.format(fmt, **kwargs)
        return str(value).format(fmt, **kwargs)
    return str(value)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/render")
async def render_template(request: Request) -> dict:
    body = await request.json()
    template_str = body.get("template", "")
    context = body.get("context", {})

    env = SandboxedEnvironment()
    env.filters["fmt"] = format_filter

    try:
        tmpl = env.from_string(template_str)
        result = tmpl.render(**context)
        return {"rendered": result}
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/config")
async def load_config(request: Request) -> dict:
    body = await request.json()
    template_str = body.get("template", "")

    env = SandboxedEnvironment()
    env.filters["fmt"] = format_filter

    try:
        tmpl = env.from_string(template_str)
        result = tmpl.render()
        return {"result": result}
    except Exception as exc:
        return {"error": str(exc)}
