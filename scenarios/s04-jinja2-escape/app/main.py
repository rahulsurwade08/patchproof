"""Jinja2 sandbox escape scenario (CVE-2024-56326).

Vulnerable Jinja2 version (3.1.2) with a custom filter that calls
str.format() on user input.

CVE-2024-56326: the sandbox's ``call_method`` has ``inspect_format_method``
which blocks format-spec attribute access when ``.format()`` is called through
the sandbox.  But a custom filter calling ``value.format()`` in native Python
bypasses the sandbox entirely — the C-level format engine resolves
``{0.__class__.__mro__}`` without any sandbox checks.

Patch: upgrade jinja2>=3.1.5 (strengthens ``inspect_format_method``) AND
rewrite the filter to not call ``.format()`` on user input.
"""

from fastapi import FastAPI, Request
from jinja2.sandbox import SandboxedEnvironment

app = FastAPI(title="patchproof-scenario")


def format_filter(value, fmt="", **kwargs):
    """Custom filter that calls str.format() — common pattern in real apps.

    CVE-2024-56326: the sandbox only intercepts format() calls made through
    Jinja2's call_method.  When the filter invokes value.format() directly,
    Python's C-level format engine resolves ``{0.__class__…}`` without ever
    touching the sandbox, breaking out completely.

    Patch: must rewrite filter to NOT call .format() on user input, AND
    upgrade jinja2 to >=3.1.5 which strengthens inspect_format_method.
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
