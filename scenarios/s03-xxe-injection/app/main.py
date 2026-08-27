"""Document parser service vulnerable to XXE (XML External Entity).

POST /parse accepts XML input and returns the parsed content.  Using
lxml with default settings (resolve_entities=True), external entity
references are expanded — allowing an attacker to read local files or
cause SSRF.

Do not expose this service anywhere but a sandbox.
"""

from fastapi import FastAPI, Request
from lxml import etree

app = FastAPI(title="doc-parser-s03")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/parse")
async def parse_xml(request: Request) -> dict:
    """Parse XML input (DELIBERATELY VULNERABLE to XXE)."""
    raw = await request.body()
    try:
        # Vulnerable: lxml resolves external entities by default
        tree = etree.fromstring(raw)
        # Extract all text content (entity expansion happens during parsing)
        text = etree.tostring(tree, encoding="unicode", pretty_print=True)
        return {"parsed": text[:2000]}
    except Exception as exc:
        return {"error": str(exc)}
