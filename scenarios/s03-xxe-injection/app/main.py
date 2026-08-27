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
        # Vulnerable: explicit parser with resolve_entities=True.
        # lxml >= 5.0 changed the default to False; this service deliberately
        # enables it to demonstrate the XXE vulnerability class.
        parser = etree.XMLParser(resolve_entities=True)
        tree = etree.fromstring(raw, parser)
        # Extract all text content (entity expansion happens during parsing)
        text = etree.tostring(tree, encoding="unicode", pretty_print=True)
        return {"parsed": text[:2000]}
    except Exception as exc:
        return {"error": str(exc)}
