"""DocuFlow — demo vulnerable app for PatchProof.

A realistic document + config service that mixes reachable and not-reachable
usages of two OSV-verified vulnerable pins:

- pyyaml==5.3.1  — GHSA-8q59-q68h-6hv4 (fixed in 5.4) — FullLoader RCE
- jinja2==3.1.5  — GHSA-cpwx-vrp4-4pq7 (fixed in 3.1.6) — sandbox escape via fmt filter

Scanner (Trivy/Grype) flags both. PatchProof proves which call sites are
actually reachable with attacker-controlled input in *this* repo.

Routes:
  POST /api/config/import  — YAML body via yaml.load(FullLoader)  [REACHABLE, exploitable]
  GET  /api/config/defaults — yaml.safe_load on checked-in file  [NOT_REACHABLE, safe]
  POST /api/render          — Jinja from JSON body via SandboxedEnvironment + fmt filter [REACHABLE]
  GET  /api/documents/{id}/export — render of checked-in template file  [NOT_REACHABLE]
  GET  /health, /api/documents, POST /api/documents, GET /api/templates
Frontend served from /frontend (static) — see frontend/ for the demo UI.
"""

import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config as cfg
from . import templates as tmpl
from .models import DocumentCreate, Document
from .utils import init_db, get_db

ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT / "frontend"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # NOT_REACHABLE example: load static YAML at startup (checked-in file, not user input)
    # This call site is present but never attacker-controlled — analyzer must mark NOT_REACHABLE.
    _defaults = cfg.load_defaults()
    yield


app = FastAPI(title="DocuFlow Demo", version="0.1.0", lifespan=lifespan)

# Serve frontend static if present (for full-stack demo video)
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def root():
    idx = FRONTEND_DIR / "index.html"
    if idx.exists():
        return HTMLResponse(idx.read_text())
    return HTMLResponse("<h1>DocuFlow</h1><p>Frontend not built — see frontend/</p>")


# --- Config: YAML (pyyaml) ---

@app.post("/api/config/import")
async def import_config(request: Request):
    """REACHABLE: FullLoader on raw HTTP body — exploitable on pyyaml==5.3.1."""
    raw = await request.body()
    try:
        data = cfg.load_user_yaml(raw)
        return {"loaded": data is not None, "keys": list(data.keys()) if isinstance(data, dict) else []}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/config/defaults")
def get_defaults():
    """NOT_REACHABLE: safe_load on checked-in file."""
    data = cfg.load_defaults()
    return {"defaults": data}


# --- Documents (DB) ---

@app.get("/api/documents")
async def list_documents():
    db = await get_db()
    cur = await db.execute("SELECT id, title, body FROM documents ORDER BY id DESC")
    rows = await cur.fetchall()
    await cur.close()
    return {"documents": [{"id": r[0], "title": r[1], "body": r[2]} for r in rows]}


@app.post("/api/documents", status_code=201)
async def create_document(doc: DocumentCreate):
    db = await get_db()
    cur = await db.execute("INSERT INTO documents (title, body) VALUES (?, ?)", (doc.title, doc.body))
    await db.commit()
    doc_id = cur.lastrowid
    await cur.close()
    return {"id": doc_id, "title": doc.title, "body": doc.body}


@app.get("/api/documents/{doc_id}")
async def get_document(doc_id: int):
    db = await get_db()
    cur = await db.execute("SELECT id, title, body FROM documents WHERE id = ?", (doc_id,))
    row = await cur.fetchone()
    await cur.close()
    if not row:
        raise HTTPException(404, "not found")
    return {"id": row[0], "title": row[1], "body": row[2]}


@app.get("/api/documents/{doc_id}/export")
async def export_document(doc_id: int):
    """NOT_REACHABLE: renders a *checked-in* template file, not user template string.

    The Jinja template path is fixed on disk (templates/invoice.html.j2), not
    attacker-controlled. Analyzer must mark this call site NOT_REACHABLE even
    though it uses the same vulnerable fmt filter.
    """
    db = await get_db()
    cur = await db.execute("SELECT title, body FROM documents WHERE id = ?", (doc_id,))
    row = await cur.fetchone()
    await cur.close()
    if not row:
        raise HTTPException(404, "not found")
    rendered = tmpl.render_fixed_template("invoice.html.j2", {"title": row[0], "body": row[1]})
    return {"rendered": rendered}


# --- Render: Jinja2 (jinja2) ---

@app.post("/api/render")
async def render(request: Request):
    """REACHABLE: user-supplied template string via JSON body — sandbox escape on jinja2==3.1.5."""
    body = await request.json()
    template_str = body.get("template", "")
    context = body.get("context", {})
    try:
        rendered = tmpl.render_user_template(template_str, context)
        return {"rendered": rendered}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/templates")
def list_templates():
    return {"templates": [p.name for p in TEMPLATES_DIR.glob("*.j2")] if TEMPLATES_DIR.exists() else []}
