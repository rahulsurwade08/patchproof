"""Scenario service scaffold. Copy this folder and adjust cve-meta.json.

Replace the placeholder endpoint with the vulnerable code path named in
cve-meta.json entry_point.
"""

from fastapi import FastAPI

app = FastAPI(title="patchproof-scenario")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/config")
async def load_config(request) -> dict:
    raise NotImplementedError("implement vulnerable endpoint here")
