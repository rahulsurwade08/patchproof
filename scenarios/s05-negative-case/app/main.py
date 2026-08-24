"""Config service NOT vulnerable to CVE-2020-14343.

Identical dependency set and version to s01 (pyyaml==5.3.1), but the untrusted
input path uses safe_load, which never instantiates Python objects.
Demonstrates the negative case: same CVE, not exploitable in this codebase.
"""

import yaml
from fastapi import FastAPI, Request

app = FastAPI(title="config-service-s05")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/config")
async def load_config(request: Request) -> dict:
    raw = await request.body()
    # Safe: safe_load rejects python/object constructors entirely
    cfg = yaml.safe_load(raw)
    return {"loaded": cfg is not None}
