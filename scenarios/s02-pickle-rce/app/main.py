"""Session service vulnerable to unsafe pickle deserialization.

POST /session accepts a base64-encoded pickle blob and restores the session
from it.  pickle.loads() executes arbitrary code during deserialization —
an attacker can craft a payload that runs any Python code on the server.

Do not expose this service anywhere but a sandbox.
"""

import base64
import pickle

from fastapi import FastAPI, Request

app = FastAPI(title="session-service-s02")

MARKER = "/tmp/patchproof_pwned"


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/session")
async def restore_session(request: Request) -> dict:
    """Restore a session from a pickled blob (DELIBERATELY VULNERABLE)."""
    raw = await request.body()
    try:
        # Vulnerable: pickle.loads on untrusted input allows arbitrary code exec
        data = pickle.loads(base64.b64decode(raw))
        return {"session": data}
    except Exception as exc:
        return {"error": str(exc)}
