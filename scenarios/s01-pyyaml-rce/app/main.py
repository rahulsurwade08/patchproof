"""Config service vulnerable to CVE-2020-14343.

POST /config loads an untrusted YAML body with FullLoader on PyYAML 5.3.1.
FullLoader was believed safe; CVE-2020-14343 is the bypass that yields
arbitrary code execution. Do not expose this service anywhere but a sandbox.
"""

import yaml
from fastapi import FastAPI, Request

app = FastAPI(title="config-service-s01")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/config")
async def load_config(request: Request) -> dict:
    raw = await request.body()
    # Vulnerable: FullLoader on untrusted input (CVE-2020-14343, pyyaml<=5.3.1)
    cfg = yaml.load(raw, Loader=yaml.FullLoader)
    return {"loaded": cfg is not None}
