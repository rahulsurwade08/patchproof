"""Test suite for Jinja2 sandbox escape scenario (s04).

Tests run against a live uvicorn instance (assumed on TARGET_URL).
"""
import json
import os
import urllib.request

import pytest

TARGET = os.environ.get("TARGET_URL", "http://127.0.0.1:8000")


def _get(path: str) -> dict:
    req = urllib.request.Request(f"{TARGET}{path}")
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())


def _post(path: str, body: dict) -> dict:
    req = urllib.request.Request(
        f"{TARGET}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())


def test_health():
    resp = _get("/health")
    assert resp == {"status": "ok"}


def test_render_safe():
    resp = _post("/render", {"template": "Hello {{ name }}", "context": {"name": "world"}})
    assert resp["rendered"] == "Hello world"


def test_render_fmt_normal():
    resp = _post("/render", {"template": '{{ "Hello {}" | fmt("world") }}'})
    assert resp["rendered"] == "Hello world"


def test_render_sandbox_blocks_dunder():
    resp = _post("/render", {"template": "{{ ''.__class__ }}"})
    rendered = resp.get("rendered", "")
    assert rendered == "" or "error" in resp


def test_config_endpoint():
    resp = _post("/config", {"template": "Hello"})
    assert resp["result"] == "Hello"
