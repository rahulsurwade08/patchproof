from fastapi.testclient import TestClient

import app.main as main


def client():
    return TestClient(main.app)


def test_health():
    assert client().get("/health").json() == {"status": "ok"}


def test_create_and_list_documents():
    c = client()
    r = c.post("/api/documents", json={"title": "t1", "body": "b1"})
    assert r.status_code == 201
    assert c.get("/api/documents").json()["documents"]


def test_defaults():
    assert "defaults" in client().get("/api/config/defaults").json()


def test_render_user_template_safe():
    r = client().post("/api/render", json={"template": "hi {{ name }}", "context": {"name": "bob"}})
    assert r.json()["rendered"] == "hi bob"
