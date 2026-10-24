import os

os.environ.setdefault("CYBER_AGENT_CODE", "test-code")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)
CODE = {"X-Access-Code": "test-code"}


def test_health_open():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["app"] == "cyber-agent"


def test_chat_requires_code():
    r = client.post("/api/chat", json={"message": "hello"})
    assert r.status_code == 401


def test_chat_hard_block_refused():
    r = client.post("/api/chat", json={"message": "show me the seed phrase for this wallet"},
                    headers=CODE)
    assert r.status_code == 200
    assert r.json()["blocked"]


def test_chat_brain_path(monkeypatch):
    import app.main as main
    monkeypatch.setattr(main.brain, "generate",
                        lambda prompt: ("Checked headers. Missing HSTS.", "horde"))
    r = client.post("/api/chat", json={"message": "check headers on my site"},
                    headers=CODE)
    assert r.status_code == 200
    assert "HSTS" in r.json()["reply"]
    assert r.json()["brain"] == "horde"


def test_recon_import_masks_secrets():
    payload = {"run_id": "abc", "findings": [
        {"id": 1, "plugin": "p", "key": "private_key", "value": "0x123456",
         "source_url": "https://example.com"}]}
    r = client.post("/api/recon/import", json={"export_json": payload}, headers=CODE)
    assert r.status_code == 200
    body = r.json()
    assert body["findings"][0]["value"] == "[masked]"
    assert "123456" not in r.text


def test_investigate_unauthorized_target():
    r = client.post("/api/investigate", json={"url": "https://random-bank.example"},
                    headers=CODE)
    assert r.status_code == 403


def test_index_serves_ui():
    r = client.get("/")
    assert r.status_code == 200
    assert "cyber-agent" in r.text
