import os

import app.composio as comp


def test_search_degraded_without_key(monkeypatch):
    monkeypatch.delenv("COMPOSIO_API_KEY", raising=False)
    out = comp.composio_search("gmail")
    assert "not configured" in out


def test_execute_degraded_without_key(monkeypatch):
    monkeypatch.delenv("COMPOSIO_API_KEY", raising=False)
    out = comp.composio_execute("GMAIL_SEND_EMAIL", {"to": "x"})
    assert "not configured" in out


def test_configured_flag(monkeypatch):
    monkeypatch.delenv("COMPOSIO_API_KEY", raising=False)
    assert comp.configured() is False
    monkeypatch.setenv("COMPOSIO_API_KEY", "dummy")
    assert comp.configured() is True
