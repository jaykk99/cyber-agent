"""ReconAnything connector.

Two paths, both honest about what the live instance allows:

1. IMPORT (fully working, no ReconAnything auth needed): the user pastes
   or uploads a ReconAnything export (GET /api/runs/{id}/export?format=json
   from their own signed-in browser session). Findings are normalized and
   secret-valued rows are masked on import. Secrets are never stored full.

2. LIVE (works only against fallback-mode instances): list runs, run
   detail, export, and start a scan, authenticated per-request with an
   X-Access-Code header value the user supplies for that call. The value
   is never stored. Against the live sign-in-mode instance this returns
   401 "sign in with GitHub required", because that instance has no
   server-to-server key: its /api routes require a GitHub session cookie,
   and this app deliberately never accepts or stores session cookies.
   Closing that gap needs a service-key endpoint on ReconAnything itself.
"""

from __future__ import annotations

import os

from .http import client as http_client

SECRET_KEYS = {
    "token", "secret", "password", "passwd", "key", "seed", "mnemonic",
    "private_key", "privkey", "api_key", "apikey", "auth", "cookie",
    "session", "bearer", "credentials", "wallet", "wif", "xprv",
}


def mask_value(key: str, value) -> str:
    if str(key).lower() in SECRET_KEYS:
        return "[masked]"
    return value


def normalize_findings(payload) -> dict:
    """Normalize an export payload into {run_id, findings: [...]}."""
    if isinstance(payload, list):
        rows, run_id = payload, None
    elif isinstance(payload, dict):
        rows = payload.get("findings") or payload.get("rows") or []
        run_id = payload.get("run_id") or payload.get("id")
    else:
        raise ValueError("export must be a JSON object or list")
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        key = str(r.get("key", ""))
        out.append({
            "id": r.get("id"),
            "plugin": r.get("plugin", ""),
            "category": r.get("category", ""),
            "key": key,
            "value": mask_value(key, r.get("value", "")),
            "source": r.get("source", ""),
            "source_url": r.get("source_url", ""),
            "evidence": r.get("evidence", ""),
            "confidence": r.get("confidence", ""),
            "severity": r.get("bounty_value", "") or r.get("severity", ""),
        })
    return {"run_id": run_id, "findings": out, "count": len(out)}


class ReconClient:
    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or os.environ.get(
            "RECON_BASE_URL", "https://recon-anything.onrender.com")).rstrip("/")

    def _headers(self, access_code: str | None) -> dict:
        h = {"User-Agent": "cyber-agent/1.0"}
        if access_code:
            h["X-Access-Code"] = access_code
        return h

    def list_runs(self, access_code: str | None = None, limit: int = 30) -> dict:
        with http_client(30) as c:
            r = c.get(f"{self.base_url}/api/runs", params={"limit": limit},
                      headers=self._headers(access_code))
        return {"status": r.status_code, "body": _safe_json(r)}

    def get_run(self, run_id: str, access_code: str | None = None) -> dict:
        with http_client(30) as c:
            r = c.get(f"{self.base_url}/api/runs/{run_id}",
                      headers=self._headers(access_code))
        return {"status": r.status_code, "body": _safe_json(r)}

    def get_export(self, run_id: str, access_code: str | None = None) -> dict:
        with http_client(60) as c:
            r = c.get(f"{self.base_url}/api/runs/{run_id}/export",
                      params={"format": "json"},
                      headers=self._headers(access_code))
        if r.status_code == 200:
            return {"status": 200, "import": normalize_findings(_safe_json(r))}
        return {"status": r.status_code, "body": _safe_json(r)}

    def start_run(self, targets: str, mode: str = "passive",
                  source_type: str = "website", plugins: list | None = None,
                  access_code: str | None = None) -> dict:
        body = {"targets": targets, "mode": mode, "source_type": source_type,
                "plugins": plugins or [], "bounty": False}
        with http_client(60) as c:
            r = c.post(f"{self.base_url}/api/runs", json=body,
                       headers=self._headers(access_code))
        return {"status": r.status_code, "body": _safe_json(r)}


def _safe_json(r):
    try:
        return r.json()
    except Exception:
        return {"text": r.text[:500]}
