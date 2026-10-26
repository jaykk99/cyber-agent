# cyber-agent

A defensive cybersecurity agent with a real computer. Browser-first
investigation, ReconAnything import + live connector, Composio, GitHub,
allowlisted terminal, and an uncensored Horde-first AI brain.

Detection only, on authorized targets only.

## What it does

- **Chat agent** (`/api/chat`): single-page UI at `/`. The agent gets a
  browser route, a terminal, ReconAnything, Composio, and GitHub tools,
  and answers with evidence and a plain-language fix per finding.
- **ReconAnything connection** (`/api/recon/import`, live client in
  `app/recon.py`):
  - Import: paste or upload a ReconAnything export
    (`GET /api/runs/{id}/export?format=json` from your own signed-in
    browser). Findings are normalized and secret-valued rows are masked
    on import. Secrets are never stored in full.
  - Live: list runs, run detail, export, and start a scan against
    fallback-mode instances with a per-request `X-Access-Code` header
    value (never stored).
  - **Known gap, verified live 2026-10-24:** the production
    ReconAnything instance returns `401 "sign in with GitHub required"`
    anonymously, because in sign-in mode every `/api` route requires a
    GitHub session cookie and there is no server-to-server key. This app
    deliberately never accepts or stores session cookies. Closing that
    gap needs a service-key endpoint on ReconAnything itself; until
    then, use the import path for production runs.
- **Finds MORE than the scanner** (`/api/investigate`, `app/investigate.py`):
  on top of imported findings it verifies each finding live through the
  browser route, and runs its own direct detectors: security-header
  analysis, cookie flags, server version disclosure, JS library versions
  mapped to public OSV advisories, exposed `.git`, and subdomain
  expansion via crt.sh. Every added finding carries fetched evidence and
  a plain-language fix.
- **Composio** (`composio_search`, `composio_execute`): owner-only,
  audit-logged (tool slug + argument keys only, never values). Env-gated
  on `COMPOSIO_API_KEY`. Without a key the tools return a clean degraded
  message. Known state: the key on file returns 401 from Composio, so
  live Composio needs Jay to re-paste the key.
- **GitHub** (read-only): repo search, code search, file reads on
  authorized targets via `GITHUB_TOKEN`. No writes in v1.
- **Browser route** (`app/fetch.py`): SSRF-guarded fetch with redirect
  re-validation, cert info, and header/body evidence. This is the
  primary investigation route.
- **Terminal** (`app/terminal.py`): detection commands only:
  `curl`, `dig`, `nslookup`, `whois`, `host`, `openssl s_client`,
  `python3` script files. No shell, no file writes, no uploads, no
  installs, no listeners, no miners. curl URLs pass the SSRF check.
- **Uncensored brain** (`app/brain.py`): AI Horde first
  (Stheno/Heretic/Rocinante workers), Pollinations keyless fallback.
  Never GPT/Claude/Gemini. Tool use is emulated with fenced
  `tool_call` JSON blocks. A refusal detector retries once on legit
  defensive requests instead of showing a refusal. The probe battery in
  `tests/test_refusal_battery.py` pins the line: legit security work
  passes, hard-limit topics refuse.

## Hard boundaries (in the system prompt AND the code)

- Detection only, on authorized targets only. Jay's own assets
  (jaykk99 repos, his apps and domains) are pre-authorized; any other
  target needs an explicit allowlist entry (`/api/allowlist`) first.
- crypto.com is NEVER a scan target, allowlist or not.
- No exploit confirmation, brute-forcing, auth bypass, private-data
  access, person lookup, facial recognition, key/seed display or theft,
  wallet sweeping, or mixers.
- No autonomous money movement, posts, messages, or deploys from the
  agent without the user's explicit tap.
- Secrets are never stored in full, never printed in logs or reports.

## Run it (one command)

```bash
pip install -r requirements.txt
CYBER_AGENT_CODE=your-code-here uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open http://localhost:8000, enter the access code, and chat.
Environment: `CYBER_AGENT_CODE` (required), `COMPOSIO_API_KEY`,
`GITHUB_TOKEN`, `HORDE_API_KEY` (optional, anon key works),
`RECON_BASE_URL` (default: the ReconAnything service URL).

Tests: `python3 -m pytest tests/ -q` (52 tests, all green 2026-10-24).

## Deploy status

Not deployed yet, honestly:

- Cloudflare dashboard cannot host this backend: Pages/Workers do not
  run a Python FastAPI app, and the dashboard route was the preferred
  path. No CLI-host workaround was used per Jay's simplification.
- Render is at 25/25 services, and the PostgREST slot has priority, so
  Render is not available unless a slot frees. `render.yaml` is in the
  repo for that day.
- Fly.io CLI deploy was dropped per Jay's order (dashboard paths only).

Until a host frees up, run it with the one command above.

## Verified end to end (2026-10-24, local run)

- `GET /api/health` returns ok, composio=false (no key), recon base set.
- ReconAnything export import (real export schema): 2 findings in,
  secret-valued row masked, count correct.
- Live investigation of error-inbox (pre-authorized):
  HTTP 200, one real added finding (missing Content Security Policy)
  with fetched header evidence and a fix.
- Horde brain live: job accepted (202), completed with a real generation.
- Composio without a key: clean degraded message, no crash.
