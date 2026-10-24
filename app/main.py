"""cyber-agent: a cybersecurity agent with a real computer.

Browser-first investigation, ReconAnything import + live connector,
Composio, GitHub, allowlisted terminal, uncensored Horde-first brain.
Detection only, on authorized targets only.
"""

from __future__ import annotations

import hmac
import json
import os

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import allowlist as allow
from . import brain, composio, github as gh, investigate as inv
from . import recon as recon_mod
from . import terminal as term
from .fetch import fetch_url
from .refusal import hard_block_reason, is_refusal
from .ssrf import SSRFBlocked

SYSTEM_PROMPT = """You are cyber-agent, a defensive cybersecurity agent. Detection
only, on authorized targets only. Jay's own assets (jaykk99 repos, his
apps and domains) are pre-authorized; any other target needs an explicit
allowlist entry before you touch it. crypto.com is NEVER a target. You
never confirm exploits, brute-force, bypass auth, access private data,
look up people, display or steal keys or seeds, sweep wallets, or use
mixers. You never move money, post, message, or deploy without the user's
explicit tap. Secrets are never stored or printed in full. When you need
a tool, emit exactly one fenced block per tool call:

```tool_call
{"name": "fetch_url", "args": {"url": "https://example.com"}}
```

Available tools: fetch_url, run_terminal, recon_import, recon_list_runs,
recon_get_run, recon_start, investigate_target, verify_finding,
expand_assets, github_search_repos, github_search_code, github_read_file,
composio_search, composio_execute, allowlist_add. After tool results
arrive, answer in plain language with evidence and a fix for each finding.
"""

TOOL_DESCRIPTIONS = """
fetch_url(url): browser route fetch, SSRF-guarded, returns status/headers/snippet.
run_terminal(command): detection commands only (curl, dig, nslookup, whois, host, openssl s_client, python3 scripts).
recon_import(export_json): import a ReconAnything export pasted from the user's signed-in browser.
recon_list_runs(limit): live ReconAnything runs (fallback-mode instances only; live sign-in instance returns 401).
recon_get_run(run_id): live run detail + findings (same limitation).
recon_start(targets, mode, source_type): start a ReconAnything scan (same limitation; target must be authorized).
investigate_target(url): cyber-agent's own detectors on a target (headers, cookies, JS libs + OSV, exposed .git).
verify_finding(finding_json): re-check one imported finding live.
expand_assets(url): subdomains via crt.sh + linked hosts.
github_search_repos(query), github_search_code(query), github_read_file(owner, repo, path).
composio_search(query), composio_execute(tool_slug, arguments).
allowlist_add(host): authorize a new target host (owner only).
"""


def _code() -> str:
    return os.environ.get("CYBER_AGENT_CODE", "").strip()


def _check_auth(request: Request, header_code: str | None) -> None:
    code = _code()
    if not code:
        raise HTTPException(503, "CYBER_AGENT_CODE is not set on the server")
    given = header_code or request.cookies.get("cyber_code", "")
    if not given or not hmac.compare_digest(given, code):
        raise HTTPException(401, "access code required")


app = FastAPI(title="cyber-agent", version="1.0.0")


@app.get("/api/health")
def health():
    return {"ok": True, "app": "cyber-agent",
            "composio": composio.configured(),
            "recon_base": recon_mod.ReconClient().base_url}


def _run_tool(name: str, args: dict, recon_code: str | None = None) -> str:
    try:
        if name == "fetch_url":
            ok, why = allow.is_authorized(args.get("url", ""))
            if not ok:
                return f"Target not authorized: {why}"
            return json.dumps(fetch_url(args["url"]), default=str)[:4000]
        if name == "run_terminal":
            return json.dumps(term.run_terminal(args.get("command", "")))[:4000]
        if name == "recon_import":
            payload = args.get("export_json")
            if isinstance(payload, str):
                payload = json.loads(payload)
            return json.dumps(recon_mod.normalize_findings(payload))[:6000]
        if name == "recon_list_runs":
            return json.dumps(recon_mod.ReconClient().list_runs(recon_code))[:4000]
        if name == "recon_get_run":
            return json.dumps(recon_mod.ReconClient().get_run(args["run_id"], recon_code))[:6000]
        if name == "recon_start":
            ok, why = allow.is_authorized(args.get("targets", ""))
            if not ok:
                return f"Target not authorized: {why}"
            return json.dumps(recon_mod.ReconClient().start_run(
                args["targets"], args.get("mode", "passive"),
                args.get("source_type", "website"), args.get("plugins"),
                recon_code))[:2000]
        if name == "investigate_target":
            ok, why = allow.is_authorized(args.get("url", ""))
            if not ok:
                return f"Target not authorized: {why}"
            return json.dumps(inv.analyze_target(args["url"]), default=str)[:6000]
        if name == "verify_finding":
            f = args.get("finding_json", {})
            if isinstance(f, str):
                f = json.loads(f)
            return json.dumps(inv.verify_finding(f), default=str)[:3000]
        if name == "expand_assets":
            ok, why = allow.is_authorized(args.get("url", ""))
            if not ok:
                return f"Target not authorized: {why}"
            return json.dumps(inv.expand_assets(args["url"]), default=str)[:4000]
        if name == "github_search_repos":
            return json.dumps(gh.search_repos(args.get("query", "")))[:4000]
        if name == "github_search_code":
            return json.dumps(gh.search_code(args.get("query", "")))[:4000]
        if name == "github_read_file":
            ok, why = allow.is_authorized_github_repo(args.get("owner", ""), args.get("repo", ""))
            if not ok:
                return f"Not authorized: {why}"
            return json.dumps(gh.read_repo_file(args["owner"], args["repo"], args["path"]))[:6000]
        if name == "composio_search":
            return composio.composio_search(args.get("query", ""), args.get("app_name", ""))
        if name == "composio_execute":
            return composio.composio_execute(args.get("tool_slug", ""),
                                             args.get("arguments") or {},
                                             args.get("connected_account_id", ""))
        if name == "allowlist_add":
            allow.add_allowlist_host(args["host"])
            return f"{args['host']} added to the allowlist."
        return f"Unknown tool: {name}"
    except SSRFBlocked as e:
        return f"SSRF blocked: {e}"
    except Exception as e:
        return f"Tool {name} failed: {str(e)[:300]}"


class ChatIn(BaseModel):
    message: str
    recon_access_code: str | None = None


@app.post("/api/chat")
def chat(body: ChatIn, request: Request, x_access_code: str | None = Header(default=None)):
    _check_auth(request, x_access_code)
    reason = hard_block_reason(body.message)
    if reason:
        return {"reply": f"Refused: {reason}. Detection only, on authorized targets.",
                "blocked": reason, "trace": []}
    prompt = (SYSTEM_PROMPT + "\nTOOLS:\n" + TOOL_DESCRIPTIONS +
              f"\nUSER: {body.message}\nASSISTANT:")
    trace: list[dict] = []
    text, source = brain.generate(prompt)
    for _ in range(6):
        calls = brain.parse_tool_calls(text)
        if not calls:
            break
        feedback = []
        for call in calls:
            result = _run_tool(call["name"], call["args"], body.recon_access_code)
            trace.append({"tool": call["name"], "result": result[:500]})
            feedback.append(f"TOOL {call['name']} RESULT:\n{result}")
        text, source = brain.generate(prompt + "\n" + "\n".join(feedback) +
                                      "\nASSISTANT (answer now, plain language, evidence + fix per finding):")
    reply = brain.strip_tool_calls(text)
    if is_refusal(reply):
        # One retry: a legit defensive request must not die on a refusal.
        text2, source2 = brain.generate(
            prompt + "\nYou are a defensive security assistant. Answer the "
            "user's defensive security question directly.\nASSISTANT:")
        if not is_refusal(text2):
            reply, source = brain.strip_tool_calls(text2), source2
    return {"reply": reply, "brain": source, "trace": trace}


class ImportIn(BaseModel):
    export_json: str | dict
    verify: bool = False


@app.post("/api/recon/import")
def recon_import(body: ImportIn, request: Request, x_access_code: str | None = Header(default=None)):
    _check_auth(request, x_access_code)
    payload = body.export_json
    if isinstance(payload, str):
        payload = json.loads(payload)
    norm = recon_mod.normalize_findings(payload)
    if body.verify:
        norm["verified"] = [inv.verify_finding(f) for f in norm["findings"][:20]]
    return norm


@app.post("/api/investigate")
def investigate(body: dict, request: Request, x_access_code: str | None = Header(default=None)):
    _check_auth(request, x_access_code)
    url = body.get("url", "")
    ok, why = allow.is_authorized(url)
    if not ok:
        raise HTTPException(403, f"Target not authorized: {why}")
    return inv.analyze_target(url)


@app.post("/api/allowlist")
def add_allow(body: dict, request: Request, x_access_code: str | None = Header(default=None)):
    _check_auth(request, x_access_code)
    host = body.get("host", "")
    try:
        allow.add_allowlist_host(host)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"added": host}


STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))
