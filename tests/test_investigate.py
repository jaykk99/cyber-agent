import app.investigate as inv

PAGE = """<html><head>
<script src="https://cdn.example.com/jquery-1.12.4.min.js"></script>
</head><body><a href="https://sub.example.com/page">sub</a></body></html>"""

GIT_HEAD = "ref: refs/heads/main\n"


def _fake_fetch_factory(headers=None, body=None, git_body=None):
    def fake_fetch(url, **kwargs):
        if url.endswith("/.git/HEAD"):
            return {"url": url, "status": 200, "headers": {},
                    "text_snippet": git_body or "", "bytes": len(git_body or "")}
        return {"url": url, "status": 200,
                "headers": headers or {"server": "nginx/1.18.0"},
                "text_snippet": body if body is not None else PAGE,
                "bytes": 500}
    return fake_fetch


def test_missing_headers_detected(monkeypatch):
    monkeypatch.setattr(inv, "fetch_url", _fake_fetch_factory())
    monkeypatch.setattr(inv, "osv_lookup", lambda *a: [])
    out = inv.analyze_target("https://example.com")
    kinds = {f["kind"] for f in out["added_findings"]}
    assert "header" in kinds
    titles = " ".join(f["title"] for f in out["added_findings"])
    assert "HSTS" in titles
    assert all("fix" in f and f["fix"] for f in out["added_findings"])


def test_server_version_disclosure(monkeypatch):
    monkeypatch.setattr(inv, "fetch_url", _fake_fetch_factory())
    monkeypatch.setattr(inv, "osv_lookup", lambda *a: [])
    out = inv.analyze_target("https://example.com")
    assert any(f["kind"] == "version-disclosure" for f in out["added_findings"])


def test_js_library_with_osv(monkeypatch):
    monkeypatch.setattr(inv, "fetch_url", _fake_fetch_factory())
    monkeypatch.setattr(inv, "osv_lookup",
                        lambda p, v, e="npm": [{"id": "GHSA-test-1", "summary": "xss"}])
    out = inv.analyze_target("https://example.com")
    js = [f for f in out["added_findings"] if f["kind"] == "js-library"]
    assert js and "jquery 1.12.4" in js[0]["title"]
    assert "GHSA-test-1" in js[0]["evidence"]


def test_js_library_clean_without_advisories(monkeypatch):
    monkeypatch.setattr(inv, "fetch_url", _fake_fetch_factory())
    monkeypatch.setattr(inv, "osv_lookup", lambda *a: [])
    out = inv.analyze_target("https://example.com")
    assert not [f for f in out["added_findings"] if f["kind"] == "js-library"]


def test_exposed_git_detected(monkeypatch):
    monkeypatch.setattr(inv, "fetch_url", _fake_fetch_factory(git_body=GIT_HEAD))
    monkeypatch.setattr(inv, "osv_lookup", lambda *a: [])
    out = inv.analyze_target("https://example.com")
    assert any(f["kind"] == "exposed-git" for f in out["added_findings"])


def test_verify_finding_live(monkeypatch):
    monkeypatch.setattr(inv, "fetch_url",
                        lambda url, **k: {"url": url, "status": 200,
                                          "headers": {}, "text_snippet": "ok",
                                          "bytes": 2})
    out = inv.verify_finding({"id": 7, "plugin": "clickjack",
                              "source_url": "https://example.com"})
    assert out["status"] == "live"


def test_verify_finding_no_url():
    out = inv.verify_finding({"id": 7, "plugin": "x"})
    assert out["status"] == "no-url"
