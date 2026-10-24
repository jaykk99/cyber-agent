from app import allowlist as allow


def test_own_asset_authorized():
    ok, why = allow.is_authorized("https://error-inbox.onrender.com")
    assert ok


def test_crypto_com_never():
    ok, _ = allow.is_authorized("https://crypto.com")
    assert not ok
    ok, _ = allow.is_authorized("https://app.crypto.com/login")
    assert not ok


def test_unknown_host_denied():
    ok, why = allow.is_authorized("https://random-bank.example")
    assert not ok
    assert "allowlist" in why


def test_add_host_then_allowed(tmp_path):
    allow.ALLOWLIST_PATH = str(tmp_path / "allow.json")
    assert not allow.is_authorized("https://victim-bank.example")[0]
    allow.add_allowlist_host("victim-bank.example")
    assert allow.is_authorized("https://victim-bank.example")[0]


def test_cannot_allowlist_crypto(tmp_path):
    allow.ALLOWLIST_PATH = str(tmp_path / "allow.json")
    try:
        allow.add_allowlist_host("crypto.com")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_own_github_owner():
    assert allow.is_authorized_github_repo("jaykk99", "error-inbox")[0]
    assert not allow.is_authorized_github_repo("someone-else", "x")[0]
