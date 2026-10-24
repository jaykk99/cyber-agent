from app.recon import mask_value, normalize_findings

EXPORT = {
    "run_id": "a539e1fdc7d3",
    "findings": [
        {"id": 1, "plugin": "clickjack", "category": "web",
         "key": "missing_header", "value": "X-Frame-Options",
         "source": "page", "source_url": "https://example.com",
         "evidence": "no frame header", "confidence": "high",
         "bounty_value": "medium"},
        {"id": 2, "plugin": "cp_secret_env_privkey", "category": "crypto",
         "key": "private_key", "value": "0xdeadbeefcafe1234",
         "source": "page", "source_url": "https://example.com",
         "evidence": "hex key", "confidence": "high",
         "bounty_value": "high"},
    ],
}


def test_normalize_shape_and_count():
    norm = normalize_findings(EXPORT)
    assert norm["run_id"] == "a539e1fdc7d3"
    assert norm["count"] == 2
    assert norm["findings"][0]["plugin"] == "clickjack"


def test_secret_values_masked_on_import():
    norm = normalize_findings(EXPORT)
    assert norm["findings"][1]["value"] == "[masked]"
    assert "deadbeef" not in str(norm)


def test_non_secret_values_kept():
    norm = normalize_findings(EXPORT)
    assert norm["findings"][0]["value"] == "X-Frame-Options"


def test_list_payload_accepted():
    norm = normalize_findings(EXPORT["findings"])
    assert norm["count"] == 2
    assert norm["run_id"] is None


def test_bad_payload_rejected():
    try:
        normalize_findings("not json")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_mask_keys():
    assert mask_value("api_key", "secret123") == "[masked]"
    assert mask_value("token", "abc") == "[masked]"
    assert mask_value("title", "hello") == "hello"
