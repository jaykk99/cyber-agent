from app.brain import parse_tool_calls, strip_tool_calls


def test_parse_tool_call_block():
    text = ('Let me check.\n```tool_call\n{"name": "fetch_url", '
            '"args": {"url": "https://example.com"}}\n```\nDone.')
    calls = parse_tool_calls(text)
    assert len(calls) == 1
    assert calls[0]["name"] == "fetch_url"
    assert calls[0]["args"]["url"] == "https://example.com"


def test_parse_ignores_bad_json():
    text = '```tool_call\n{not json}\n```'
    assert parse_tool_calls(text) == []


def test_strip_removes_blocks():
    text = 'Hello\n```tool_call\n{"name": "x", "args": {}}\n```\nWorld'
    stripped = strip_tool_calls(text)
    assert "tool_call" not in stripped
    assert "Hello" in stripped and "World" in stripped


def test_no_calls_in_plain_text():
    assert parse_tool_calls("Just a normal answer.") == []
