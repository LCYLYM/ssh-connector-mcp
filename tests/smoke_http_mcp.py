#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local daemon smoke test for Web API and MCP-over-HTTP.

This intentionally does not add SSH hosts or execute remote commands; those
remain covered by deliver_test.py with real host credentials.
"""
import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:7600"
MASTER_PASSWORD = "local-smoke-master-password"


def request(path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return res, res.read().decode()
    except urllib.error.HTTPError as err:
        return err, err.read().decode()


def parse_json(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid JSON response: {text[:200]}") from exc


def mcp_data_line(text):
    lines = [line[6:] for line in text.splitlines() if line.startswith("data: ")]
    if not lines:
        raise AssertionError(f"missing SSE data line: {text[:200]}")
    return parse_json(lines[-1])


def main():
    _, text = request("/api/status")
    status = parse_json(text)
    if not status["vault_initialized"]:
        _, text = request("/api/vault/init", {"master_password": MASTER_PASSWORD})
        assert parse_json(text)["ok"] is True

    _, text = request("/api/status")
    status = parse_json(text)
    assert status["vault_initialized"] is True
    if not status["vault_unlocked"]:
        print(
            "local Web API reachable, but vault is locked; unlock it before MCP tool calls",
            file=sys.stderr,
        )
        sys.exit(2)

    init_body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "local-smoke", "version": "1"},
        },
    }
    res, text = request(
        "/mcp",
        init_body,
        {"Accept": "application/json, text/event-stream"},
    )
    session_id = res.headers.get("mcp-session-id")
    assert session_id, "missing mcp-session-id header"
    init_result = mcp_data_line(text)
    assert init_result["result"]["protocolVersion"]

    request(
        "/mcp",
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "Accept": "application/json, text/event-stream",
            "mcp-session-id": session_id,
        },
    )

    _, text = request(
        "/mcp",
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "host_list", "arguments": {}},
        },
        {
            "Accept": "application/json, text/event-stream",
            "mcp-session-id": session_id,
        },
    )
    call_result = mcp_data_line(text)
    tool_text = call_result["result"]["content"][0]["text"]
    assert parse_json(tool_text) == {"hosts": []}

    print("local Web API + MCP-over-HTTP smoke: ok")


if __name__ == "__main__":
    main()
