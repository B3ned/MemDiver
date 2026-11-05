"""McpToolClient against a REAL ``memdiver mcp`` child, and the tool_events helpers."""

from __future__ import annotations

import asyncio
import os
import sys

import pytest

from memdiver.analysis.case import Case
from memdiver.app.agent_chat.tool_events import (
    SUMMARY_CHARS, access_label, is_error_payload, result_text, tool_result_event)


@pytest.fixture
def server(tmp_path):
    """A sandboxed stdio server dict (mirrors test_agent_chat_sdk_backend's case env)."""
    uploads = tmp_path / "uploads"
    Case.init(uploads / "case")
    env = {**os.environ, "MEMDIVER_ALLOWED_ROOTS": str(tmp_path),
           "MEMDIVER_UPLOAD_DIR": str(uploads), "MEMDIVER_MCP_RESULT_BUDGET": "20000",
           "XDG_DATA_HOME": str(tmp_path / "xdg")}
    return {"command": sys.executable, "args": ["-m", "memdiver.cli", "mcp"],
            "env": env, "cwd": str(tmp_path)}


# -- McpToolClient ----------------------------------------------------------------------


def test_list_tools_from_real_server(server):
    pytest.importorskip("mcp")
    from memdiver.app.agent_chat.mcp_tools import McpToolClient

    async def go():
        client = McpToolClient(server)
        try:
            await asyncio.wait_for(client.start(), 120)
            await client.start()  # idempotent
            return await asyncio.wait_for(client.list_tools(), 60)
        finally:
            await client.kill()

    tools = asyncio.run(go())
    assert len(tools) > 100
    names = {name for name, _desc, _schema in tools}
    assert "case_manifest" in names
    assert all(isinstance(schema, dict) for _n, _d, schema in tools)
    assert all(isinstance(desc, str) for _n, desc, _s in tools)


def test_call_then_kill_is_idempotent(server):
    pytest.importorskip("mcp")
    from memdiver.app.agent_chat.mcp_tools import McpToolClient

    async def go():
        client = McpToolClient(server)
        text, is_error = await asyncio.wait_for(client.call("case_manifest", {}), 120)
        await client.kill()
        await client.kill()  # repeated kill is a no-op
        return text, is_error, client._task.done()

    text, is_error, done = asyncio.run(go())
    assert isinstance(text, str) and isinstance(is_error, bool)
    assert done


def test_kill_before_start_is_a_noop():
    from memdiver.app.agent_chat.mcp_tools import McpToolClient

    async def go():
        client = McpToolClient({"command": sys.executable})
        await client.kill()
        await client.close()

    asyncio.run(go())


def test_scripted_transport_keeps_old_names():
    pytest.importorskip("claude_agent_sdk")
    from memdiver.app.agent_chat import mcp_tools, scripted_transport

    assert scripted_transport._McpWorker is mcp_tools.McpToolClient
    assert scripted_transport.load_script is mcp_tools.load_script


# -- tool_events ----------------------------------------------------------------------


def test_tool_result_event_ok():
    event = tool_result_event("t1", "x" * (SUMMARY_CHARS + 50), False)
    assert event.type == "tool_result"
    assert event.data == {"id": "t1", "ok": True, "summary": "x" * SUMMARY_CHARS,
                          "bytes": SUMMARY_CHARS + 50, "truncated": False}


def test_tool_result_event_error_flag_and_payload():
    assert tool_result_event("t", "boom", True).data["ok"] is False
    assert tool_result_event("t", '{"error": "sandbox"}', False).data["ok"] is False
    assert tool_result_event("t", '{"ok": 1}', False).data["ok"] is True


def test_tool_result_event_truncated_and_utf8_bytes():
    data = tool_result_event("t", '{"_result_budget": 1}', False).data
    assert data["truncated"] is True
    assert tool_result_event("t", "é", False).data["bytes"] == 2


def test_is_error_payload_and_result_text():
    assert is_error_payload('{"error": 1}') and not is_error_payload("{bad json")
    assert not is_error_payload('["error"]') and not is_error_payload("error")
    assert result_text(None) == "" and result_text("a") == "a"
    assert result_text([{"type": "text", "text": "a"}, {"text": "b"}]) == "ab"


def test_access_label_fails_closed():
    access = {"r": "read", "w": "write", "n": "never"}
    assert access_label(access, "r") == "read"
    assert access_label(access, "w") == "write"
    assert access_label(access, "n") == "write"
    assert access_label(access, "unknown") == "write"
    assert access_label({}, "r") == "write"


def test_backends_factory_matches_old_delegate(monkeypatch, tmp_path):
    pytest.importorskip("claude_agent_sdk")
    from memdiver.app.agent_chat import backends, sdk_backend
    from memdiver.core.service_errors import CapabilityError

    assert isinstance(backends.make_backend("sdk"), sdk_backend.SdkAgentBackend)
    script = tmp_path / "s.json"
    script.write_text('{"turns": [[{"text": "hi"}]]}', encoding="utf-8")
    env = {"MEMDIVER_AGENT_SCRIPT": str(script)}
    assert isinstance(backends.make_backend("scripted", env=env), sdk_backend.SdkAgentBackend)
    with pytest.raises(CapabilityError):
        backends.make_backend("scripted", env={})
    with pytest.raises(CapabilityError):
        backends.make_backend("nope")
