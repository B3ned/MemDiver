"""Backend-neutral construction of the ``tool_call``/``tool_result`` event payloads.

Every :class:`contracts.AgentBackend` builds its tool events here, so all backends emit
byte-identical ``tool_result`` data (summary, size, truncation flag, locations) and the
same ``read``/``write`` access labels.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Mapping

from memdiver.app.agent_chat import contracts as c
from memdiver.app.agent_chat.locations import extract_locations

#: Characters of a tool result shown as its summary.
SUMMARY_CHARS = 300
#: Marker ``mcp_server.result_budget`` leaves in a result it truncated.
_TRUNCATION_MARKER = "_result_budget"


def result_text(content: Any) -> str:
    """Flatten a ``tool_result`` content (str, or list of text blocks) to text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts = []
    for block in content if isinstance(content, list) else [content]:
        parts.append(block.get("text", "") if isinstance(block, dict) else str(block))
    return "".join(parts)


def is_error_payload(text: str) -> bool:
    """MemDiver tools report failures as ``{"error": ...}`` JSON, not as MCP errors."""
    if not text.startswith("{"):
        return False
    try:
        body = json.loads(text)
    except ValueError:
        return False
    return isinstance(body, dict) and "error" in body


def tool_result_event(tool_id: str, text: str, is_error: bool) -> c.ChatEvent:
    """The ``tool_result`` event for one finished tool call."""
    data: Dict[str, Any] = {
        "id": tool_id,
        "ok": not is_error and not is_error_payload(text),
        "summary": text[:SUMMARY_CHARS],
        "bytes": len(text.encode("utf-8")),
        "truncated": _TRUNCATION_MARKER in text}
    locations = extract_locations(text)
    if locations:
        data["locations"] = locations
    return c.ChatEvent("tool_result", data)


def access_label(tool_access: Mapping[str, str], name: str) -> str:
    """``read`` or ``write`` for a ``tool_call`` event; unknown/``never`` tools are
    labelled ``write`` (fail closed)."""
    access = tool_access.get(name, "write")
    return access if access in ("read", "write") else "write"
