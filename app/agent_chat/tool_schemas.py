"""MemDiver MCP tools as OpenAI function definitions (pure; no SDK, no network).

The OpenAI-compatible backend offers the model the same MCP tools the Claude SDK
path sees, translated to Chat Completions ``tools`` entries:

- ``never`` tools (``mcp_server.tool_policy.NEVER_AUTO``) are dropped;
- the list is sorted by name, so the request prefix stays byte-stable (prompt caching);
- schemas are sanitized for non-strict function calling: pydantic's Optional shape
  ``anyOf: [X, {"type": "null"}]`` collapses to ``X``, ``default: null`` and every
  ``title`` are removed, and the top level is always an object with ``properties``.

Tool sets (``providers.TOOL_SET_CHOICES``) trade coverage for context: ``full`` is
everything, ``compact`` keeps every tool but cuts descriptions to one sentence and
drops parameter descriptions, ``minimal`` offers only :data:`MINIMAL_TOOLS` (compact).
"""

from __future__ import annotations

import copy
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from .providers import TOOL_SET_CHOICES

#: Cheap READ recon/inventory tools for small local models (``tool_set="minimal"``):
#: the case inventory the system prompt asks for first, the capture/image overview,
#: and bounded byte-level reads. ``tests/test_agent_chat_tool_schemas.py`` asserts each
#: exists and classifies as READ.
MINIMAL_TOOLS: Tuple[str, ...] = (
    "analyze_region",
    "annotations_list",
    "case_manifest",
    "case_query",
    "case_schema",
    "case_status",
    "context_at",
    "get_entropy",
    "get_modules",
    "get_processes",
    "get_session_info",
    "image_probe",
    "image_processes",
    "read_hex",
    "search_bytes",
    "vas_regions",
)

#: Cap of a compact (first-sentence) description.
COMPACT_DESCRIPTION_CHARS = 200

ListedTool = Tuple[str, str, Mapping[str, Any]]


def _is_null_branch(branch: Any) -> bool:
    return isinstance(branch, dict) and branch.get("type") == "null"


def _collapse_optional(node: Dict[str, Any]) -> Dict[str, Any]:
    """``{anyOf: [X, null], ...rest}`` -> ``{...X, ...rest}``; other shapes unchanged."""
    branches = node.get("anyOf")
    if not isinstance(branches, list):
        return node
    kept = [b for b in branches if not _is_null_branch(b)]
    if len(kept) != 1 or len(kept) == len(branches) or not isinstance(kept[0], dict):
        return node
    rest = {k: v for k, v in node.items() if k != "anyOf"}
    return {**kept[0], **rest}


def _clean(node: Any) -> Any:
    """Recursively collapse Optionals and drop ``title`` and ``default: None``."""
    if isinstance(node, list):
        return [_clean(item) for item in node]
    if not isinstance(node, dict):
        return node
    node = _collapse_optional(node)
    return {key: _clean_properties(value) if key == "properties" else _clean(value)
            for key, value in node.items()
            if key != "title" and not (key == "default" and value is None)}


def _clean_properties(properties: Any) -> Any:
    """A ``properties`` map: its keys are parameter names (a ``title`` one is kept)."""
    if not isinstance(properties, dict):
        return _clean(properties)
    return {name: _clean(spec) for name, spec in properties.items()}


def sanitize_schema(schema: Mapping[str, Any]) -> Dict[str, Any]:
    """A cleaned deep copy of ``schema`` whose top level is ``{type: object, properties}``."""
    cleaned = _clean(copy.deepcopy(dict(schema or {})))
    properties = cleaned.get("properties")
    cleaned["type"] = "object"
    cleaned["properties"] = properties if isinstance(properties, dict) else {}
    return cleaned


def first_sentence(text: str) -> str:
    """Up to the first ``". "`` or newline, capped at :data:`COMPACT_DESCRIPTION_CHARS`."""
    text = (text or "").strip()
    cut = len(text)
    for marker in (". ", "\n"):
        index = text.find(marker)
        if index != -1:
            cut = min(cut, index + (1 if marker == ". " else 0))
    return text[:cut].strip()[:COMPACT_DESCRIPTION_CHARS]


def _without_parameter_descriptions(schema: Dict[str, Any]) -> Dict[str, Any]:
    properties = {
        name: {k: v for k, v in spec.items() if k != "description"}
        if isinstance(spec, dict) else spec
        for name, spec in schema["properties"].items()
    }
    return {**schema, "properties": properties}


def to_function(name: str, description: str, schema: Mapping[str, Any],
                compact: bool = False) -> Dict[str, Any]:
    """One Chat Completions ``tools`` entry for an MCP tool."""
    parameters = sanitize_schema(schema)
    if compact:
        description = first_sentence(description)
        parameters = _without_parameter_descriptions(parameters)
    return {"type": "function", "function": {
        "name": name, "description": description or "", "parameters": parameters}}


def _offered(listed: Iterable[ListedTool], tool_access: Mapping[str, str],
             tool_set: str) -> List[ListedTool]:
    tools = [t for t in listed if tool_access.get(t[0]) != "never"]
    if tool_set == "minimal":
        tools = [t for t in tools if t[0] in MINIMAL_TOOLS]
    return sorted(tools, key=lambda t: t[0])


def build_tools(listed: Iterable[ListedTool], tool_access: Mapping[str, str],
                tool_set: str) -> List[Dict[str, Any]]:
    """The ``tools`` list for ``tool_set`` (``full|compact|minimal``), sorted by name.

    A tool missing from ``tool_access`` is still offered: the gate treats it as WRITE.
    """
    if tool_set not in TOOL_SET_CHOICES:
        raise ValueError(f"unknown tool set: {tool_set}")
    compact = tool_set != "full"
    return [to_function(name, description, schema, compact=compact)
            for name, description, schema in _offered(listed, tool_access, tool_set)]
