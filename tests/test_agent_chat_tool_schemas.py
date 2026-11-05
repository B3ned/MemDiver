"""MCP tool -> OpenAI function translation of the OpenAI-compatible agent backend."""

from __future__ import annotations

import asyncio
import json
import re

import pytest

from memdiver.app.agent_chat.tool_schemas import (
    MINIMAL_TOOLS, build_tools, first_sentence, sanitize_schema, to_function,
)

NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@pytest.fixture(scope="module")
def listed():
    from memdiver.mcp_server.server import create_server

    tools = asyncio.run(create_server().list_tools())
    return [(t.name, t.description or "", t.input_schema) for t in tools]


@pytest.fixture(scope="module")
def access():
    from memdiver.mcp_server.tool_policy import classify_tools, gate_access

    return {name: gate_access(cls) for name, cls in classify_tools().items()}


def _walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def _size(tools):
    return len(json.dumps(tools))


# -- sanitize_schema ------------------------------------------------------------------

def test_optional_collapses_to_its_type_and_keeps_the_description():
    schema = {"title": "fArguments", "type": "object", "required": ["a"], "properties": {
        "a": {"title": "A", "type": "string"},
        "b": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None,
              "title": "B", "description": "the b"}}}
    out = sanitize_schema(schema)
    assert out == {"type": "object", "required": ["a"], "properties": {
        "a": {"type": "string"}, "b": {"type": "integer", "description": "the b"}}}
    assert "title" in schema and "anyOf" in schema["properties"]["b"]  # deep copy


def test_a_parameter_named_title_survives():
    out = sanitize_schema({"properties": {"title": {"title": "Title", "type": "string"}}})
    assert out["properties"] == {"title": {"type": "string"}}


def test_generic_anyof_and_non_null_defaults_are_kept():
    prop = {"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}],
            "default": 3}
    out = sanitize_schema({"properties": {"x": prop}})
    assert out["properties"]["x"] == prop


def test_top_level_object_is_ensured():
    assert sanitize_schema({}) == {"type": "object", "properties": {}}
    assert sanitize_schema(None) == {"type": "object", "properties": {}}


def test_every_real_schema_is_sanitized(listed):
    for name, _, schema in listed:
        assert NAME_PATTERN.match(name), name
        out = sanitize_schema(schema)
        assert out["type"] == "object" and isinstance(out["properties"], dict)
        for node in _walk(out):
            assert not isinstance(node.get("title"), str), name
            assert node.get("default", 0) is not None, name
            assert not any(b == {"type": "null"} for b in node.get("anyOf", [])), name


# -- to_function / compact --------------------------------------------------------------

def test_first_sentence_cuts_at_period_space_or_newline():
    assert first_sentence("Read bytes. Returns hex.") == "Read bytes."
    assert first_sentence("Line one\nline two. more") == "Line one"
    assert first_sentence("v1.2 parser") == "v1.2 parser"
    assert len(first_sentence("x" * 500)) == 200


def test_compact_drops_parameter_descriptions():
    schema = {"properties": {"a": {"type": "string", "description": "long"}}}
    full = to_function("t", "Does it. Really.", schema)
    compact = to_function("t", "Does it. Really.", schema, compact=True)
    assert full["function"]["description"] == "Does it. Really."
    assert full["function"]["parameters"]["properties"]["a"]["description"] == "long"
    assert compact == {"type": "function", "function": {
        "name": "t", "description": "Does it.",
        "parameters": {"type": "object", "properties": {"a": {"type": "string"}}}}}


# -- build_tools / tool sets ------------------------------------------------------------

def test_minimal_tools_exist_and_are_read(listed, access):
    names = {name for name, _, _ in listed}
    assert 12 <= len(MINIMAL_TOOLS) <= 20
    assert len(set(MINIMAL_TOOLS)) == len(MINIMAL_TOOLS)
    for name in MINIMAL_TOOLS:
        assert name in names, name
        assert access[name] == "read", name


def test_never_tools_dropped_and_sorted(listed, access):
    tools = build_tools(listed, access, "full")
    names = [t["function"]["name"] for t in tools]
    assert names == sorted(names)
    assert "capture_dump" not in names
    assert len(names) == len(listed) - sum(v == "never" for v in access.values())


def test_minimal_is_the_curated_subset_with_compact_descriptions(listed, access):
    tools = build_tools(listed, access, "minimal")
    assert [t["function"]["name"] for t in tools] == sorted(MINIMAL_TOOLS)
    for tool in tools:
        assert "\n" not in tool["function"]["description"]


def test_unknown_tool_set_is_refused(listed, access):
    with pytest.raises(ValueError):
        build_tools(listed, access, "huge")


def test_tool_set_sizes(listed, access):
    # Measured 2026-11-05 over 120 tools (json chars): full 135,312,
    # compact 63,637 (0.47x), minimal 6,307 (0.047x).
    full = _size(build_tools(listed, access, "full"))
    compact = _size(build_tools(listed, access, "compact"))
    minimal = _size(build_tools(listed, access, "minimal"))
    assert compact < 0.6 * full
    assert minimal < 0.15 * full
