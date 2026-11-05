"""ChatModel port: the stream accumulator and the openai adapter over a mocked wire."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from memdiver.app.agent_chat import providers as P
from memdiver.app.agent_chat.chat_model import (
    ModelTurn, OpenAICompatModel, StreamAccumulator, ToolCallRequest, Usage,
    OllamaContextProbe, check_context_fits, check_truncation, message_for_history,
    native_base_url, ollama_context_length, request_chars,
)
from memdiver.core.service_errors import CapabilityError

SECRET = "sk-test-SECRET-value-123"
MESSAGES = [{"role": "system", "content": "s"}, {"role": "user", "content": "hi"}]
TOOLS = [{"type": "function", "function": {
    "name": "case_manifest", "description": "Inventory.",
    "parameters": {"type": "object", "properties": {}}}}]


def _chunk(delta=None, finish=None, usage=None, choices=True):
    body = {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
            "choices": [{"index": 0, "delta": delta or {}, "finish_reason": finish}]
            if choices else []}
    if usage is not None:
        body["usage"] = usage
    return body


def _call(index, id=None, name=None, args=None):
    fragment = {"index": index, "function": {}}
    if id:
        fragment.update(id=id, type="function")
    if name:
        fragment["function"]["name"] = name
    if args is not None:
        fragment["function"]["arguments"] = args
    return {"tool_calls": [fragment]}


TOOL_STREAM = [
    _chunk({"role": "assistant", "content": "Looking"}),
    _chunk({"content": " now."}),
    _chunk(_call(0, id="call_A", name="case_query", args="")),
    _chunk(_call(0, args='{"sql": "SELECT')),
    _chunk(_call(0, args=' 1"}')),
    _chunk(finish="tool_calls"),
    _chunk(choices=False, usage={"prompt_tokens": 120, "completion_tokens": 30,
                                 "total_tokens": 150}),
]


# -- StreamAccumulator (dict chunks) ----------------------------------------------------

def test_accumulator_groups_split_calls_by_index_and_estimates_usage():
    acc = StreamAccumulator()
    deltas = [acc.feed(c) for c in (
        _chunk({"reasoning_content": "think "}), _chunk({"reasoning_content": "more"}),
        _chunk(_call(0, id="a", name="read_hex")), _chunk(_call(1, id="b", name="get_entropy")),
        _chunk(_call(0, args='{"dump_path":')), _chunk(_call(1, args="{}")),
        _chunk(_call(0, args=' "x"}')), _chunk({"content": "ok"}, finish="tool_calls"))]
    turn = acc.result(request_chars=400)
    assert deltas[-1] == "ok" and not any(deltas[:-1])
    assert turn.tool_calls == (ToolCallRequest("a", "read_hex", '{"dump_path": "x"}'),
                               ToolCallRequest("b", "get_entropy", "{}"))
    assert turn.reasoning == "think more" and turn.text == "ok"
    assert turn.finish_reason == "tool_calls"
    assert turn.usage.estimated and turn.usage.prompt_tokens == 100


def test_accumulator_tolerates_missing_index_and_reads_reasoning_alias():
    acc = StreamAccumulator()
    acc.feed({"choices": [{"delta": {"reasoning": "r", "tool_calls": [
        {"id": "x", "function": {"name": "n", "arguments": "{}"}}]}}]})
    turn = acc.result(0)
    assert turn.reasoning == "r" and turn.tool_calls[0].provider_id == "x"


def test_truncation_guard():
    check_truncation(Usage(10, 1, estimated=True), 100_000)       # estimate: never
    check_truncation(Usage(10, 1, estimated=False), 10_000)       # small request
    check_truncation(Usage(15_000, 1, estimated=False), 100_000)  # 60%: fine
    with pytest.raises(CapabilityError) as err:
        check_truncation(Usage(2_048, 1, estimated=False), 100_000)
    assert err.value.code == "agent.context_truncated"
    assert "minimal" in err.value.message and "OLLAMA_CONTEXT_LENGTH" in err.value.message


# -- the wire: real AsyncOpenAI over httpx.MockTransport --------------------------------

def _sse(chunks):
    body = "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n"
    return httpx.Response(200, headers={"content-type": "text/event-stream"},
                          content=body.encode())


def _model(preset_id, handler, **kw):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    preset = P.get_preset(preset_id)
    return OpenAICompatModel(preset, "m-1", "low", "http://provider.test/v1", SECRET,
                             http_client=client, **kw), preset


def _run(preset_id, chunks, tools=TOOLS):
    seen, texts = {}, []

    def handler(request):
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization")
        return _sse(chunks)

    async def on_text(text):
        texts.append(text)

    async def go():
        model, preset = _model(preset_id, handler)
        try:
            return await model.complete(MESSAGES, tools, on_text), preset
        finally:
            await model.aclose()

    turn, preset = asyncio.run(go())
    return turn, preset, seen, texts


def test_wire_openai_tool_call_and_request_shape():
    turn, _, seen, texts = _run("openai", TOOL_STREAM)
    assert texts == ["Looking", " now."]
    assert turn == ModelTurn("Looking now.", (ToolCallRequest(
        "call_A", "case_query", '{"sql": "SELECT 1"}'),), "", Usage(120, 30, False),
        "tool_calls")
    body = seen["body"]
    assert "tool_choice" not in body
    assert body["stream"] is True and body["stream_options"] == {"include_usage": True}
    assert body["max_completion_tokens"] == 8192 and "max_tokens" not in body
    assert body["reasoning_effort"] == "low" and body["tools"] == TOOLS
    assert seen["auth"] == f"Bearer {SECRET}"


@pytest.mark.parametrize("preset_id", ["deepseek", "ollama"])
def test_wire_compat_presets_use_max_tokens_and_no_effort(preset_id):
    _, _, seen, _ = _run(preset_id, TOOL_STREAM, tools=[])
    body = seen["body"]
    assert body["max_tokens"] == 8192 and "max_completion_tokens" not in body
    assert "reasoning_effort" not in body and "tools" not in body
    assert "tool_choice" not in body


REASONING_STREAM = [
    _chunk({"role": "assistant", "reasoning_content": "Let me "}),
    _chunk({"reasoning_content": "check."}),
    _chunk(_call(0, id="call_R", name="case_schema", args="{}")),
    _chunk(finish="tool_calls"),
]


def test_reasoning_is_echoed_for_deepseek_only():
    turn, deepseek, _, texts = _run("deepseek", REASONING_STREAM)
    assert texts == [] and turn.reasoning == "Let me check."
    assert turn.usage.estimated
    assert message_for_history(turn, deepseek) == {
        "role": "assistant", "content": None, "reasoning_content": "Let me check.",
        "tool_calls": [{"id": "call_R", "type": "function",
                        "function": {"name": "case_schema", "arguments": "{}"}}]}
    ollama_message = message_for_history(turn, P.get_preset("ollama"))
    assert "reasoning_content" not in ollama_message


BIG_REQUEST = [{"role": "user", "content": "x" * 40_000}]  # ~10 000 tokens
#: The ``prompt_eval_count`` shape of a KV-cache hit: far fewer tokens than were sent.
CACHE_HIT_STREAM = [
    _chunk({"content": "hi"}, finish="stop"),
    _chunk(choices=False, usage={"prompt_tokens": 2048, "completion_tokens": 1,
                                 "total_tokens": 2049})]


def _ps_body(context_length, name="m-1:latest"):
    """``/api/ps`` as Ollama 0.13.5 returns it (trimmed; see ollama_context_length)."""
    return {"models": [{"name": name, "model": name, "size": 43876075520,
                        "details": {"family": "llama"}, "size_vram": 43876075520,
                        "context_length": context_length}]}


def _complete_on_wire(preset_id, handler, messages):
    async def on_text(_):
        pass

    async def go():
        model, _ = _model(preset_id, handler)
        model._client = model._client.with_options(max_retries=0)
        try:
            return await model.complete(messages, [], on_text)
        finally:
            await model.aclose()

    return asyncio.run(go())


def _ollama_handler(ps, hits):
    """Serves ``/api/ps`` from ``ps`` (a body, a status int or an exception) and SSE."""
    def handler(request):
        hits.append(request.url.path)
        if request.url.path == "/api/ps":
            if isinstance(ps, Exception):
                raise ps
            if isinstance(ps, int):
                return httpx.Response(ps, json={"error": "boom"})
            return httpx.Response(200, json=ps)
        return _sse(CACHE_HIT_STREAM)
    return handler


def test_wire_ratio_guard_still_trips_for_vllm():
    with pytest.raises(CapabilityError) as err:
        _complete_on_wire("vllm", lambda request: _sse(CACHE_HIT_STREAM), BIG_REQUEST)
    assert err.value.code == "agent.context_truncated"


def test_wire_ratio_guard_never_runs_for_ollama_kv_cache_hit():
    hits = []
    turn = _complete_on_wire("ollama", _ollama_handler(_ps_body(32_768), hits), BIG_REQUEST)
    assert turn.usage.prompt_tokens == 2048 and not turn.usage.estimated
    assert hits == ["/api/ps", "/v1/chat/completions"]


def test_ollama_proactive_check_refuses_before_sending():
    hits = []
    with pytest.raises(CapabilityError) as err:
        _complete_on_wire("ollama", _ollama_handler(_ps_body(4096), hits), BIG_REQUEST)
    assert err.value.code == "agent.context_truncated" and err.value.status == 400
    assert "/v1/chat/completions" not in hits and hits == ["/api/ps"]
    message = err.value.message
    assert f"~{request_chars(BIG_REQUEST, []) // 4} tokens" in message
    assert "(4096 tokens)" in message
    assert "minimal" in message and "OLLAMA_CONTEXT_LENGTH" in message


@pytest.mark.parametrize("ps", [
    {"models": []},                                   # model not loaded yet
    _ps_body(4096, name="other:latest"),              # another model loaded
    {"models": [{"name": "m-1:latest"}]},              # no context_length field
    500,                                              # server error
    httpx.ConnectError("refused"),                    # unreachable
])
def test_ollama_proactive_check_fails_open(ps):
    hits = []
    turn = _complete_on_wire("ollama", _ollama_handler(ps, hits), BIG_REQUEST)
    assert turn.text == "hi" and hits[-1] == "/v1/chat/completions"


def test_ollama_reply_reserve_is_capped():
    # ~3 000 request tokens + min(8192, 1024) reply <= 4096: fits
    small = [{"role": "user", "content": "x" * 11_950}]
    assert request_chars(small, []) // 4 + 1024 <= 4096
    hits = []
    _complete_on_wire("ollama", _ollama_handler(_ps_body(4096), hits), small)
    assert hits == ["/api/ps", "/v1/chat/completions"]


def test_context_fits_boundary():
    check_context_fits(3000, 1096, 4096)
    with pytest.raises(CapabilityError) as err:
        check_context_fits(3001, 1096, 4096)
    assert err.value.code == "agent.context_truncated"


def test_ollama_context_length_matches_tagged_names():
    body = _ps_body(8192, name="llama3.3:latest")
    assert ollama_context_length(body, "llama3.3") == 8192
    assert ollama_context_length(body, "llama3.3:latest") == 8192
    assert ollama_context_length(body, "llama3.3:70b") is None
    assert ollama_context_length(None, "llama3.3") is None
    assert ollama_context_length({"models": [{"name": "m:latest",
                                              "context_length": 0}]}, "m") is None


@pytest.mark.parametrize("base, native", [
    ("http://127.0.0.1:11434/v1", "http://127.0.0.1:11434"),
    ("http://127.0.0.1:11434/v1/", "http://127.0.0.1:11434"),
    ("http://host:11434", "http://host:11434"),
])
def test_native_base_url(base, native):
    assert native_base_url(base) == native


def test_probe_caches_the_window_and_invalidates():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=_ps_body(4096))

    async def go():
        probe = OllamaContextProbe("http://o.test/v1",
                                   httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        assert await probe.context_length("m-1") == 4096
        assert await probe.context_length("m-1") == 4096
        assert len(calls) == 1
        probe.invalidate()
        assert await probe.context_length("m-1") == 4096
        assert len(calls) == 2

    asyncio.run(go())


def test_probe_does_not_cache_an_unloaded_model():
    bodies = [{"models": []}, _ps_body(4096)]

    def handler(request):
        return httpx.Response(200, json=bodies.pop(0))

    async def go():
        probe = OllamaContextProbe("http://o.test/v1",
                                   httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        assert await probe.context_length("m-1") is None
        assert await probe.context_length("m-1") == 4096

    asyncio.run(go())


@pytest.mark.parametrize("status, message, code", [
    (401, f"Incorrect API key provided: {SECRET}", "agent.auth_failed"),
    (403, "forbidden", "agent.auth_failed"),
    (404, "The model `m-1` does not exist", "agent.model_not_found"),
    (429, "Rate limit reached", "agent.rate_limited"),
    (400, "This model's maximum context length is 8192 tokens", "agent.context_overflow"),
    (400, "Invalid 'messages'", "agent.provider_rejected"),
    (500, "boom", "agent.provider_rejected"),
])
def test_error_mapping_never_leaks_the_key(status, message, code):
    def handler(request):
        return httpx.Response(status, json={"error": {"message": message, "type": "x"}})

    async def on_text(_):
        pass

    async def go():
        model, _ = _model("openai", handler)
        model._client = model._client.with_options(max_retries=0)
        try:
            await model.complete(MESSAGES, TOOLS, on_text)
        finally:
            await model.aclose()

    with pytest.raises(CapabilityError) as err:
        asyncio.run(go())
    assert err.value.code == code
    assert SECRET not in str(err.value) and SECRET not in repr(err.value.details)
    if code == "agent.model_not_found":
        assert "Responses API" in err.value.message


def test_unreachable_provider_maps_to_503():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    async def on_text(_):
        pass

    async def go():
        model, _ = _model("ollama", handler)
        model._client = model._client.with_options(max_retries=0)
        try:
            await model.complete(MESSAGES, [], on_text)
        finally:
            await model.aclose()

    with pytest.raises(CapabilityError) as err:
        asyncio.run(go())
    assert err.value.code == "agent.provider_unreachable" and err.value.status == 503


def test_missing_openai_package_gives_an_install_hint(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "openai":
            raise ImportError("no openai")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(CapabilityError) as err:
        OpenAICompatModel(P.get_preset("openai"), "m", "low", "http://x/v1", SECRET)
    assert err.value.code == "agent.openai_missing" and "openai" in err.value.message
