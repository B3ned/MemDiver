"""The ChatModel port of the OpenAI-compatible backend, and its ``openai`` adapter.

:class:`ChatModel` is one model call: messages + tools in, one :class:`ModelTurn` out,
text streamed through ``on_text`` as it arrives. :class:`StreamAccumulator` (pure, no
SDK import) folds streamed chunks into a turn; :class:`OpenAICompatModel` drives the
``openai`` SDK, which is imported lazily so MemDiver imports without it
(``pip install "memdiver[agent]"``).

Request rules (plan module 6): ``stream_options.include_usage`` is always requested,
the output cap uses the preset's ``max_tokens_param``, ``reasoning_effort`` is sent
only when the preset supports it, and ``tool_choice`` is NEVER sent (the model decides).
Errors become :class:`CapabilityError` with ``agent.*`` codes; no message ever carries
the API key.

Context guards: a preset with ``context_probe="ollama"`` is checked BEFORE each request
(:class:`OllamaContextProbe` reads the loaded model's runtime window from ``/api/ps``).
Every other preset keeps the post-hoc :func:`check_truncation` ratio guard. It cannot
run for Ollama: ``prompt_eval_count`` leaves out the KV-cache-reused prefix (the
byte-stable system prompt and tool list, even across chats), so a growing request
reports SHRINKING prompt tokens and the ratio guard false-alarms.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, Tuple

from memdiver.core.install_hints import missing_package_message
from memdiver.core.service_errors import CapabilityError, ErrorCategory

from .providers import ProviderPreset

logger = logging.getLogger(__name__)

OnText = Callable[[str], Awaitable[None]]

#: Rough token estimate when the provider reports no usage.
CHARS_PER_TOKEN = 4
#: Truncation guard: requests smaller than this are never flagged.
TRUNCATION_MIN_REQUEST_CHARS = 20_000
#: Truncation guard: reported prompt tokens below this share of our estimate trip it.
TRUNCATION_RATIO = 0.5
_REDACTED = "[redacted]"
#: Proactive Ollama check: ``/api/ps`` timeout and how long a read window stays cached.
CONTEXT_PROBE_TIMEOUT_S = 2.0
CONTEXT_PROBE_TTL_S = 30.0
#: Reply room reserved in the window: the requested output cap, but at most this much
#: (Ollama does not pre-reserve ``num_predict``; the full 8192 cap would reject every
#: request on its 4096-token default window).
CONTEXT_REPLY_RESERVE_TOKENS = 1024


@dataclass(frozen=True)
class Usage:
    prompt_tokens: int
    completion_tokens: int
    #: True when estimated from characters (the provider sent no usage chunk).
    estimated: bool


@dataclass(frozen=True)
class ToolCallRequest:
    """One tool call as the model asked for it."""

    #: The provider's call id; it stays inside the history (the UI gets its own ids).
    provider_id: str
    name: str
    #: The raw JSON string the model produced (may be invalid JSON).
    arguments: str


@dataclass(frozen=True)
class ModelTurn:
    text: str
    tool_calls: Tuple[ToolCallRequest, ...]
    #: Hidden reasoning (``reasoning_content`` / ``reasoning``); never displayed.
    reasoning: str
    usage: Usage
    finish_reason: Optional[str]


class ChatModel(Protocol):
    """One model call per :meth:`complete`; :meth:`aclose` releases the client."""

    async def complete(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]],
                       on_text: OnText) -> ModelTurn: ...

    async def aclose(self) -> None: ...


def _field(obj: Any, name: str) -> Any:
    """``obj[name]`` for dicts, ``obj.name`` for SDK objects; ``None`` when absent."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def request_chars(messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> int:
    """Size of the request payload in characters (the basis of every estimate)."""
    return len(json.dumps(messages, default=str)) + len(json.dumps(tools, default=str))


class StreamAccumulator:
    """Folds streamed Chat Completions chunks (SDK objects or dicts) into a ModelTurn."""

    def __init__(self) -> None:
        self._text: List[str] = []
        self._reasoning: List[str] = []
        self._calls: Dict[int, Dict[str, str]] = {}
        self._usage: Any = None
        self._finish: Optional[str] = None

    def feed(self, chunk: Any) -> str:
        """Absorb one chunk; returns its visible text delta (``""`` if none)."""
        usage = _field(chunk, "usage")
        if usage is not None:
            self._usage = usage
        text = ""
        for choice in _field(chunk, "choices") or []:
            text += self._feed_choice(choice)
        return text

    def _feed_choice(self, choice: Any) -> str:
        self._finish = _field(choice, "finish_reason") or self._finish
        delta = _field(choice, "delta")
        reasoning = _field(delta, "reasoning_content") or _field(delta, "reasoning")
        if isinstance(reasoning, str):
            self._reasoning.append(reasoning)
        for fragment in _field(delta, "tool_calls") or []:
            self._feed_tool_call(fragment)
        content = _field(delta, "content")
        if isinstance(content, str) and content:
            self._text.append(content)
            return content
        return ""

    def _feed_tool_call(self, fragment: Any) -> None:
        index = _field(fragment, "index")
        if not isinstance(index, int):
            index = len(self._calls)
        call = self._calls.setdefault(index, {"id": "", "name": "", "arguments": ""})
        call["id"] = _field(fragment, "id") or call["id"]
        function = _field(fragment, "function")
        call["name"] += _field(function, "name") or ""
        call["arguments"] += _field(function, "arguments") or ""

    def result(self, request_chars: int) -> ModelTurn:
        """The finished turn; usage estimated at chars/4 when the provider sent none."""
        text = "".join(self._text)
        calls = tuple(ToolCallRequest(c["id"], c["name"], c["arguments"])
                      for _, c in sorted(self._calls.items()))
        return ModelTurn(text, calls, "".join(self._reasoning),
                         self._final_usage(request_chars, text, calls), self._finish)

    def _final_usage(self, request_chars: int, text: str,
                     calls: Tuple[ToolCallRequest, ...]) -> Usage:
        prompt = _field(self._usage, "prompt_tokens")
        completion = _field(self._usage, "completion_tokens")
        if isinstance(prompt, int) and isinstance(completion, int):
            return Usage(prompt, completion, estimated=False)
        produced = len(text) + sum(len(c.name) + len(c.arguments) for c in calls)
        return Usage(request_chars // CHARS_PER_TOKEN, produced // CHARS_PER_TOKEN,
                     estimated=True)


def check_truncation(usage: Usage, chars: int) -> None:
    """Raise ``agent.context_truncated`` when the provider saw far less than we sent.

    Post-hoc guard for presets without a ``context_probe`` (vLLM etc. report the full
    prompt). Never used for Ollama, whose prompt count excludes the KV-cache-reused
    prefix (see the module docstring).
    """
    if usage.estimated or chars <= TRUNCATION_MIN_REQUEST_CHARS:
        return
    if usage.prompt_tokens < TRUNCATION_RATIO * (chars / CHARS_PER_TOKEN):
        raise CapabilityError(
            f"the provider read only {usage.prompt_tokens} prompt tokens of a request of "
            f"about {chars // CHARS_PER_TOKEN}; it truncated the context. Use the tool "
            "set 'minimal' or raise OLLAMA_CONTEXT_LENGTH on the Ollama server.",
            category=ErrorCategory.PRECONDITION, status=400,
            code="agent.context_truncated")


def check_context_fits(request_tokens: int, reply_tokens: int, window: int) -> None:
    """Raise ``agent.context_truncated`` when the request plus reply room overflow ``window``."""
    if request_tokens + reply_tokens <= window:
        return
    raise CapabilityError(
        f"the request (~{request_tokens} tokens) exceeds the model's context window "
        f"({window} tokens) on the Ollama server; use tool set 'minimal', start a new "
        "chat, or raise OLLAMA_CONTEXT_LENGTH",
        category=ErrorCategory.PRECONDITION, status=400, code="agent.context_truncated")


def native_base_url(base_url: str) -> str:
    """The provider's native API root: the OpenAI-compatible base without ``/v1``."""
    base = base_url.rstrip("/")
    return base[:-len("/v1")] if base.endswith("/v1") else base


def _with_tag(name: str) -> str:
    """``llama3.3`` -> ``llama3.3:latest`` (Ollama lists models with their tag)."""
    return name if ":" in name else f"{name}:latest"


def ollama_context_length(ps_body: Any, model: str) -> Optional[int]:
    """The runtime ``context_length`` of ``model`` in an ``/api/ps`` body, else ``None``.

    Observed on Ollama 0.13.5 (llama3.3 loaded on the default server config)::

        {"models": [{"name": "llama3.3:latest", "model": "llama3.3:latest",
                     "size": 43876075520, "digest": "a6eb...", "details": {...},
                     "expires_at": "...", "size_vram": 43876075520,
                     "context_length": 4096}]}

    ``context_length`` is the window the loaded runner uses (``OLLAMA_CONTEXT_LENGTH``),
    not the model maximum of ``/api/show`` (131072 for llama3.3). A model that is not
    loaded is absent: its window is unknown until the first request loads it.
    """
    wanted = _with_tag(model)
    for entry in _field(ps_body, "models") or []:
        names = {_with_tag(str(_field(entry, k) or "")) for k in ("name", "model")}
        length = _field(entry, "context_length")
        if wanted in names and isinstance(length, int) and length > 0:
            return length
    return None


class OllamaContextProbe:
    """Reads (and briefly caches) a loaded model's runtime context window from Ollama.

    Fails open: an unreachable server, a malformed body or an unloaded model yields
    ``None`` (logged at debug) and the request goes out unchecked.
    """

    def __init__(self, base_url: str, http_client: Any = None) -> None:
        self._ps_url = native_base_url(base_url) + "/api/ps"
        self._http = http_client
        self._owns_http = http_client is None
        self._cache: Dict[str, Tuple[int, float]] = {}

    async def context_length(self, model: str) -> Optional[int]:
        cached = self._cache.get(model)
        if cached and time.monotonic() - cached[1] < CONTEXT_PROBE_TTL_S:
            return cached[0]
        length = ollama_context_length(await self._read_ps(), model)
        if length is None:
            logger.debug("ollama context probe: no window for %s; request unchecked", model)
            self._cache.pop(model, None)
        else:
            self._cache[model] = (length, time.monotonic())
        return length

    async def _read_ps(self) -> Any:
        try:
            response = await self._client().get(self._ps_url,
                                                 timeout=CONTEXT_PROBE_TIMEOUT_S)
            response.raise_for_status()
            return response.json()
        except Exception as exc:  # noqa: BLE001 - the probe must never break a chat
            logger.debug("ollama context probe failed (%s); request unchecked",
                         type(exc).__name__)
            return None

    def _client(self) -> Any:
        if self._http is None:
            import httpx  # shipped with openai
            self._http = httpx.AsyncClient(timeout=CONTEXT_PROBE_TIMEOUT_S)
        return self._http

    def invalidate(self) -> None:
        """Forget cached windows (after a failed request the server may have changed)."""
        self._cache.clear()

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()


def message_for_history(turn: ModelTurn, preset: ProviderPreset) -> Dict[str, Any]:
    """The assistant message to append to the history after ``turn``."""
    message: Dict[str, Any] = {"role": "assistant", "content": turn.text or None}
    if turn.tool_calls:
        message["tool_calls"] = [
            {"id": call.provider_id, "type": "function",
             "function": {"name": call.name, "arguments": call.arguments}}
            for call in turn.tool_calls]
    if preset.echo_reasoning and turn.reasoning:
        message["reasoning_content"] = turn.reasoning
    return message


def _load_openai() -> Any:
    try:
        import openai
    except ImportError as exc:
        raise CapabilityError(
            missing_package_message("openai", "agent"),
            category=ErrorCategory.PRECONDITION, status=503,
            code="agent.openai_missing") from exc
    return openai


def _is_context_length(message: str) -> bool:
    lowered = message.lower()
    return "context length" in lowered or "context_length" in lowered \
        or "maximum context" in lowered or "context window" in lowered


#: ``(exception class name, code, category, status, message)``; first match wins, so
#: subclasses come before their bases (``APITimeoutError`` < ``APIConnectionError``).
_ERROR_TABLE: Tuple[Tuple[str, str, ErrorCategory, int, str], ...] = (
    ("APITimeoutError", "agent.provider_unreachable", ErrorCategory.PRECONDITION, 503,
     "the model provider timed out"),
    ("APIConnectionError", "agent.provider_unreachable", ErrorCategory.PRECONDITION, 503,
     "cannot reach the model provider; check that it is running and reachable"),
    ("AuthenticationError", "agent.auth_failed", ErrorCategory.PRECONDITION, 502,
     "the model provider rejected the API key"),
    ("PermissionDeniedError", "agent.auth_failed", ErrorCategory.PRECONDITION, 502,
     "the API key is not allowed to use this model"),
    ("RateLimitError", "agent.rate_limited", ErrorCategory.PRECONDITION, 429,
     "the model provider is rate limiting (or the account is out of credit)"),
    ("NotFoundError", "agent.model_not_found", ErrorCategory.NOT_FOUND, 404,
     "model not found at this provider; newer OpenAI flagships may need the "
     "Responses API, which this backend does not speak"),
)


class OpenAICompatModel:
    """:class:`ChatModel` over an OpenAI-compatible Chat Completions endpoint."""

    def __init__(self, preset: ProviderPreset, model: str, effort: str, base_url: str,
                 api_key: str, max_output_tokens: int = 8192,
                 http_client: Any = None) -> None:
        self._openai = _load_openai()
        self._preset = preset
        self._model = model
        self._effort = effort
        self._api_key = api_key
        self._max_output_tokens = max_output_tokens
        self._client = self._openai.AsyncOpenAI(
            base_url=base_url, api_key=api_key, http_client=http_client, max_retries=2)
        self._context_probe = (OllamaContextProbe(base_url, http_client)
                               if preset.context_probe == "ollama" else None)

    def _request(self, messages: List[Dict[str, Any]],
                 tools: List[Dict[str, Any]]) -> Dict[str, Any]:
        request: Dict[str, Any] = {
            "model": self._model, "messages": messages, "stream": True,
            "stream_options": {"include_usage": True},
            self._preset.max_tokens_param: self._max_output_tokens,
        }
        if tools:
            request["tools"] = tools
        if self._preset.supports_effort:
            request["reasoning_effort"] = self._effort
        return request

    async def complete(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]],
                       on_text: OnText) -> ModelTurn:
        chars = request_chars(messages, tools)
        await self._check_context_window(chars)
        try:
            turn = await self._stream(self._request(messages, tools), on_text, chars)
        except self._openai.OpenAIError as exc:
            if self._context_probe is not None:
                self._context_probe.invalidate()
            raise self._map_error(exc) from None
        if self._context_probe is None:
            check_truncation(turn.usage, chars)
        return turn

    async def _check_context_window(self, chars: int) -> None:
        """Proactive guard (probe presets only): refuse a request the window cannot hold."""
        if self._context_probe is None:
            return
        window = await self._context_probe.context_length(self._model)
        if window is not None:
            reply = min(self._max_output_tokens, CONTEXT_REPLY_RESERVE_TOKENS)
            check_context_fits(chars // CHARS_PER_TOKEN, reply, window)

    async def _stream(self, request: Dict[str, Any], on_text: OnText,
                      chars: int) -> ModelTurn:
        accumulator = StreamAccumulator()
        stream = await self._client.chat.completions.create(**request)
        async for chunk in stream:
            text = accumulator.feed(chunk)
            if text:
                await on_text(text)
        return accumulator.result(chars)

    def _map_error(self, exc: Exception) -> CapabilityError:
        """The ``agent.*`` CapabilityError for an openai exception (key redacted)."""
        detail = self._redact(str(getattr(exc, "message", "") or exc))
        for class_name, code, category, status, message in _ERROR_TABLE:
            if isinstance(exc, getattr(self._openai, class_name)):
                return CapabilityError(f"{message} ({detail})", category=category,
                                       status=status, code=code)
        if isinstance(exc, self._openai.BadRequestError) and _is_context_length(detail):
            return CapabilityError(
                f"the conversation exceeds the model's context window ({detail}); start a "
                "new chat or use the tool set 'minimal'",
                category=ErrorCategory.PRECONDITION, status=400, code="agent.context_overflow")
        return CapabilityError(f"the model provider rejected the request ({detail})",
                               category=ErrorCategory.PRECONDITION, status=502,
                               code="agent.provider_rejected")

    def _redact(self, text: str) -> str:
        key = self._api_key
        return text.replace(key, _REDACTED) if key and len(key) >= 4 else text

    async def aclose(self) -> None:
        if self._context_probe is not None:
            await self._context_probe.aclose()
        await self._client.close()
