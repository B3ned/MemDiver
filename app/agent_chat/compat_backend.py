"""OpenAI-compatible implementation of :class:`contracts.AgentBackend` (our own tool loop).

One :class:`CompatAgentBackend` = one chat = one :class:`chat_model.ChatModel` plus one
sandboxed ``memdiver mcp`` child driven through :class:`mcp_tools.McpToolClient`. Unlike
the Claude SDK path, MemDiver runs the agentic loop itself, so this module owns the
invariants the SDK enforces there:

- every tool call goes through the :class:`contracts.PermissionGate` (READ tools pass,
  WRITE tools wait for the analyst) -- except calls that are invalid on their face (a
  name the MCP server never listed, e.g. a doubled ``mcp__memdiver__`` prefix, or
  arguments that are not a JSON object): they get an error result and NEVER reach the
  gate or the server;
- exactly ONE ``usage`` and ONE ``result`` event per :meth:`send`, whatever happens;
- the stop reasons are the SDK's (``success``, ``error_max_turns``,
  ``error_max_budget_usd``, ``error_during_execution``) plus ``error_max_output_tokens``
  (a reply cut off by the provider's output limit), so the UI reducer is shared;
- every assistant message in the history has a string ``content`` (``""`` for an empty
  turn): ``null`` content without tool calls makes OpenAI/DeepSeek reject every later
  request with HTTP 400;
- **H1**: after :meth:`send` returns, every assistant ``tool_call`` id in the history
  has exactly one ``tool`` message (an interrupted call gets ``interrupted: not run``);
  without it the next request fails with HTTP 400 on every provider;
- event ids are chat-unique (uuid hex); provider call ids (which may be empty or
  repeated) live only inside the history.

Security stance: tool calls are taken ONLY from the provider's structured
``tool_calls``. A model that writes JSON as plain text gets nothing executed.

Known limits (v1): a context overflow is reported as an error, not compacted; an
interrupt abandons the result of an in-flight tool, which keeps running in the child.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple

from memdiver.app.agent_chat import contracts as c
from memdiver.app.agent_chat.chat_model import (
    ChatModel, ModelTurn, ToolCallRequest, Usage, message_for_history)
from memdiver.app.agent_chat.mcp_tools import McpToolClient
from memdiver.app.agent_chat.providers import ProviderPreset, get_preset, price_known
from memdiver.app.agent_chat.tool_events import access_label, tool_result_event
from memdiver.app.agent_chat.tool_schemas import build_tools
from memdiver.core.service_errors import CapabilityError, ErrorCategory

__all__ = ["CompatAgentBackend", "INTERRUPTED_TOOL_TEXT", "ModelFactory", "repair_history"]

logger = logging.getLogger(__name__)

ModelFactory = Callable[[c.ChatSpec], ChatModel]

STOP_SUCCESS = "success"
STOP_MAX_TURNS = "error_max_turns"
STOP_MAX_BUDGET = "error_max_budget_usd"
STOP_DURING_EXECUTION = "error_during_execution"
STOP_MAX_OUTPUT = "error_max_output_tokens"
#: ``finish_reason`` of a reply cut off by the provider's output-token limit.
_FINISH_LENGTH = "length"

#: Tool message filled in for a call that never ran (invariant H1).
INTERRUPTED_TOOL_TEXT = "interrupted: not run"
#: Bound on starting the MCP child and listing its tools.
START_TIMEOUT_SECONDS = 120.0
#: Bound on the graceful MCP close; below ``session.BACKEND_CLOSE_TIMEOUT_SECONDS`` so
#: :meth:`CompatAgentBackend.close` finishes (and releases the model) before the session
#: gives up on it. On timeout the child is killed.
MCP_CLOSE_TIMEOUT_SECONDS = 4.0
#: Bound on releasing the model's HTTP client (close and kill).
MODEL_CLOSE_TIMEOUT_SECONDS = 1.0
_TOKENS_PER_MTOK = 1_000_000


async def _discard_event(_event: c.ChatEvent) -> None:
    """Emit target before ``start`` supplies the real one."""


@dataclasses.dataclass
class _Run:
    """Bookkeeping of one :meth:`CompatAgentBackend.send` (one user message)."""

    turns: int = 0
    cost: float = 0.0
    stop: str = STOP_SUCCESS


@dataclasses.dataclass(frozen=True)
class _Call:
    """One tool call of a model turn: UI id, history id, and what the model asked."""

    event_id: str
    history_id: str
    name: str
    arguments: str


def _new_id() -> str:
    return uuid.uuid4().hex


# -- invariant H1 ------------------------------------------------------------------------


def _tool_call_ids(message: Mapping[str, Any]) -> List[str]:
    if message.get("role") != "assistant":
        return []
    return [str(call.get("id", "")) for call in message.get("tool_calls") or []]


def _answers(history: List[Dict[str, Any]], start: int) -> Tuple[Dict[str, Dict[str, Any]], int]:
    """The ``tool`` messages directly after ``history[start]`` (first per id), and the
    index of the first message after them."""
    found: Dict[str, Dict[str, Any]] = {}
    index = start + 1
    while index < len(history) and history[index].get("role") == "tool":
        found.setdefault(str(history[index].get("tool_call_id", "")), history[index])
        index += 1
    return found, index


def repair_history(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """``history`` with every assistant tool call answered by exactly one ``tool``
    message, in call order (missing ones: :data:`INTERRUPTED_TOOL_TEXT`; duplicates and
    orphans dropped)."""
    repaired: List[Dict[str, Any]] = []
    index = 0
    while index < len(history):
        message = history[index]
        if message.get("role") == "tool":  # orphan: no assistant call precedes it
            index += 1
            continue
        repaired.append(message)
        ids = _tool_call_ids(message)
        if not ids:
            index += 1
            continue
        found, index = _answers(history, index)
        repaired.extend(found.get(i) or {"role": "tool", "tool_call_id": i,
                                         "content": INTERRUPTED_TOOL_TEXT} for i in ids)
    return repaired


# -- the backend -------------------------------------------------------------------------


class CompatAgentBackend:
    """:class:`contracts.AgentBackend` over a :class:`ChatModel` and the MCP child.

    ``model_factory(spec)`` builds the model (``OpenAICompatModel`` for a real provider,
    ``ScriptedChatModel`` for tests/demos). ``tool_access`` is the API layer's
    ``{tool: read|write|write_once|never}`` map; ``spec.tool_access`` overrides it.
    """

    def __init__(self, model_factory: ModelFactory,
                 tool_access: Optional[Mapping[str, str]] = None) -> None:
        self._model_factory = model_factory
        self._tool_access: Mapping[str, str] = tool_access or {}
        self._emit: c.Emit = _discard_event
        self._gate: Optional[c.PermissionGate] = None
        self._mcp: Optional[McpToolClient] = None
        self._model: Optional[ChatModel] = None
        self._settings = c.AgentSettings()
        self._preset: ProviderPreset = get_preset("anthropic")
        self._listed: Set[str] = set()
        self._tools: List[Dict[str, Any]] = []
        self._history: List[Dict[str, Any]] = []
        self._history_ids: Set[str] = set()
        self._turn: Optional["asyncio.Task[None]"] = None
        self._interrupted = False
        #: True while :meth:`send` runs; an interrupt that lands before the inner turn
        #: task exists is remembered in ``_interrupt_pending`` (only then).
        self._sending = False
        self._interrupt_pending = False
        self._session_id = f"compat-{uuid.uuid4().hex[:12]}"

    # -- lifecycle ---------------------------------------------------------------

    async def start(self, spec: c.ChatSpec, gate: c.PermissionGate, emit: c.Emit) -> None:
        self._emit, self._gate, self._settings = emit, gate, spec.settings
        self._preset = get_preset(spec.settings.provider)
        if spec.tool_access:
            self._tool_access = spec.tool_access
        await self._emit(c.ChatEvent("status", {"state": "starting"}))
        try:
            self._model = self._model_factory(spec)
            await asyncio.wait_for(self._start_tools(spec), START_TIMEOUT_SECONDS)
        except Exception as exc:
            await self._abort_start()
            raise _start_error(exc) from exc
        self._history = [{"role": "system", "content": spec.system_prompt}]
        await self._emit(c.ChatEvent("status", {"state": "ready"}))

    async def _start_tools(self, spec: c.ChatSpec) -> None:
        """Start the MCP child; remember EVERY listed name (``never`` ones included, for
        the unknown-name check) and offer the model the effective tool set."""
        self._mcp = McpToolClient({
            "command": spec.mcp.command, "args": list(spec.mcp.args),
            "env": dict(spec.mcp.env), "cwd": spec.cwd})
        await self._mcp.start()
        listed = await self._mcp.list_tools()
        self._listed = {name for name, _description, _schema in listed}
        self._tools = build_tools(listed, self._tool_access,
                                  self._settings.effective_tool_set())

    async def _abort_start(self) -> None:
        await self.kill()  # stops the MCP child and releases the model client

    async def send(self, text: str) -> None:
        if self._model is None or self._mcp is None:
            raise CapabilityError("the chat is not started", category=ErrorCategory.PRECONDITION,
                                  code="agent.not_started")
        self._sending, self._interrupt_pending = True, False
        try:
            await self._emit(c.ChatEvent("status", {"state": "running"}))
            self._history.append({"role": "user", "content": text})
            run, self._interrupted = _Run(), False
            try:
                await self._run_unless_interrupted(run)
            finally:
                self._turn = None
                self._history = repair_history(self._history)
                await self._finish(run)
                await self._emit(c.ChatEvent("status", {"state": "ready"}))
        finally:
            self._sending = self._interrupt_pending = False

    async def _run_unless_interrupted(self, run: _Run) -> None:
        """Run the inner loop task, unless an interrupt arrived before it was created."""
        if self._interrupt_pending:
            run.stop = STOP_DURING_EXECUTION
            return
        self._turn = asyncio.get_running_loop().create_task(self._loop(run))
        await self._await_turn(run)

    async def _await_turn(self, run: _Run) -> None:
        """Await the inner loop task; map interrupts and model failures to a stop reason.
        Only a cancellation of ``send`` itself (not :meth:`interrupt`) propagates."""
        turn = self._turn
        if turn is None:
            return
        try:
            await turn
        except asyncio.CancelledError:
            run.stop = STOP_DURING_EXECUTION
            if not self._interrupted:
                raise
        except Exception as exc:
            run.stop = STOP_DURING_EXECUTION
            err = _as_capability_error(exc)
            await self._emit(c.ChatEvent("error", {
                "code": err.code or "agent.error", "message": str(err)}))

    async def interrupt(self) -> None:
        """Cancel the running turn only; ``send`` still emits its single result.

        Between :meth:`send` starting and its inner task existing, the interrupt is
        remembered and honoured by that send; while idle it is ignored, so it never
        stops the NEXT message.
        """
        if self._turn is not None and not self._turn.done():
            self._interrupted = True
            self._turn.cancel()
        elif self._sending:
            self._interrupt_pending = True

    async def close(self) -> None:
        """Graceful close, bounded by :data:`MCP_CLOSE_TIMEOUT_SECONDS` (then a kill); the
        model client is released even when this close is cancelled."""
        if self._mcp is None and self._model is None:
            return
        try:
            await self._close_tools()
        finally:
            await self._release_model()
        await self._emit(c.ChatEvent("status", {"state": "closed"}))

    async def _close_tools(self) -> None:
        mcp = self._mcp
        if mcp is None:
            return
        try:
            await asyncio.wait_for(mcp.close(), MCP_CLOSE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            logger.warning("agent chat: the MCP child did not close in time; killing it")
            await self.kill()
            return
        self._mcp = None

    async def _release_model(self) -> None:
        """Close the model's HTTP client (bounded, best-effort). Safe to repeat."""
        model, self._model = self._model, None
        if model is not None:
            await _quietly(asyncio.wait_for(model.aclose(), MODEL_CLOSE_TIMEOUT_SECONDS))

    async def kill(self) -> None:
        """Hard stop of the MCP child (``stdio_client`` reaps it) plus a bounded release
        of the model client. Safe to repeat."""
        mcp, self._mcp = self._mcp, None
        try:
            if mcp is not None:
                await mcp.kill()
        finally:
            await self._release_model()

    # -- the tool loop -------------------------------------------------------------

    async def _loop(self, run: _Run) -> None:
        while True:
            stop = self._limit_reached(run)
            if stop:
                run.stop = stop
                return
            turn = await self._started()[0].complete(
                self._history, self._tools, self._on_text)
            run.turns += 1
            run.cost += self._price(turn.usage)
            calls = self._record_turn(turn)
            if turn.text:
                await self._emit(c.ChatEvent("assistant_message", {"text": turn.text}))
            if not calls:
                await self._stop_if_truncated(run, turn)
                return
            await self._run_calls(calls)

    async def _stop_if_truncated(self, run: _Run, turn: ModelTurn) -> None:
        """A final reply cut off by the output-token limit is not a success."""
        if turn.finish_reason != _FINISH_LENGTH:
            return
        run.stop = STOP_MAX_OUTPUT
        await self._emit(c.ChatEvent("error", {
            "code": "agent.output_truncated",
            "message": "the model's reply was cut off by the provider's output-token "
                       "limit; ask for a shorter answer or continue in a new message"}))

    def _started(self) -> Tuple[ChatModel, c.PermissionGate, McpToolClient]:
        """The live model, gate and MCP client; ``agent.not_started`` once closed (an
        explicit check, not an ``assert``: it guards the gate path)."""
        if self._model is None or self._gate is None or self._mcp is None:
            raise CapabilityError("the chat is not started (or already closed)",
                                  category=ErrorCategory.PRECONDITION, code="agent.not_started")
        return self._model, self._gate, self._mcp

    def _limit_reached(self, run: _Run) -> Optional[str]:
        """The SDK's limits, applied per user message, checked before each model turn."""
        if run.turns >= self._settings.max_turns:
            return STOP_MAX_TURNS
        if run.cost >= self._settings.max_budget_usd:
            return STOP_MAX_BUDGET
        return None

    async def _on_text(self, text: str) -> None:
        await self._emit(c.ChatEvent("text_delta", {"text": text}))

    def _price(self, usage: Usage) -> float:
        price_in, price_out = self._settings.effective_prices()
        return (usage.prompt_tokens * price_in
                + usage.completion_tokens * price_out) / _TOKENS_PER_MTOK

    def _record_turn(self, turn: ModelTurn) -> List[_Call]:
        """Append the assistant message (history ids made unique) and return its calls."""
        calls = [_Call(_new_id(), self._history_id(t.provider_id), t.name, t.arguments)
                 for t in turn.tool_calls]
        renamed = dataclasses.replace(turn, tool_calls=tuple(
            ToolCallRequest(call.history_id, call.name, call.arguments) for call in calls))
        self._history.append(_with_text_content(message_for_history(renamed, self._preset)))
        return calls

    def _history_id(self, provider_id: str) -> str:
        """The provider's id when it is non-empty and new in this chat, else a fresh one."""
        history_id = provider_id
        if not history_id or history_id in self._history_ids:
            history_id = f"call_{_new_id()}"
        self._history_ids.add(history_id)
        return history_id

    async def _run_calls(self, calls: List[_Call]) -> None:
        parsed = [(call, *self._validate(call)) for call in calls]
        for call, arguments, _problem in parsed:
            await self._emit(c.ChatEvent("tool_call", {
                "id": call.event_id, "name": call.name, "input": arguments,
                "access": access_label(self._tool_access, call.name)}))
        for call, arguments, problem in parsed:
            text, is_error = (problem, True) if problem else await self._execute(
                call.name, arguments)
            self._history.append({"role": "tool", "tool_call_id": call.history_id,
                                  "content": text})
            await self._emit(tool_result_event(call.event_id, text, is_error))

    def _validate(self, call: _Call) -> Tuple[Dict[str, Any], str]:
        """``(arguments, problem)``; a non-empty problem means: do not run, do not ask."""
        if call.name not in self._listed:
            return {}, (f"unknown tool '{call.name[:80]}'; use the tool names exactly as "
                        "offered (no prefix)")
        try:
            arguments = json.loads(call.arguments) if call.arguments.strip() else {}
        except ValueError:
            return {}, "bad args: the arguments are not valid JSON"
        if not isinstance(arguments, dict):
            return {}, "bad args: the arguments must be a JSON object"
        return arguments, ""

    async def _execute(self, name: str, arguments: Dict[str, Any]) -> Tuple[str, bool]:
        _model, gate, mcp = self._started()
        decision = await gate.decide(c.TOOL_PREFIX + name, arguments)
        if not decision.allow:
            return f"Denied: {decision.message or 'Denied.'}", True
        try:
            return await mcp.call(name, arguments)
        except Exception as exc:  # noqa: BLE001 - reported to the model as a tool error
            return f"MCP server failed: {type(exc).__name__}: {exc}", True

    async def _finish(self, run: _Run) -> None:
        """The single ``usage`` + ``result`` pair of one send."""
        prices = self._settings.effective_prices()
        cost = round(run.cost, 6)
        await self._emit(c.ChatEvent("usage", {
            "turns": run.turns, "max_turns": self._settings.max_turns,
            "cost_estimate_usd": cost, "max_budget_usd": self._settings.max_budget_usd,
            "cost_known": price_known(self._preset, prices)}))
        await self._emit(c.ChatEvent("result", {
            "session_id": self._session_id, "num_turns": run.turns,
            "cost_estimate_usd": cost, "stop_reason": run.stop,
            "is_error": run.stop != STOP_SUCCESS}))


def _with_text_content(message: Dict[str, Any]) -> Dict[str, Any]:
    """``message`` with ``content`` ``""`` instead of ``None`` when it has no tool calls
    (an empty turn): providers reject a ``null`` assistant content without tool calls."""
    if message.get("content") is None and not message.get("tool_calls"):
        return {**message, "content": ""}
    return message


# -- errors ------------------------------------------------------------------------------


async def _quietly(awaitable: Any) -> None:
    try:
        await awaitable
    except Exception as exc:  # noqa: BLE001 - releasing a client must never fail a close
        logger.debug("agent chat: releasing the model client failed: %s", exc)


def _as_capability_error(exc: Exception) -> CapabilityError:
    if isinstance(exc, CapabilityError):
        return exc
    return CapabilityError(f"agent error: {type(exc).__name__}: {exc}",
                           category=ErrorCategory.INTERNAL, status=500, code="agent.error")


def _start_error(exc: Exception) -> CapabilityError:
    if isinstance(exc, CapabilityError):
        return exc
    if isinstance(exc, asyncio.TimeoutError):
        detail = "it did not start in time"
    else:
        detail = f"{type(exc).__name__}: {exc}"
    return CapabilityError(f"the MemDiver tool server could not be started ({detail})",
                           category=ErrorCategory.INTERNAL, status=502,
                           code="agent.tools_unavailable")
