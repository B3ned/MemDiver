"""A scripted stand-in for the Claude Code CLI: TEST / DEMO transport, NO MODEL.

``ScriptedCliTransport`` is a ``claude_agent_sdk.Transport`` that plays the CLI side of
the SDK's stream-json CONTROL PROTOCOL, so the REAL ``ClaudeSDKClient`` (options,
``can_use_tool`` callback, message parsing, our event mapping) runs end to end with no
network, no API key, no model and no ``claude`` binary.

What it does, per user message (one inner list of the script = one user message):

* ``{"text": "..."}``                  -> stream_event deltas + an assistant text message
* ``{"tool": "case_manifest", "input": {...}}`` -> an assistant ``tool_use`` block, then
  - tool in ``options.allowed_tools``  -> executed for real (see below)
  - otherwise                          -> a ``can_use_tool`` control_request; the SDK's
    callback (our gate) answers allow/deny; denied -> an ``is_error`` tool_result and the
    tool is NOT run
* finally a ``result`` message (``success``; ``error_max_turns`` when ``options.max_turns``
  is hit; ``error_during_execution`` on interrupt).

"Executed for real" means: the tool is called on the MemDiver MCP server described by
``options.mcp_servers["memdiver"]`` through the ``mcp`` stdio client (one child per
transport, started lazily, closed in ``close()``). The model is the only fake part.

Script JSON: ``{"turns": [[step, ...], ...]}``. More user messages than turns get the
text ``(script exhausted)``. Each step is one agentic turn for the ``max_turns`` limit.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, AsyncIterator, Dict, List, Optional

from claude_agent_sdk import Transport

from memdiver.app.agent_chat.contracts import MCP_SERVER_NAME, TOOL_PREFIX
from memdiver.app.agent_chat.mcp_tools import McpToolClient, load_script

__all__ = ["EXHAUSTED_TEXT", "McpToolClient", "ScriptedCliTransport", "load_script"]

EXHAUSTED_TEXT = "(script exhausted)"
_CHUNK = 12  # characters per scripted text delta


#: Backward-compatible name of the MCP worker (now :class:`mcp_tools.McpToolClient`).
_McpWorker = McpToolClient


class ScriptedCliTransport(Transport):
    """Plays the CLI side of the SDK control protocol from a script. NO MODEL."""

    def __init__(self, script: Dict[str, Any]) -> None:
        self._turns: List[List[Dict[str, Any]]] = list(script.get("turns", []))
        self._out: "asyncio.Queue[Optional[Dict[str, Any]]]" = asyncio.Queue()
        self._allowed: List[str] = []
        self._max_turns: Optional[int] = None
        self._mcp_server: Optional[Dict[str, Any]] = None
        self._worker: Optional[McpToolClient] = None
        self._pending: Dict[str, "asyncio.Future[Dict[str, Any]]"] = {}
        self._tasks: set = set()
        self._current: Optional["asyncio.Task[None]"] = None
        self._user_messages = 0
        self._session_id = f"scripted-{uuid.uuid4().hex[:12]}"
        self._ready = False
        self._counter = 0

    def bind_options(self, options: Any) -> None:
        """Called by ``SdkAgentBackend`` with the finished ``ClaudeAgentOptions``."""
        self._allowed = list(options.allowed_tools or [])
        self._max_turns = options.max_turns
        servers = options.mcp_servers if isinstance(options.mcp_servers, dict) else {}
        self._mcp_server = servers.get(MCP_SERVER_NAME)

    # -- Transport interface ---------------------------------------------------------

    async def connect(self) -> None:
        self._ready = True

    def is_ready(self) -> bool:
        return self._ready

    async def end_input(self) -> None:
        return None

    async def read_messages(self) -> AsyncIterator[Dict[str, Any]]:
        while (message := await self._out.get()) is not None:
            yield message

    async def write(self, data: str) -> None:
        for line in data.splitlines():
            if line.strip():
                self._on_line(json.loads(line))

    async def close(self) -> None:
        self._ready = False
        for task in list(self._tasks):
            task.cancel()
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        if self._worker is not None:
            await self._worker.close()
        self._out.put_nowait(None)

    async def kill(self) -> None:
        """Hard stop (escalation of a close that hung): cancel the MCP worker so the
        stdio client tears its child down, without the graceful drain."""
        self._ready = False
        if self._worker is not None:
            await self._worker.kill()
        self._out.put_nowait(None)

    # -- what the SDK writes to "the CLI's stdin" -----------------------------------------

    def _on_line(self, message: Dict[str, Any]) -> None:
        kind = message.get("type")
        if kind == "control_request":
            self._on_control_request(message)
        elif kind == "control_response":
            response = message.get("response", {})
            future = self._pending.pop(response.get("request_id"), None)
            if future is not None and not future.done():
                future.set_result(response)
        elif kind == "user":
            self._current = self._spawn(self._play_turn())

    def _on_control_request(self, message: Dict[str, Any]) -> None:
        subtype = (message.get("request") or {}).get("subtype")
        if subtype == "interrupt" and self._current is not None:
            self._current.cancel()
            self._emit_result("error_during_execution", is_error=True, turns=0)
        body = {"commands": [], "models": [], "output_style": "default"} \
            if subtype == "initialize" else {}
        self._put({"type": "control_response", "response": {
            "subtype": "success", "request_id": message["request_id"], "response": body}})

    def _spawn(self, coro: Any) -> "asyncio.Task[None]":
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # -- playing one scripted user turn --------------------------------------------------

    async def _play_turn(self) -> None:
        index = self._user_messages
        self._user_messages += 1
        steps = self._turns[index] if index < len(self._turns) else [{"text": EXHAUSTED_TEXT}]
        if index == 0:
            self._put({"type": "system", "subtype": "init", "session_id": self._session_id,
                       "uuid": self._uuid(), "tools": [], "mcp_servers": []})
        turns = 0
        last_text = ""
        for step in steps:
            if self._max_turns is not None and turns >= self._max_turns:
                self._emit_result("error_max_turns", is_error=True, turns=turns)
                return
            turns += 1
            if "text" in step:
                last_text = str(step["text"])
                self._emit_text(last_text)
            elif "tool" in step:
                await self._run_tool(step)
        self._emit_result("success", is_error=False, turns=turns, text=last_text)

    def _emit_text(self, text: str) -> None:
        for i in range(0, len(text), _CHUNK):
            self._put({"type": "stream_event", "uuid": self._uuid(),
                       "session_id": self._session_id, "parent_tool_use_id": None,
                       "event": {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "text_delta", "text": text[i:i + _CHUNK]}}})
        self._assistant([{"type": "text", "text": text}])

    async def _run_tool(self, step: Dict[str, Any]) -> None:
        name = str(step["tool"])
        full = name if name.startswith("mcp__") else TOOL_PREFIX + name
        arguments = dict(step.get("input") or {})
        self._counter += 1
        tool_id = f"toolu_scripted_{self._counter}"
        self._assistant([{"type": "tool_use", "id": tool_id, "name": full, "input": arguments}])
        allowed, message = True, ""
        if full not in self._allowed:
            allowed, message, arguments = await self._ask_permission(
                full, arguments, tool_id)
        if allowed:
            text, is_error = await self._execute(full, arguments)
        else:
            text, is_error = message or "Permission denied.", True
        self._put({"type": "user", "uuid": self._uuid(), "session_id": self._session_id,
                   "parent_tool_use_id": None,
                   "message": {"role": "user", "content": [{
                       "type": "tool_result", "tool_use_id": tool_id,
                       "content": [{"type": "text", "text": text}], "is_error": is_error}]}})

    async def _ask_permission(self, tool: str, arguments: Dict[str, Any], tool_id: str):
        """Send a ``can_use_tool`` control_request; ``(allowed, deny_message, input)``."""
        request_id = f"cli_req_{uuid.uuid4().hex[:8]}"
        future: "asyncio.Future[Dict[str, Any]]" = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        self._put({"type": "control_request", "request_id": request_id, "request": {
            "subtype": "can_use_tool", "tool_name": tool, "input": arguments,
            "tool_use_id": tool_id, "permission_suggestions": []}})
        response = await future
        body = response.get("response") or {}
        if response.get("subtype") == "success" and body.get("behavior") == "allow":
            return True, "", dict(body.get("updatedInput") or arguments)
        return False, str(body.get("message") or response.get("error") or ""), arguments

    async def _execute(self, full_name: str, arguments: Dict[str, Any]) -> tuple[str, bool]:
        if self._mcp_server is None:
            return f"no '{MCP_SERVER_NAME}' MCP server configured", True
        if self._worker is None:
            self._worker = McpToolClient(self._mcp_server)
        try:
            return await self._worker.call(full_name[len(TOOL_PREFIX):], arguments)
        except Exception as exc:
            return f"MCP server failed: {type(exc).__name__}: {exc}", True

    # -- message builders --------------------------------------------------------------

    def _assistant(self, content: List[Dict[str, Any]]) -> None:
        self._put({"type": "assistant", "uuid": self._uuid(), "session_id": self._session_id,
                   "parent_tool_use_id": None,
                   "message": {"id": f"msg_{self._uuid()[:8]}", "role": "assistant",
                               "model": "scripted", "content": content,
                               "stop_reason": None, "usage": {}}})

    def _emit_result(self, subtype: str, *, is_error: bool, turns: int, text: str = "") -> None:
        self._put({"type": "result", "subtype": subtype, "is_error": is_error,
                   "duration_ms": 0, "duration_api_ms": 0, "num_turns": turns,
                   "session_id": self._session_id, "total_cost_usd": 0.0, "usage": {},
                   "result": text, "stop_reason": "end_turn" if not is_error else subtype,
                   "uuid": self._uuid()})

    def _put(self, message: Dict[str, Any]) -> None:
        self._out.put_nowait(message)

    @staticmethod
    def _uuid() -> str:
        return str(uuid.uuid4())
