"""Claude Agent SDK implementation of :class:`contracts.AgentBackend`.

One :class:`SdkAgentBackend` = one chat = one ``ClaudeSDKClient``. The SDK is imported
lazily so MemDiver imports without it (``pip install "memdiver[agent]"``).

Safety posture (design note §2/§4): no built-in tools (``tools=[]``), the sandboxed
MemDiver MCP server is the only tool source (``strict_mcp_config``), READ tools are
pre-approved via ``allowed_tools``, everything else goes through the
:class:`contracts.PermissionGate`, no user/project settings are loaded, and the
credentials come from the server environment only (this module never injects any).
"""

from __future__ import annotations

import os
import signal
import warnings
from typing import Any, Dict, List, Mapping, Optional

from memdiver.app.agent_chat import contracts as c
from memdiver.app.agent_chat.tool_events import (
    SUMMARY_CHARS, access_label, is_error_payload, result_text, tool_result_event)
from memdiver.core.install_hints import missing_package_message
from memdiver.core.service_errors import CapabilityError, ErrorCategory

__all__ = ["SUMMARY_CHARS", "SdkAgentBackend", "build_options", "make_backend"]

#: Built-in Claude Code tools refused on top of ``tools=[]`` (belt and braces).
_BUILTIN_TOOLS_DENIED = [
    "Bash", "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "NotebookEdit",
    "WebFetch", "WebSearch", "Task", "Agent", "TodoWrite", "BashOutput", "KillShell",
]


#: Slack over bytes/2 so the CLI's own MCP output cap (``MAX_MCP_OUTPUT_TOKENS``, default
#: 25000 tokens, present in the bundled CLI) never undercuts our result budget.
CLI_OUTPUT_TOKEN_MARGIN = 2_000


def cli_output_token_cap(result_budget_bytes: int) -> int:
    """Tokens (counted pessimistically at 2 bytes each) that always exceed the budget, so
    ``mcp_server.result_budget`` (which leaves a marker) is the binding limit."""
    return result_budget_bytes // 2 + CLI_OUTPUT_TOKEN_MARGIN


def _load_sdk() -> Any:
    try:
        import claude_agent_sdk
    except ImportError as exc:
        raise CapabilityError(
            missing_package_message("claude-agent-sdk", "agent"),
            category=ErrorCategory.PRECONDITION, status=503,
            code="agent.sdk_missing") from exc
    return claude_agent_sdk


async def _discard_event(_event: c.ChatEvent) -> None:
    """Emit target before ``start`` supplies the real one."""


def _process_tree_pids(root_pid: Optional[int]) -> List[int]:
    """``root_pid`` plus all its descendants (children first). Needs ``psutil`` for the
    descendants; without it only the root can be killed."""
    if not root_pid:
        return []
    try:
        import psutil

        kids = [p.pid for p in psutil.Process(root_pid).children(recursive=True)]
    except Exception:  # noqa: BLE001 - psutil missing, or the process is already gone
        kids = []
    return [*reversed(kids), root_pid]


def _kill_pids(pids: List[int]) -> None:
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except (OSError, AttributeError):  # already gone / no SIGKILL on this platform
            pass


def _strip_prefix(name: str) -> str:
    return name[len(c.TOOL_PREFIX):] if name.startswith(c.TOOL_PREFIX) else name


#: Backward-compatible private names (now public in :mod:`tool_events`).
_result_text = result_text
_is_error_payload = is_error_payload


def build_options(spec: c.ChatSpec, gate: c.PermissionGate,
                  sdk: Any = None) -> Any:
    """The ``ClaudeAgentOptions`` for one chat (pure; used by tests to inspect them)."""
    sdk = sdk or _load_sdk()

    async def can_use_tool(tool_name: str, tool_input: Dict[str, Any], _context: Any) -> Any:
        decision = await gate.decide(tool_name, tool_input)
        if decision.allow:
            return sdk.PermissionResultAllow()
        return sdk.PermissionResultDeny(message=decision.message or "Denied.")

    settings = spec.settings
    return sdk.ClaudeAgentOptions(
        model=settings.model,
        system_prompt=spec.system_prompt,  # plain string REPLACES the Claude Code preset
        tools=[],
        allowed_tools=list(spec.allowed_tools),
        disallowed_tools=list(_BUILTIN_TOOLS_DENIED),
        mcp_servers={c.MCP_SERVER_NAME: {
            "type": "stdio", "command": spec.mcp.command,
            "args": list(spec.mcp.args), "env": dict(spec.mcp.env)}},
        strict_mcp_config=True,
        permission_mode="default",
        can_use_tool=can_use_tool,
        max_turns=settings.max_turns,
        max_budget_usd=settings.max_budget_usd,
        effort=settings.effort,
        include_partial_messages=True,
        setting_sources=[],
        cwd=spec.cwd,
        env={"CLAUDE_CONFIG_DIR": spec.config_dir,
             "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
             "MAX_MCP_OUTPUT_TOKENS": str(cli_output_token_cap(settings.result_budget_bytes))},
        resume=spec.resume_session_id,
    )


class SdkAgentBackend:
    """:class:`contracts.AgentBackend` over ``claude_agent_sdk.ClaudeSDKClient``.

    ``transport_factory`` swaps the CLI subprocess for another SDK ``Transport``
    (the scripted test/demo transport). A transport that defines ``bind_options``
    receives the finished options (so it can read ``allowed_tools``/``mcp_servers``).
    ``tool_access`` is the API layer's ``{tool_name: read|write|never}`` map used to
    label ``tool_call`` events; unknown tools are labelled ``write`` (fail closed).
    """

    def __init__(self, transport_factory: Any = None,
                 tool_access: Optional[Mapping[str, str]] = None) -> None:
        self._transport_factory = transport_factory
        self._tool_access: Mapping[str, str] = tool_access or {}
        self._client: Any = None
        self._dying: Any = None  # the client whose disconnect is in flight (for ``kill``)
        self._sdk: Any = None
        self._emit: c.Emit = _discard_event
        self._max_turns = 0
        self._max_budget = 0.0

    # -- lifecycle ---------------------------------------------------------------

    async def start(self, spec: c.ChatSpec, gate: c.PermissionGate, emit: c.Emit) -> None:
        self._sdk = _load_sdk()
        self._emit = emit
        self._max_turns = spec.settings.max_turns
        self._max_budget = spec.settings.max_budget_usd
        access = getattr(spec, "tool_access", None)
        if access:
            self._tool_access = access
        await self._emit(c.ChatEvent("status", {"state": "starting"}))
        options = build_options(spec, gate, self._sdk)
        transport = None
        if self._transport_factory is not None:
            transport = self._transport_factory()
            bind = getattr(transport, "bind_options", None)
            if bind is not None:
                bind(options)
        # Assigned BEFORE connect: a start cancelled mid-connect (socket dropped) must still
        # leave ``close``/``kill`` a handle on the half-started CLI.
        self._client = self._sdk.ClaudeSDKClient(options=options, transport=transport)
        try:
            with warnings.catch_warnings():
                # Read tools are intentionally pre-approved via allowed_tools.
                warnings.filterwarnings("ignore", message="can_use_tool will not be invoked")
                await self._client.connect()
        except Exception as exc:
            self._client = None
            raise self._as_capability_error(exc) from exc
        await self._emit(c.ChatEvent("status", {"state": "ready"}))

    async def send(self, text: str) -> None:
        if self._client is None:
            raise CapabilityError("the chat is not started", category=ErrorCategory.PRECONDITION,
                                  code="agent.not_started")
        await self._emit(c.ChatEvent("status", {"state": "running"}))
        seen_result = False
        try:
            await self._client.query(text)
            async for message in self._client.receive_response():
                seen_result = await self._handle(message) or seen_result
        except Exception as exc:
            # After an error result the SDK may raise a trailing ResultError: already reported.
            if not (seen_result and isinstance(exc, self._sdk.ProcessError)):
                err = self._as_capability_error(exc)
                await self._emit(c.ChatEvent("error", {
                    "code": err.code or "agent.error", "message": str(err)}))
        finally:
            await self._emit(c.ChatEvent("status", {"state": "ready"}))

    async def interrupt(self) -> None:
        if self._client is not None:
            await self._client.interrupt()

    async def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            self._dying = client
            await client.disconnect()
            self._dying = None
            await self._emit(c.ChatEvent("status", {"state": "closed"}))

    async def kill(self) -> None:
        """Hard escalation of a close that did not finish: SIGKILL the CLI process AND every
        descendant (its stdio MCP child is NOT guaranteed to die with it), then drop the
        transport. Safe to call repeatedly or with nothing running."""
        client = self._dying or self._client
        self._client = self._dying = None
        transport = getattr(client, "_transport", None)
        pids = _process_tree_pids(getattr(getattr(transport, "_process", None), "pid", None))
        _kill_pids(pids)
        hard_kill = getattr(transport, "kill", None)  # scripted transport: its MCP child
        if hard_kill is not None:
            await hard_kill()

    # -- SDK message -> ChatEvent --------------------------------------------------

    async def _handle(self, message: Any) -> bool:
        """Emit the events for one SDK message; True when it was the ``ResultMessage``."""
        sdk = self._sdk
        if isinstance(message, sdk.StreamEvent):
            await self._stream_event(message)
        elif isinstance(message, sdk.AssistantMessage):
            await self._assistant(message)
        elif isinstance(message, sdk.UserMessage):
            await self._user(message)
        elif isinstance(message, sdk.ResultMessage):
            await self._result(message)
            return True
        return False  # system, rate-limit, thinking, ... carry nothing the UI shows

    async def _stream_event(self, message: Any) -> None:
        event = message.event or {}
        delta = event.get("delta") or {}
        if (message.parent_tool_use_id is None and event.get("type") == "content_block_delta"
                and delta.get("type") == "text_delta" and delta.get("text")):
            await self._emit(c.ChatEvent("text_delta", {"text": delta["text"]}))

    async def _assistant(self, message: Any) -> None:
        sdk = self._sdk
        for block in message.content:
            if isinstance(block, sdk.TextBlock) and block.text:
                await self._emit(c.ChatEvent("assistant_message", {"text": block.text}))
            elif isinstance(block, sdk.ToolUseBlock):
                name = _strip_prefix(block.name)
                await self._emit(c.ChatEvent("tool_call", {
                    "id": block.id, "name": name, "input": block.input,
                    "access": self._access_of(name)}))

    async def _user(self, message: Any) -> None:
        if not isinstance(message.content, list):
            return
        for block in message.content:
            if not isinstance(block, self._sdk.ToolResultBlock):
                continue
            await self._emit(tool_result_event(
                block.tool_use_id, result_text(block.content), bool(block.is_error)))

    async def _result(self, message: Any) -> None:
        cost = float(message.total_cost_usd or 0.0)
        await self._emit(c.ChatEvent("usage", {
            "turns": message.num_turns, "max_turns": self._max_turns,
            "cost_estimate_usd": cost, "max_budget_usd": self._max_budget}))
        await self._emit(c.ChatEvent("result", {
            "session_id": message.session_id, "num_turns": message.num_turns,
            "cost_estimate_usd": cost, "stop_reason": message.subtype,
            "is_error": bool(message.is_error)}))

    def _access_of(self, name: str) -> str:
        return access_label(self._tool_access, name)

    # -- errors --------------------------------------------------------------------

    def _as_capability_error(self, exc: Exception) -> CapabilityError:
        if isinstance(exc, CapabilityError):
            return exc
        sdk = self._sdk
        if isinstance(exc, sdk.CLINotFoundError):
            return CapabilityError(
                "the Claude Code runtime was not found. Reinstall with: "
                'pip install --force-reinstall "memdiver[agent]"',
                category=ErrorCategory.PRECONDITION, status=503, code="agent.cli_not_found")
        if isinstance(exc, sdk.ClaudeSDKError):
            return CapabilityError(
                f"agent runtime error: {exc}", category=ErrorCategory.INTERNAL,
                status=502, code="agent.runtime_error")
        return CapabilityError(
            f"agent error: {type(exc).__name__}: {exc}", category=ErrorCategory.INTERNAL,
            status=500, code="agent.error")


def make_backend(kind: str = "sdk", tool_access: Optional[Mapping[str, str]] = None) -> Any:
    """``"sdk"`` (real model) or ``"scripted"`` (no model; needs ``MEMDIVER_AGENT_SCRIPT``).

    Thin delegate kept for existing callers; the factory lives in :mod:`backends`."""
    from memdiver.app.agent_chat.backends import make_backend as _make_backend

    return _make_backend(kind, tool_access)
