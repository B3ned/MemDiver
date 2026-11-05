"""Contracts of the in-UI agent chat: settings, the WebSocket event protocol, the backend port.

Design: ``docs/dev/agent_chat_panel_design.md``. The chat is a CLIENT of the MemDiver
MCP server (not a fifth surface): one chat = one backend (the Claude Agent SDK, or the
scripted transport used by tests/demos) talking to a sandboxed ``memdiver mcp`` child.

Every module of the chat depends on this file only; the API layer injects what the
chat needs from outside (tool access map, sandbox roots, settings store), so ``app/``
never imports ``api/`` or ``mcp_server/``.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Protocol, Tuple

from .providers import (
    PROVIDER_IDS, PROVIDERS, TOOL_SET_CHOICES, get_preset, is_valid_price,
)

#: SDK tool-name prefix of the MemDiver MCP server (``mcp__<server>__<tool>``).
MCP_SERVER_NAME = "memdiver"
TOOL_PREFIX = f"mcp__{MCP_SERVER_NAME}__"

#: The Claude models of the ``anthropic`` preset (single source: ``providers``).
DEFAULT_MODEL = PROVIDERS["anthropic"].default_model
MODEL_CHOICES = PROVIDERS["anthropic"].model_suggestions
PROVIDER_CHOICES = PROVIDER_IDS
#: Model names of the OpenAI-compatible providers (free-form, but no spaces or quotes).
#: Always applied with ``fullmatch`` (``$`` alone would admit a trailing newline).
COMPAT_MODEL_PATTERN = re.compile(r"[A-Za-z0-9._:/@-]{1,128}")
#: Settings a provider switch resets to the new preset's defaults unless also changed.
_PROVIDER_SCOPED = ("tool_set", "price_input_per_mtok", "price_output_per_mtok")
EFFORT_CHOICES = ("low", "medium", "high")

#: Inclusive bounds a user may set; the defaults below are deliberately LOW.
LIMITS: Dict[str, tuple] = {
    "max_turns": (1, 200),
    "max_budget_usd": (0.05, 50.0),
    "result_budget_bytes": (2_000, 500_000),
}


@dataclass(frozen=True)
class AgentSettings:
    """Per-user chat settings (persisted server-side; low by default, user-adjustable)."""

    model: str = DEFAULT_MODEL
    effort: str = "low"
    max_turns: int = 8
    max_budget_usd: float = 0.50
    #: Per-tool-result cap passed to the MCP child (``MEMDIVER_MCP_RESULT_BUDGET``).
    result_budget_bytes: int = 20_000
    #: Preset id (``providers.PROVIDERS``); stored settings without it are ``anthropic``.
    provider: str = "anthropic"
    #: ``full|compact|minimal``; ``None`` means the preset's default.
    tool_set: Optional[str] = None
    #: USD per 1M tokens; ``None`` means the preset's default price.
    price_input_per_mtok: Optional[float] = None
    price_output_per_mtok: Optional[float] = None

    def validated(self) -> "AgentSettings":
        """This settings object, or ``ValueError`` naming the first bad field."""
        self._validate_provider_and_model()
        if self.tool_set is not None and self.tool_set not in TOOL_SET_CHOICES:
            raise ValueError(f"tool_set must be one of {', '.join(TOOL_SET_CHOICES)}")
        for name in ("price_input_per_mtok", "price_output_per_mtok"):
            value = getattr(self, name)
            if value is not None and not is_valid_price(value):
                raise ValueError(f"{name} must be a number between 0 and 1000")
        if self.effort not in EFFORT_CHOICES:
            raise ValueError(f"effort must be one of {', '.join(EFFORT_CHOICES)}")
        for name, (low, high) in LIMITS.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not low <= value <= high:
                raise ValueError(f"{name} must be between {low} and {high}")
        return self

    def _validate_provider_and_model(self) -> None:
        get_preset(self.provider)
        if self.provider == "anthropic":
            if self.model not in MODEL_CHOICES:
                raise ValueError(f"model must be one of {', '.join(MODEL_CHOICES)}")
        elif not self.model:
            raise ValueError(f"set a model name for {self.provider}")
        elif not isinstance(self.model, str) or not COMPAT_MODEL_PATTERN.fullmatch(self.model):
            raise ValueError("model must be 1-128 characters of letters, digits and ._:/@-")

    def merged(self, changes: Mapping[str, Any]) -> "AgentSettings":
        """A validated copy with ``changes`` applied; unknown keys are refused.

        Switching ``provider`` resets the model to the new preset's default and the tool
        set and prices to ``None`` -- each only when it is not itself in ``changes`` -- so
        ``{"provider": "ollama"}`` never sends a Claude model (or Claude prices) to Ollama.
        """
        unknown = set(changes) - set(asdict(self))
        if unknown:
            raise ValueError(f"unknown setting(s): {', '.join(sorted(unknown))}")
        return replace(self, **self._with_provider_defaults(changes)).validated()

    def _with_provider_defaults(self, changes: Mapping[str, Any]) -> Dict[str, Any]:
        updates = dict(changes)
        provider = updates.get("provider", self.provider)
        if provider == self.provider:
            return updates
        updates.setdefault("model", get_preset(provider).default_model)
        for name in _PROVIDER_SCOPED:
            updates.setdefault(name, None)
        return updates

    def effective_tool_set(self) -> str:
        """The tool set in force: the analyst's choice, else the preset's default."""
        return self.tool_set or get_preset(self.provider).default_tool_set

    def effective_prices(self) -> Tuple[float, float]:
        """``(input, output)`` USD per 1M tokens: overrides, else the preset's defaults."""
        default_in, default_out = get_preset(self.provider).default_prices
        return (default_in if self.price_input_per_mtok is None else self.price_input_per_mtok,
                default_out if self.price_output_per_mtok is None
                else self.price_output_per_mtok)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# -- events: server -> browser (the WS protocol) -------------------------------------

#: Every event ``type`` the server may send. The browser ignores unknown types.
EVENT_TYPES = (
    "status",            # {state: "starting"|"ready"|"running"|"closed"}
    "text_delta",        # {text}
    "assistant_message",  # {text}
    "tool_call",         # {id, name, input, access: "read"|"write"}
    "tool_result",       # {id, ok, summary, bytes, truncated, locations? (≤10, omitted if none)}
    "approval_request",  # {id, tool, input, access, scopes: ["once", "chat"]}
    "approval_resolved",  # {id, allowed, message}
    # {turns, max_turns, cost_estimate_usd, max_budget_usd, cost_known?}; cost_known is
    # False when the estimate is meaningless (local provider or unknown prices).
    "usage",
    "result",            # {session_id, num_turns, cost_estimate_usd, stop_reason, is_error}
    "error",             # {code, message}
)

#: Every message ``type`` the browser may send:
#: ``user_message {text}``, ``approval {id, allow, message?, scope?: "once"|"chat"}``,
#: ``interrupt {}``.
CLIENT_MESSAGE_TYPES = ("user_message", "approval", "interrupt")

#: Values of the tool access map the API layer injects (from ``mcp_server.tool_policy``).
#: ``write_once``: WRITE tools that run caller-supplied code or pick an executable; an
#: approval never covers the rest of the chat (``mcp_server.tool_policy.gate_access``).
TOOL_ACCESS = ("read", "write", "write_once", "never")
APPROVAL_SCOPES = ("once", "chat")


@dataclass(frozen=True)
class ChatEvent:
    """One server -> browser event; ``to_dict`` is the exact WS JSON."""

    type: str
    data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in EVENT_TYPES:
            raise ValueError(f"unknown chat event type: {self.type}")

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, **self.data}


Emit = Callable[[ChatEvent], Awaitable[None]]


@dataclass(frozen=True)
class Decision:
    """Outcome of :class:`PermissionGate` for one tool call."""

    allow: bool
    message: str = ""


class PermissionGate(Protocol):
    """Decides each tool call: MemDiver READ tools pass, WRITE tools wait for the analyst.

    Anything that is not a ``mcp__memdiver__*`` tool is denied (the chat has no shell,
    file or web tools); a MemDiver tool missing from the access map is treated as WRITE
    (fail closed); ``never`` tools are denied even when approved. Pending approvals are
    denied when the chat closes. ``scope="chat"`` approves that tool for the rest of the
    chat (the analyst's choice, shown in the UI), ``"once"`` only this call.
    """

    async def decide(self, tool_name: str, tool_input: Mapping[str, Any]) -> Decision: ...

    def resolve(self, request_id: str, allow: bool, message: str = "",
                scope: str = "once") -> bool: ...

    async def close(self) -> None: ...


@dataclass(frozen=True)
class McpChild:
    """How the backend starts the sandboxed MemDiver MCP server (stdio)."""

    command: str
    args: List[str]
    env: Dict[str, str]


@dataclass(frozen=True)
class ChatSpec:
    """Everything a backend needs to start one chat."""

    system_prompt: str
    settings: AgentSettings
    mcp: McpChild
    #: SDK tool names auto-approved (MemDiver READ tools); everything else goes to the gate.
    allowed_tools: List[str]
    #: Working directory of the agent process (the case dir, else MemDiver home).
    cwd: str
    #: Private config dir for the agent runtime (keeps the analyst's own config out).
    config_dir: str
    resume_session_id: Optional[str] = None
    #: Bare tool name -> "read"|"write"|"never" (``mcp_server.tool_policy``); labels
    #: tool_call events. Tools missing from it are labelled "write" (fail closed).
    tool_access: Mapping[str, str] = field(default_factory=dict)
    #: Per-chat scope note (case dir, dumps) prepended to the FIRST user message only
    #: (the system prompt stays byte-stable); ``""``: none.
    scope_note: str = ""


class AgentBackend(Protocol):
    """One chat's model loop. ``send`` runs one user turn to completion, emitting events."""

    async def start(self, spec: ChatSpec, gate: PermissionGate, emit: Emit) -> None: ...

    async def send(self, text: str) -> None: ...

    async def interrupt(self) -> None: ...

    async def close(self) -> None: ...
