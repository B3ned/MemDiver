"""A scripted stand-in for an OpenAI-compatible model: TEST / DEMO model, NO NETWORK.

:class:`ScriptedChatModel` implements :class:`chat_model.ChatModel` from the SAME script
JSON as :mod:`scripted_transport` (``{"turns": [[step, ...], ...]}``, one inner list per
user message), so :class:`compat_backend.CompatAgentBackend` runs its real loop, gate and
MCP child with no key and no model. It imports neither ``claude_agent_sdk`` nor ``openai``.

Mapping steps to model turns. The scripted CLI transport plays every step as its own
event, but a model turn that carries no tool call ENDS the compat loop, so a text step
cannot be a turn of its own when a tool step follows it. Steps are therefore grouped the
way a real model answers: a run of ``{"text"}`` steps (joined by a blank line) plus the
``{"tool", "input"}`` step that follows it form ONE turn; every further tool step is its
own turn. Once the steps of the current user message are used up, the model answers an
empty turn (no text, no calls), which ends the loop. More user messages than script turns
get the text ``(script exhausted)``.

The model is stateless: the user message and the position inside it are derived from the
``messages`` it is given (user messages counted; assistant messages since the last user
message), so an interrupted turn simply resumes nowhere -- the next user message starts
its own steps.

Compat-only optional step keys (ignored by the CLI transport): ``"id"`` (the provider
call id, may be ``""`` or repeated) and ``"arguments"`` (the raw argument string, sent
verbatim instead of ``json.dumps(input)``; e.g. ``"[1]"`` or ``"not json"``).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Optional, Tuple

from memdiver.app.agent_chat.chat_model import (
    CHARS_PER_TOKEN, ModelTurn, OnText, ToolCallRequest, Usage, request_chars)

__all__ = ["EXHAUSTED_TEXT", "ScriptedChatModel", "group_steps"]

EXHAUSTED_TEXT = "(script exhausted)"
_CHUNK = 12  # characters per scripted text delta (same as the scripted transport)

Step = Mapping[str, Any]
#: ``(text, tool step or None)`` of one model turn.
TurnPlan = Tuple[str, Optional[Step]]


def group_steps(steps: List[Step]) -> List[TurnPlan]:
    """Group a user message's steps into model turns (see the module docstring)."""
    plans: List[TurnPlan] = []
    texts: List[str] = []
    for step in steps:
        if "tool" in step:
            plans.append(("\n\n".join(texts), step))
            texts = []
        elif "text" in step:
            texts.append(str(step["text"]))
    if texts:
        plans.append(("\n\n".join(texts), None))
    return plans


def _position(messages: List[Dict[str, Any]]) -> Tuple[int, int]:
    """``(user message index, assistant turns since it)``."""
    users = 0
    since = 0
    for message in messages:
        if message.get("role") == "user":
            users, since = users + 1, 0
        elif message.get("role") == "assistant":
            since += 1
    return users - 1, since


def _tool_call(step: Step, index: int) -> ToolCallRequest:
    arguments = step.get("arguments")
    if not isinstance(arguments, str):
        arguments = json.dumps(step.get("input") or {})
    provider_id = step.get("id")
    if not isinstance(provider_id, str):
        provider_id = f"call_scripted_{index}"
    return ToolCallRequest(provider_id, str(step["tool"]), arguments)


class ScriptedChatModel:
    """:class:`chat_model.ChatModel` replaying a script; usage is a chars/4 estimate."""

    def __init__(self, script: Mapping[str, Any]) -> None:
        self._turns: List[List[Step]] = [list(t) for t in script.get("turns", [])]
        self._calls = 0

    def _plan(self, messages: List[Dict[str, Any]]) -> Optional[TurnPlan]:
        user_index, since = _position(messages)
        if 0 <= user_index < len(self._turns):
            plans = group_steps(self._turns[user_index])
        else:
            plans = [(EXHAUSTED_TEXT, None)]
        return plans[since] if since < len(plans) else None

    async def complete(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]],
                       on_text: OnText) -> ModelTurn:
        text, step = self._plan(messages) or ("", None)
        for start in range(0, len(text), _CHUNK):
            await on_text(text[start:start + _CHUNK])
        calls: Tuple[ToolCallRequest, ...] = ()
        if step is not None:
            self._calls += 1
            calls = (_tool_call(step, self._calls),)
        produced = len(text) + sum(len(c.name) + len(c.arguments) for c in calls)
        usage = Usage(request_chars(messages, tools) // CHARS_PER_TOKEN,
                      produced // CHARS_PER_TOKEN, estimated=True)
        return ModelTurn(text, calls, "", usage, "tool_calls" if calls else "stop")

    async def aclose(self) -> None:
        return None
