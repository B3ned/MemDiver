"""Factory of :class:`contracts.AgentBackend` implementations (the one place a kind is
mapped to a backend class).

Kinds:

- ``"sdk"``: a real model. ``settings.provider == "anthropic"`` (or no settings) is the
  Claude Agent SDK (:class:`SdkAgentBackend`); any other provider is the
  OpenAI-compatible loop (:class:`compat_backend.CompatAgentBackend` over
  :class:`chat_model.OpenAICompatModel`, endpoint and key resolved server-side from
  ``env``).
- ``"scripted"``: the SDK client over a scripted CLI transport (no model).
- ``"scripted-compat"``: the compat loop over :class:`scripted_model.ScriptedChatModel`
  (no model, no SDK, no openai).

Both scripted kinds read their script from ``MEMDIVER_AGENT_SCRIPT``.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Mapping, Optional

from memdiver.app.agent_chat import contracts as c
from memdiver.app.agent_chat.providers import get_preset, resolve_endpoint
from memdiver.app.agent_chat.sdk_backend import SdkAgentBackend
from memdiver.core.service_errors import CapabilityError, ErrorCategory

BACKEND_KINDS = ("sdk", "scripted", "scripted-compat")
SCRIPT_ENV = "MEMDIVER_AGENT_SCRIPT"


def make_backend(kind: str = "sdk", tool_access: Optional[Mapping[str, str]] = None,
                 settings: Optional[c.AgentSettings] = None,
                 env: Optional[Mapping[str, str]] = None) -> Any:
    """The backend for ``kind``; ``tool_access`` labels ``tool_call`` events."""
    env = os.environ if env is None else env
    if kind == "sdk":
        if settings is None or settings.provider == "anthropic":
            return SdkAgentBackend(tool_access=tool_access)
        return _compat_backend(settings, env, tool_access)
    if kind == "scripted":
        return _scripted_backend(tool_access, env)
    if kind == "scripted-compat":
        return _scripted_compat_backend(tool_access, env)
    raise CapabilityError(f"unknown agent backend '{kind}' ({'|'.join(BACKEND_KINDS)})",
                          code="agent.backend_unknown")


def _script(env: Mapping[str, str]) -> Dict[str, Any]:
    path = env.get(SCRIPT_ENV, "")
    if not path:
        raise CapabilityError(
            f"the scripted agent backend needs {SCRIPT_ENV}=<script.json>",
            category=ErrorCategory.PRECONDITION, code="agent.script_missing")
    from memdiver.app.agent_chat.mcp_tools import load_script

    return load_script(path)


def _scripted_backend(tool_access: Optional[Mapping[str, str]],
                      env: Mapping[str, str]) -> SdkAgentBackend:
    script = _script(env)
    from memdiver.app.agent_chat.scripted_transport import ScriptedCliTransport

    return SdkAgentBackend(
        transport_factory=lambda: ScriptedCliTransport(script), tool_access=tool_access)


def _scripted_compat_backend(tool_access: Optional[Mapping[str, str]],
                             env: Mapping[str, str]) -> Any:
    script = _script(env)
    from memdiver.app.agent_chat.compat_backend import CompatAgentBackend
    from memdiver.app.agent_chat.scripted_model import ScriptedChatModel

    return CompatAgentBackend(lambda _spec: ScriptedChatModel(script), tool_access)


def _compat_backend(settings: c.AgentSettings, env: Mapping[str, str],
                    tool_access: Optional[Mapping[str, str]]) -> Any:
    """The OpenAI-compatible loop for ``settings.provider``; the endpoint and key are
    resolved here, server-side, and never leave this closure."""
    from memdiver.app.agent_chat.chat_model import OpenAICompatModel
    from memdiver.app.agent_chat.compat_backend import CompatAgentBackend

    preset = get_preset(settings.provider)
    try:
        base_url, api_key = resolve_endpoint(preset, env)
    except ValueError as exc:
        raise CapabilityError(str(exc), category=ErrorCategory.PRECONDITION, status=503,
                              code="agent.provider_unavailable") from None

    def model_factory(_spec: c.ChatSpec) -> OpenAICompatModel:
        return OpenAICompatModel(preset, settings.model, settings.effort, base_url, api_key)

    return CompatAgentBackend(model_factory, tool_access)
