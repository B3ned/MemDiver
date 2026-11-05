"""Model-provider presets of the agent chat (pure data; the environment is injected).

``anthropic`` is the existing Claude Agent SDK path; every other preset speaks the
OpenAI-compatible Chat Completions protocol. This module imports only the standard
library so :mod:`contracts` can import it (not the other way round).

Security: :func:`resolve_endpoint` is server-side only. Its result (base URL and API
key) is never serialized; :func:`provider_public_info` is what the browser sees.

Default prices are USD per 1M tokens, **as of 2026-11**. They ignore cached-input
discounts, so the budget overestimates the real cost (errs safe). DeepSeek uses its
peak-hour prices for the same reason.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple

KIND_CLAUDE_SDK = "claude-sdk"
KIND_OPENAI_COMPAT = "openai-compat"

TOOL_SET_CHOICES = ("full", "compact", "minimal")

#: The ``custom`` preset reads its endpoint from these server-side variables.
CUSTOM_BASE_URL_ENV = "MEMDIVER_AGENT_OPENAI_BASE_URL"
CUSTOM_API_KEY_ENV = "MEMDIVER_AGENT_OPENAI_API_KEY"

#: The openai SDK refuses an empty key; local servers ignore whatever is sent.
PLACEHOLDER_API_KEY = "not-needed"


@dataclass(frozen=True)
class ProviderPreset:
    """One selectable provider: where it lives, how to talk to it, what it costs."""

    id: str
    kind: str
    #: Fixed endpoint; ``""`` for ``anthropic`` (SDK) and ``custom`` (from the env).
    base_url: str
    #: Env var holding the API key; ``""`` when the provider takes none.
    key_env: str
    #: ``""`` means "no sensible default": the analyst must name a model.
    default_model: str
    model_suggestions: Tuple[str, ...]
    supports_effort: bool
    #: Echo ``reasoning_content`` back in the assistant history (DeepSeek requires it).
    echo_reasoning: bool
    #: Name of the output-cap request parameter.
    max_tokens_param: str
    #: ``(input, output)`` USD per 1M tokens, as of 2026-11.
    default_prices: Tuple[float, float]
    #: Runs on the analyst's machine; it has no billable cost.
    local: bool
    default_tool_set: str
    #: A missing ``key_env`` makes the provider unavailable.
    key_required: bool
    #: Native API probed for the loaded model's context window before each request
    #: (``"ollama"``: ``GET /api/ps``); ``None`` means no proactive context check.
    context_probe: Optional[str] = None


def _preset(**fields: Any) -> ProviderPreset:
    base: Dict[str, Any] = {
        "kind": KIND_OPENAI_COMPAT, "base_url": "", "key_env": "", "default_model": "",
        "model_suggestions": (), "supports_effort": False, "echo_reasoning": False,
        "max_tokens_param": "max_tokens", "default_prices": (0.0, 0.0), "local": False,
        "default_tool_set": "full", "key_required": False, "context_probe": None,
    }
    base.update(fields)
    return ProviderPreset(**base)


_PRESETS = (
    _preset(id="anthropic", kind=KIND_CLAUDE_SDK, default_model="claude-opus-5-5",
            model_suggestions=("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"),
            supports_effort=True),
    _preset(id="openai", base_url="https://api.openai.com/v1", key_env="OPENAI_API_KEY",
            default_model="gpt-5-mini",
            model_suggestions=("gpt-5-mini", "gpt-5", "gpt-5.4", "gpt-5.4-mini", "gpt-5-nano"),
            supports_effort=True, max_tokens_param="max_completion_tokens",
            default_prices=(0.25, 2.0), key_required=True),
    _preset(id="deepseek", base_url="https://api.deepseek.com", key_env="DEEPSEEK_API_KEY",
            default_model="deepseek-flash",
            model_suggestions=("deepseek-flash", "deepseek-v4-pro"), echo_reasoning=True,
            default_prices=(0.30, 1.20), key_required=True),
    _preset(id="ollama", base_url="http://127.0.0.1:11434/v1", default_model="llama3.3",
            model_suggestions=("llama3.3",), local=True, default_tool_set="minimal",
            context_probe="ollama"),
    _preset(id="vllm", base_url="http://127.0.0.1:8000/v1", key_env="VLLM_API_KEY",
            local=True, default_tool_set="minimal"),
    _preset(id="custom", key_env=CUSTOM_API_KEY_ENV),
)

PROVIDERS: Mapping[str, ProviderPreset] = MappingProxyType({p.id: p for p in _PRESETS})
PROVIDER_IDS = tuple(PROVIDERS)


def get_preset(provider_id: str) -> ProviderPreset:
    """The preset named ``provider_id``, or ``ValueError``."""
    try:
        return PROVIDERS[provider_id]
    except (KeyError, TypeError):
        raise ValueError(f"provider must be one of {', '.join(PROVIDER_IDS)}") from None


def _env_value(env: Mapping[str, str], name: str) -> str:
    return (env.get(name) or "").strip() if name else ""


def _unavailable_reason(preset: ProviderPreset, env: Mapping[str, str]) -> Optional[str]:
    if preset.id == "custom" and not _env_value(env, CUSTOM_BASE_URL_ENV):
        return f"set {CUSTOM_BASE_URL_ENV} on the server to enable the custom provider"
    if preset.key_required and not _env_value(env, preset.key_env):
        return f"set {preset.key_env} on the server to enable {preset.id}"
    return None


def provider_availability(preset: ProviderPreset,
                          env: Mapping[str, str]) -> Tuple[bool, Optional[str]]:
    """``(available, reason)``; ``anthropic`` is always True (the API checks the SDK)."""
    if preset.kind == KIND_CLAUDE_SDK:
        return True, None
    reason = _unavailable_reason(preset, env)
    return reason is None, reason


def resolve_endpoint(preset: ProviderPreset, env: Mapping[str, str]) -> Tuple[str, str]:
    """``(base_url, api_key)`` of an OpenAI-compatible preset. Server-side only.

    Raises ``ValueError`` for the SDK preset or an unavailable provider; the message
    names the env variable, never its value.
    """
    if preset.kind != KIND_OPENAI_COMPAT:
        raise ValueError(f"{preset.id} is not an OpenAI-compatible provider")
    reason = _unavailable_reason(preset, env)
    if reason:
        raise ValueError(reason)
    base_url = _env_value(env, CUSTOM_BASE_URL_ENV) if preset.id == "custom" else preset.base_url
    return base_url, _env_value(env, preset.key_env) or PLACEHOLDER_API_KEY


def provider_public_info(preset: ProviderPreset, env: Mapping[str, str]) -> Dict[str, Any]:
    """What the browser may see about a preset: never the base URL or the key."""
    available, reason = provider_availability(preset, env)
    return {
        "id": preset.id, "kind": preset.kind, "default_model": preset.default_model,
        "model_suggestions": list(preset.model_suggestions),
        "supports_effort": preset.supports_effort,
        "default_prices": list(preset.default_prices),
        "default_tool_set": preset.default_tool_set, "local": preset.local,
        "available": available, "reason": reason,
    }


def price_known(preset: ProviderPreset, prices: Tuple[float, float]) -> bool:
    """Whether a cost estimate with ``prices`` means anything (local or all-zero: no)."""
    return not preset.local and any(p > 0 for p in prices)


def is_valid_price(value: Any) -> bool:
    """A finite, non-negative number up to 1000 USD per 1M tokens (``bool`` refused)."""
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and math.isfinite(value) and 0 <= value <= 1000)
