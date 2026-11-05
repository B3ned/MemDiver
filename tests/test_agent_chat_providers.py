"""Provider presets of the agent chat and the provider-aware settings contract."""

from __future__ import annotations

import json

import pytest

from memdiver.app.agent_chat import providers as P
from memdiver.app.agent_chat.contracts import (
    DEFAULT_MODEL, MODEL_CHOICES, PROVIDER_CHOICES, AgentSettings,
)
from memdiver.app.agent_chat.settings_store import PREF_KEY, load_settings, save_settings

SECRET = "sk-test-SECRET-value-123"


def preset(pid):
    return P.get_preset(pid)


# -- presets ------------------------------------------------------------------------

def test_presets_cover_the_plan_table():
    assert PROVIDER_CHOICES == ("anthropic", "openai", "deepseek", "ollama", "vllm", "custom")
    assert preset("anthropic").kind == P.KIND_CLAUDE_SDK
    assert all(preset(p).kind == P.KIND_OPENAI_COMPAT for p in PROVIDER_CHOICES[1:])


def test_anthropic_preset_is_the_single_source_of_claude_models():
    assert preset("anthropic").default_model == DEFAULT_MODEL
    assert preset("anthropic").model_suggestions == MODEL_CHOICES


def test_openai_and_deepseek_preset_details():
    openai, deepseek = preset("openai"), preset("deepseek")
    assert (openai.default_model, openai.default_prices) == ("gpt-5-mini", (0.25, 2.0))
    assert openai.supports_effort and openai.max_tokens_param == "max_completion_tokens"
    assert deepseek.base_url == "https://api.deepseek.com"
    assert (deepseek.default_model, deepseek.default_prices) == ("deepseek-flash", (0.30, 1.20))
    assert deepseek.echo_reasoning and not deepseek.supports_effort
    assert deepseek.max_tokens_param == "max_tokens"


def test_local_presets():
    ollama, vllm = preset("ollama"), preset("vllm")
    assert ollama.local and vllm.local and not preset("custom").local
    assert (ollama.default_model, ollama.default_tool_set) == ("llama3.3", "minimal")
    assert ollama.default_prices == (0.0, 0.0) and not ollama.key_required
    assert vllm.default_model == "" and vllm.default_tool_set == "minimal"


def test_get_preset_unknown_is_value_error():
    with pytest.raises(ValueError, match="provider must be one of"):
        P.get_preset("gemini")
    with pytest.raises(ValueError):
        P.get_preset(["openai"])  # type: ignore[arg-type]


# -- endpoint resolution and availability -------------------------------------------

def test_resolve_endpoint_returns_fixed_url_and_key():
    assert P.resolve_endpoint(preset("openai"), {"OPENAI_API_KEY": SECRET}) == \
        ("https://api.openai.com/v1", SECRET)


def test_resolve_endpoint_missing_key_names_the_env_not_a_value():
    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        P.resolve_endpoint(preset("deepseek"), {"DEEPSEEK_API_KEY": "  "})


def test_resolve_endpoint_local_uses_placeholder_key():
    assert P.resolve_endpoint(preset("ollama"), {}) == \
        ("http://127.0.0.1:11434/v1", P.PLACEHOLDER_API_KEY)
    assert P.resolve_endpoint(preset("vllm"), {"VLLM_API_KEY": SECRET})[1] == SECRET
    assert P.resolve_endpoint(preset("vllm"), {})[1] == P.PLACEHOLDER_API_KEY


def test_resolve_endpoint_custom_reads_env():
    env = {P.CUSTOM_BASE_URL_ENV: "http://gpu-box:9000/v1"}
    assert P.resolve_endpoint(preset("custom"), env) == \
        ("http://gpu-box:9000/v1", P.PLACEHOLDER_API_KEY)
    env[P.CUSTOM_API_KEY_ENV] = SECRET
    assert P.resolve_endpoint(preset("custom"), env)[1] == SECRET
    with pytest.raises(ValueError, match=P.CUSTOM_BASE_URL_ENV):
        P.resolve_endpoint(preset("custom"), {P.CUSTOM_API_KEY_ENV: SECRET})


def test_resolve_endpoint_refuses_the_sdk_preset():
    with pytest.raises(ValueError, match="not an OpenAI-compatible"):
        P.resolve_endpoint(preset("anthropic"), {})


def test_availability_reasons():
    assert P.provider_availability(preset("anthropic"), {}) == (True, None)
    assert P.provider_availability(preset("ollama"), {}) == (True, None)
    ok, reason = P.provider_availability(preset("openai"), {})
    assert not ok and "OPENAI_API_KEY" in reason
    ok, reason = P.provider_availability(preset("custom"), {})
    assert not ok and P.CUSTOM_BASE_URL_ENV in reason
    assert P.provider_availability(preset("openai"), {"OPENAI_API_KEY": SECRET}) == (True, None)


@pytest.mark.parametrize("pid", P.PROVIDER_IDS)
def test_public_info_never_leaks_url_or_key(pid):
    env = {"OPENAI_API_KEY": SECRET, "DEEPSEEK_API_KEY": SECRET, "VLLM_API_KEY": SECRET,
           P.CUSTOM_API_KEY_ENV: SECRET, P.CUSTOM_BASE_URL_ENV: "http://gpu-box:9000/v1"}
    info = P.provider_public_info(preset(pid), env)
    blob = json.dumps(info)
    assert "http" not in blob and SECRET not in blob and "gpu-box" not in blob
    assert set(info) == {"id", "kind", "default_model", "model_suggestions",
                         "supports_effort", "default_prices", "default_tool_set",
                         "local", "available", "reason"}
    assert info["available"] is True


def test_price_known():
    assert P.price_known(preset("openai"), (0.25, 2.0))
    assert not P.price_known(preset("ollama"), (1.0, 1.0))
    assert not P.price_known(preset("custom"), (0.0, 0.0))
    assert P.price_known(preset("custom"), (0.0, 3.0))


# -- settings contract --------------------------------------------------------------

def test_default_settings_are_anthropic():
    s = AgentSettings().validated()
    assert (s.provider, s.tool_set, s.price_input_per_mtok) == ("anthropic", None, None)
    assert s.effective_tool_set() == "full"


@pytest.mark.parametrize("changes,match", [
    ({"provider": "gemini"}, "provider must be one of"),
    ({"model": "llama3.3"}, "model must be one of"),
    ({"provider": "ollama", "model": "bad model"}, "1-128 characters"),
    ({"provider": "ollama", "model": "x" * 129}, "1-128 characters"),
    ({"provider": "vllm"}, "set a model name for vllm"),
    ({"tool_set": "tiny"}, "tool_set must be one of"),
])
def test_settings_validation_refuses(changes, match):
    with pytest.raises(ValueError, match=match):
        AgentSettings().merged(changes)


@pytest.mark.parametrize("model", ["qwen2.5:14b", "meta-llama/Llama-3.3-70B", "m@v1_x-2"])
def test_compat_model_names_accepted(model):
    assert AgentSettings().merged({"provider": "vllm", "model": model}).model == model


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -0.01, 1000.5, True, "1"])
def test_price_validation_refuses(bad):
    with pytest.raises(ValueError, match="price_input_per_mtok"):
        AgentSettings().merged({"price_input_per_mtok": bad})


def test_prices_and_effective_values():
    s = AgentSettings().merged({"provider": "openai"})
    assert s.effective_prices() == (0.25, 2.0)
    s = s.merged({"price_output_per_mtok": 0, "price_input_per_mtok": 3})
    assert s.effective_prices() == (3, 0)
    assert s.merged({"tool_set": "compact"}).effective_tool_set() == "compact"


def test_provider_switch_resets_model_tool_set_and_prices():
    s = AgentSettings().merged({"provider": "openai", "tool_set": "compact",
                                "price_input_per_mtok": 1.0})
    switched = s.merged({"provider": "ollama"})
    assert switched.model == "llama3.3"
    assert (switched.tool_set, switched.price_input_per_mtok) == (None, None)
    assert switched.effective_tool_set() == "minimal"
    back = switched.merged({"provider": "anthropic"})
    assert back.model == DEFAULT_MODEL


def test_provider_switch_keeps_explicit_values():
    s = AgentSettings().merged({"provider": "ollama", "model": "qwen3:8b",
                                "tool_set": "full", "price_output_per_mtok": 0.5})
    assert (s.model, s.tool_set, s.price_output_per_mtok) == ("qwen3:8b", "full", 0.5)


def test_provider_switch_with_model_still_resets_tool_set_and_prices():
    """Regression: naming ``model`` in a provider switch kept the old prices/tool set."""
    s = AgentSettings().merged({"provider": "openai", "tool_set": "compact",
                                "price_input_per_mtok": 9.0})
    switched = s.merged({"provider": "ollama", "model": "qwen3:8b"})
    assert switched.model == "qwen3:8b"
    assert (switched.tool_set, switched.price_input_per_mtok) == (None, None)


def test_compat_model_name_refuses_a_trailing_newline():
    """Regression: ``$`` admitted ``"model\n"``."""
    with pytest.raises(ValueError, match="1-128 characters"):
        AgentSettings().merged({"provider": "vllm", "model": "qwen3\n"})


def test_same_provider_change_keeps_model():
    s = AgentSettings().merged({"provider": "ollama", "model": "qwen3:8b"})
    assert s.merged({"provider": "ollama", "max_turns": 9}).model == "qwen3:8b"


def test_unknown_keys_still_refused():
    with pytest.raises(ValueError, match="unknown setting"):
        AgentSettings().merged({"provider": "ollama", "base_url": "http://evil"})


# -- persistence --------------------------------------------------------------------

def test_old_stored_settings_load_unchanged():
    old = {"model": "claude-sonnet-5-5", "effort": "medium", "max_turns": 12,
           "max_budget_usd": 1.0, "result_budget_bytes": 30_000}
    settings, warning = load_settings(lambda key, default: old if key == PREF_KEY else default)
    assert not warning
    assert settings == AgentSettings(model="claude-sonnet-5-5", effort="medium",
                                     max_turns=12, max_budget_usd=1.0,
                                     result_budget_bytes=30_000)
    assert settings.provider == "anthropic"


def test_provider_settings_round_trip():
    store = {}
    saved = save_settings(store.__setitem__, {"provider": "ollama", "tool_set": "compact"})
    loaded, warning = load_settings(lambda key, default: store.get(key, default))
    assert not warning and loaded == saved
    assert loaded.model == "llama3.3" and loaded.tool_set == "compact"
