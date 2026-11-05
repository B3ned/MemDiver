"""CompatAgentBackend against a REAL local Ollama model and a REAL ``memdiver mcp`` child.

Opt-in (marker ``e2e``, deselected by default): it needs an Ollama server on
127.0.0.1:11434 that already lists ``llama3.3`` (``GET /api/tags``); it skips otherwise
and never pulls a model. No paid provider, no API key. The first request can take
minutes while Ollama loads the 70B model, hence the generous timeout.

Run: ``pytest -m e2e tests/test_agent_chat_ollama_live.py -s``
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import urllib.request
from typing import Any, Dict, List

import pytest

pytest.importorskip("mcp")
pytest.importorskip("openai")

from memdiver.analysis.case import Case  # noqa: E402
from memdiver.api.services import agent_playbooks  # noqa: E402
from memdiver.api.services.agent_chat import (  # noqa: E402
    tool_access_map, tool_names_by_access)
from memdiver.app.agent_chat import contracts as c  # noqa: E402
from memdiver.app.agent_chat.backends import make_backend  # noqa: E402
from memdiver.app.agent_chat.chat_model import OpenAICompatModel  # noqa: E402
from memdiver.app.agent_chat.compat_backend import CompatAgentBackend  # noqa: E402
from memdiver.app.agent_chat.gate import ApprovalGate  # noqa: E402
from memdiver.app.agent_chat.system_prompt import (  # noqa: E402
    build_system_prompt, render_scope, with_scope)

pytestmark = pytest.mark.e2e

OLLAMA_TAGS = "http://127.0.0.1:11434/api/tags"
MODEL = "llama3.3"
RUN_TIMEOUT = 1800  # first load of a 42 GB model, then up to 6 slow turns
PROMPT = ("Use the case_manifest tool to list what this case contains, "
          "then summarise it in one sentence.")
ACCESS = tool_access_map()


def _ollama_models() -> List[str]:
    try:
        with urllib.request.urlopen(OLLAMA_TAGS, timeout=3) as response:  # nosec B310
            body = json.load(response)
    except (OSError, ValueError):
        return []
    return [m.get("name", "") for m in body.get("models", [])]


def _has_model(names: List[str]) -> bool:
    return any(n == MODEL or n.startswith(MODEL + ":") for n in names)


@pytest.fixture
def ollama() -> None:
    names = _ollama_models()
    if not names:
        pytest.skip("Ollama is not reachable at 127.0.0.1:11434")
    if not _has_model(names):
        pytest.skip(f"Ollama does not list {MODEL} (never pulled by this test)")


@pytest.fixture
def case(tmp_path):
    uploads = tmp_path / "uploads"
    case_dir = str(Case.init(uploads / "case").dir)
    env = {**os.environ, "MEMDIVER_ALLOWED_ROOTS": str(tmp_path),
           "MEMDIVER_UPLOAD_DIR": str(uploads), "MEMDIVER_MCP_RESULT_BUDGET": "20000",
           "XDG_DATA_HOME": str(tmp_path / "xdg")}
    env.pop("OPENAI_API_KEY", None)
    return case_dir, env


def _spec(tmp_path, env, case_dir: str, settings: c.AgentSettings) -> c.ChatSpec:
    read, _write = tool_names_by_access(ACCESS)
    prompt = build_system_prompt(playbook_index=agent_playbooks.playbook_index(),
                                 start_text=agent_playbooks.start_text())
    return c.ChatSpec(
        system_prompt=prompt, settings=settings,
        mcp=c.McpChild(sys.executable, ["-m", "memdiver.cli", "mcp"], env),
        allowed_tools=[c.TOOL_PREFIX + n for n in read], cwd=str(tmp_path),
        config_dir=str(tmp_path / "cfg"), tool_access=ACCESS,
        scope_note=render_scope(case_dir, []))


def _recording_usage(monkeypatch) -> List[Any]:
    """Record each model turn's provider usage (the events carry only turns/cost)."""
    usages: List[Any] = []
    real_complete = OpenAICompatModel.complete

    async def complete(self, messages, tools, on_text):
        turn = await real_complete(self, messages, tools, on_text)
        usages.append((len(tools), turn.usage))
        return turn

    monkeypatch.setattr(OpenAICompatModel, "complete", complete)
    return usages


async def _chat(backend, spec, events: List[c.ChatEvent]) -> None:
    gate_box: Dict[str, ApprovalGate] = {}

    async def emit(event: c.ChatEvent) -> None:
        events.append(event)
        if event.type == "approval_request":  # writes are auto-denied
            asyncio.get_running_loop().call_soon(
                lambda: gate_box["gate"].resolve(event.data["id"], False, "no", "once"))

    gate = gate_box["gate"] = ApprovalGate(ACCESS, emit)
    await asyncio.wait_for(backend.start(spec, gate, emit), RUN_TIMEOUT)
    try:
        # the first message carries the chat scope, exactly as ChatSession sends it
        await asyncio.wait_for(backend.send(with_scope(PROMPT, spec.scope_note)), RUN_TIMEOUT)
    finally:
        await gate.close()
        await backend.close()


@pytest.mark.timeout(RUN_TIMEOUT + 120)
def test_llama33_calls_a_real_memdiver_tool(ollama, case, tmp_path, monkeypatch):
    case_dir, env = case
    settings = c.AgentSettings(provider="ollama", model=MODEL, tool_set="minimal",
                               max_turns=6)
    backend = make_backend("sdk", ACCESS, settings=settings, env={})
    assert isinstance(backend, CompatAgentBackend)
    usages = _recording_usage(monkeypatch)
    events: List[c.ChatEvent] = []

    started = time.monotonic()
    asyncio.run(_chat(backend, _spec(tmp_path, env, case_dir, settings), events))
    elapsed = time.monotonic() - started

    of = lambda t: [e.data for e in events if e.type == t]  # noqa: E731
    calls, results = of("tool_call"), {r["id"]: r for r in of("tool_result")}
    text = "".join(d["text"] for d in of("text_delta"))
    print(f"\n[ollama-live] {elapsed:.1f}s case={case_dir}")
    for call in calls:
        result = results.get(call["id"], {})
        print(f"[ollama-live] tool_call {call['name']} {json.dumps(call['input'])[:200]} "
              f"-> ok={result.get('ok')} bytes={result.get('bytes')} "
              f"summary={str(result.get('summary'))[:300]!r}")
    print(f"[ollama-live] usage per model turn (tools offered, usage): {usages}")
    print(f"[ollama-live] result: {of('result')}  errors: {of('error')}")
    print(f"[ollama-live] final text: {text!r}")

    assert of("error") == []
    real = [k for k in calls if ACCESS.get(k["name"]) is not None]
    assert real, f"no MemDiver tool was called: {calls}"
    assert any(results.get(k["id"], {}).get("ok") for k in real)
    result = of("result")
    assert len(result) == 1 and result[0]["stop_reason"] == "success", result
