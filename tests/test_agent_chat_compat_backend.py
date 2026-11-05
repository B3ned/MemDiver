"""CompatAgentBackend (our own tool loop) against a REAL ``memdiver mcp`` child.

The model is a :class:`ScriptedChatModel` (or a tiny fake for usage/id edge cases); the
gate is the real :class:`ApprovalGate` with the real tool access map, and the tools run
on a sandboxed MCP child over a synthetic case in ``tmp_path``.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess  # nosec B404 - runs this interpreter only
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

pytest.importorskip("mcp")

from memdiver.analysis.case import Case  # noqa: E402
from memdiver.api.services.agent_chat import (  # noqa: E402
    tool_access_map, tool_names_by_access)
from memdiver.app.agent_chat import contracts as c  # noqa: E402
from memdiver.app.agent_chat.backends import make_backend  # noqa: E402
from memdiver.app.agent_chat.chat_model import (  # noqa: E402
    ModelTurn, ToolCallRequest, Usage)
from memdiver.app.agent_chat.compat_backend import (  # noqa: E402
    INTERRUPTED_TOOL_TEXT, CompatAgentBackend, repair_history)
from memdiver.app.agent_chat.gate import ApprovalGate  # noqa: E402
from memdiver.app.agent_chat.scripted_model import (  # noqa: E402
    EXHAUSTED_TEXT, ScriptedChatModel, group_steps)
from memdiver.app.tools_annotations import annotations_list_result  # noqa: E402

CAP = "cap1"
ACCESS = tool_access_map()
WRITE_ONCE_TOOL = next(n for n, a in sorted(ACCESS.items()) if a == "write_once")
FIXTURE = Path(__file__).parent / "e2e" / "fixtures" / "agent_chat" / "p6_gate_wf1_script.json"
RUN_TIMEOUT = 180

Policy = Callable[[Dict[str, Any]], Optional[Tuple[bool, str]]]


def approve(scope: str = "once") -> Policy:
    return lambda _request: (True, scope)


def deny(_request: Dict[str, Any]) -> Optional[Tuple[bool, str]]:
    return (False, "once")


@pytest.fixture
def case(tmp_path):
    uploads = tmp_path / "uploads"
    case_dir = str(Case.init(uploads / "case").dir)
    env = {**os.environ, "MEMDIVER_ALLOWED_ROOTS": str(tmp_path),
           "MEMDIVER_UPLOAD_DIR": str(uploads), "MEMDIVER_MCP_RESULT_BUDGET": "20000",
           "XDG_DATA_HOME": str(tmp_path / "xdg")}
    return case_dir, env


def _spec(tmp_path, env, **settings: Any) -> c.ChatSpec:
    read, _write = tool_names_by_access(ACCESS)
    return c.ChatSpec(
        system_prompt="SYSTEM", settings=c.AgentSettings(**settings),
        mcp=c.McpChild(sys.executable, ["-m", "memdiver.cli", "mcp"], env),
        allowed_tools=[c.TOOL_PREFIX + n for n in read], cwd=str(tmp_path),
        config_dir=str(tmp_path / "cfg"), tool_access=ACCESS)


class Harness:
    """Collects events; answers approvals by ``policy`` (``None``: leave pending)."""

    def __init__(self, policy: Optional[Policy] = None,
                 on_approval: Optional[Callable[[], Any]] = None) -> None:
        self.events: List[c.ChatEvent] = []
        self.policy, self.on_approval = policy, on_approval
        self.decided: List[str] = []
        self.gate = ApprovalGate(ACCESS, self.emit)
        real_decide = self.gate.decide

        async def decide(name, tool_input):
            self.decided.append(name)
            return await real_decide(name, tool_input)

        self.gate.decide = decide  # type: ignore[method-assign]

    async def emit(self, event: c.ChatEvent) -> None:
        self.events.append(event)
        if event.type != "approval_request":
            return
        loop = asyncio.get_running_loop()
        if self.on_approval is not None:
            loop.create_task(self.on_approval())
        answer = self.policy(event.data) if self.policy else None
        if answer is not None:
            allow, scope = answer
            loop.call_soon(lambda: self.gate.resolve(event.data["id"], allow, "no", scope))

    def of(self, type_: str) -> List[Dict[str, Any]]:
        return [e.data for e in self.events if e.type == type_]


async def _drive(backend, spec, harness: Harness, messages=("go",)) -> None:
    await asyncio.wait_for(backend.start(spec, harness.gate, harness.emit), RUN_TIMEOUT)
    try:
        for text in messages:
            await asyncio.wait_for(backend.send(text), RUN_TIMEOUT)
    finally:
        await harness.gate.close()
        await backend.close()


def _run_script(tmp_path, env, turns, harness, messages=("go",), **settings):
    backend = CompatAgentBackend(lambda _s: ScriptedChatModel({"turns": turns}))
    asyncio.run(_drive(backend, _spec(tmp_path, env, **settings), harness, messages))
    return backend


def _note(case_dir: str, label: str, value: int = 4096) -> Dict[str, Any]:
    return {"tool": "annotations_add", "input": {
        "case_dir": case_dir, "capture_id": CAP, "kind": "annotation", "label": label,
        "locations": [{"space": "physical", "value": value}]}}


def _labels(case_dir: str) -> List[str]:
    return [e.get("label") for e in annotations_list_result(case_dir, CAP).payload["entries"]]


def assert_h1(history: List[Dict[str, Any]]) -> None:
    """Every assistant tool call id is answered by exactly one directly-following tool msg."""
    for index, message in enumerate(history):
        ids = [t["id"] for t in message.get("tool_calls") or []]
        if message.get("role") != "assistant" or not ids:
            continue
        answers = []
        for follower in history[index + 1:]:
            if follower.get("role") != "tool":
                break
            answers.append(follower["tool_call_id"])
        assert answers == ids, (ids, answers)


def assert_single_result(harness: Harness, sends: int = 1) -> None:
    assert len(harness.of("usage")) == sends and len(harness.of("result")) == sends


class FakeModel:
    """Returns the given turns in order, then empty turns; records every request."""

    def __init__(self, turns: List[ModelTurn]) -> None:
        self.turns, self.requests = list(turns), []

    async def complete(self, messages, tools, on_text):
        self.requests.append(json.loads(json.dumps(messages)))
        if self.turns:
            return self.turns.pop(0)
        return ModelTurn("", (), "", Usage(1, 1, True), "stop")

    async def aclose(self):
        return None


def _turn(*calls: Tuple[str, str, str], prompt: int = 10, completion: int = 10) -> ModelTurn:
    return ModelTurn("", tuple(ToolCallRequest(*call) for call in calls), "",
                     Usage(prompt, completion, False), "tool_calls")


# -- pure helpers -------------------------------------------------------------------------


def test_group_steps_joins_text_with_the_following_tool():
    steps = [{"text": "a"}, {"text": "b"}, {"tool": "x"}, {"tool": "y"}, {"text": "c"}]
    assert group_steps(steps) == [("a\n\nb", steps[2]), ("", steps[3]), ("c", None)]


def test_scripted_model_positions_and_exhaustion():
    model = ScriptedChatModel({"turns": [[{"text": "hi"}, {"tool": "t", "input": {"a": 1}}]]})
    chunks: List[str] = []

    async def on_text(text):
        chunks.append(text)

    async def go():
        user = [{"role": "system", "content": "S"}, {"role": "user", "content": "u"}]
        first = await model.complete(user, [], on_text)
        second = await model.complete(user + [{"role": "assistant"}], [], on_text)
        third = await model.complete(user + [{"role": "assistant"}, {"role": "user"}], [], on_text)
        return first, second, third

    first, second, third = asyncio.run(go())
    assert first.text == "hi" and first.tool_calls[0].name == "t"
    assert json.loads(first.tool_calls[0].arguments) == {"a": 1} and first.usage.estimated
    assert second.text == "" and second.tool_calls == ()
    assert third.text == EXHAUSTED_TEXT


def test_scripted_model_imports_without_sdk_or_openai():
    code = ("import sys; sys.modules['claude_agent_sdk'] = None; sys.modules['openai'] = None;"
            "import memdiver.app.agent_chat.scripted_model, memdiver.app.agent_chat.compat_backend")
    assert subprocess.run([sys.executable, "-c", code], check=False).returncode == 0


def test_repair_history_fills_drops_and_orders():
    history = [
        {"role": "system", "content": "S"}, {"role": "tool", "tool_call_id": "orphan"},
        {"role": "assistant", "tool_calls": [{"id": "a"}, {"id": "b"}]},
        {"role": "tool", "tool_call_id": "b", "content": "B"},
        {"role": "tool", "tool_call_id": "b", "content": "dup"},
        {"role": "user", "content": "next"}]
    repaired = repair_history(history)
    assert_h1(repaired)
    assert [m.get("content") for m in repaired] == ["S", None, INTERRUPTED_TOOL_TEXT, "B", "next"]


# -- the loop on a real MCP child -----------------------------------------------------------


def test_read_runs_unasked_write_waits_and_is_approved(tmp_path, case):
    case_dir, env = case
    turns = [[{"text": "Looking."}, {"tool": "case_manifest", "input": {"case_dir": case_dir}},
              _note(case_dir, "seen"), {"text": "[seen] recorded."}]]
    harness = Harness(approve())
    backend = _run_script(tmp_path, env, turns, harness)
    calls = harness.of("tool_call")
    assert [(k["name"], k["access"]) for k in calls] == [
        ("case_manifest", "read"), ("annotations_add", "write")]
    assert [r["ok"] for r in harness.of("tool_result")] == [True, True]
    assert [a["tool"] for a in harness.of("approval_request")] == ["annotations_add"]
    assert _labels(case_dir) == ["seen"]
    assert [m["text"] for m in harness.of("assistant_message")] == ["Looking.", "[seen] recorded."]
    assert "".join(d["text"] for d in harness.of("text_delta")).startswith("Looking.")
    assert_single_result(harness)
    result = harness.of("result")[0]
    assert result["stop_reason"] == "success" and result["is_error"] is False
    assert result["session_id"].startswith("compat-")
    assert harness.of("usage")[0]["cost_known"] is False  # anthropic preset: no prices
    assert [e.data["state"] for e in harness.events if e.type == "status"][0] == "starting"
    assert harness.events[-1].type == "status" and harness.events[-1].data["state"] == "closed"
    assert_h1(backend._history)


def test_denied_write_is_not_run(tmp_path, case):
    case_dir, env = case
    harness = Harness(deny)
    _run_script(tmp_path, env, [[_note(case_dir, "nope"), {"text": "ok"}]], harness)
    result = harness.of("tool_result")[0]
    assert result["ok"] is False and result["summary"].startswith("Denied: no")
    assert _labels(case_dir) == []
    assert_single_result(harness)
    assert harness.of("result")[0]["stop_reason"] == "success"


def test_chat_scope_covers_writes_but_never_write_once(tmp_path, case):
    case_dir, env = case
    turns = [[_note(case_dir, "a"), _note(case_dir, "b", 8192),
              {"tool": WRITE_ONCE_TOOL, "input": {}}, {"tool": WRITE_ONCE_TOOL, "input": {}}]]
    harness = Harness(approve("chat"))
    _run_script(tmp_path, env, turns, harness)
    requests = harness.of("approval_request")
    assert [r["tool"] for r in requests] == ["annotations_add", WRITE_ONCE_TOOL, WRITE_ONCE_TOOL]
    assert requests[1]["scopes"] == ["once"] and requests[2]["scopes"] == ["once"]
    assert sorted(_labels(case_dir)) == ["a", "b"]
    assert_single_result(harness)


def test_max_turns_stops_with_one_result(tmp_path, case):
    case_dir, env = case
    step = {"tool": "case_manifest", "input": {"case_dir": case_dir}}
    harness = Harness()
    _run_script(tmp_path, env, [[step, step, {"text": "never"}]], harness, max_turns=1)
    assert len(harness.of("tool_result")) == 1
    assert_single_result(harness)
    result = harness.of("result")[0]
    assert result["stop_reason"] == "error_max_turns" and result["is_error"] is True
    assert result["num_turns"] == 1


def test_budget_stop_with_priced_usage(tmp_path, case):
    case_dir, env = case
    model = FakeModel([_turn(("p1", "case_manifest", json.dumps({"case_dir": case_dir})),
                             prompt=10_000_000)] * 3)
    harness = Harness()
    backend = CompatAgentBackend(lambda _s: model)
    spec = _spec(tmp_path, env, provider="openai", model="gpt-5-mini", max_budget_usd=0.05)
    asyncio.run(_drive(backend, spec, harness))
    assert_single_result(harness)
    result, usage = harness.of("result")[0], harness.of("usage")[0]
    assert result["stop_reason"] == "error_max_budget_usd" and result["num_turns"] == 1
    assert usage["cost_known"] is True and usage["cost_estimate_usd"] > 0.05


def test_interrupt_mid_approval_then_next_send_has_valid_history(tmp_path, case):
    case_dir, env = case
    turns = [[_note(case_dir, "never"), {"text": "never said"}], [{"text": "after"}]]
    seen: List[List[Dict[str, Any]]] = []
    inner = ScriptedChatModel({"turns": turns})

    class Recording:
        async def complete(self, messages, tools, on_text):
            seen.append(json.loads(json.dumps(messages)))
            return await inner.complete(messages, tools, on_text)

        async def aclose(self):
            return None

    backend = CompatAgentBackend(lambda _s: Recording())
    harness = Harness(on_approval=backend.interrupt)
    asyncio.run(_drive(backend, _spec(tmp_path, env), harness, ("one", "two")))
    results = harness.of("result")
    assert [r["stop_reason"] for r in results] == ["error_during_execution", "success"]
    assert_single_result(harness, sends=2)
    assert _labels(case_dir) == []
    last_request = seen[-1]
    assert_h1(last_request)
    tool_messages = [m for m in last_request if m["role"] == "tool"]
    assert [m["content"] for m in tool_messages] == [INTERRUPTED_TOOL_TEXT]
    assert [m["role"] for m in last_request] == ["system", "user", "assistant", "tool", "user"]
    assert harness.of("assistant_message")[-1]["text"] == "after"


def test_invalid_calls_never_reach_the_gate(tmp_path, case):
    case_dir, env = case
    bad = [("a", c.TOOL_PREFIX + "case_manifest", "{}"), ("b", "no_such_tool", "{}"),
           ("c", "annotations_add", "[]"), ("d", "annotations_add", "null"),
           ("e", "annotations_add", "{not json")]
    model = FakeModel([_turn(*bad)])
    harness = Harness(approve())
    backend = CompatAgentBackend(lambda _s: model)
    asyncio.run(_drive(backend, _spec(tmp_path, env), harness))
    assert harness.decided == [] and harness.of("approval_request") == []
    assert [r["ok"] for r in harness.of("tool_result")] == [False] * len(bad)
    assert [k["name"] for k in harness.of("tool_call")] == [b[1] for b in bad]
    summaries = [r["summary"] for r in harness.of("tool_result")]
    assert summaries[0].startswith("unknown tool") and "bad args" in summaries[2]
    assert_single_result(harness)
    assert_h1(model.requests[-1])


def test_duplicate_and_empty_provider_ids_get_unique_ids(tmp_path, case):
    case_dir, env = case
    args = json.dumps({"case_dir": case_dir})
    model = FakeModel([_turn(("dup", "case_manifest", args), ("dup", "case_manifest", args),
                             ("", "case_manifest", args)),
                       _turn(("dup", "case_manifest", args), ("", "case_manifest", args))])
    harness = Harness()
    backend = CompatAgentBackend(lambda _s: model)
    asyncio.run(_drive(backend, _spec(tmp_path, env), harness))
    event_ids = [k["id"] for k in harness.of("tool_call")]
    assert len(event_ids) == 5 and len(set(event_ids)) == 5
    assert [r["id"] for r in harness.of("tool_result")] == event_ids
    history = model.requests[-1]
    history_ids = [t["id"] for m in history for t in m.get("tool_calls") or []]
    assert len(set(history_ids)) == 5 and all(history_ids)
    assert_h1(history)
    assert_single_result(harness)


def test_model_error_gives_error_event_and_single_result(tmp_path, case):
    _case_dir, env = case
    from memdiver.core.service_errors import CapabilityError

    class Broken(FakeModel):
        async def complete(self, messages, tools, on_text):
            raise CapabilityError("provider down", code="agent.provider_unreachable")

    harness = Harness()
    backend = CompatAgentBackend(lambda _s: Broken([]))
    asyncio.run(_drive(backend, _spec(tmp_path, env), harness))
    assert harness.of("error") == [{"code": "agent.provider_unreachable",
                                    "message": "provider down"}]
    assert_single_result(harness)
    assert harness.of("result")[0]["stop_reason"] == "error_during_execution"


def test_empty_turn_keeps_string_content_in_history(tmp_path, case):
    """Regression: an empty turn stored ``content: None``; OpenAI/DeepSeek then 400."""
    _case_dir, env = case
    model = FakeModel([])  # every turn: no text, no tool calls
    harness = Harness()
    backend = CompatAgentBackend(lambda _s: model)
    asyncio.run(_drive(backend, _spec(tmp_path, env), harness, ("one", "two")))
    assistants = [m for m in model.requests[-1] if m["role"] == "assistant"]
    assert [m["content"] for m in assistants] == [""]
    assert [m["role"] for m in model.requests[-1]] == ["system", "user", "assistant", "user"]
    assert [r["stop_reason"] for r in harness.of("result")] == ["success", "success"]


def test_length_truncated_reply_stops_with_max_output_tokens(tmp_path, case):
    _case_dir, env = case
    cut = ModelTurn("partial ans", (), "", Usage(10, 10, False), "length")
    harness = Harness()
    backend = CompatAgentBackend(lambda _s: FakeModel([cut]))
    asyncio.run(_drive(backend, _spec(tmp_path, env), harness))
    result = harness.of("result")[0]
    assert (result["stop_reason"], result["is_error"]) == ("error_max_output_tokens", True)
    assert [e["code"] for e in harness.of("error")] == ["agent.output_truncated"]
    assert_single_result(harness)


class EmitHook(Harness):
    """A :class:`Harness` that runs ``hook`` once, on the first ``status: running``."""

    def __init__(self, hook: Callable[[], Any]) -> None:
        super().__init__()
        self.hook: Optional[Callable[[], Any]] = hook

    async def emit(self, event: c.ChatEvent) -> None:
        await super().emit(event)
        if self.hook is not None and event.type == "status" \
                and event.data["state"] == "running":
            hook, self.hook = self.hook, None
            await hook()


def test_interrupt_before_the_turn_task_exists_is_honoured(tmp_path, case):
    """Regression: an interrupt landing before ``send`` created its inner task was lost."""
    _case_dir, env = case
    model = FakeModel([])
    backend = CompatAgentBackend(lambda _s: model)
    harness = EmitHook(backend.interrupt)
    asyncio.run(_drive(backend, _spec(tmp_path, env), harness, ("one", "two")))
    assert [r["stop_reason"] for r in harness.of("result")] == [
        "error_during_execution", "success"]
    assert len(model.requests) == 1  # the interrupted send never called the model
    assert_single_result(harness, sends=2)


def test_interrupt_while_idle_does_not_stop_the_next_send(tmp_path, case):
    _case_dir, env = case
    model = FakeModel([])
    backend = CompatAgentBackend(lambda _s: model)
    harness = Harness()

    async def go():
        await backend.start(_spec(tmp_path, env), harness.gate, harness.emit)
        try:
            await backend.interrupt()
            await backend.send("go")
        finally:
            await harness.gate.close()
            await backend.close()

    asyncio.run(go())
    assert harness.of("result")[0]["stop_reason"] == "success" and len(model.requests) == 1


class ClosingModel(FakeModel):
    def __init__(self) -> None:
        super().__init__([])
        self.closed = 0

    async def aclose(self):
        self.closed += 1


def test_kill_releases_the_model_client(tmp_path, case):
    """Regression: ``kill`` (the session's escalation) leaked the model's HTTP client."""
    _case_dir, env = case
    model = ClosingModel()
    harness = Harness()

    async def go():
        backend = CompatAgentBackend(lambda _s: model)
        await backend.start(_spec(tmp_path, env), harness.gate, harness.emit)
        await backend.kill()
        await backend.kill()

    asyncio.run(go())
    assert model.closed == 1


def _hang_mcp_close(backend: CompatAgentBackend) -> None:
    async def hang() -> None:
        await asyncio.sleep(3600)

    backend._mcp.close = hang  # type: ignore[union-attr,method-assign]


def test_cancelled_close_still_releases_the_model_client(tmp_path, case):
    """Regression: the session's close timeout cancelled ``close`` before the model
    client was released."""
    _case_dir, env = case
    model = ClosingModel()
    harness = Harness()

    async def go():
        backend = CompatAgentBackend(lambda _s: model)
        await backend.start(_spec(tmp_path, env), harness.gate, harness.emit)
        _hang_mcp_close(backend)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(backend.close(), 0.3)
        assert model.closed == 1
        await backend.kill()

    asyncio.run(go())


def test_close_is_bounded_when_the_mcp_child_hangs(tmp_path, case, monkeypatch):
    """The graceful close finishes (child killed, model released) instead of hanging."""
    from memdiver.app.agent_chat import compat_backend

    monkeypatch.setattr(compat_backend, "MCP_CLOSE_TIMEOUT_SECONDS", 0.3, raising=False)
    _case_dir, env = case
    model = ClosingModel()
    harness = Harness()

    async def go():
        backend = CompatAgentBackend(lambda _s: model)
        await backend.start(_spec(tmp_path, env), harness.gate, harness.emit)
        _hang_mcp_close(backend)
        await asyncio.wait_for(backend.close(), 10)
        assert backend._mcp is None and model.closed == 1

    asyncio.run(go())
    assert harness.of("status")[-1] == {"state": "closed"}


def test_start_failure_is_a_capability_error(tmp_path):
    from memdiver.core.service_errors import CapabilityError

    spec = c.ChatSpec(system_prompt="S", settings=c.AgentSettings(),
                      mcp=c.McpChild(str(tmp_path / "missing-binary"), [], {}),
                      allowed_tools=[], cwd=str(tmp_path), config_dir=str(tmp_path))
    harness = Harness()
    backend = CompatAgentBackend(lambda _s: FakeModel([]))
    with pytest.raises(CapabilityError) as info:
        asyncio.run(backend.start(spec, harness.gate, harness.emit))
    assert info.value.code == "agent.tools_unavailable"


# -- no leaked children -------------------------------------------------------------------


def _mcp_children() -> List[Any]:
    psutil = pytest.importorskip("psutil")

    def cmdline(proc):
        try:
            return " ".join(proc.cmdline())
        except psutil.Error:
            return ""

    return [p for p in psutil.Process().children(recursive=True)
            if "memdiver.cli" in cmdline(p)]


def _wait_for_children(limit: int, seconds: float = 20.0) -> int:
    deadline = time.time() + seconds
    while time.time() < deadline and len(_mcp_children()) > limit:
        time.sleep(0.2)
    return len(_mcp_children())


def test_close_and_kill_leave_no_mcp_child(tmp_path, case):
    case_dir, env = case
    baseline = len(_mcp_children())
    harness = Harness()
    _run_script(tmp_path, env, [[{"tool": "case_manifest", "input": {"case_dir": case_dir}}]],
                harness)
    assert _wait_for_children(baseline) == baseline

    async def killed():
        backend = CompatAgentBackend(lambda _s: FakeModel([]))
        await backend.start(_spec(tmp_path, env), harness.gate, harness.emit)
        await backend.kill()
        await backend.kill()  # idempotent

    asyncio.run(killed())
    assert _wait_for_children(baseline) == baseline


# -- parity with the SDK scripted backend ---------------------------------------------------


def _parity_script(tmp_path: Path, case_dir: str) -> Path:
    """The real-case demo script with its case and dump paths pointed at tmp_path."""
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    dump = tmp_path / "dump.lime"
    dump.write_bytes(bytes(range(256)) * 64)
    text = json.dumps(raw)
    for step in raw["turns"][0]:
        for anchor in (step.get("input") or {}).get("anchors", []):
            text = text.replace(json.dumps(anchor["dump_path"])[1:-1], str(dump))
    text = text.replace("/Users/danielbaier/.memdiver/cases/p6_gate_wf1", case_dir)
    path = tmp_path / "script.json"
    path.write_text(text, encoding="utf-8")
    return path


def _normalized(harness: Harness) -> Tuple[List[Tuple[Any, ...]], str]:
    """Event sequence with ids/costs/turns/status/deltas/resolutions masked."""
    keep = []
    for event in harness.events:
        d = event.data
        if event.type in ("status", "text_delta", "approval_resolved", "usage"):
            continue
        keep.append((event.type, d.get("name") or d.get("tool"), d.get("ok"),
                     d.get("access"), d.get("stop_reason"), d.get("text")))
    return keep, "".join(d["text"] for d in harness.of("text_delta"))


def _parity_run(kind: str, tmp_path: Path, env: Dict[str, str], script: Path):
    backend = make_backend(kind, ACCESS, env={"MEMDIVER_AGENT_SCRIPT": str(script)})
    harness = Harness(approve("chat"))
    asyncio.run(_drive(backend, _spec(tmp_path, env), harness, ("one", "two")))
    return harness


def test_parity_scripted_sdk_vs_scripted_compat(tmp_path, case):
    pytest.importorskip("claude_agent_sdk")
    case_dir, env = case
    script = _parity_script(tmp_path, case_dir)
    sdk = _parity_run("scripted", tmp_path, env, script)
    compat = _parity_run("scripted-compat", tmp_path, env, script)
    assert _normalized(compat) == _normalized(sdk)
    assert len(compat.of("tool_call")) == 5 and len(compat.of("approval_request")) == 1
    assert [r["stop_reason"] for r in compat.of("result")] == ["success", "success"]
