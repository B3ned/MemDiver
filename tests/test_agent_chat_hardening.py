"""Hardening of the in-UI agent chat: child lifecycle (M1), read-root scope (M2),
child credential env (L2) and the CLI output cap (L5)."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("claude_agent_sdk")
pytest.importorskip("mcp")
psutil = pytest.importorskip("psutil")

from memdiver.analysis.case import Case  # noqa: E402
from memdiver.api.config import get_settings  # noqa: E402
from memdiver.api.main import create_app  # noqa: E402
from memdiver.api.services import agent_chat as chats  # noqa: E402
from memdiver.app.agent_chat import contracts as c  # noqa: E402
from memdiver.app.agent_chat import sdk_backend  # noqa: E402
from memdiver.app.agent_chat.session import ChatRegistry, ChatSession  # noqa: E402


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(uploads))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(tmp_path / "tasks"))
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(tmp_path / "oracles"))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    for name in ("MEMDIVER_ALLOWED_ROOTS", "MEMDIVER_API_TOKEN", "MEMDIVER_HOST"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(chats.BACKEND_ENV, "scripted")
    get_settings.cache_clear()
    chats.reset_chat_registry()
    yield tmp_path
    chats.reset_chat_registry()
    get_settings.cache_clear()


@pytest.fixture
def client(env):
    with TestClient(create_app()) as test_client:
        yield test_client


def _case(env: Path) -> str:
    return str(Case.init(env / "uploads" / "case").dir)


def _script(env: Path, monkeypatch, case_dir: str) -> None:
    turns = [[{"tool": "case_manifest", "input": {"case_dir": case_dir}},
              {"tool": "case_init", "input": {"case": "x1"}}]]
    path = env / "script.json"
    path.write_text(json.dumps({"turns": turns}))
    monkeypatch.setenv(chats.SCRIPT_ENV, str(path))


# -- M2: client-supplied paths cannot widen the child's read sandbox ---------------------


def _post(client, **body):
    return client.post("/api/agent/chats", json=body)


def test_case_dir_root_is_rejected(client, env, monkeypatch):
    _script(env, monkeypatch, _case(env))
    r = _post(client, case_dir="/")
    assert r.status_code == 422 and "too broad" in r.json()["detail"]


def test_case_dir_home_and_ancestor_are_rejected(client, env, monkeypatch):
    _script(env, monkeypatch, _case(env))
    for path in (Path.home(), Path.home().parent):
        r = _post(client, case_dir=str(path))
        assert r.status_code == 422 and "too broad" in r.json()["detail"], path


def test_case_dir_ancestor_of_memdiver_home_is_rejected(client, env, monkeypatch):
    _script(env, monkeypatch, _case(env))
    r = _post(client, case_dir=str(env))  # tmp_path holds xdg/memdiver
    assert r.status_code == 422 and "too broad" in r.json()["detail"]


def test_case_dir_must_be_a_case(client, env, monkeypatch):
    _script(env, monkeypatch, _case(env))
    plain = env / "uploads" / "plain"
    plain.mkdir()
    r = _post(client, case_dir=str(plain))
    assert r.status_code == 422 and "not a case" in r.json()["detail"]


def test_dump_must_be_a_file_not_a_directory(client, env, monkeypatch):
    _script(env, monkeypatch, _case(env))
    r = _post(client, dump_paths=[str(env / "uploads")])
    assert r.status_code == 422 and "regular file" in r.json()["detail"]


def test_dump_root_is_the_exact_file_never_its_parent(env):
    secret_dir = env / "dot_ssh"
    secret_dir.mkdir()
    dump = secret_dir / "x.raw"
    dump.write_bytes(b"\0" * 16)
    roots = chats._child_roots(None, [dump])
    assert str(dump) in roots and str(secret_dir) not in roots
    from memdiver.core import path_sandbox

    resolved = path_sandbox.resolve_roots(roots)
    assert path_sandbox.within(dump.resolve(), resolved)
    assert not path_sandbox.within((secret_dir / "id_rsa").resolve(), resolved)


def test_normal_case_and_dump_are_accepted_and_warn_when_read_only(client, env, monkeypatch):
    case = _case(env)
    _script(env, monkeypatch, case)
    dump = env / "uploads" / "d.raw"
    dump.write_bytes(b"\0" * 16)
    ok = _post(client, case_dir=case, dump_paths=[str(dump)])
    assert ok.status_code == 200 and ok.json()["warnings"] == []
    outside = Case.init(env / "elsewhere" / "case").dir
    warned = _post(client, case_dir=str(outside))
    assert warned.status_code == 200
    assert any("cannot write" in w for w in warned.json()["warnings"])


def test_configured_sandbox_still_denies_outside_paths(env, monkeypatch):
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(env / "uploads"))
    get_settings.cache_clear()
    outside = env / "elsewhere"
    outside.mkdir()
    (outside / "d.raw").write_bytes(b"\0")
    with TestClient(create_app()) as test_client:
        r = test_client.post("/api/agent/chats", json={"dump_paths": [str(outside / "d.raw")]})
    assert r.status_code in (403, 422)


# -- L2 / L5: child env and CLI options -----------------------------------------------------


def test_child_env_blanks_credentials_even_when_inherited(env, monkeypatch):
    for name in chats.CHILD_ENV_BLANKED:
        monkeypatch.setenv(name, "sk-secret-value")
    child = chats._child_env([str(env)])
    for name in chats.CHILD_ENV_BLANKED:
        assert child[name] == "", name  # present and EMPTY: it overrides the inherited value


PROVIDER_KEY_NAMES = ("OPENAI_API_KEY", "DEEPSEEK_API_KEY", "VLLM_API_KEY",
                      "MEMDIVER_AGENT_OPENAI_API_KEY")


def test_child_env_has_no_provider_keys(env, monkeypatch):
    """Dropped from the base env (the compat stdio client layers it over a whitelist) AND
    blanked (the Claude CLI layers it over the full server env)."""
    for name in PROVIDER_KEY_NAMES:
        monkeypatch.setenv(name, f"sk-secret-{name}")
    spec = chats.build_spec(None, [], {})
    for name in PROVIDER_KEY_NAMES:
        assert name in chats.CHILD_ENV_BLANKED and name in chats._CHILD_ENV_DROPPED
        assert not spec.mcp.env.get(name), name
    assert "sk-secret-" not in json.dumps(spec.mcp.env)


def test_options_pass_blanked_child_env_and_output_cap(env, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-value")
    monkeypatch.setenv("MEMDIVER_API_TOKEN", "tok")
    spec = chats.build_spec(None, [], {})
    options = sdk_backend.build_options(spec, gate=None)  # gate only used inside callbacks
    child_env = options.mcp_servers[c.MCP_SERVER_NAME]["env"]
    assert child_env["ANTHROPIC_API_KEY"] == "" and child_env["MEMDIVER_API_TOKEN"] == ""
    assert "sk-secret-value" not in json.dumps(options.mcp_servers)
    budget = spec.settings.result_budget_bytes
    cap = int(options.env["MAX_MCP_OUTPUT_TOKENS"])
    assert cap == sdk_backend.cli_output_token_cap(budget) and cap > budget // 2


def test_output_cap_scales_with_budget_up_to_the_maximum():
    lo, hi = c.LIMITS["result_budget_bytes"]
    assert sdk_backend.cli_output_token_cap(hi) >= hi // 2
    assert sdk_backend.cli_output_token_cap(lo) > lo // 2


# -- M1: close survives cancellation; escalation; no leaked MCP children ------------------


class _Gate:
    async def close(self):
        pass


class _SlowBackend:
    def __init__(self, hang: bool):
        self.hang = hang
        self.killed = 0
        self.closed = False

    async def start(self, spec, gate, emit): ...

    async def send(self, text): ...

    async def interrupt(self): ...

    async def close(self):
        if self.hang:
            await asyncio.sleep(3600)
        await asyncio.sleep(0.05)
        self.closed = True

    async def kill(self):
        self.killed += 1


def _session(backend, chat_id="c1"):
    async def emit(_event):
        return None

    spec = c.ChatSpec(system_prompt="s", settings=c.AgentSettings(),
                      mcp=c.McpChild("m", [], {}), allowed_tools=[], cwd=".", config_dir=".")
    return ChatSession(chat_id, backend, lambda _e: _Gate(), spec, emit)


def test_cancelling_the_close_caller_does_not_abort_the_close():
    async def scenario():
        backend = _SlowBackend(hang=False)
        registry = ChatRegistry()
        registry.create(_session(backend))
        caller = asyncio.ensure_future(registry.close("c1"))
        await asyncio.sleep(0.01)
        caller.cancel()
        await asyncio.gather(caller, return_exceptions=True)
        assert registry.get("c1") is not None  # still registered until the close completed
        await registry.close_all()  # waits for the straggler
        assert backend.closed and registry.get("c1") is None

    asyncio.run(scenario())


def test_hung_backend_close_is_escalated_to_kill(monkeypatch):
    monkeypatch.setattr("memdiver.app.agent_chat.session.BACKEND_CLOSE_TIMEOUT_SECONDS", 0.1)

    async def scenario():
        backend = _SlowBackend(hang=True)
        session = _session(backend)
        await asyncio.wait_for(session.close(), 5)
        assert backend.killed == 1 and session.finished

    asyncio.run(scenario())


def _mcp_children():
    return [p for p in psutil.Process().children(recursive=True)
            if "memdiver.cli" in " ".join(_cmdline(p))]


def _cmdline(proc):
    try:
        return proc.cmdline()
    except psutil.Error:
        return []


def _wait_for_children(limit: int, seconds: float = 20.0) -> int:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if len(_mcp_children()) <= limit:
            break
        time.sleep(0.2)
    return len(_mcp_children())


def _drop_ws_at_approval(client, case_dir):
    chat = client.post("/api/agent/chats", json={"case_dir": case_dir}).json()
    with client.websocket_connect(chat["ws_path"]) as ws:
        ws.send_json({"type": "user_message", "text": "go"})
        while ws.receive_json()["type"] != "approval_request":
            pass
        assert _mcp_children(), "the scripted run should have an MCP child by now"


def test_ws_drops_leave_no_mcp_children(client, env, monkeypatch):
    case_dir = _case(env)
    _script(env, monkeypatch, case_dir)
    baseline = len(_mcp_children())
    for _ in range(3):
        _drop_ws_at_approval(client, case_dir)
    assert _wait_for_children(baseline) == baseline


def test_shutdown_with_open_chat_leaves_no_children(env, monkeypatch):
    case_dir = _case(env)
    _script(env, monkeypatch, case_dir)
    baseline = len(_mcp_children())

    async def scenario() -> float:
        # The lifespan shutdown hook is exactly ``close_all_chats`` (Starlette's TestClient
        # cannot model it: it waits for a still-open client socket that uvicorn would close).
        ticket = await chats.create_chat(case_dir, [])
        handle = chats.get_handle(ticket["chat_id"])
        await handle.session.start()
        await handle.session.handle_client_message({"type": "user_message", "text": "go"})
        while (await handle.queue.get()).type != "approval_request":
            pass
        assert len(_mcp_children()) > baseline
        started = time.time()
        await chats.close_all_chats()
        return time.time() - started

    elapsed = asyncio.run(scenario())
    assert elapsed < chats.CLOSE_ALL_TIMEOUT_SECONDS
    assert _wait_for_children(baseline) == baseline
