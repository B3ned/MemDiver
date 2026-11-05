"""Web API of the in-UI agent chat: status, settings, playbooks, chat lifecycle and the WS.

The WebSocket tests run the REAL stack with no model: ``MEMDIVER_AGENT_BACKEND=scripted``
plays the Claude CLI side of the SDK protocol and executes tools on a REAL sandboxed
``memdiver mcp`` child (see ``test_agent_chat_sdk_backend.py``).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

pytest.importorskip("claude_agent_sdk")
pytest.importorskip("mcp")

from memdiver.analysis.case import Case  # noqa: E402
from memdiver.api.config import get_settings  # noqa: E402
from memdiver.api.main import create_app  # noqa: E402
from memdiver.api.services import agent_chat as chats  # noqa: E402
from memdiver.app.agent_chat import contracts as c  # noqa: E402
from memdiver.app.tools_annotations import annotations_list_result  # noqa: E402

CAP = "cap1"
SECRET = "sk-ant-TEST-SECRET-VALUE-0123456789"


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    """Isolated MemDiver home (XDG), upload dir and a scripted agent backend."""
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(uploads))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(tmp_path / "tasks"))
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(tmp_path / "oracles"))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("MEMDIVER_API_TOKEN", raising=False)
    monkeypatch.delenv("MEMDIVER_HOST", raising=False)
    for name in (*chats.CREDENTIAL_VARS, *chats.CLOUD_PROVIDER_FLAGS,
                 *chats.PROVIDER_KEY_VARS, "MEMDIVER_AGENT_OPENAI_BASE_URL"):
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


def _write_script(env: Path, monkeypatch, turns) -> None:
    path = env / "script.json"
    path.write_text(json.dumps({"turns": turns}))
    monkeypatch.setenv(chats.SCRIPT_ENV, str(path))


def _make_case(env: Path) -> str:
    return str(Case.init(env / "uploads" / "case").dir)


# -- status ------------------------------------------------------------------------------


def test_status_scripted_available_without_credentials(client, monkeypatch, env):
    _write_script(env, monkeypatch, [[{"text": "hi"}]])
    body = client.get("/api/agent/status").json()
    assert body["available"] is True and body["backend"] == "scripted"
    assert body["credentials"] is False


def test_status_scripted_without_script_is_unavailable(client):
    body = client.get("/api/agent/status").json()
    assert body["available"] is False and "MEMDIVER_AGENT_SCRIPT" in body["reason"]


def test_status_sdk_reports_credentials_as_bool_only(client, monkeypatch):
    monkeypatch.setenv(chats.BACKEND_ENV, "sdk")
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    response = client.get("/api/agent/status")
    body = response.json()
    assert body["backend"] == "sdk" and body["available"] is True
    assert body["credentials"] is True
    assert SECRET not in response.text


@pytest.mark.parametrize("flag", chats.CLOUD_PROVIDER_FLAGS)
def test_status_cloud_provider_flag_counts_as_credentials(client, monkeypatch, flag):
    monkeypatch.setenv(chats.BACKEND_ENV, "sdk")
    monkeypatch.setenv(flag, "1")
    assert client.get("/api/agent/status").json()["credentials"] is True


def test_status_sdk_missing_gives_install_hint(client, monkeypatch):
    monkeypatch.setenv(chats.BACKEND_ENV, "sdk")
    monkeypatch.setattr(chats.importlib.util, "find_spec", lambda name: None)
    body = client.get("/api/agent/status").json()
    assert body["available"] is False and "agent" in body["install_hint"]


# -- settings ----------------------------------------------------------------------------


def test_settings_get_defaults_and_shape(client):
    body = client.get("/api/agent/settings").json()
    assert body["settings"] == body["defaults"] == c.AgentSettings().to_dict()
    choices = body["choices"]
    assert choices["model"] == list(c.MODEL_CHOICES)
    assert choices["effort"] == list(c.EFFORT_CHOICES)
    assert choices["provider"] == list(c.PROVIDER_CHOICES)
    assert [p["id"] for p in choices["providers"]] == list(c.PROVIDER_CHOICES)
    assert choices["tool_set"] == ["full", "compact", "minimal"]
    assert not any("url" in key or "key" in key for p in choices["providers"] for key in p)
    assert body["limits"]["max_turns"] == [1, 200]
    assert body["warning"] is False


def test_settings_put_partial_persists(client):
    body = client.put("/api/agent/settings", json={"max_turns": 12, "effort": "high"}).json()
    assert body["settings"]["max_turns"] == 12 and body["settings"]["effort"] == "high"
    assert body["settings"]["model"] == c.DEFAULT_MODEL
    again = client.get("/api/agent/settings").json()
    assert again["settings"] == body["settings"]


@pytest.mark.parametrize("changes", [
    {"max_turns": 0}, {"max_turns": 201}, {"max_budget_usd": 0.01},
    {"result_budget_bytes": 1_999}, {"result_budget_bytes": 500_001},
    {"model": "gpt-nope"}, {"effort": "extreme"}, {"bogus": 1}, {"max_turns": True},
])
def test_settings_put_invalid_is_422_and_unchanged(client, changes):
    response = client.put("/api/agent/settings", json=changes)
    assert response.status_code == 422 and response.json()["detail"]
    assert client.get("/api/agent/settings").json()["settings"] == c.AgentSettings().to_dict()


def test_settings_bounds_are_inclusive(client):
    ok = client.put("/api/agent/settings", json={"max_turns": 200, "result_budget_bytes": 2_000})
    assert ok.status_code == 200


# -- playbooks ---------------------------------------------------------------------------


def test_playbooks_list_has_the_eight_prompts(client):
    books = client.get("/api/agent/playbooks").json()
    names = {b["name"] for b in books}
    assert len(books) == 8 and "memdiver_start" in names and "isf_workbench" in names
    by_name = {b["name"]: b for b in books}
    assert by_name["isf_workbench"]["params"] == ["image_path", "case", "draft"]
    assert by_name["memdiver_start"]["params"] == []
    assert all(b["summary"] and "\n" not in b["summary"] for b in books)


def test_playbook_render_substitutes_args(client):
    response = client.post("/api/agent/playbooks/code_evidence/render",
                           json={"args": {"function": "my_func"}})
    assert response.status_code == 200 and "my_func" in response.json()["text"]


def test_playbook_render_unknown_name_404_and_bad_args_422(client):
    assert client.post("/api/agent/playbooks/nope/render", json={"args": {}}).status_code == 404
    bad = client.post("/api/agent/playbooks/code_evidence/render", json={"args": {"zzz": "1"}})
    assert bad.status_code == 422
    not_str = client.post("/api/agent/playbooks/code_evidence/render",
                          json={"args": {"function": 5}})
    assert not_str.status_code == 422


# -- chat lifecycle ----------------------------------------------------------------------


def test_chat_create_delete_and_unknown_404(client, env, monkeypatch):
    _write_script(env, monkeypatch, [[{"text": "hi"}]])
    created = client.post("/api/agent/chats", json={"case_dir": _make_case(env)})
    assert created.status_code == 200
    body = created.json()
    assert body["ws_path"] == f"/ws/agent/{body['chat_id']}"
    assert "case_manifest" in body["read_tools"] and "annotations_add" in body["write_tools"]
    assert "capture_dump" not in body["read_tools"] + body["write_tools"]
    assert client.delete(f"/api/agent/chats/{body['chat_id']}").status_code == 204
    assert client.delete(f"/api/agent/chats/{body['chat_id']}").status_code == 404
    assert client.delete("/api/agent/chats/never-existed").status_code == 404


def test_chat_create_rejects_missing_paths(client, env, monkeypatch):
    _write_script(env, monkeypatch, [[{"text": "hi"}]])
    missing = str(env / "nope")
    assert client.post("/api/agent/chats", json={"case_dir": missing}).status_code == 422
    assert client.post("/api/agent/chats", json={"dump_paths": [missing]}).status_code == 422


def test_chat_create_unavailable_is_503(client):
    response = client.post("/api/agent/chats", json={})
    assert response.status_code == 503


def test_chat_create_registry_cap_is_429(client, env, monkeypatch):
    _write_script(env, monkeypatch, [[{"text": "hi"}]])
    ids = [client.post("/api/agent/chats", json={}).json()["chat_id"]
           for _ in range(chats.MAX_OPEN_CHATS)]
    assert client.post("/api/agent/chats", json={}).status_code == 429
    assert client.delete(f"/api/agent/chats/{ids[0]}").status_code == 204
    assert client.post("/api/agent/chats", json={}).status_code == 200


def test_chat_spec_confines_the_mcp_child(env, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    case = _make_case(env)
    dump = env / "d" / "x.dump"
    dump.parent.mkdir()
    dump.write_bytes(b"\0" * 16)
    spec = chats.build_spec(case, [str(dump)], chats.tool_access_map())
    roots = spec.mcp.env["MEMDIVER_ALLOWED_ROOTS"].split(":")
    # the dump is admitted as an EXACT-FILE root, never its parent directory
    assert str(Path(case).resolve()) in roots and str(dump.resolve()) in roots
    assert str(dump.parent.resolve()) not in roots
    assert spec.mcp.env["MEMDIVER_UPLOAD_DIR"] == str(env / "uploads")
    assert spec.mcp.env["MEMDIVER_MCP_RESULT_BUDGET"] == str(c.AgentSettings().result_budget_bytes)
    assert spec.mcp.env["ANTHROPIC_API_KEY"] == ""  # blanked, not merely dropped (L2)
    assert spec.mcp.args == ["-m", "memdiver.cli", "mcp"] and spec.cwd == str(Path(case).resolve())
    assert c.TOOL_PREFIX + "case_manifest" in spec.allowed_tools
    assert c.TOOL_PREFIX + "annotations_add" not in spec.allowed_tools
    assert spec.tool_access["capture_dump"] == "never"


def test_chat_spec_tells_the_model_its_scope(env):
    """Regression (live llama3.3 run): the model was never told the case/dump paths and
    called case_manifest with an invented '/path/to/case/directory'."""
    case = _make_case(env)
    dump = env / "d" / "x.dump"
    dump.parent.mkdir()
    dump.write_bytes(b"\0" * 16)
    spec = chats.build_spec(case, [str(dump)], chats.tool_access_map())
    assert f"case_dir: {json.dumps(str(Path(case).resolve()))}" in spec.scope_note
    assert f"dump_path: {json.dumps(str(dump.resolve()))}" in spec.scope_note
    assert str(Path(case).resolve()) not in spec.system_prompt  # prompt stays byte-stable
    assert chats.build_spec(None, [], chats.tool_access_map()).scope_note == ""


def test_chat_spec_uses_configured_sandbox_roots(env, monkeypatch):
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(env))
    get_settings.cache_clear()
    spec = chats.build_spec(None, [], chats.tool_access_map())
    assert spec.mcp.env["MEMDIVER_ALLOWED_ROOTS"] == str(env)


def test_sandbox_refuses_case_dir_outside_roots(env, monkeypatch):
    _write_script(env, monkeypatch, [[{"text": "hi"}]])
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(env / "uploads"))
    get_settings.cache_clear()
    with TestClient(create_app()) as sandboxed:
        assert sandboxed.post("/api/agent/chats", json={"case_dir": "/etc"}).status_code == 403


# -- security ----------------------------------------------------------------------------


def test_non_loopback_without_token_is_refused(env, monkeypatch):
    _write_script(env, monkeypatch, [[{"text": "hi"}]])
    monkeypatch.setenv("MEMDIVER_HOST", "0.0.0.0")  # nosec B104 - the thing under test
    monkeypatch.setenv("MEMDIVER_ALLOW_INSECURE", "1")  # must NOT lift the refusal
    get_settings.cache_clear()
    with TestClient(create_app()) as exposed:
        for method, path in (("get", "/api/agent/status"), ("get", "/api/agent/settings"),
                             ("get", "/api/agent/playbooks"), ("post", "/api/agent/chats")):
            response = getattr(exposed, method)(path)
            assert response.status_code == 403, path
            assert "MEMDIVER_API_TOKEN" in response.json()["detail"]
        with pytest.raises(WebSocketDisconnect):
            with exposed.websocket_connect("/ws/agent/whatever"):
                pass


def test_non_loopback_with_token_is_allowed(env, monkeypatch):
    monkeypatch.setenv("MEMDIVER_HOST", "0.0.0.0")  # nosec B104
    monkeypatch.setenv("MEMDIVER_API_TOKEN", "tok")
    get_settings.cache_clear()
    with TestClient(create_app()) as exposed:
        assert exposed.get("/api/agent/status").status_code == 401
        ok = exposed.get("/api/agent/status", headers={"Authorization": "Bearer tok"})
        assert ok.status_code == 200


def test_ws_token_is_required_when_configured(env, monkeypatch):
    _write_script(env, monkeypatch, [[{"text": "hi"}]])
    monkeypatch.setenv("MEMDIVER_API_TOKEN", "tok")
    get_settings.cache_clear()
    with TestClient(create_app()) as secured:
        auth = {"Authorization": "Bearer tok"}
        chat_id = secured.post("/api/agent/chats", json={}, headers=auth).json()["chat_id"]
        with secured.websocket_connect(f"/ws/agent/{chat_id}?token=wrong") as ws:
            with pytest.raises(WebSocketDisconnect) as closed:
                ws.receive_json()
        assert closed.value.code == 1008


def test_ws_unknown_chat_sends_error(client):
    with client.websocket_connect("/ws/agent/nope") as ws:
        frame = ws.receive_json()
    assert frame["type"] == "error" and frame["code"] == "unknown_chat"


# -- WebSocket end to end (scripted backend, real MCP child) ----------------------------------


def _read_until(ws, stop) -> list:
    events = []
    while True:
        event = ws.receive_json()
        events.append(event)
        if stop(event):
            return events


def _types(events) -> list:
    return [e["type"] for e in events]


def _ready(ws) -> list:
    """The startup handshake: the backend's and the session's own ``ready``."""
    ready = {"type": "status", "state": "ready"}
    seen: list = []
    while seen.count(ready) < 2:
        seen.append(ws.receive_json())
    return seen


def _annotations(case_dir: str, label: str) -> list:
    entries = annotations_list_result(case_dir, CAP).payload["entries"]
    return [e for e in entries if e.get("label") == label]


def _write_turn(case_dir: str, label: str) -> list:
    return [[
        {"text": "Looking at the case."},
        {"tool": "case_manifest", "input": {"case_dir": case_dir}},
        {"tool": "annotations_add", "input": {
            "case_dir": case_dir, "capture_id": CAP, "kind": "annotation",
            "label": label, "locations": [{"space": "physical", "value": 4096}]}},
        {"text": "[seen] recorded."},
    ]]


def test_ws_end_to_end_approved_write(client, env, monkeypatch):
    case_dir = _make_case(env)
    _write_script(env, monkeypatch, _write_turn(case_dir, "seen"))
    chat = client.post("/api/agent/chats", json={"case_dir": case_dir}).json()
    with client.websocket_connect(chat["ws_path"]) as ws:
        first = _ready(ws)
        assert first[0] == {"type": "status", "state": "starting"}
        ws.send_json({"type": "user_message", "text": "go"})
        events = _read_until(ws, lambda e: e["type"] == "approval_request")
        request = events[-1]
        assert request["tool"] == "annotations_add" and request["scopes"] == ["once", "chat"]
        assert request["access"] == "write"
        assert _annotations(case_dir, "seen") == []  # not run before approval
        ws.send_json({"type": "approval", "id": request["id"], "allow": True, "scope": "chat"})
        events += _read_until(ws, lambda e: e["type"] == "result")

    types = _types(events)
    calls = [(e["name"], e["access"]) for e in events if e["type"] == "tool_call"]
    assert calls == [("case_manifest", "read"), ("annotations_add", "write")]
    results = [e for e in events if e["type"] == "tool_result"]
    assert [r["ok"] for r in results] == [True, True]
    assert types.index("approval_request") < types.index("approval_resolved")
    assert types.index("approval_resolved") < len(types) - 1 - types[::-1].index("tool_result")
    resolved = next(e for e in events if e["type"] == "approval_resolved")
    assert resolved["allowed"] is True and resolved["id"] == request["id"]
    messages = [e["text"] for e in events if e["type"] == "assistant_message"]
    assert messages[-1] == "[seen] recorded." and messages[0] == "Looking at the case."
    assert events[-1]["type"] == "result" and events[-1]["is_error"] is False
    assert len(_annotations(case_dir, "seen")) == 1
    # the chat ended with the socket
    assert chats.get_handle(chat["chat_id"]) is None


def test_ws_denied_write_does_not_run(client, env, monkeypatch):
    case_dir = _make_case(env)
    _write_script(env, monkeypatch, _write_turn(case_dir, "nope"))
    chat = client.post("/api/agent/chats", json={"case_dir": case_dir}).json()
    with client.websocket_connect(chat["ws_path"]) as ws:
        _ready(ws)
        ws.send_json({"type": "user_message", "text": "go"})
        request = _read_until(ws, lambda e: e["type"] == "approval_request")[-1]
        ws.send_json({"type": "approval", "id": request["id"], "allow": False,
                      "message": "analyst said no"})
        events = _read_until(ws, lambda e: e["type"] == "result")
    resolved = next(e for e in events if e["type"] == "approval_resolved")
    assert resolved["allowed"] is False
    last_result = [e for e in events if e["type"] == "tool_result"][-1]
    assert last_result["ok"] is False and "analyst said no" in last_result["summary"]
    assert _annotations(case_dir, "nope") == []


def test_ws_disconnect_closes_chat_and_denies_pending_approval(client, env, monkeypatch):
    case_dir = _make_case(env)
    _write_script(env, monkeypatch, _write_turn(case_dir, "orphan"))
    chat = client.post("/api/agent/chats", json={"case_dir": case_dir}).json()
    handle = chats.get_handle(chat["chat_id"])
    assert handle is not None
    session = handle.session
    with client.websocket_connect(chat["ws_path"]) as ws:
        _ready(ws)
        ws.send_json({"type": "user_message", "text": "go"})
        _read_until(ws, lambda e: e["type"] == "approval_request")
        # leave with the approval still pending
    assert session.closed is True
    assert chats.get_handle(chat["chat_id"]) is None
    assert _annotations(case_dir, "orphan") == []
    assert client.delete(f"/api/agent/chats/{chat['chat_id']}").status_code in (204, 404)


def test_ws_second_connection_is_refused(client, env, monkeypatch):
    _write_script(env, monkeypatch, [[{"text": "hi"}]])
    chat = client.post("/api/agent/chats", json={}).json()
    with client.websocket_connect(chat["ws_path"]) as first:
        _ready(first)
        with client.websocket_connect(chat["ws_path"]) as second:
            frame = second.receive_json()
        assert frame["code"] == "already_attached"


def test_ws_delete_closes_the_socket(client, env, monkeypatch):
    _write_script(env, monkeypatch, [[{"text": "hi"}]])
    chat = client.post("/api/agent/chats", json={}).json()
    with client.websocket_connect(chat["ws_path"]) as ws:
        _ready(ws)
        assert client.delete(f"/api/agent/chats/{chat['chat_id']}").status_code == 204
        tail = []
        with pytest.raises(WebSocketDisconnect):
            while True:
                tail.append(ws.receive_json())
    assert {"type": "status", "state": "closed"} in tail


# -- providers (OpenAI-compatible presets) -----------------------------------------------

PROVIDER_SECRET = "sk-secret-test"


def test_status_lists_providers_without_urls_or_keys(client, monkeypatch, env):
    _write_script(env, monkeypatch, [[{"text": "hi"}]])
    monkeypatch.setenv("DEEPSEEK_API_KEY", PROVIDER_SECRET)
    response = client.get("/api/agent/status")
    body = response.json()
    assert body["provider"] == "anthropic"
    by_id = {p["id"]: p for p in body["providers"]}
    assert by_id["deepseek"]["available"] is True and by_id["openai"]["available"] is False
    assert PROVIDER_SECRET not in response.text and "api.deepseek.com" not in response.text


def test_status_compat_provider_missing_key_names_the_variable(client, monkeypatch):
    monkeypatch.setenv(chats.BACKEND_ENV, "sdk")
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    assert client.put("/api/agent/settings", json={"provider": "deepseek"}).status_code == 200
    response = client.get("/api/agent/status")
    body = response.json()
    assert body["provider"] == "deepseek" and body["available"] is False
    assert body["credentials"] is False
    assert "DEEPSEEK_API_KEY" in body["reason"] and SECRET not in response.text


def test_status_compat_provider_with_key_is_available(client, monkeypatch):
    pytest.importorskip("openai")
    monkeypatch.setenv(chats.BACKEND_ENV, "sdk")
    monkeypatch.setenv("DEEPSEEK_API_KEY", PROVIDER_SECRET)
    client.put("/api/agent/settings", json={"provider": "deepseek"})
    response = client.get("/api/agent/status")
    assert response.json()["available"] is True and response.json()["credentials"] is True
    assert PROVIDER_SECRET not in response.text


def test_status_compat_provider_without_openai_gives_install_hint(client, monkeypatch):
    monkeypatch.setenv(chats.BACKEND_ENV, "sdk")
    client.put("/api/agent/settings", json={"provider": "ollama"})
    real = chats.importlib.util.find_spec
    monkeypatch.setattr(chats.importlib.util, "find_spec",
                        lambda name: None if name == "openai" else real(name))
    body = client.get("/api/agent/status").json()
    assert body["available"] is False and "agent" in body["install_hint"]
    assert body["credentials"] is True  # ollama takes no key


def test_status_scripted_compat_needs_neither_sdk_nor_openai(client, monkeypatch, env):
    _write_script(env, monkeypatch, [[{"text": "hi"}]])
    monkeypatch.setenv(chats.BACKEND_ENV, "scripted-compat")
    monkeypatch.setattr(chats.importlib.util, "find_spec", lambda name: None)
    body = client.get("/api/agent/status").json()
    assert body["available"] is True and body["backend"] == "scripted-compat"


def test_status_scripted_compat_without_script_is_unavailable(client, monkeypatch):
    monkeypatch.setenv(chats.BACKEND_ENV, "scripted-compat")
    body = client.get("/api/agent/status").json()
    assert body["available"] is False and "MEMDIVER_AGENT_SCRIPT" in body["reason"]


def test_custom_provider_without_prices_is_refused(client, monkeypatch):
    """Regression: ``custom`` defaults to prices (0, 0), so max_budget_usd never tripped."""
    pytest.importorskip("openai")
    monkeypatch.setenv(chats.BACKEND_ENV, "sdk")
    monkeypatch.setenv("MEMDIVER_AGENT_OPENAI_BASE_URL", "http://127.0.0.1:9/v1")
    assert client.put("/api/agent/settings",
                      json={"provider": "custom", "model": "m1"}).status_code == 200
    body = client.get("/api/agent/status").json()
    assert body["available"] is False and "'custom' provider" in body["reason"]
    created = client.post("/api/agent/chats", json={})
    assert created.status_code == 409
    assert created.json()["code"] == "agent.prices_required"
    client.put("/api/agent/settings", json={"price_output_per_mtok": 1.0})
    assert client.get("/api/agent/status").json()["available"] is True


@pytest.mark.parametrize("changes", [
    {"base_url": "http://evil.example/v1"}, {"api_key": "sk-x"},
    {"provider": "nope"}, {"tool_set": "huge"}, {"price_input_per_mtok": -1},
])
def test_settings_put_refuses_endpoint_and_bad_provider_fields(client, changes):
    response = client.put("/api/agent/settings", json=changes)
    assert response.status_code == 422
    assert client.get("/api/agent/settings").json()["settings"] == c.AgentSettings().to_dict()


def test_settings_put_provider_switch_resets_model(client):
    body = client.put("/api/agent/settings", json={"provider": "ollama"}).json()
    assert body["settings"]["provider"] == "ollama"
    assert body["settings"]["model"] == "llama3.3"


def _mock_models(monkeypatch, handler) -> list:
    """Route the models client through ``handler``; returns the seen requests."""
    openai = pytest.importorskip("openai")
    import httpx

    from memdiver.api.routers import agent_chat as router_mod

    seen: list = []

    def recorder(request):
        seen.append(request)
        return handler(request)

    def factory(base_url, api_key):
        return openai.AsyncOpenAI(
            base_url=base_url, api_key=api_key, max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(recorder)))

    monkeypatch.setattr(router_mod, "_models_client", factory)
    return seen


def _models_payload(*ids):
    import httpx

    return httpx.Response(200, json={"object": "list", "data": [
        {"id": i, "object": "model", "created": 0, "owned_by": "x"} for i in ids]})


@pytest.mark.parametrize("provider_id", ["nope", "anthropic", "..%2Fetc"])
def test_provider_models_refuses_unknown_and_sdk_ids(client, provider_id):
    response = client.post(f"/api/agent/providers/{provider_id}/models")
    assert 400 <= response.status_code < 500


def test_provider_models_lists_sorted_ids(client, monkeypatch):
    seen = _mock_models(monkeypatch, lambda r: _models_payload("qwen3", "llama3.3"))
    response = client.post("/api/agent/providers/ollama/models")
    assert response.status_code == 200 and response.json() == {"models": ["llama3.3", "qwen3"]}
    assert str(seen[0].url) == "http://127.0.0.1:11434/v1/models"


def test_provider_models_unavailable_names_variable_only(client, monkeypatch):
    seen = _mock_models(monkeypatch, lambda r: _models_payload("x"))
    response = client.post("/api/agent/providers/deepseek/models")
    assert response.status_code == 409 and "DEEPSEEK_API_KEY" in response.text
    assert seen == []


def test_provider_models_sends_key_but_never_echoes_it(client, monkeypatch):
    import httpx

    monkeypatch.setenv("DEEPSEEK_API_KEY", PROVIDER_SECRET)
    seen = _mock_models(monkeypatch, lambda r: httpx.Response(
        401, json={"error": {"message": f"bad key {PROVIDER_SECRET}"}}))
    response = client.post("/api/agent/providers/deepseek/models")
    assert response.status_code == 502
    assert seen[0].headers["authorization"] == f"Bearer {PROVIDER_SECRET}"
    assert PROVIDER_SECRET not in response.text and "deepseek.com" not in response.text


def test_provider_models_unreachable_is_503(client, monkeypatch):
    import httpx

    monkeypatch.setenv("DEEPSEEK_API_KEY", PROVIDER_SECRET)

    def refuse(request):
        raise httpx.ConnectError("connection refused", request=request)

    _mock_models(monkeypatch, refuse)
    response = client.post("/api/agent/providers/deepseek/models")
    assert response.status_code == 503 and "provider_unreachable" in response.text
    assert PROVIDER_SECRET not in response.text


def test_provider_models_cross_site_post_is_refused(client, monkeypatch):
    seen = _mock_models(monkeypatch, lambda r: _models_payload("x"))
    response = client.post("/api/agent/providers/ollama/models",
                           headers={"Origin": "https://evil.example"})
    assert response.status_code == 403 and seen == []
