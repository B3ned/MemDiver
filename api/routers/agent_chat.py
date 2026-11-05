"""In-UI agent chat: REST (status, settings, playbooks, chat lifecycle) + the chat WebSocket.

The chat is a CLIENT of the MemDiver MCP server, not a capability: there is no app-layer
producer here, only wiring (``api/services/agent_chat.py``) around ``app/agent_chat``.
Two routers on purpose: ``router`` (HTTP, carries the read-path policy and the bind
refusal as dependencies) and ``ws_router`` (the WebSocket, which cannot take
``Request``-based dependencies and does its own refusal + token check).
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Response, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from memdiver.api.config import get_settings
from memdiver.api.security import agent_chat_refusal, check_ws_token
from memdiver.api.services import agent_chat as chats
from memdiver.api.services import agent_playbooks
from memdiver.api.user_prefs import read_pref, write_pref
from memdiver.app.agent_chat import contracts as c
from memdiver.app.agent_chat.providers import (
    KIND_OPENAI_COMPAT, PROVIDERS, TOOL_SET_CHOICES, provider_availability,
    provider_public_info, resolve_endpoint)
from memdiver.app.agent_chat.settings_store import load_settings, save_settings
from memdiver.core.install_hints import missing_package_message

logger = logging.getLogger("memdiver.api.routers.agent_chat")

#: ``GET {base_url}/models`` of a provider: bounded so a dead endpoint cannot hang the UI.
MODELS_TIMEOUT_SECONDS = 5.0
MAX_LISTED_MODELS = 500


def _require_safe_bind() -> None:
    reason = agent_chat_refusal(get_settings())
    if reason:
        raise HTTPException(status_code=403, detail=reason)


router = APIRouter(dependencies=[Depends(_require_safe_bind)])
ws_router = APIRouter()


class ChatRequest(BaseModel):
    case_dir: Optional[str] = None
    dump_paths: List[str] = Field(default_factory=list)


class RenderRequest(BaseModel):
    args: Dict[str, Any] = Field(default_factory=dict)


# -- status / settings -------------------------------------------------------------------


@router.get("/api/agent/status")
def get_agent_status() -> dict:
    return chats.agent_status()


def _settings_body() -> dict:
    settings, warning = load_settings(read_pref)
    return {
        "settings": settings.to_dict(),
        "defaults": c.AgentSettings().to_dict(),
        "limits": {name: list(bounds) for name, bounds in c.LIMITS.items()},
        "choices": {
            "model": list(c.MODEL_CHOICES), "effort": list(c.EFFORT_CHOICES),
            "provider": list(c.PROVIDER_CHOICES),
            "providers": [provider_public_info(p, os.environ) for p in PROVIDERS.values()],
            "tool_set": list(TOOL_SET_CHOICES),
        },
        "warning": warning,
    }


@router.get("/api/agent/settings")
def get_agent_settings() -> dict:
    return _settings_body()


@router.put("/api/agent/settings")
def put_agent_settings(changes: Dict[str, Any]) -> dict:
    current, _ = load_settings(read_pref)
    try:
        save_settings(write_pref, changes, current)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _settings_body()


# -- provider models ---------------------------------------------------------------------


def _models_client(base_url: str, api_key: str) -> Any:
    """The OpenAI-compatible client of the models listing (tests swap this factory)."""
    from openai import AsyncOpenAI

    return AsyncOpenAI(base_url=base_url, api_key=api_key,
                       timeout=MODELS_TIMEOUT_SECONDS, max_retries=0)


def _compat_endpoint(provider_id: str) -> Tuple[str, str]:
    """``(base_url, api_key)`` of a known, available OpenAI-compatible preset, else 4xx."""
    preset = PROVIDERS.get(provider_id)
    if preset is None or preset.kind != KIND_OPENAI_COMPAT:
        raise HTTPException(status_code=404,
                            detail="unknown OpenAI-compatible provider")
    available, reason = provider_availability(preset, os.environ)
    if not available:
        raise HTTPException(status_code=409, detail=reason)
    return resolve_endpoint(preset, os.environ)


async def _list_model_ids(base_url: str, api_key: str) -> List[str]:
    import openai

    client = _models_client(base_url, api_key)
    try:
        page = await client.models.list()
        return sorted({str(m.id) for m in page.data})[:MAX_LISTED_MODELS]
    except openai.APIConnectionError as exc:  # includes timeouts
        raise HTTPException(status_code=503, detail={
            "code": "provider_unreachable",
            "message": "the provider did not answer"}) from exc
    except openai.APIStatusError as exc:
        status = exc.status_code
        message = ("the provider refused the API key" if status in (401, 403)
                   else f"the provider answered HTTP {status}")
        raise HTTPException(status_code=502, detail={
            "code": "provider_error", "message": message}) from exc
    finally:
        await client.close()


@router.post("/api/agent/providers/{provider_id}/models")
async def list_provider_models(provider_id: str) -> dict:
    """Model ids the provider serves. A POST so the cross-site guard covers it (it makes a
    key-bearing outbound call); the key and base URL never appear in the answer."""
    base_url, api_key = _compat_endpoint(provider_id)
    if importlib.util.find_spec("openai") is None:
        raise HTTPException(status_code=503, detail={
            "code": "agent.unavailable",
            "message": missing_package_message("openai", "agent")})
    return {"models": await _list_model_ids(base_url, api_key)}


# -- playbooks ------------------------------------------------------------------------------


@router.get("/api/agent/playbooks")
def get_playbooks() -> list:
    return agent_playbooks.list_playbooks()


@router.post("/api/agent/playbooks/{name}/render")
def render_playbook(name: str, req: RenderRequest) -> dict:
    try:
        return {"text": agent_playbooks.render_playbook(name, req.args)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"unknown playbook '{name}'") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# -- chat lifecycle ----------------------------------------------------------------------------


@router.post("/api/agent/chats")
async def create_chat(req: ChatRequest) -> dict:
    try:
        return await chats.create_chat(req.case_dir, req.dump_paths)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc


@router.delete("/api/agent/chats/{chat_id}", status_code=204)
async def delete_chat(chat_id: str) -> Response:
    if not await chats.close_chat(chat_id):
        raise HTTPException(status_code=404, detail="unknown chat")
    return Response(status_code=204)


# -- WebSocket ---------------------------------------------------------------------------------


async def _pump(websocket: WebSocket, handle: chats.ChatHandle) -> None:
    """Forward the chat's events to the browser; close the socket once the chat closed."""
    while True:
        event = await handle.queue.get()
        await websocket.send_json(event.to_dict())
        if event.type == "status" and event.data.get("state") == "closed":
            await websocket.close()
            return


async def _receive(websocket: WebSocket, handle: chats.ChatHandle,
                   started: "asyncio.Task[None]") -> None:
    """Route browser messages to the session until the browser goes away."""
    try:
        while True:
            raw = await websocket.receive_text()
            if not started.done():
                await asyncio.shield(started)
            try:
                message = json.loads(raw)
            except ValueError:
                message = {}
            await handle.session.handle_client_message(message)
    except WebSocketDisconnect:
        return


async def _reject_ws(websocket: WebSocket, code: str, message: str) -> None:
    await websocket.send_json({"type": "error", "code": code, "message": message})
    await websocket.close()


@ws_router.websocket("/ws/agent/{chat_id}")
async def ws_agent_chat(websocket: WebSocket, chat_id: str, token: str | None = None) -> None:
    """Stream one chat. Auth: ``?token=`` exactly like ``/ws/tasks`` (1008 on mismatch)."""
    settings = get_settings()
    if agent_chat_refusal(settings):
        await websocket.close(code=1008)  # before accept: the handshake answers 403
        return
    await websocket.accept()
    if settings.api_token and not check_ws_token(settings.api_token, token):
        await websocket.close(code=1008)
        return
    handle = chats.get_handle(chat_id)
    if handle is None:
        await _reject_ws(websocket, "unknown_chat", "unknown or closed chat")
        return
    if handle.attached:
        await _reject_ws(websocket, "already_attached", "this chat already has a connection")
        return
    handle.attached = True
    pump = asyncio.create_task(_pump(websocket, handle))
    started = asyncio.create_task(handle.session.start())
    receiver = asyncio.create_task(_receive(websocket, handle, started))
    tasks = (pump, started, receiver)
    try:
        await asyncio.wait({pump, receiver}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        # Disconnect (or a server-side close) ends the chat: pending approvals are denied.
        # The close runs as its own task and is shielded: this handler is routinely being
        # CANCELLED here (dropped socket), which must not abort the close and leak the MCP child.
        closing = asyncio.ensure_future(chats.close_chat(chat_id))
        try:
            await asyncio.shield(closing)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
