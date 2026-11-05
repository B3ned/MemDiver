"""One chat session (client-message router around an AgentBackend) and the registry."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, Mapping, Optional

from .contracts import (
    CLIENT_MESSAGE_TYPES,
    AgentBackend,
    ChatEvent,
    ChatSpec,
    Emit,
    PermissionGate,
)
from .system_prompt import with_scope

logger = logging.getLogger(__name__)

GateFactory = Callable[[Emit], PermissionGate]

#: A graceful backend close longer than this is escalated to ``backend.kill()``.
BACKEND_CLOSE_TIMEOUT_SECONDS = 6.0


class ChatSession:
    """Runs at most one user turn at a time; never lets an exception escape the router."""

    def __init__(self, chat_id: str, backend: AgentBackend, gate_factory: GateFactory,
                 spec: ChatSpec, emit: Emit) -> None:
        self.chat_id = chat_id
        self._backend = backend
        self._spec = spec
        self._emit = emit
        self._gate = gate_factory(emit)
        self._task: Optional["asyncio.Task[None]"] = None
        self._closed = False
        self._close_task: Optional["asyncio.Task[None]"] = None
        self._scope_sent = False

    async def _status(self, state: str) -> None:
        await self._emit(ChatEvent("status", {"state": state}))

    async def _error(self, code: str, message: str) -> None:
        await self._emit(ChatEvent("error", {"code": code, "message": message}))

    async def start(self) -> None:
        await self._status("starting")
        try:
            await self._backend.start(self._spec, self._gate, self._emit)
        except Exception as exc:  # noqa: BLE001 - surfaced as an event, no stack trace
            await self._error("backend_error", str(exc))
            await self.close()
            return
        await self._status("ready")

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def handle_client_message(self, message: Mapping[str, Any]) -> None:
        try:
            kind = message.get("type") if isinstance(message, Mapping) else None
            if kind not in CLIENT_MESSAGE_TYPES:
                await self._error("bad_message", "unknown or malformed message")
            elif kind == "user_message":
                await self._on_user_message(message)
            elif kind == "approval":
                await self._on_approval(message)
            else:
                cancel = getattr(self._gate, "cancel_pending", None)
                if cancel is not None:
                    cancel("interrupted")
                await self._backend.interrupt()
        except Exception as exc:  # noqa: BLE001
            logger.warning("chat %s: message handling failed: %s", self.chat_id, exc)
            await self._error("bad_message", "message could not be handled")

    async def _on_user_message(self, message: Mapping[str, Any]) -> None:
        text = message.get("text")
        if not isinstance(text, str) or not text.strip():
            await self._error("bad_message", "user_message needs non-empty text")
        elif self._closed:
            await self._error("closed", "chat is closed")
        elif self.running:
            await self._error("busy", "a turn is already running")
        else:
            self._task = asyncio.get_running_loop().create_task(
                self._run_turn(self._first_with_scope(text)))

    def _first_with_scope(self, text: str) -> str:
        """The scope note rides each message until one was sent successfully."""
        if self._scope_sent:
            return text
        return with_scope(text, self._spec.scope_note)

    async def _run_turn(self, text: str) -> None:
        await self._status("running")
        try:
            await self._backend.send(text)
            self._scope_sent = True  # only once a send got through without raising
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            await self._error("backend_error", str(exc))
        if not self._closed:
            await self._status("ready")

    async def _on_approval(self, message: Mapping[str, Any]) -> None:
        request_id = message.get("id")
        scope = message.get("scope", "once")
        if not isinstance(request_id, str) or scope not in ("once", "chat") \
                or not self._gate.resolve(request_id, bool(message.get("allow")),
                                          str(message.get("message") or ""), scope):
            await self._error("bad_approval", "unknown or already answered approval id")

    async def wait_idle(self) -> None:
        """Wait for the running turn (if any) to finish."""
        if self._task is not None:
            await asyncio.gather(self._task, return_exceptions=True)

    @property
    def finished(self) -> bool:
        """True once the close ran to completion (backend and its children are gone)."""
        return self._close_task is not None and self._close_task.done()

    async def close(self) -> None:
        """Close once; every caller awaits the SAME run, and cancelling a caller (a dropped
        WebSocket handler) never aborts it: the work lives in its own task."""
        if self._close_task is None:
            self._closed = True
            self._close_task = asyncio.get_running_loop().create_task(self._do_close())
        await asyncio.shield(self._close_task)

    async def _do_close(self) -> None:
        await self._gate.close()
        await self._close_backend()
        if self.running and self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        await self._status("closed")

    async def _close_backend(self) -> None:
        """Graceful backend close, bounded; on timeout/failure escalate to a hard kill."""
        try:
            await asyncio.wait_for(self._backend.close(), BACKEND_CLOSE_TIMEOUT_SECONDS)
            return
        except asyncio.TimeoutError:
            logger.warning("chat %s: backend close timed out; killing it", self.chat_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("chat %s: backend close failed: %s", self.chat_id, exc)
        kill = getattr(self._backend, "kill", None)
        if kill is not None:
            try:
                await kill()
            except Exception as exc:  # noqa: BLE001
                logger.warning("chat %s: backend kill failed: %s", self.chat_id, exc)


class ChatRegistry:
    """Open chats keyed by id, with a concurrency cap and shutdown support."""

    def __init__(self, max_chats: int = 4) -> None:
        self._max = max_chats
        self._chats: Dict[str, ChatSession] = {}

    def create(self, session: ChatSession) -> ChatSession:
        """Register ``session``; ``RuntimeError`` when the cap is reached."""
        self._prune()
        if len(self._chats) >= self._max:
            raise RuntimeError(f"too many open chats (max {self._max})")
        self._chats[session.chat_id] = session
        return session

    def _prune(self) -> None:
        for chat_id in [c for c, s in self._chats.items() if s.finished]:
            del self._chats[chat_id]

    def get(self, chat_id: str) -> Optional[ChatSession]:
        return self._chats.get(chat_id)

    async def close(self, chat_id: str) -> bool:
        """Close ``chat_id``; it stays registered (and so reachable by ``close_all``) until
        its close has COMPLETED."""
        session = self._chats.get(chat_id)
        if session is None:
            return False
        try:
            await session.close()
        finally:
            if session.finished:
                self._chats.pop(chat_id, None)
        return True

    async def close_all(self) -> None:
        """Close every chat concurrently, stragglers (closes already running) included."""
        await asyncio.gather(*(self.close(c) for c in list(self._chats)),
                             return_exceptions=True)
