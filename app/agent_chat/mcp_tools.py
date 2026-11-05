"""A minimal MCP stdio client for the MemDiver tool server (no Claude SDK import).

:class:`McpToolClient` owns ONE ``mcp`` stdio client session in ONE asyncio task: anyio
cancel scopes must exit in the task that entered them, so every request (tool listing,
tool call) is queued to that worker task rather than run on the caller's task.

Used by the scripted CLI transport (tool execution for the scripted demo) and reusable by
any backend that drives the MCP server itself.

Known limit: an interrupt that abandons an awaiting ``call`` does NOT stop the tool in the
child -- the tool keeps running there and its result is simply dropped. Only ``kill`` (or
``close``) ends the child.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

_CLOSE_TIMEOUT = 10.0

#: ``(name, description, input_schema)`` of one MCP tool.
ToolInfo = Tuple[str, str, Dict[str, Any]]
_Request = Callable[[Any], Awaitable[Any]]


def load_script(path: str) -> Dict[str, Any]:
    """Read and minimally validate a script file."""
    script = json.loads(Path(path).read_text(encoding="utf-8"))
    turns = script.get("turns") if isinstance(script, dict) else None
    if not isinstance(turns, list) or not all(isinstance(t, list) for t in turns):
        raise ValueError('script must be {"turns": [[step, ...], ...]}')
    return script


def _tool_info(tool: Any) -> ToolInfo:
    """``(name, description, schema)``; mcp 2.x names the schema ``input_schema``."""
    schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None) or {}
    return str(tool.name), str(getattr(tool, "description", None) or ""), dict(schema)


class McpToolClient:
    """Owns the MCP stdio client in ONE task (anyio scopes must exit where they entered).

    ``server`` is a stdio server dict: ``command``, optional ``args``/``env``/``cwd``.
    The child starts on ``start()`` or lazily on the first request.
    """

    def __init__(self, server: Dict[str, Any]) -> None:
        self._server = server
        self._queue: "asyncio.Queue[Any]" = asyncio.Queue()
        self._task: Optional["asyncio.Task[None]"] = None
        self._ready: "asyncio.Future[None]" = asyncio.get_running_loop().create_future()

    async def start(self) -> None:
        """Start the child and initialize the session (idempotent)."""
        if self._task is None:
            self._task = asyncio.create_task(self._run())
        await self._ready

    async def call(self, name: str, arguments: Dict[str, Any]) -> Tuple[str, bool]:
        """``(text, is_error)`` of one real tool call."""
        return await self._request(lambda session: self._call_tool(session, name, arguments))

    async def list_tools(self) -> List[ToolInfo]:
        """Every tool the server offers, as ``(name, description, input_schema)``."""
        return await self._request(self._list_tools)

    async def close(self) -> None:
        """Graceful stop: drain the queue, exit the session; cancel if that hangs."""
        if self._task is None:
            return
        await self._queue.put(None)
        try:
            await asyncio.wait_for(self._task, _CLOSE_TIMEOUT)
        except (asyncio.TimeoutError, Exception):
            self._task.cancel()

    async def kill(self) -> None:
        """Hard stop: cancel the worker task and wait for it (``stdio_client`` reaps the
        child on cancel). Safe to call repeatedly or when never started."""
        task = self._task
        if task is None:
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        if not self._ready.done():
            self._ready.set_exception(RuntimeError("MCP client was killed"))
            self._ready.exception()  # mark retrieved: nobody may be awaiting it

    async def _request(self, request: _Request) -> Any:
        await self.start()
        future: "asyncio.Future[Any]" = asyncio.get_running_loop().create_future()
        await self._queue.put((request, future))
        return await future

    async def _run(self) -> None:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        params = StdioServerParameters(
            command=self._server["command"], args=list(self._server.get("args", [])),
            env=self._server.get("env") or None, cwd=self._server.get("cwd") or None)
        try:
            async with AsyncExitStack() as stack:
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                self._ready.set_result(None)
                while (item := await self._queue.get()) is not None:
                    await self._serve(session, *item)
        except Exception as exc:  # startup failure: unblock waiters
            if not self._ready.done():
                self._ready.set_exception(exc)

    @staticmethod
    async def _serve(session: Any, request: _Request, future: "asyncio.Future[Any]") -> None:
        """Run one queued request; its failure goes to its caller, not the worker."""
        try:
            result = await request(session)
        except Exception as exc:
            if not future.done():
                future.set_exception(exc)
            return
        if not future.done():
            future.set_result(result)

    @staticmethod
    async def _call_tool(session: Any, name: str,
                         arguments: Dict[str, Any]) -> Tuple[str, bool]:
        try:
            result = await session.call_tool(name, arguments)
            text = "".join(getattr(b, "text", "") for b in result.content)
            is_error = bool(getattr(result, "is_error", getattr(result, "isError", False)))
            return text, is_error
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}", True

    @staticmethod
    async def _list_tools(session: Any) -> List[ToolInfo]:
        tools: List[ToolInfo] = []
        cursor: Optional[str] = None
        while True:
            params = None
            if cursor:
                from mcp import types

                params = types.PaginatedRequestParams(cursor=cursor)
            page = await session.list_tools(params=params)
            tools.extend(_tool_info(t) for t in page.tools)
            cursor = getattr(page, "next_cursor", None) or getattr(page, "nextCursor", None)
            if not cursor:
                return tools
