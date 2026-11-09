"""Heap context for located-key hits (``locate_key(..., allocator=...)``).

Given an OPEN source and the view offsets a secret was found at, report for
each hit the allocator chunk holding it: ``{allocator, chunk_va, chunk_size,
state, offset_in_chunk, role}``, or ``None`` when the hit is outside every
chunk (or its offset has no virtual address). The heap is parsed once per
source through the cached :func:`memdiver.heap.analyze.analyze_heap` facade.

Annotation is soft: a parser failure is logged and every hit reads ``None``;
it never turns a searched dump into an unreadable one.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Sequence, Tuple

logger = logging.getLogger("memdiver.engine.heap_hits")

#: ``allocator`` value that disables hit annotation.
ALLOCATOR_OFF = "off"

#: View a source is searched in when it names none (``RawDumpSource``'s).
_DEFAULT_VIEW = "raw"

HitHeap = Optional[Dict[str, Any]]


def validate_allocator(allocator: str) -> None:
    """Raise ``ValueError`` for an unknown allocator name ("off" is valid)."""
    if allocator == ALLOCATOR_OFF:
        return
    from memdiver.heap.analyze import parse_allocator_hint

    parse_allocator_hint(allocator)


def _role_name(layout: Any, va: int) -> str:
    for _start, _length, role in layout.role_runs(va, va + 1):
        return str(role.name.lower())
    return "none"


def _hit_heap(layout: Any, memory: Any, offset: int, view: str) -> HitHeap:
    va = memory.view_offset_to_va(int(offset), view)
    chunk = layout.chunk_at(va) if va is not None else None
    if chunk is None:
        return None
    hit: Dict[str, Any] = {
        "allocator": layout.allocator.value,
        "chunk_va": int(chunk.va),
        "chunk_size": int(chunk.size),
        "state": chunk.state.value,
        "offset_in_chunk": int(va - chunk.va),
        "role": _role_name(layout, va),
    }
    return {**hit, **_arena_entry(layout, chunk)}


def _arena_entry(layout: Any, chunk: Any) -> Dict[str, str]:
    """``{"arena": kind}`` when the chunk's arena is known, else ``{}``."""
    from memdiver.heap.model import arena_entry

    arena_kind = getattr(layout, "arena_kind", None)
    arena_id = getattr(chunk, "arena_id", None)
    return arena_entry(arena_kind(arena_id) if arena_kind is not None else None)


def heap_hit_annotations(source: Any, offsets: Sequence[int],
                         view: Optional[str], allocator: str) -> Tuple[HitHeap, ...]:
    """One heap dict (or ``None``) per offset in *offsets*, in order."""
    from memdiver.heap.analyze import analyze_heap
    from memdiver.heap.memory import VaMemory

    try:
        layout = analyze_heap(source, allocator)
        memory = VaMemory(source, layout.platform)
        return tuple(_hit_heap(layout, memory, off, view or _DEFAULT_VIEW)
                     for off in offsets)
    except Exception:  # noqa: BLE001 — annotation must never fail the search
        logger.warning("heap annotation of key hits failed", exc_info=True)
        return tuple(None for _ in offsets)
