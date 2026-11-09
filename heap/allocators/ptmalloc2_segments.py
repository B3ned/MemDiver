"""Segment bookkeeping for the boundary-tag (ptmalloc2 / dlmalloc) parsers.

:mod:`.ptmalloc2` walks chunks; this module holds the pieces that turn a
walk into arenas and segments for :class:`~memdiver.heap.segments.LayoutAssembler`
and that do not need the walker's internals:

* :class:`WalkSpan` — which slice of the walked chunks (and how many bytes
  walked / skipped / uncaptured) belongs to one segment;
* :func:`is_fencepost` — glibc's end-of-heap fencepost pattern (defined in
  :mod:`.ptmalloc2_walk`, re-exported here);
* :func:`main_heap_segment` / :func:`main_arena` — arena 0 and its regions;
* :func:`assemble_layout` — the final :class:`~memdiver.heap.model.HeapLayout`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence

from memdiver.heap.allocators.ptmalloc2_walk import is_fencepost
from memdiver.heap.model import (ARENA_MAIN, REGION_MAIN_HEAP, AllocatorKind,
                                 Evidence, FreeList, HeapArena, HeapChunk,
                                 HeapLayout)
from memdiver.heap.platform import MappedRegion, TargetPlatform
from memdiver.heap.segments import HeapSegment, LayoutAssembler

MAIN_ARENA_ID = 0


@dataclass(frozen=True)
class WalkSpan:
    """One walked segment: ``chunks[first:stop]`` plus its byte accounting."""

    segment: HeapSegment
    first: int
    stop: int
    walked: int = 0
    skipped: int = 0
    uncaptured: int = 0
    total: Optional[int] = None  # bytes_total share; None: the segment's size


def main_heap_segment(region: MappedRegion) -> HeapSegment:
    """*region* as a main-arena segment walked from its first byte."""
    return HeapSegment(region.va, region.end, region.va, MAIN_ARENA_ID,
                       REGION_MAIN_HEAP, region.name)


def main_arena(spans: Sequence[WalkSpan], top_slot_va: Optional[int] = None,
               top_chunk_va: Optional[int] = None, va: Optional[int] = None) -> HeapArena:
    """Arena 0 owning every span's segment.

    ``top_slot_va`` is the VA of the arena's ``top`` pointer slot (ptmalloc2:
    ``&main_arena.top``, i.e. ``coverage["main_arena_top_va"]``) when it was
    found; the walked top chunk, when there is one, goes into ``extra``.
    ``va`` is the ``malloc_state`` start when the caller knows the top
    offset (it depends on the glibc version's layout before ``fastbinsY``).
    """
    extra: Dict[str, Any] = {}
    if top_chunk_va is not None:
        extra["top_chunk_va"] = top_chunk_va
    return HeapArena(MAIN_ARENA_ID, ARENA_MAIN, va, top_slot_va,
                     tuple(span.segment.va for span in spans), extra)


def assemble_layout(kind: AllocatorKind, platform: TargetPlatform,
                    arenas: Sequence[HeapArena], spans: Sequence[WalkSpan],
                    chunks: Sequence[HeapChunk], *,
                    free_lists: Sequence[FreeList], diagnostics: Sequence[str],
                    version_hint: str, walk_summary: str,
                    truncated_at: Optional[int],
                    extra_coverage: Mapping[str, Any],
                    evidence: Sequence[Evidence]) -> HeapLayout:
    """Build the layout; the assembler computes the standard coverage keys.

    *walk_summary* becomes the leading ``walk`` evidence, scored with the
    walked share of all bytes (the layout's confidence); *truncated_at* is
    ``max_chunks`` when the walk stopped there, else ``None``.
    """
    asm = LayoutAssembler(kind, platform)
    for arena in arenas:
        asm.add_arena(arena)
    for span in spans:
        asm.add_segment(span.segment, chunks[span.first:span.stop],
                        walked=span.walked, skipped=span.skipped,
                        uncaptured=span.uncaptured, total=span.total)
    for free_list in free_lists:
        asm.add_free_list(free_list)
    for message in diagnostics:
        asm.diagnose(message)
    if truncated_at is not None:
        asm.mark_truncated(truncated_at)
    walk = Evidence("walk", walk_summary, asm.default_confidence())
    return asm.build(version_hint=version_hint, extra_coverage=extra_coverage,
                     extra_evidence=(walk, *evidence))


__all__ = ["MAIN_ARENA_ID", "WalkSpan", "is_fencepost", "main_heap_segment",
           "main_arena", "assemble_layout"]
