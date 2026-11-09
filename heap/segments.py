"""Arenas + segments: the shared shape every allocator parser can follow.

A parser works in three steps:

1. **Discover** the allocator's arenas (:class:`~.model.HeapArena`) and the
   contiguous memory segments (:class:`HeapSegment`) each arena owns — the
   main heap, thread heaps, mmapped chunks, size-class regions, groups.
2. **Walk** each segment from its ``walk_start``, producing
   :class:`~.model.HeapChunk` objects, while a :class:`ChunkBudget` enforces
   ``ParseOptions.max_chunks`` the same way for every allocator.
3. **Hand** each segment's chunks to a :class:`LayoutAssembler`, which stamps
   ``arena_id`` onto chunks and regions, accumulates the standard coverage
   keys and builds the final :class:`~.model.HeapLayout`.

Skeleton::

    def parse(memory, ctx, opts):
        asm = LayoutAssembler(AllocatorKind.PTMALLOC2, ctx.platform)
        budget = ChunkBudget(opts.max_chunks)
        for arena, segments in discover(memory, ctx, opts):
            asm.add_arena(arena)
            for seg in segments:
                chunks, walked = walk(memory, seg, budget)
                asm.add_segment(seg, chunks, walked=walked)
        if budget.truncated:
            asm.mark_truncated(budget.max_chunks)
        return asm.build(version_hint="2.35")

Standard coverage keys (``HeapLayout.coverage``): ``regions`` (segment
names, or hex VAs for nameless segments), ``arenas`` (count),
``bytes_total``, ``bytes_walked``, ``bytes_skipped``, ``bytes_uncaptured``,
``chunk_count`` and ``truncated``. Allocator-specific keys passed as
``extra_coverage`` are merged last and may override them.

Truncation: :meth:`LayoutAssembler.mark_truncated` adds the shared
:func:`truncation_diagnostic` once; a parser that already reported that text
while walking (ptmalloc2 does, to keep it in walk order) is not given a copy.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from memdiver.heap.model import (AllocatorKind, Evidence, FreeList, HeapArena,
                                 HeapChunk, HeapLayout, HeapRegion)
from memdiver.heap.platform import TargetPlatform

#: Truncation diagnostic of :meth:`LayoutAssembler.mark_truncated` and
#: ptmalloc2 / dlmalloc (``str.format`` template). Other parsers predating
#: :mod:`.segments` (e.g. mallocng) still word their own.
TRUNCATION_DIAGNOSTIC = "stopped after max_chunks={max_chunks} chunks"


def truncation_diagnostic(max_chunks: Optional[int] = None) -> str:
    """The shared "stopped after max_chunks" diagnostic for *max_chunks*."""
    if max_chunks is None:
        return "stopped after max_chunks chunks"
    return TRUNCATION_DIAGNOSTIC.format(max_chunks=max_chunks)


@dataclass(frozen=True)
class HeapSegment:
    """A contiguous ``[va, end)`` range of one arena, walked from ``walk_start``.

    ``kind`` becomes the recorded :attr:`HeapRegion.kind` (see the
    ``REGION_*`` constants in :mod:`.model`; allocator-specific kinds are
    allowed); ``name`` is the mapping name, when there is one. The recorded
    region keeps ``name`` as is (possibly empty); coverage lists ``label``.
    """

    va: int
    end: int
    walk_start: int
    arena_id: int
    kind: str
    name: str = ""

    @property
    def size(self) -> int:
        return max(0, self.end - self.va)

    @property
    def label(self) -> str:
        """``name`` when set, else the segment's hex VA."""
        return self.name or hex(self.va)


class ChunkBudget:
    """A ``max_chunks`` allowance shared across every segment of one parse."""

    def __init__(self, max_chunks: int):
        self.max_chunks = max_chunks
        self._used = 0
        self.truncated = False

    @property
    def remaining(self) -> int:
        return max(0, self.max_chunks - self._used)

    @property
    def exhausted(self) -> bool:
        return self.remaining == 0

    def take(self, n: int = 1) -> bool:
        """Consume *n* chunks; ``False`` (and ``truncated``) when they don't fit."""
        if n > self.remaining:
            self.truncated = True
            return False
        self._used += n
        return True

    def diagnostic(self) -> str:
        return truncation_diagnostic(self.max_chunks)


class LayoutAssembler:
    """Collects arenas, segments and chunks, then builds one :class:`HeapLayout`."""

    def __init__(self, kind: AllocatorKind,
                 platform: Optional[TargetPlatform] = None):
        self.kind = kind
        self.platform = platform
        self.truncated = False
        self._arenas: List[HeapArena] = []
        self._regions: List[HeapRegion] = []
        self._region_labels: List[str] = []
        self._chunks: List[HeapChunk] = []
        self._free_lists: List[FreeList] = []
        self._evidence: List[Evidence] = []
        self._diagnostics: List[str] = []
        self._bytes = {"total": 0, "walked": 0, "skipped": 0, "uncaptured": 0}

    def add_arena(self, arena: HeapArena) -> None:
        self._arenas.append(arena)

    def add_segment(self, segment: HeapSegment, chunks: Iterable[HeapChunk], *,
                    walked: int = 0, skipped: int = 0, uncaptured: int = 0,
                    total: Optional[int] = None) -> None:
        """Record *segment* as a region and its *chunks*, stamped with its arena.

        *total* is what the segment adds to ``bytes_total`` (default: its
        size), for segments whose accounted bytes are not the whole range.
        """
        self._regions.append(HeapRegion(segment.va, segment.size, segment.name,
                                        segment.kind, segment.arena_id))
        self._region_labels.append(segment.label)
        self._chunks.extend(_stamped(chunk, segment.arena_id) for chunk in chunks)
        self._bytes["total"] += segment.size if total is None else total
        self._bytes["walked"] += walked
        self._bytes["skipped"] += skipped
        self._bytes["uncaptured"] += uncaptured

    def add_free_list(self, free_list: FreeList) -> None:
        self._free_lists.append(free_list)

    def diagnose(self, message: str) -> None:
        self._diagnostics.append(message)

    def evidence(self, evidence: Evidence) -> None:
        self._evidence.append(evidence)

    def mark_truncated(self, max_chunks: Optional[int] = None) -> None:
        """Flag the walk as truncated; the shared diagnostic is added once."""
        self.truncated = True
        message = truncation_diagnostic(max_chunks)
        if message not in self._diagnostics:
            self._diagnostics.append(message)

    def coverage(self) -> Dict[str, Any]:
        """The standard coverage keys for everything added so far."""
        return {
            "regions": list(self._region_labels),
            "arenas": len(self._arenas),
            "bytes_total": self._bytes["total"],
            "bytes_walked": self._bytes["walked"],
            "bytes_skipped": self._bytes["skipped"],
            "bytes_uncaptured": self._bytes["uncaptured"],
            "chunk_count": len(self._chunks),
            "truncated": self.truncated,
        }

    def default_confidence(self) -> float:
        """Walked share of all segment bytes, clamped to ``[0, 1]``."""
        share = self._bytes["walked"] / max(1, self._bytes["total"])
        return min(1.0, max(0.0, share))

    def build(self, *, version_hint: Optional[str] = None,
              confidence: Optional[float] = None,
              extra_coverage: Optional[Mapping[str, Any]] = None,
              extra_evidence: Sequence[Evidence] = ()) -> HeapLayout:
        """The assembled layout; *extra_coverage* overrides standard keys."""
        coverage = {**self.coverage(), **dict(extra_coverage or {})}
        return HeapLayout(
            allocator=self.kind, version_hint=version_hint,
            platform=self.platform, regions=tuple(self._regions),
            chunks=tuple(self._chunks), free_lists=tuple(self._free_lists),
            evidence=tuple(self._evidence) + tuple(extra_evidence),
            confidence=(self.default_confidence() if confidence is None
                        else confidence),
            diagnostics=tuple(self._diagnostics), coverage=coverage,
            arenas=tuple(self._arenas),
        )


def _stamped(chunk: HeapChunk, arena_id: int) -> HeapChunk:
    """*chunk* with ``arena_id`` set, unless the parser already set one."""
    if chunk.arena_id is not None:
        return chunk
    return replace(chunk, arena_id=arena_id)


__all__ = [
    "HeapSegment", "ChunkBudget", "LayoutAssembler",
    "TRUNCATION_DIAGNOSTIC", "truncation_diagnostic",
]
