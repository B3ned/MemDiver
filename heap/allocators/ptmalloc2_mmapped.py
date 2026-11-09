"""glibc ptmalloc2 mmapped chunks: a page-granular scan of anonymous mappings.

Requests above the mmap threshold (128 KiB by default, adjusted dynamically
up to 32 MiB on 64-bit) are served by ``sysmalloc``'s mmap path
(``malloc/malloc.c``)::

    p = (mchunkptr) (mm + correction);
    set_prev_size (p, correction);
    set_head (p, (size - correction) | IS_MMAPPED);

so the chunk header sits ``correction`` bytes (the ``MALLOC_ALIGNMENT``
fix-up, normally 0) past a page-aligned mapping start, its ``prev_size``
holds that ``correction`` and its size word has IS_MMAPPED set with
PREV_INUSE and NON_MAIN_ARENA clear. ``csize + correction`` is the whole,
page-rounded mapping. Freed mmapped chunks are ``munmap``-ed, so every hit
is in use. The kernel may merge adjacent anonymous mappings into one maps
entry, so several chunks can sit back to back in one region.

Validator (header at ``h = page + correction``, ``correction`` one of the
first :data:`MAX_CORRECTION_SLOTS` multiples of the chunk alignment)::

    prev_size == correction            (so % align == 0 and < page)
    size & IS_MMAPPED
    not size & (PREV_INUSE | NON_MAIN_ARENA)
    csize = size & ~7 >= page
    (csize + correction) % page == 0
    h + csize <= region end            (overrunning chunks are rejected)

A hit whose last word was not captured is kept at confidence
:data:`TAIL_UNCAPTURED_CONFIDENCE` instead of :data:`HIT_CONFIDENCE`. After
a hit the scan resumes at the page following the chunk, otherwise at the
next page.

Candidate regions: captured, writable, not file-backed, named ``""`` or
``[anon:X]`` (minus allocator/stack/runtime labels), not claimed by the main
heap walk, not a thread heap and not inside the ``HEAP_MAX_SIZE``
reservation of one, and accepted by ``ParseOptions.selects``.

Coverage decision: a hit counts its whole mapping (``correction + csize``)
as both ``bytes_total`` and ``bytes_walked``; bytes of a scanned region that
hold no chunk are not counted at all. Scanning extra anonymous memory
therefore never lowers the layout's walked-share confidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from memdiver.heap.allocators.ptmalloc2_arenas import (ArenaDiscovery, heap_max_size,
                                                       is_anonymous_writable,
                                                       is_thread_heap_region)
from memdiver.heap.allocators.ptmalloc2_segments import WalkSpan
from memdiver.heap.allocators.ptmalloc2_walk import (_FLAG_BITS, _IS_MMAPPED,
                                                     _NON_MAIN_ARENA, _PAGE,
                                                     _PREV_INUSE, _PagedReader,
                                                     _align_up)
from memdiver.heap.model import (ARENA_MMAP, REGION_MMAPPED_CHUNK, ChunkState,
                                 Evidence, HeapArena, HeapChunk)
from memdiver.heap.platform import MappedRegion
from memdiver.heap.segments import ChunkBudget, HeapSegment

#: ``correction`` values tried per page: ``0, align, ..., (n - 1) * align``.
MAX_CORRECTION_SLOTS = 4
HIT_CONFIDENCE = 0.6
TAIL_UNCAPTURED_CONFIDENCE = 0.45
MMAPPED_BIN = "mmapped"

Range = Tuple[int, int]


@dataclass
class MmapScan:
    """Mmapped chunks found, grouped into one segment per region with hits."""

    arena_id: int
    runs: List[Tuple[HeapSegment, List[HeapChunk]]] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)

    @cached_property
    def chunks(self) -> List[HeapChunk]:
        """Every hit in VA order (read once :attr:`runs` is complete)."""
        return [chunk for _segment, chunks in self.runs for chunk in chunks]

    def spans(self, first_index: int) -> List[WalkSpan]:
        """:class:`WalkSpan` s for the chunks appended at *first_index*."""
        spans, idx = [], first_index
        for segment, chunks in self.runs:
            walked = sum(_mapping_size(chunk) for chunk in chunks)
            spans.append(WalkSpan(segment, idx, idx + len(chunks), walked=walked,
                                  total=walked))
            idx += len(chunks)
        return spans

    def arenas(self) -> List[HeapArena]:
        """The ``mmap`` pseudo arena, only when something was found."""
        count = len(self.chunks)
        if not count:
            return []
        return [HeapArena(self.arena_id, ARENA_MMAP,
                          region_vas=tuple(seg.va for seg, _c in self.runs),
                          extra={"chunks": count})]

    def evidence(self) -> Tuple[Evidence, ...]:
        count = len(self.chunks)
        if not count:
            return ()
        return (Evidence("mmap", f"mmap: {count} mmapped chunks", HIT_CONFIDENCE),)


def _mapping_size(chunk: HeapChunk) -> int:
    return chunk.size + int(chunk.extra.get("prev_size", 0))


# -- candidate regions ---------------------------------------------------------------


def is_candidate_region(region: MappedRegion) -> bool:
    """At least a page of captured, writable, anonymous, unowned memory."""
    return region.size >= _PAGE and is_anonymous_writable(region)


def claimed_ranges(main_regions: Iterable[MappedRegion], threads: ArenaDiscovery,
                   ptr: int) -> List[Range]:
    """Main heap regions plus every discovered thread heap's reservation."""
    hms = heap_max_size(ptr)
    claimed = [(r.va, r.end) for r in main_regions]
    for arena in threads.arenas:
        for heap in arena.heaps:
            base = heap.segment.va & ~(hms - 1)
            claimed.append((base, max(base + hms, heap.segment.end)))
    return claimed


def _overlaps(region: MappedRegion, claimed: Sequence[Range]) -> bool:
    return any(lo < region.end and region.va < hi for lo, hi in claimed)


def _scannable(reader: _PagedReader, region: MappedRegion, claimed: Sequence[Range],
               selects: Callable[[MappedRegion], bool]) -> bool:
    if not is_candidate_region(region) or _overlaps(region, claimed):
        return False
    return selects(region) and not is_thread_heap_region(reader, region, reader.geo.ptr)


# -- the validator --------------------------------------------------------------------


def valid_mmapped_header(prev_size: int, size_word: int, correction: int,
                         align: int) -> bool:
    """The header rules of the module docstring, minus the region-end check."""
    if prev_size != correction or correction % align or correction >= _PAGE:
        return False
    if not size_word & _IS_MMAPPED or size_word & (_PREV_INUSE | _NON_MAIN_ARENA):
        return False
    csize = size_word & ~_FLAG_BITS
    return csize >= _PAGE and (csize + correction) % _PAGE == 0


def _header_at_page(reader: _PagedReader, page_va: int) -> Optional[Tuple[int, int]]:
    """``(correction, size_word)`` of a valid mmapped header at *page_va*."""
    ptr, align = reader.geo.ptr, reader.geo.align
    head = reader.words(page_va, 2 * MAX_CORRECTION_SLOTS)
    if head is None:
        return None
    for slot in range(MAX_CORRECTION_SLOTS):
        correction = slot * align
        prev_size = head[correction // ptr]
        size_word = head[correction // ptr + 1]
        if valid_mmapped_header(prev_size, size_word, correction, align):
            return correction, size_word
    return None


def _chunk(reader: _PagedReader, header: int, correction: int, size_word: int,
           arena_id: int) -> HeapChunk:
    csize, hdr = size_word & ~_FLAG_BITS, reader.geo.header
    tail_captured = reader.word(header + csize - reader.geo.ptr) is not None
    return HeapChunk(
        va=header, size=csize, state=ChunkState.IN_USE, header_len=hdr,
        user_va=header + hdr, user_len=csize - hdr, flags=size_word & _FLAG_BITS,
        bin=MMAPPED_BIN,
        confidence=HIT_CONFIDENCE if tail_captured else TAIL_UNCAPTURED_CONFIDENCE,
        extra={"prev_size": correction, "size_word": size_word, "mmapped": True},
        arena_id=arena_id)


def scan_region(reader: _PagedReader, region: MappedRegion, arena_id: int,
                budget: ChunkBudget) -> List[HeapChunk]:
    """Every mmapped chunk in *region*, page by page, within *budget*."""
    chunks: List[HeapChunk] = []
    page = _align_up(region.va, _PAGE)
    while page + _PAGE <= region.end:
        found = _header_at_page(reader, page)
        if found is not None:
            correction, size_word = found
            header = page + correction
            if header + (size_word & ~_FLAG_BITS) <= region.end:
                if not budget.take():
                    return chunks
                chunk = _chunk(reader, header, correction, size_word, arena_id)
                chunks.append(chunk)
                page = chunk.end
                continue
        page += _PAGE
    return chunks


def _segment(region: MappedRegion, chunks: Sequence[HeapChunk], arena_id: int) -> HeapSegment:
    start = chunks[0].va - int(chunks[0].extra["prev_size"])
    return HeapSegment(start, min(region.end, chunks[-1].end), start, arena_id,
                       REGION_MMAPPED_CHUNK, region.name)


def scan_mmapped_chunks(reader: _PagedReader, regions: Sequence[MappedRegion], *,
                        arena_id: int, budget: ChunkBudget, claimed: Sequence[Range],
                        selects: Callable[[MappedRegion], bool]) -> MmapScan:
    """Scan every candidate region of *regions* for mmapped chunks."""
    runs: List[Tuple[HeapSegment, List[HeapChunk]]] = []
    for region in sorted(regions, key=lambda r: r.va):
        if budget.truncated:
            break
        if not _scannable(reader, region, claimed, selects):
            continue
        chunks = scan_region(reader, region, arena_id, budget)
        if chunks:
            runs.append((_segment(region, chunks, arena_id), chunks))
    return MmapScan(arena_id, runs)


def starts_with_mmapped_chunk(reader: _PagedReader, region: MappedRegion) -> bool:
    """*region* is a candidate whose first page holds a valid mmapped header."""
    if not is_candidate_region(region) or region.va % _PAGE:
        return False
    found = _header_at_page(reader, region.va)
    return found is not None and region.va + found[0] + (found[1] & ~_FLAG_BITS) <= region.end


__all__ = [
    "MAX_CORRECTION_SLOTS", "HIT_CONFIDENCE", "TAIL_UNCAPTURED_CONFIDENCE",
    "MMAPPED_BIN", "MmapScan", "is_candidate_region", "claimed_ranges",
    "valid_mmapped_header", "scan_region", "scan_mmapped_chunks",
    "starts_with_mmapped_chunk",
]
