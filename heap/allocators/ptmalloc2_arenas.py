"""glibc ptmalloc2 non-main (thread) arena discovery.

A thread arena is a ``malloc_state`` living at the start of its first heap
mapping, right after that heap's ``heap_info``. Every non-main heap is an
mmap aligned to ``HEAP_MAX_SIZE`` (``2 * DEFAULT_MMAP_THRESHOLD_MAX``: 64 MiB
on 64-bit, 1 MiB on 32-bit) and starts with ``heap_info { ar_ptr, prev,
size, mprotect_size [, pagesize (glibc >= 2.35)] }`` padded to
``MALLOC_ALIGNMENT``. Chunks of a heap other than an arena's first one begin
right after ``heap_info``; in the first heap they begin after
``malloc_state`` (realigned so the user pointer is aligned).

``struct malloc_state``: ``mutex``, ``flags``, [``have_fastchunks``, glibc >=
2.27], ``fastbinsY[NFASTBINS]``, ``top``, ``last_remainder``,
``bins[2 * NBINS - 2]``, ``binmap[4]`` (uint32), ``next``, ``next_free``,
``attached_threads``, ``system_mem``, ``max_system_mem``. Measured from the
``top`` field: ``bins[0]`` is at ``+2 * ptr`` and ``next`` at
``+256 * ptr + 16`` (``top`` + ``last_remainder`` + 254 bin words + 16
bytes of binmap). ``top_off`` is the offset of ``top`` inside the struct.

Discovery, in order of preference:

* **ring** -- ``main_arena.next`` -> arena 1 -> ... -> ``&main_arena`` (all
  ``malloc_state`` base addresses). ``top_off`` is learnt as the candidate
  offset for which the ring closes exactly at ``&main_arena.top - top_off``.
  Each ring arena's heap is ``top & ~(HEAP_MAX_SIZE - 1)``; older heaps are
  reached through ``heap_info.prev``. Every ``heap_info`` must name the
  arena (``ar_ptr``).
* **heap_info scan** -- when ``main_arena`` (and hence the ring) is not
  available: captured anonymous writable regions aligned to
  ``HEAP_MAX_SIZE`` whose first words form a valid ``heap_info`` and whose
  first chunks form a plausible boundary-tag chain, grouped by ``ar_ptr``.
  ``top_off`` is unknown, so the arenas' bins are not decoded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import (Callable, Dict, Iterable, List, Optional, Protocol, Sequence,
                    Tuple)

from memdiver.heap.allocators.ptmalloc2_bins import _nfastbins
from memdiver.heap.allocators.ptmalloc2_walk import (_FLAG_BITS, _NON_MAIN_ARENA, _PAGE,
                                                     _PTMALLOC2, _Geometry, _header_word,
                                                     _PagedReader)
from memdiver.heap.model import (ARENA_THREAD, REGION_THREAD_HEAP, Evidence,
                                 HeapArena)
from memdiver.heap.platform import MappedRegion
from memdiver.heap.segments import HeapSegment
from memdiver.msl.region_names import anon_label, classify_mapping_name

MAX_ARENAS = 1024
MAX_HEAPS_PER_ARENA = 1024
#: Largest ``top_off`` tried while closing the ring.
MAX_TOP_OFF = 0x100
#: How far past the ``malloc_state`` estimate the first chunk is searched.
FIRST_CHUNK_SEARCH = 0x100
#: Consecutive plausible headers (or reaching the heap end) that make a start.
CHAIN_PROBE = 3

DISCOVERY_RING = "ring"
DISCOVERY_SCAN = "heap_info_scan"
SCAN_DIAGNOSTIC = ("thread arenas found via heap_info scan; bins not decoded "
                   "(main_arena unavailable)")

#: glibc >= 2.39 names its own mappings ``[anon: glibc: malloc arena]`` /
#: ``[anon: glibc: malloc]`` (tunable ``glibc.mem.decorate_maps``).
_GLIBC_ANON_LABEL = " glibc: "


class WordReader(Protocol):
    def word(self, va: int) -> Optional[int]: ...


# -- geometry -------------------------------------------------------------------------


def heap_max_size(ptr: int) -> int:
    """``HEAP_MAX_SIZE``: 64 MiB on 64-bit, 1 MiB on 32-bit."""
    return (64 << 20) if ptr == 8 else (1 << 20)


def heap_info_sizes(geo: _Geometry) -> Tuple[int, int]:
    """``sizeof(heap_info)`` before / since glibc 2.35 (``pagesize`` added)."""
    return geo.align_up(4 * geo.ptr), geo.align_up(5 * geo.ptr)


def next_offset(ptr: int) -> int:
    """Offset of ``malloc_state.next`` from ``malloc_state.top``."""
    return 256 * ptr + 16


def malloc_state_size(top_off: int, ptr: int) -> int:
    """``sizeof(struct malloc_state)`` for a struct whose ``top`` is at *top_off*."""
    return top_off + next_offset(ptr) + 5 * ptr


def min_top_off(geo: _Geometry) -> int:
    """Smallest ``top_off`` (no ``have_fastchunks``): mutex, flags, fastbinsY."""
    return 8 + _nfastbins(geo) * geo.ptr


# -- heap_info ------------------------------------------------------------------------


@dataclass(frozen=True)
class HeapInfo:
    """A validated ``heap_info`` header at ``va``."""

    va: int
    ar_ptr: int
    prev: int
    size: int
    mprotect_size: int

    @property
    def end(self) -> int:
        return self.va + self.size

    def hosts(self, va: int) -> bool:
        return self.va < va < self.end


def heap_info_at(reader: WordReader, va: int, ptr: int,
                 page: int = _PAGE) -> Optional[HeapInfo]:
    """The ``heap_info`` at *va* when every field is plausible, else ``None``."""
    hms = heap_max_size(ptr)
    if va % hms:
        return None
    words = [reader.word(va + i * ptr) for i in range(4)]
    if any(w is None for w in words):
        return None
    ar_ptr, prev, size, mprotect = (int(w or 0) for w in words)
    if not (0 < size <= hms and size % page == 0):
        return None
    if not (size <= mprotect <= hms and mprotect % page == 0):
        return None
    if prev and (prev % hms or prev == va):
        return None
    if not ar_ptr or ar_ptr % ptr or reader.word(ar_ptr) is None:
        return None
    return HeapInfo(va, ar_ptr, prev, size, mprotect)


def is_anonymous_name(name: str) -> bool:
    """``""`` or ``[anon:X]`` naming no other allocator, stack or runtime.

    ``X`` is rejected when :func:`~memdiver.msl.region_names.classify_mapping_name`
    gives it a category (scudo, jemalloc, ``*malloc*``, dalvik, stacks, ...),
    except glibc's own decorated labels; ``[anon_shmem:X]`` is shared memory.
    """
    if not name:
        return True
    label = anon_label(name) if name.startswith("[anon:") else None
    if label is None:
        return False
    return label.startswith(_GLIBC_ANON_LABEL) or classify_mapping_name(name) is None


def is_anonymous_writable(region: MappedRegion) -> bool:
    """Captured, writable, not file-backed and :func:`is_anonymous_name`."""
    return (region.captured and "w" in region.perms and not region.module_path
            and is_anonymous_name(region.name))


def thread_heap_info(reader: WordReader, region: MappedRegion,
                     ptr: int) -> Optional[HeapInfo]:
    """The ``heap_info`` starting the anonymous writable *region*, else ``None``."""
    if not is_anonymous_writable(region):
        return None
    return heap_info_at(reader, region.va, ptr)


def is_thread_heap_region(reader: WordReader, region: MappedRegion, ptr: int) -> bool:
    """*region* is an anonymous mapping that starts with a valid ``heap_info``."""
    return thread_heap_info(reader, region, ptr) is not None


# -- the arena ring -------------------------------------------------------------------


def ring_arenas(reader: WordReader, main_top_slot: int, ptr: int,
                libc_regions: Sequence[MappedRegion]
                ) -> Tuple[Optional[int], List[int], List[str]]:
    """``(top_off, thread arena bases, diagnostics)`` from ``main_arena.next``.

    ``top_off`` is ``None`` when the ring is absent (``next`` null or
    unreadable: quietly) or does not close back to ``main_arena`` (with a
    diagnostic). Guards: at most :data:`MAX_ARENAS` arenas, no repeated
    node, every pointer readable and word-aligned.
    """
    first = reader.word(main_top_slot + next_offset(ptr))
    if not first:
        return None, [], []
    home = next((r for r in libc_regions if r.va <= main_top_slot < r.end), None)
    for top_off in range(ptr, MAX_TOP_OFF + 1, ptr):
        main_base = main_top_slot - top_off
        if home is not None and main_base < home.va:
            break
        ring = _follow_ring(reader, first, main_base, top_off, ptr)
        if ring is not None:
            return top_off, ring, []
    return None, [], [
        f"arena ring from main_arena.next ({first:#x}) does not lead back to "
        f"main_arena (cycle, invalid pointer or more than {MAX_ARENAS} arenas); "
        "thread arenas not decoded from the ring"]


def _follow_ring(reader: WordReader, first: int, main_base: int, top_off: int,
                 ptr: int) -> Optional[List[int]]:
    """Thread arena bases from *first* until *main_base*, or ``None`` if broken."""
    arenas: List[int] = []
    seen = set()
    node: Optional[int] = first
    while node != main_base:
        if not node or node % ptr or node in seen or len(arenas) >= MAX_ARENAS:
            return None
        arenas.append(node)
        seen.add(node)
        node = reader.word(node + top_off + next_offset(ptr))
    return arenas


# -- per-arena heaps ------------------------------------------------------------------


@dataclass(frozen=True)
class ThreadHeap:
    """One heap of a thread arena; ``holds_arena``: hosts its ``malloc_state``."""

    info: HeapInfo
    segment: HeapSegment
    holds_arena: bool


@dataclass
class ThreadArena:
    """A discovered thread arena (``base`` = its ``malloc_state``)."""

    arena_id: int
    base: int
    top_slot: Optional[int]
    top_chunk_va: Optional[int]
    heaps: List[ThreadHeap]

    @property
    def first_heap(self) -> Optional[ThreadHeap]:
        return next((h for h in self.heaps if h.holds_arena), None)


@dataclass
class ArenaDiscovery:
    """Every thread arena found, how, and what went wrong on the way."""

    arenas: List[ThreadArena] = field(default_factory=list)
    method: Optional[str] = None
    top_off: Optional[int] = None
    diagnostics: List[str] = field(default_factory=list)


@dataclass
class _Found:
    base: int
    top_slot: Optional[int]
    top_chunk_va: Optional[int]
    heaps: List[Tuple[HeapInfo, int, bool]]      # (info, walk_start, holds_arena)


def _chain_ok(reader: _PagedReader, va: int, end: int, geo: _Geometry) -> bool:
    """:data:`CHAIN_PROBE` plausible headers from *va*, or reaching *end*."""
    for _ in range(CHAIN_PROBE):
        if va == end:
            return True
        word = _header_word(reader, va, end, geo, _PTMALLOC2)
        if word is None:
            return False
        va += word & ~_FLAG_BITS
    return True


def _first_chunk(reader: _PagedReader, lo: int, end: int, geo: _Geometry) -> Optional[int]:
    """First aligned VA in ``[lo, lo + FIRST_CHUNK_SEARCH)`` that starts a chain."""
    va = geo.align_up(lo)
    while va < min(end, lo + FIRST_CHUNK_SEARCH):
        if _chain_ok(reader, va, end, geo):
            return va
        va += geo.align
    return None


def _subheap_start(reader: _PagedReader, info: HeapInfo, header: Optional[int],
                   geo: _Geometry) -> Optional[int]:
    sizes = (header,) if header is not None else heap_info_sizes(geo)
    return next((info.va + s for s in sizes
                 if _chain_ok(reader, info.va + s, info.end, geo)), None)


def _heap_starts(reader: _PagedReader, base: int, top_off: Optional[int],
                 infos: Sequence[HeapInfo], geo: _Geometry, strict: bool,
                 diagnostics: List[str]) -> List[Tuple[HeapInfo, int, bool]]:
    """``(info, walk_start, holds_arena)`` per heap; *strict* drops unprovable heaps."""
    host = next((i for i in infos if i.prev == 0 and i.hosts(base)), None)
    header = None if host is None else base - host.va
    out: List[Tuple[HeapInfo, int, bool]] = []
    for info in infos:
        if info is host:
            lo = base + malloc_state_size(min_top_off(geo) if top_off is None else top_off,
                                          geo.ptr)
            start = _first_chunk(reader, lo, info.end, geo)
            fallback = geo.align_up(lo)
        else:
            start = _subheap_start(reader, info, header, geo)
            fallback = info.va + (header or heap_info_sizes(geo)[0])
        if start is None and strict:
            continue
        if start is None:
            diagnostics.append(f"thread heap {info.va:#x}: no plausible first chunk; "
                               f"walking from {fallback:#x}")
        out.append((info, fallback if start is None else start, info is host))
    return out


def _heap_chain(reader: WordReader, va: int, base: int, ptr: int,
                diagnostics: List[str]) -> List[HeapInfo]:
    """Heaps of the arena at *base*, newest (*va*) first, following ``prev``."""
    chain: List[HeapInfo] = []
    seen = set()
    while va and len(chain) < MAX_HEAPS_PER_ARENA:
        if va in seen:
            diagnostics.append(f"thread arena {base:#x}: heap_info.prev cycle at {va:#x}")
            break
        info = heap_info_at(reader, va, ptr)
        if info is None or info.ar_ptr != base:
            diagnostics.append(f"thread arena {base:#x}: no valid heap_info naming it "
                               f"at {va:#x}")
            break
        chain.append(info)
        seen.add(va)
        va = info.prev
    return chain


def _ring_arena(reader: _PagedReader, base: int, top_off: int, geo: _Geometry,
                diagnostics: List[str]) -> Optional[_Found]:
    top_slot = base + top_off
    top_chunk = reader.word(top_slot)
    if not top_chunk:
        diagnostics.append(f"thread arena {base:#x}: top pointer unreadable or null")
        return None
    chain = _heap_chain(reader, top_chunk & ~(heap_max_size(geo.ptr) - 1), base, geo.ptr,
                        diagnostics)
    if not chain:
        return None
    heaps = _heap_starts(reader, base, top_off, chain[::-1], geo, False, diagnostics)
    return _Found(base, top_slot, top_chunk, heaps)


def scan_heap_infos(reader: _PagedReader, regions: Sequence[MappedRegion],
                    geo: _Geometry) -> List[_Found]:
    """Thread arenas from ``HEAP_MAX_SIZE``-aligned anonymous regions (no ring)."""
    groups: Dict[int, List[HeapInfo]] = {}
    for region in regions:
        info = thread_heap_info(reader, region, geo.ptr)
        if info is not None:
            groups.setdefault(info.ar_ptr, []).append(info)
    found = []
    for base in sorted(groups):
        infos = sorted(groups[base], key=lambda i: (not i.hosts(base), i.va))
        heaps = _heap_starts(reader, base, None, infos, geo, True, [])
        if heaps:
            found.append(_Found(base, None, None, heaps))
    return found


# -- discovery ------------------------------------------------------------------------


def _region_at(regions: Sequence[MappedRegion], va: int) -> Optional[MappedRegion]:
    return next((r for r in regions if r.captured and r.va <= va < r.end), None)


def _assign(found: Sequence[_Found], regions: Sequence[MappedRegion],
            selects: Callable[[MappedRegion], bool]) -> List[ThreadArena]:
    """Number the arenas 1..n, keeping only heaps whose region *selects* accepts."""
    arenas: List[ThreadArena] = []
    for item in found:
        arena_id = len(arenas) + 1
        heaps = []
        for info, start, holds in item.heaps:
            region = _region_at(regions, info.va)
            if region is None or not selects(region):
                continue
            segment = HeapSegment(info.va, info.end, start, arena_id,
                                  REGION_THREAD_HEAP, region.name)
            heaps.append(ThreadHeap(info, segment, holds))
        if heaps:
            arenas.append(ThreadArena(arena_id, item.base, item.top_slot,
                                      item.top_chunk_va, heaps))
    return arenas


def discover_thread_arenas(reader: _PagedReader, geo: _Geometry,
                           regions: Sequence[MappedRegion], *,
                           main_top_slot: Optional[int],
                           libc_regions: Sequence[MappedRegion],
                           selects: Callable[[MappedRegion], bool]) -> ArenaDiscovery:
    """Thread arenas via the ring when ``main_arena`` is known, else a scan."""
    result = ArenaDiscovery()
    if main_top_slot is not None:
        top_off, bases, diagnostics = ring_arenas(reader, main_top_slot, geo.ptr,
                                                  libc_regions)
        result.diagnostics.extend(diagnostics)
        if top_off is not None:
            found = [f for f in (_ring_arena(reader, b, top_off, geo, result.diagnostics)
                                 for b in bases) if f]
            result.top_off, result.method = top_off, DISCOVERY_RING
            result.arenas = _assign(found, regions, selects)
            return result
    result.arenas = _assign(scan_heap_infos(reader, regions, geo), regions, selects)
    if result.arenas:
        result.method = DISCOVERY_SCAN
        result.diagnostics.append(SCAN_DIAGNOSTIC)
    return result


# -- layout pieces --------------------------------------------------------------------


def thread_heap_arena(reader: WordReader, arena: ThreadArena, ptr: int,
                      walked_top: Optional[int], discovery: Optional[str]) -> HeapArena:
    """The :class:`HeapArena` record of *arena* (``top_va`` = ``&arena.top``).

    *discovery* is :attr:`ArenaDiscovery.method` of the run that found it.
    """
    extra: Dict[str, object] = {"heaps": len(arena.heaps), "discovery": discovery}
    top_chunk = arena.top_chunk_va if arena.top_chunk_va is not None else walked_top
    if top_chunk is not None:
        extra["top_chunk_va"] = top_chunk
    if arena.top_slot is not None:
        system_mem = reader.word(arena.top_slot + next_offset(ptr) + 3 * ptr)
        if system_mem is not None:
            extra["system_mem"] = system_mem
    return HeapArena(arena.arena_id, ARENA_THREAD, arena.base, arena.top_slot,
                     tuple(h.segment.va for h in arena.heaps), extra)


def arena_flag_check(flags: Iterable[Tuple[int, bool]]
                     ) -> Tuple[Optional[Evidence], Optional[str]]:
    """Evidence (and a mismatch diagnostic) from ``(size flags, in thread arena)``.

    Main-arena chunks must have NON_MAIN_ARENA clear, thread-arena chunks set.
    """
    pairs = list(flags)
    if not pairs:
        return None, None
    matched = sum(bool(f & _NON_MAIN_ARENA) == thread for f, thread in pairs)
    evidence = Evidence("arena_flags", f"{matched}/{len(pairs)} chunks carry the "
                        "NON_MAIN_ARENA flag their arena implies", matched / len(pairs))
    if matched == len(pairs):
        return evidence, None
    return evidence, (f"{len(pairs) - matched} chunk(s) whose NON_MAIN_ARENA flag "
                      "disagrees with their arena (main: clear, thread: set)")


__all__ = [
    "HeapInfo", "ThreadHeap", "ThreadArena", "ArenaDiscovery",
    "DISCOVERY_RING", "DISCOVERY_SCAN", "SCAN_DIAGNOSTIC",
    "heap_max_size", "heap_info_sizes", "next_offset", "malloc_state_size",
    "min_top_off", "heap_info_at", "is_anonymous_name", "is_anonymous_writable",
    "thread_heap_info", "is_thread_heap_region", "ring_arenas",
    "scan_heap_infos", "discover_thread_arenas", "thread_heap_arena",
    "arena_flag_check",
]
