"""glibc ptmalloc2 and Doug Lea dlmalloc boundary-tag heap parsers.

Both allocators lay chunks out back to back, each behind a two-word header
``{prev_size, size}`` whose low three bits are flags. The walker reads the
size word, masks the flags (``size & ~7``) and steps to the next chunk; the
alignment is ``2 * SIZE_SZ`` (16 on 64-bit, 8 on 32-bit — an i386 glibc
built with ``MALLOC_ALIGNMENT == 16`` is not handled).

ptmalloc2 (levels L0-L3):

* flags are PREV_INUSE (1), IS_MMAPPED (2, never set inside a heap) and
  NON_MAIN_ARENA (4); a chunk is free when its successor's PREV_INUSE is
  clear, the last chunk of the heap is ``top``;
* the first chunk is ``tcache_perthread_struct`` (ALLOCATOR_META); its size
  gives the version hint (0x290: ``uint16_t counts`` glibc >= 2.30, 0x250:
  ``char counts`` 2.26-2.29). Its bins are walked with plain and with
  safe-linked (``(pos >> 12) ^ ptr``, glibc >= 2.32) ``next`` pointers and
  the decoding that forms in-heap chains wins. Tcache'd chunks are CACHED
  with ``next``/``key`` marked FREE_LINK;
* ``main_arena`` is located by scanning glibc's writable mapping for a
  word equal to the walked top chunk whose surrounding ``bins[]`` are all
  self-linked or point into the heap. When found, fastbins (CACHED, ``fd``
  FREE_LINK) and the unsorted / small / large bins are walked.

dlmalloc (levels L0-L2): the same walker; bit 2 is CINUSE so a chunk's own
head says whether it is in use. Free chunks are labelled ``smallbin`` /
``treebin`` by size; ``malloc_state`` is not decoded.

Corrupt headers are skipped by resyncing to the next aligned header whose
successor is also plausible (a diagnostic names the address); pages the
dump never captured are skipped the same way and counted in ``coverage``.

Thread arenas (ptmalloc2 only, see :mod:`.ptmalloc2_arenas`): reached from
``main_arena.next`` (the arena ring) or, when ``main_arena`` is unavailable,
by scanning ``HEAP_MAX_SIZE``-aligned anonymous maps for ``heap_info``. Each
of their heaps is walked as a ``thread_heap`` segment of arena 1..n; the
arena's tcache and (ring discovery only) bins are decoded. With an explicit
:attr:`ParseOptions.regions`, a thread heap is walked only when its region
is selected. Mmapped chunks (IS_MMAPPED) are found by a page-granular
scan of the remaining anonymous maps (:mod:`.ptmalloc2_mmapped`), as in-use
chunks of an ``mmap`` pseudo arena; the scan only runs when a main heap was
walked or a thread arena found (mmapped chunks alone give an empty layout).

Limitations: only the regions named like the main heap (``[heap]``; for
dlmalloc also ``[anon:libc_malloc]``) and discovered thread heaps are
walked unless :attr:`ParseOptions.regions` selects others. ``main_arena``
is not found in statically linked binaries (no glibc module mapping; thread
arenas are then found by the ``heap_info`` scan but their bins are not
decoded), one ``malloc_state`` top offset is assumed for every arena, and
dlmalloc mmapped chunks are not enumerated. The static-binary case adds a
diagnostic instead of a guess.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from memdiver.heap.allocators.ptmalloc2_arenas import (ArenaDiscovery,
                                                       arena_flag_check,
                                                       discover_thread_arenas,
                                                       is_thread_heap_region,
                                                       thread_heap_arena)
from memdiver.heap.allocators.ptmalloc2_bins import (
    _Lists, _mark_tcache_struct, _mark_tcache_struct_at, _decode_tcache, _version_hint,
    _libc_data_regions, _decode_arena as _decode_arena, _decode_arena_at,
    _locate_main_arena, _decode_main_arena,
)
from memdiver.heap.allocators.ptmalloc2_mmapped import (MmapScan, claimed_ranges,
                                                        scan_mmapped_chunks,
                                                        starts_with_mmapped_chunk)
from memdiver.heap.allocators.ptmalloc2_segments import (MAIN_ARENA_ID, WalkSpan,
                                                         assemble_layout, main_arena,
                                                         main_heap_segment)
from memdiver.heap.allocators.ptmalloc2_walk import (
    _PREV_INUSE, _IS_MMAPPED, _NON_MAIN_ARENA, _FLAG_BITS, _PROBE_HEADERS, _PROBE_REGIONS,
    _GLIBC_MODULES, _Geometry, _geometry, _Flavor, _PTMALLOC2, _DLMALLOC, _PagedReader, _Walk,
    _header_word, _walk_region, _Slot, _initial_slot, _Heap,
)
from memdiver.heap.memory import VaMemory
from memdiver.heap.model import (AllocatorKind, ChunkState, Evidence, HeapArena,
                                 HeapChunk, HeapLayout)
from memdiver.heap.platform import MappedRegion, TargetPlatform
from memdiver.heap.registry import (DetectContext, DetectScore, ParseOptions,
                                    name_matches)
from memdiver.heap.segments import ChunkBudget, HeapSegment, truncation_diagnostic

# The boundary-tag walker lives in ptmalloc2_walk and the free-list decoders in
# ptmalloc2_bins; their remaining names are re-exported (``name as name``) so
# everything stays importable from this module.
from memdiver.heap.allocators.ptmalloc2_bins import (
    _Chain as _Chain, _reveal as _reveal, _walk_singly as _walk_singly,
    _walk_double as _walk_double, _chains_badness as _chains_badness,
    _pick_decoding as _pick_decoding, _record as _record, _mark as _mark,
    _tcache_struct_sizes as _tcache_struct_sizes, _VERSION_BY_WIDTH as _VERSION_BY_WIDTH,
    _tcache_heads as _tcache_heads, _aligned_hits as _aligned_hits,
    _bins_consistent as _bins_consistent, _find_main_arena as _find_main_arena,
    _nfastbins as _nfastbins, _decode_fastbins as _decode_fastbins, _bin_label as _bin_label,
    _decode_bins as _decode_bins,
)
from memdiver.heap.allocators.ptmalloc2_walk import (
    _TCACHE_BINS as _TCACHE_BINS, _NBINS as _NBINS, _FIRST_LARGE_BIN as _FIRST_LARGE_BIN,
    _DL_MIN_LARGE_SIZE as _DL_MIN_LARGE_SIZE, _PAGE as _PAGE, _MAX_LIST_LEN as _MAX_LIST_LEN,
    _MAX_ARENA_SCAN as _MAX_ARENA_SCAN, _CACHE_PAGES as _CACHE_PAGES, _Roles as _Roles,
    _Raw as _Raw, _plausible as _plausible, _resync as _resync,
    _ends_with_fencepost as _ends_with_fencepost, _skip_bad_header as _skip_bad_header,
    _link_roles as _link_roles, _successor as _successor, _base_state as _base_state,
    _is_top as _is_top,
)
from memdiver.heap.allocators.ptmalloc2_walk import is_fencepost as is_fencepost
from memdiver.heap.model import FreeList as FreeList, HeapRole as HeapRole


# -- region selection ----------------------------------------------------------------


def _target_regions(ctx: DetectContext, flavor: _Flavor,
                    opts: Optional[ParseOptions]) -> List[MappedRegion]:
    regions = [r for r in ctx.regions if r.captured and r.size > 0]
    if opts is not None and opts.regions is not None:
        return [r for r in regions if opts.selects(r)]
    named = [r for r in regions
             if any(name_matches(r.name, p) for p in flavor.region_patterns)]
    if named or flavor.dlmalloc:
        return named
    return _nameless_main_heap(ctx, regions, flavor)


#: A candidate heap must score at least this on the boundary-tag probe.
_NAMELESS_MIN_PROBE_SCORE = 0.5


def _nameless_main_heap(ctx: DetectContext, regions: Sequence[MappedRegion],
                        flavor: _Flavor) -> List[MappedRegion]:
    """The brk heap of a dump whose map lost the ``[heap]`` label.

    An imported ``.msl`` keeps the executable's and libraries' paths but not
    the pseudo-names, so ``[heap]`` is an anonymous ``rw-`` region. On Linux
    the brk heap lies above the main executable's image, but the lowest such
    region is often the executable's own ``.bss`` continuation; so the
    candidates are tried in address order (``ctx.regions`` is not assumed
    sorted) and the first whose content passes the boundary-tag probe wins.
    Only offered when glibc is mapped; the walk's own header checks still
    have to agree before anything is reported.
    """
    if not ctx.matching_modules(*_GLIBC_MODULES):
        return []
    image_end = _first_module_end(ctx.regions)
    if image_end is None:
        return []
    candidates = sorted((r for r in regions if r.va >= image_end and "w" in r.perms
                         and not r.name and not r.module_path), key=lambda r: r.va)
    geo = _geometry(ctx.platform)
    reader = _PagedReader(ctx.memory, geo)
    for region in candidates:
        if _probe_score(*_probe_region(reader, region, geo, flavor)) >= _NAMELESS_MIN_PROBE_SCORE:
            return [region]
    return []


def _first_module_end(regions: Sequence[MappedRegion]) -> Optional[int]:
    """End of the last mapping of the lowest-VA file-backed module."""
    mapped = [r for r in regions if r.module_path]
    if not mapped:
        return None
    first_path = min(mapped, key=lambda r: r.va).module_path
    return max(r.end for r in mapped if r.module_path == first_path)


# -- probe ----------------------------------------------------------------------------


def _dl_consistent(prev_word: Optional[int], word: int) -> bool:
    """dlmalloc: a free chunk (CINUSE clear) has a successor with PINUSE clear."""
    return prev_word is None or bool(prev_word & _IS_MMAPPED) or not word & _PREV_INUSE


def _probe_region(reader: _PagedReader, region: MappedRegion, geo: _Geometry,
                  flavor: _Flavor) -> Tuple[int, bool]:
    """``(plausible consecutive headers, reached the region end)``."""
    va, good, prev = geo.align_up(region.va), 0, None
    while good < _PROBE_HEADERS and va + geo.header <= region.end:
        word = _header_word(reader, va, region.end, geo, flavor)
        if word is None or (flavor.dlmalloc and not _dl_consistent(prev, word)):
            return good, False
        good, prev, va = good + 1, word, va + (word & ~_FLAG_BITS)
    return good, va == region.end


def _probe_score(good: int, complete: bool) -> float:
    if good == 0:
        return 0.0
    fraction = 1.0 if complete or good >= _PROBE_HEADERS else good / (good + 1)
    return fraction * min(1.0, good / 4)


def _probe(ctx: DetectContext, flavor: _Flavor) -> DetectScore:
    regions = _target_regions(ctx, flavor, None)[:_PROBE_REGIONS]
    if not regions:
        return DetectScore(0.0, [])
    geo = _geometry(ctx.platform)
    reader = _PagedReader(ctx.memory, geo)
    results = [(_probe_score(*_probe_region(reader, r, geo, flavor)), r) for r in regions]
    score, region = max(results, key=lambda item: item[0])
    detail = (f"{flavor.kind.value} boundary-tag walk of {region.name or hex(region.va)}"
              f" scored {score:.2f}")
    return DetectScore(score, [Evidence("content", detail, score)])


def probe_ptmalloc2(ctx: DetectContext) -> DetectScore:
    """Content probe: plausible consecutive ptmalloc2 headers in ``[heap]``."""
    return _probe(ctx, _PTMALLOC2)


def probe_dlmalloc(ctx: DetectContext) -> DetectScore:
    """Content probe: plausible, CINUSE-consistent dlmalloc headers."""
    return _probe(ctx, _DLMALLOC)


# -- parse ----------------------------------------------------------------------------


def _walk_all(reader: _PagedReader, regions: Sequence[MappedRegion], geo: _Geometry,
              flavor: _Flavor, max_chunks: int) -> _Walk:
    walk = _Walk()
    _walk_segments(reader, [main_heap_segment(r) for r in regions], geo, flavor,
                   max_chunks, walk)
    return walk


def _walk_segments(reader: _PagedReader, segments: Sequence[HeapSegment], geo: _Geometry,
                   flavor: _Flavor, max_chunks: int, walk: _Walk) -> None:
    """Walk *segments* in order into *walk*, sharing its ``max_chunks`` budget."""
    for segment in segments:
        if not walk.truncated:
            _walk_segment(reader, segment, geo, flavor, max_chunks, walk)
            if walk.truncated:
                walk.diagnostics.append(truncation_diagnostic(max_chunks))
        else:
            first = len(walk.raws)
            walk.spans.append(WalkSpan(segment, first, first))


def _walk_segment(reader: _PagedReader, segment: HeapSegment, geo: _Geometry,
                  flavor: _Flavor, max_chunks: int, walk: _Walk) -> None:
    """Walk *segment* from ``walk_start`` and record its :class:`WalkSpan`.

    Bytes before ``walk_start`` (a thread heap's ``heap_info`` and
    ``malloc_state``) are decoded metadata and count as walked.
    """
    first, skipped, uncaptured = len(walk.raws), walk.skipped, walk.uncaptured
    region = MappedRegion(segment.va, segment.size, "rw-", segment.name, None, True)
    _walk_region(reader, region, geo, flavor, max_chunks, walk,
                 start=segment.walk_start, end=segment.end)
    walk.spans.append(WalkSpan(
        segment, first, len(walk.raws),
        walked=segment.walk_start - segment.va + sum(r.size for r in walk.raws[first:]),
        skipped=walk.skipped - skipped, uncaptured=walk.uncaptured - uncaptured))


_LINKED_STATES = (ChunkState.FREE, ChunkState.CACHED)


def _header_fields(reader: _PagedReader, slot: _Slot, geo: _Geometry) -> Dict[str, Any]:
    """Raw header words, plus the first two user words of a linked free chunk.

    ``fd``/``bk`` are stored as read (still safe-linked for tcache/fastbins);
    the decoded chain lives in the layout's free lists.
    """
    raw = slot.raw
    fields = {"prev_size": reader.word(raw.va), "size_word": reader.word(raw.va + geo.ptr)}
    if slot.state in _LINKED_STATES and slot.bin != "top":
        user_va = raw.va + geo.header
        fields["fd"] = reader.word(user_va)
        fields["bk"] = reader.word(user_va + geo.ptr)
    return {name: word for name, word in fields.items() if word is not None}


def _to_chunk(reader: _PagedReader, slot: _Slot, geo: _Geometry,
              arena_id: Optional[int] = None) -> HeapChunk:
    raw = slot.raw
    extra = {**_header_fields(reader, slot, geo), **slot.extra}
    return HeapChunk(va=raw.va, size=raw.size, state=slot.state, header_len=geo.header,
                     user_va=raw.va + geo.header, user_len=raw.size - geo.header,
                     flags=raw.flags, bin=slot.bin, extra=extra,
                     confidence=0.7 if raw.after_gap else 1.0, roles=slot.roles,
                     arena_id=arena_id)


def _walked_chunks(reader: _PagedReader, heap: _Heap, walk: _Walk,
                   geo: _Geometry) -> List[HeapChunk]:
    """Every walked slot as a chunk, already carrying its segment's ``arena_id``."""
    return [_to_chunk(reader, slot, geo, span.segment.arena_id)
            for span in walk.spans for slot in heap.slots[span.first:span.stop]]


def _coverage(arena_top: Optional[int], safe: Optional[bool], threads: ArenaDiscovery,
              mmapped: MmapScan) -> Dict[str, Any]:
    """The ptmalloc2-specific coverage keys (the assembler adds the standard ones)."""
    return {
        "main_arena_top_va": arena_top,
        "safe_linking": safe,
        "thread_arenas": len(threads.arenas),
        "arena_discovery": threads.method,
        "mmapped_chunks": len(mmapped.chunks),
    }


def _ptmalloc2_overlays(memory: VaMemory, reader: _PagedReader, ctx: DetectContext,
                        opts: ParseOptions, heap: _Heap, walk: _Walk, geo: _Geometry,
                        lists: _Lists) -> Tuple[str, Optional[int], ArenaDiscovery]:
    """Tcache + main/thread arena decoding: ``(version_hint, main top slot, threads)``.

    Every heap (main and thread) is walked before any free list is decoded,
    so a list may lead into another arena's heap (a cross-thread free puts
    a thread arena's chunk into the freeing thread's tcache).
    """
    struct_slot = _mark_tcache_struct(heap, geo)
    arena_top = _locate_main_arena(memory, reader, ctx, heap, geo)
    threads = _walk_thread_arenas(reader, ctx, opts, heap, walk, geo, arena_top)
    if struct_slot is not None:
        _decode_tcache(reader, heap, struct_slot, geo, lists)
    _decode_main_arena(reader, heap, arena_top, geo, lists)
    lists.diagnostics.extend(threads.diagnostics)
    _decode_thread_arenas(reader, heap, walk, geo, lists, threads)
    if not threads.arenas and any(s.raw.flags & _NON_MAIN_ARENA for s in heap.slots):
        lists.diagnostics.append(
            "NON_MAIN_ARENA chunks present; non-main arenas are not decoded")
    if struct_slot is None:
        struct_slot = next((s for s in heap.slots
                            if s.bin == "tcache_perthread_struct"), None)
    return _version_hint(struct_slot, lists.safe), arena_top, threads


def _thread_arenas(reader: _PagedReader, ctx: DetectContext, opts: ParseOptions,
                   heap: _Heap, walk: _Walk, geo: _Geometry, lists: _Lists,
                   arena_top: Optional[int]) -> ArenaDiscovery:
    """Discover, walk and decode the thread arenas (appended to *walk*/*heap*)."""
    threads = _walk_thread_arenas(reader, ctx, opts, heap, walk, geo, arena_top)
    lists.diagnostics.extend(threads.diagnostics)
    _decode_thread_arenas(reader, heap, walk, geo, lists, threads)
    return threads


def _walk_thread_arenas(reader: _PagedReader, ctx: DetectContext, opts: ParseOptions,
                        heap: _Heap, walk: _Walk, geo: _Geometry,
                        arena_top: Optional[int]) -> ArenaDiscovery:
    """Discover the thread arenas and walk their heaps (appended to *walk*/*heap*)."""
    threads = discover_thread_arenas(
        reader, geo, ctx.regions, main_top_slot=arena_top,
        libc_regions=_libc_data_regions(ctx.regions), selects=opts.selects)
    segments = [h.segment for arena in threads.arenas for h in arena.heaps]
    first = len(walk.raws)
    _walk_segments(reader, segments, geo, _PTMALLOC2, opts.max_chunks, walk)
    heap.extend([_initial_slot(walk.raws, i, geo, _PTMALLOC2)
                 for i in range(first, len(walk.raws))], segments)
    return threads


def _decode_thread_arenas(reader: _PagedReader, heap: _Heap, walk: _Walk, geo: _Geometry,
                          lists: _Lists, threads: ArenaDiscovery) -> None:
    """Decode each thread arena's tcache and (when its top slot is known) bins."""
    spans = {span.segment: span for span in walk.spans}
    for arena in threads.arenas:
        host = arena.first_heap
        if host is not None:
            struct_slot = _mark_tcache_struct_at(_first_slot(heap, spans[host.segment]), geo)
            if struct_slot is not None:
                _decode_tcache(reader, heap, struct_slot, geo, lists, arena.arena_id)
        if arena.top_slot is not None:
            _decode_arena_at(reader, heap, arena.top_slot, geo, lists, arena.arena_id)


def _first_slot(heap: _Heap, span: WalkSpan) -> Optional[_Slot]:
    """The first chunk walked in *span* (slot ``i`` is walked chunk ``i``)."""
    return heap.slots[span.first] if span.first < span.stop else None


def _arena_evidence(heap: _Heap, walk: _Walk, threads: ArenaDiscovery,
                    lists: _Lists) -> Tuple[Evidence, ...]:
    """NON_MAIN_ARENA flag agreement (in-use/cached chunks), with thread arenas only."""
    if not threads.arenas:
        return ()
    evidence, diagnostic = arena_flag_check(
        (slot.raw.flags, span.segment.arena_id != MAIN_ARENA_ID)
        for span in walk.spans for slot in heap.slots[span.first:span.stop]
        if slot.state is not ChunkState.FREE and not slot.extra.get("fencepost"))
    if diagnostic is not None:
        lists.diagnostics.append(diagnostic)
    return () if evidence is None else (evidence,)


def _empty_layout(flavor: _Flavor, platform: TargetPlatform) -> HeapLayout:
    patterns = ", ".join(flavor.region_patterns)
    return HeapLayout(flavor.kind, platform=platform, diagnostics=(
        f"no captured {flavor.kind.value} heap region (looked for {patterns})",),
        coverage={"regions": [], "bytes_total": 0, "chunk_count": 0})


def _main_regions(ctx: DetectContext, flavor: _Flavor, opts: ParseOptions,
                  reader: _PagedReader, geo: _Geometry) -> List[MappedRegion]:
    """Target regions, minus (ptmalloc2) thread heaps, which are walked as such."""
    regions = _target_regions(ctx, flavor, opts)
    if flavor.dlmalloc:
        return regions
    return [r for r in regions if not is_thread_heap_region(reader, r, geo.ptr)
            and not starts_with_mmapped_chunk(reader, r)]


def _mmapped(reader: _PagedReader, ctx: DetectContext, opts: ParseOptions,
             regions: Sequence[MappedRegion], walk: _Walk,
             threads: ArenaDiscovery) -> MmapScan:
    """Mmapped chunks outside every walked heap, within what max_chunks has left."""
    budget = ChunkBudget(max(0, opts.max_chunks - len(walk.raws)))
    scan = scan_mmapped_chunks(
        reader, ctx.regions, arena_id=MAIN_ARENA_ID + 1 + len(threads.arenas),
        budget=budget, claimed=claimed_ranges(regions, threads, reader.geo.ptr),
        selects=opts.selects)
    if budget.truncated and not walk.truncated:
        walk.truncated = True
        walk.diagnostics.append(truncation_diagnostic(opts.max_chunks))
    return scan


def _parse(memory: VaMemory, ctx: DetectContext, opts: ParseOptions,
           flavor: _Flavor) -> HeapLayout:
    geo = _geometry(memory.platform)
    reader = _PagedReader(memory, geo)
    regions = _main_regions(ctx, flavor, opts, reader, geo)
    if not regions and flavor.dlmalloc:
        return _empty_layout(flavor, memory.platform)
    walk = _walk_all(reader, regions, geo, flavor, opts.max_chunks)
    heap = _Heap([_initial_slot(walk.raws, i, geo, flavor) for i in range(len(walk.raws))],
                 regions)
    lists = _Lists()
    version, arena_top, threads = "dlmalloc 2.8.x", None, ArenaDiscovery()
    mmapped = MmapScan(0)
    if not flavor.dlmalloc:
        version, arena_top, threads = _ptmalloc2_overlays(memory, reader, ctx, opts, heap,
                                                          walk, geo, lists)
        if not regions and not threads.arenas:
            # Mmapped-looking pages alone are no evidence of ptmalloc2.
            return _empty_layout(flavor, memory.platform)
        mmapped = _mmapped(reader, ctx, opts, regions, walk, threads)
    if not walk.spans and not mmapped.runs:
        return _empty_layout(flavor, memory.platform)
    evidence = _arena_evidence(heap, walk, threads, lists) + mmapped.evidence()
    return assemble_layout(
        flavor.kind, memory.platform,
        _arenas(reader, heap, walk, geo, arena_top, threads) + mmapped.arenas(),
        walk.spans + mmapped.spans(len(heap.slots)),
        _walked_chunks(reader, heap, walk, geo) + mmapped.chunks,
        free_lists=lists.free_lists, diagnostics=walk.diagnostics + lists.diagnostics,
        version_hint=version,
        walk_summary=f"{len(walk.raws)} chunks walked in {len(walk.spans)} region(s)",
        truncated_at=opts.max_chunks if walk.truncated else None,
        extra_coverage=_coverage(arena_top, lists.safe, threads, mmapped),
        evidence=evidence)


def _arenas(reader: _PagedReader, heap: _Heap, walk: _Walk, geo: _Geometry,
            arena_top: Optional[int], threads: ArenaDiscovery) -> List[HeapArena]:
    """Arena 0 followed by every thread arena (each with its walked top chunk)."""
    va = (None if arena_top is None or threads.top_off is None
          else arena_top - threads.top_off)
    return [_main_arena(heap, walk, arena_top, va)] + [
        thread_heap_arena(reader, t, geo.ptr, _walked_top(heap, walk, t.arena_id),
                          threads.method)
        for t in threads.arenas]


def _arena_spans(walk: _Walk, arena_id: int) -> List[WalkSpan]:
    return [span for span in walk.spans if span.segment.arena_id == arena_id]


def _walked_top(heap: _Heap, walk: _Walk, arena_id: int) -> Optional[int]:
    top = heap.top_of(_arena_spans(walk, arena_id))
    return None if top is None else top.raw.va


def _main_arena(heap: _Heap, walk: _Walk, arena_top: Optional[int],
                va: Optional[int] = None) -> HeapArena:
    """Arena 0 (glibc ``main_arena`` / dlmalloc's global ``malloc_state``)."""
    return main_arena(_arena_spans(walk, MAIN_ARENA_ID), arena_top,
                      _walked_top(heap, walk, MAIN_ARENA_ID), va)


def parse_ptmalloc2(memory: VaMemory, ctx: DetectContext,
                    opts: ParseOptions) -> HeapLayout:
    """Walk glibc ptmalloc2 heap regions (chunks, tcache, main_arena bins)."""
    return _parse(memory, ctx, opts, _PTMALLOC2)


def parse_dlmalloc(memory: VaMemory, ctx: DetectContext,
                   opts: ParseOptions) -> HeapLayout:
    """Walk dlmalloc 2.8.x segments (chunks only; no malloc_state)."""
    return _parse(memory, ctx, opts, _DLMALLOC)


DESCRIPTOR_OVERRIDES = {
    AllocatorKind.PTMALLOC2: (probe_ptmalloc2, parse_ptmalloc2),
    AllocatorKind.DLMALLOC: (probe_dlmalloc, parse_dlmalloc),
}

__all__ = ["probe_ptmalloc2", "parse_ptmalloc2", "probe_dlmalloc",
           "parse_dlmalloc", "DESCRIPTOR_OVERRIDES"]
