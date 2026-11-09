"""ptmalloc2/dlmalloc through LayoutAssembler: arenas, segments, fenceposts."""

import dataclasses

import pytest

from memdiver.heap.allocators import ptmalloc2 as pt
from memdiver.heap.allocators.ptmalloc2 import parse_dlmalloc, parse_ptmalloc2
from memdiver.heap.allocators.ptmalloc2_segments import is_fencepost
from memdiver.heap.memory import VaMemory
from memdiver.heap.model import (ARENA_MAIN, REGION_MAIN_HEAP, ChunkState,
                                 HeapRole)
from memdiver.heap.registry import DetectContext, ParseOptions
from tests.fixtures import synth_heap as sh
from tests.test_heap_ptmalloc2 import _arena_fixture, _platform

HEAP_VA = 0x5555_5555_9000
FENCE_OFF = 0x400


@pytest.fixture
def load_heaps(tmp_path):
    """Open synthetic heaps as a regioned raw dump -> (memory, ctx)."""
    opened = []

    def _load(*heaps, pointer_size=8):
        path = tmp_path / str(len(opened))
        source = sh.open_regioned(sh.as_regioned_raw(path, heaps))
        opened.append(source)
        platform = _platform(pointer_size)
        return VaMemory(source, platform), DetectContext(source, platform=platform)

    yield _load
    for source in opened:
        source.close()


def _fenced_heap(trailer=0 | sh.PREV_INUSE, ptr=8):
    """Chunks 0x30, 0x30, a former top up to FENCE_OFF, then a fencepost.

    Everything after the fencepost is 0xFF garbage that would otherwise be
    reported as implausible headers.
    """
    buf = bytearray(b"\xff" * sh.PAGE)
    offset = 0
    for size in (0x30, 0x30, FENCE_OFF - 0x60):
        sh._write_boundary_chunk(buf, offset, size | sh.PREV_INUSE, ptr)
        buf[offset + 2 * ptr:offset + size] = bytes(size - 2 * ptr)
        offset += size
    sh._write_boundary_chunk(buf, FENCE_OFF, 2 * ptr | sh.PREV_INUSE, ptr)
    sh._put_word(buf, FENCE_OFF + 2 * ptr, 2 * ptr, ptr)  # trailer prev_size
    sh._put_word(buf, FENCE_OFF + 3 * ptr, trailer, ptr)
    return sh.SynthHeap(bytes(buf), HEAP_VA, "ptmalloc2", ptr,
                        [(HEAP_VA, sh.PAGE, "[heap]")], [],
                        (HEAP_VA, HEAP_VA + sh.PAGE), ["rw-p"])


# -- arenas & segments ------------------------------------------------------------


def test_main_arena_is_recorded_with_its_top_slot(load_heaps):
    heap, libc, top_slot = _arena_fixture()
    memory, ctx = load_heaps(heap, libc)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    (arena,) = layout.arenas
    assert (arena.arena_id, arena.kind) == (0, ARENA_MAIN)
    assert arena.top_va == layout.coverage["main_arena_top_va"] == top_slot
    assert arena.region_vas == (heap.base_va,)
    assert arena.extra["top_chunk_va"] == heap.chunks[-1].va
    assert layout.coverage["arenas"] == 1


def test_chunks_and_regions_belong_to_arena_zero(load_heaps):
    memory, ctx = load_heaps(sh.glibc_heap())
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert layout.chunks and all(c.arena_id == 0 for c in layout.chunks)
    assert [(r.kind, r.arena_id, r.name) for r in layout.regions] == [
        (REGION_MAIN_HEAP, 0, "[heap]")]
    assert layout.to_dict()["chunks"][0]["arena_id"] == 0


def test_missing_main_arena_leaves_top_va_unset(load_heaps):
    memory, ctx = load_heaps(sh.glibc_heap())
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert layout.arenas[0].top_va is None
    assert layout.coverage["main_arena_top_va"] is None


def test_dlmalloc_has_one_main_arena(load_heaps):
    heap = sh.dlmalloc_heap()
    memory, ctx = load_heaps(heap)
    layout = parse_dlmalloc(memory, ctx, ParseOptions())
    (arena,) = layout.arenas
    assert (arena.kind, arena.top_va, arena.region_vas) == (ARENA_MAIN, None,
                                                            (heap.base_va,))
    assert all(c.arena_id == 0 for c in layout.chunks)


def test_truncated_walk_keeps_every_region_as_a_segment(load_heaps):
    second = sh.glibc_heap(base_va=0x5555_6666_0000)
    memory, ctx = load_heaps(sh.glibc_heap(), second)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions(max_chunks=3))
    assert layout.coverage["truncated"] is True
    assert layout.coverage["bytes_total"] == 2 * sh.PAGE
    assert len(layout.regions) == 2 and layout.arenas[0].region_vas[1] == second.base_va


# -- walker start / end --------------------------------------------------------------


def test_walk_region_honours_start_and_end(load_heaps):
    heap = sh.glibc_heap()
    memory, ctx = load_heaps(heap)
    geo = pt._geometry(memory.platform)
    region = next(r for r in ctx.regions if r.va == heap.base_va)
    start, end = heap.chunks[1].va, heap.chunks[4].va
    walk = pt._Walk()
    pt._walk_region(pt._PagedReader(memory, geo), region, geo, pt._PTMALLOC2, 100,
                    walk, start=start, end=end)
    assert [raw.va for raw in walk.raws] == [c.va for c in heap.chunks[1:4]]
    assert all(raw.region_end == end for raw in walk.raws)
    assert not walk.diagnostics


def test_walk_region_defaults_cover_the_region(load_heaps):
    heap = sh.glibc_heap()
    memory, ctx = load_heaps(heap)
    geo = pt._geometry(memory.platform)
    region = next(r for r in ctx.regions if r.va == heap.base_va)
    walk = pt._Walk()
    pt._walk_region(pt._PagedReader(memory, geo), region, geo, pt._PTMALLOC2, 100, walk)
    assert [raw.va for raw in walk.raws] == [c.va for c in heap.chunks]


# -- fenceposts ----------------------------------------------------------------------


@pytest.mark.parametrize("ptr", [8, 4])
def test_fencepost_ends_the_walk_cleanly(load_heaps, ptr):
    memory, ctx = load_heaps(_fenced_heap(ptr=ptr), pointer_size=ptr)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert [c.va - HEAP_VA for c in layout.chunks] == [0, 0x30, 0x60, FENCE_OFF]
    fence = layout.chunks[-1]
    assert (fence.size, fence.bin, fence.state) == (2 * ptr, "fencepost",
                                                    ChunkState.IN_USE)
    assert fence.extra["meta"] is True and fence.extra["fencepost"] is True
    assert layout.chunks[-2].state is ChunkState.IN_USE
    assert not any("implausible" in d or "resync" in d for d in layout.diagnostics)


def test_fencepost_is_never_a_free_candidate(load_heaps):
    memory, ctx = load_heaps(_fenced_heap())
    geo = pt._geometry(memory.platform)
    walk = pt._walk_all(pt._PagedReader(memory, geo), pt._target_regions(
        ctx, pt._PTMALLOC2, None), geo, pt._PTMALLOC2, 100)
    slots = [pt._initial_slot(walk.raws, i, geo, pt._PTMALLOC2)
             for i in range(len(walk.raws))]
    heap = pt._Heap(slots, [])
    assert heap.free_candidate(HEAP_VA + FENCE_OFF) is None


def test_fencepost_without_zero_trailer_still_resyncs(load_heaps):
    memory, ctx = load_heaps(_fenced_heap(trailer=0x40 | sh.PREV_INUSE))
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert all(c.bin != "fencepost" for c in layout.chunks)
    assert any("implausible chunk header" in d for d in layout.diagnostics)


def test_fencepost_needs_a_preceding_chunk(load_heaps):
    heap = _fenced_heap()
    buf = bytearray(heap.data)
    sh._write_boundary_chunk(buf, 0, 0x10 | sh.PREV_INUSE, 8)
    sh._put_word(buf, 0x18, sh.PREV_INUSE, 8)
    memory, ctx = load_heaps(dataclasses.replace(heap, data=bytes(buf)))
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    fences = [c.va - HEAP_VA for c in layout.chunks if c.bin == "fencepost"]
    assert fences == [FENCE_OFF]  # the leading one is resynced over instead
    assert "implausible chunk header at 0x555555559000" in layout.diagnostics[0]


def test_is_fencepost_pattern():
    words = {0x18: 0x1, 0x38: 0x41}
    assert is_fencepost(words.get, 0x0, 0x11, 0x100, 8)
    assert is_fencepost(words.get, 0x0, 0x15, 0x100, 8)       # NON_MAIN_ARENA ok
    assert is_fencepost(words.get, 0x0, 0x10, 0x100, 8)       # old top freed
    assert not is_fencepost(words.get, 0x0, 0x11, 0x18, 8)    # trailer outside
    assert not is_fencepost(words.get, 0x20, 0x11, 0x100, 8)  # trailer size != 0
    assert not is_fencepost(words.get, 0x40, 0x11, 0x100, 8)  # trailer uncaptured


def test_is_fencepost_reexported_from_walker():
    from memdiver.heap.allocators import ptmalloc2_walk
    assert is_fencepost is ptmalloc2_walk.is_fencepost is pt.is_fencepost


def test_main_arena_takes_malloc_state_va():
    from memdiver.heap.allocators.ptmalloc2_segments import main_arena
    arena = main_arena([], top_slot_va=0x7000_0060, top_chunk_va=0x5000, va=0x7000_0000)
    assert (arena.va, arena.top_va, arena.extra) == (0x7000_0000, 0x7000_0060,
                                                     {"top_chunk_va": 0x5000})
    assert main_arena([]).va is None


def test_record_takes_arena_id_explicitly():
    lists = pt._Lists()
    chain = pt._Chain((0x10,), broken=True)
    pt._record(lists, "tcache", 3, 0x100, chain, True, 2)
    pt._record(lists, "tcache", 4, 0x108, chain, True)
    assert [f.arena_id for f in lists.free_lists] == [2, 0]
    assert lists.diagnostics[0].startswith("arena 2 tcache[3]")
    assert lists.diagnostics[1].startswith("tcache[4]")


def test_to_chunk_carries_arena_id(load_heaps):
    heap = sh.glibc_heap()
    memory, ctx = load_heaps(heap)
    geo = pt._geometry(memory.platform)
    reader = pt._PagedReader(memory, geo)
    walk = pt._walk_all(reader, pt._target_regions(ctx, pt._PTMALLOC2, None), geo,
                        pt._PTMALLOC2, 100)
    slot = pt._initial_slot(walk.raws, 0, geo, pt._PTMALLOC2)
    assert pt._to_chunk(reader, slot, geo).arena_id is None
    assert pt._to_chunk(reader, slot, geo, 3).arena_id == 3


def test_first_slot_of_span(load_heaps):
    heap = sh.glibc_heap()
    memory, ctx = load_heaps(heap)
    geo = pt._geometry(memory.platform)
    walk = pt._walk_all(pt._PagedReader(memory, geo), pt._target_regions(
        ctx, pt._PTMALLOC2, None), geo, pt._PTMALLOC2, 100)
    parsed = pt._Heap([pt._initial_slot(walk.raws, i, geo, pt._PTMALLOC2)
                       for i in range(len(walk.raws))], [])
    span = walk.spans[0]
    assert pt._first_slot(parsed, span) is parsed.slots[0]
    assert pt._first_slot(parsed, dataclasses.replace(span, stop=span.first)) is None


# -- tcache / arena helpers ------------------------------------------------------------


def test_mark_tcache_struct_at_any_slot(load_heaps):
    heap = sh.glibc_heap()
    memory, ctx = load_heaps(heap)
    geo = pt._geometry(memory.platform)
    walk = pt._walk_all(pt._PagedReader(memory, geo), pt._target_regions(
        ctx, pt._PTMALLOC2, None), geo, pt._PTMALLOC2, 100)
    slots = [pt._initial_slot(walk.raws, i, geo, pt._PTMALLOC2)
             for i in range(len(walk.raws))]
    parsed = pt._Heap(slots, [r for r in ctx.regions if r.va == heap.base_va])
    assert pt._mark_tcache_struct_at(None, geo) is None
    assert pt._mark_tcache_struct_at(parsed.slots[1], geo) is None
    first = parsed.first_slot_in(heap.base_va, heap.base_va + sh.PAGE)
    assert pt._mark_tcache_struct_at(first, geo) is first
    assert first.extra["struct"] == "tcache_perthread_struct"


def test_decode_arena_at_decodes_bins_for_a_known_top_slot(load_heaps):
    heap, libc, top_slot = _arena_fixture()
    memory, ctx = load_heaps(heap, libc)
    geo = pt._geometry(memory.platform)
    reader = pt._PagedReader(memory, geo)
    regions = pt._target_regions(ctx, pt._PTMALLOC2, None)
    walk = pt._walk_all(reader, regions, geo, pt._PTMALLOC2, 100)
    parsed = pt._Heap([pt._initial_slot(walk.raws, i, geo, pt._PTMALLOC2)
                       for i in range(len(walk.raws))], regions)
    lists = pt._Lists()
    pt._decode_arena_at(reader, parsed, top_slot, geo, lists)
    kinds = {(f.kind, f.index) for f in lists.free_lists}
    assert kinds == {("fastbin", 1), ("smallbin", 5)}
    fast = parsed.by_va[heap.chunks[1].va]
    assert fast.bin == "fastbin[1]" and fast.roles[0][2] is HeapRole.FREE_LINK
