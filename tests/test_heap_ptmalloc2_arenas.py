"""glibc ptmalloc2 thread (non-main) arenas: ring + heap_info discovery."""

import dataclasses
import struct

import pytest

from memdiver.heap.allocators import ptmalloc2_arenas as pa
from memdiver.heap.allocators.ptmalloc2 import parse_ptmalloc2
from memdiver.heap.allocators.ptmalloc2_walk import _Geometry
from memdiver.heap.memory import VaMemory
from memdiver.heap.model import (ARENA_MAIN, ARENA_THREAD, REGION_MAIN_HEAP,
                                 REGION_THREAD_HEAP, ChunkState)
from memdiver.heap.platform import MappedRegion
from memdiver.heap.registry import DetectContext, ParseOptions
from tests.fixtures import synth_heap as sh
from tests.test_heap_ptmalloc2 import _arena_fixture, _platform

OLD_NON_MAIN = "NON_MAIN_ARENA chunks present; non-main arenas are not decoded"
SECOND_BASE = 0x7FFF_EC00_0000


@pytest.fixture
def load(tmp_path):
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


def _process(*thread_kwargs, pointer_size=8, with_libc=True):
    """Main heap + libc ``main_arena`` page + thread arenas chained in a ring."""
    main = sh.glibc_heap(pointer_size=pointer_size)
    default_base = 0x7FFF_E400_0000 if pointer_size == 8 else 0xB7A0_0000
    arena_vas = [sh.thread_arena_va(kw.get("base_va", default_base), pointer_size)
                 for kw in thread_kwargs]
    libc = sh.glibc_main_arena_page(main.chunks[-1].va, pointer_size=pointer_size,
                                    next_arena=arena_vas[0] if arena_vas else None)
    ring = arena_vas[1:] + [libc.meta["arena_va"]]
    threads = [sh.glibc_thread_arena(pointer_size=pointer_size, next_arena=nxt, **kw)
               for kw, nxt in zip(thread_kwargs, ring)]
    return main, (libc if with_libc else None), threads


def _parse(load, main, libc, threads, pointer_size=8, opts=None):
    heaps = [h for h in (main, libc, *threads) if h is not None]
    memory, ctx = load(*heaps, pointer_size=pointer_size)
    return parse_ptmalloc2(memory, ctx, opts or ParseOptions())


def _rows(chunks, arena_id=None):
    return [(c.va, c.size, c.state, c.bin, c.flags) for c in chunks
            if arena_id is None or c.arena_id == arena_id]


def _expected_rows(heap):
    return [(c.va, c.size, c.state, c.bin, c.flags) for c in heap.chunks]


def _scan_rows(heap):
    """Expected rows when bins are not decoded (heap_info scan: no smallbin label)."""
    return [r if r[3] is None or not r[3].startswith("smallbin") else r[:3] + (None, r[4])
            for r in _expected_rows(heap)]


def _with_word(heap, va, value):
    buf = bytearray(heap.data)
    struct.pack_into("<Q" if heap.pointer_size == 8 else "<I", buf,
                     _offset(heap, va), value)
    return dataclasses.replace(heap, data=bytes(buf))


def _offset(heap, va):
    offset = 0
    for region_va, size, _name in heap.regions:
        if region_va <= va < region_va + size:
            return offset + va - region_va
        offset += size
    raise ValueError(hex(va))


class _Words(dict):
    """Dict-backed word reader for unit tests."""

    def word(self, va):
        return self.get(va)


# -- ring discovery -------------------------------------------------------------------


@pytest.mark.parametrize("pointer_size", [8, 4])
def test_one_thread_arena_from_the_ring(load, pointer_size):
    main, libc, (thread,) = _process({}, pointer_size=pointer_size)
    layout = _parse(load, main, libc, [thread], pointer_size)
    assert layout.coverage["thread_arenas"] == 1
    assert layout.coverage["arena_discovery"] == "ring"
    assert _rows(layout.chunks, 1) == _expected_rows(thread)
    assert [(c.va, c.size) for c in layout.chunks if c.arena_id == 0] == \
        [(c.va, c.size) for c in main.chunks]
    main_arena, arena = layout.arenas
    assert (main_arena.kind, main_arena.va) == (ARENA_MAIN, libc.meta["arena_va"])
    assert (arena.arena_id, arena.kind) == (1, ARENA_THREAD)
    assert arena.va == thread.meta["arena_va"]
    assert arena.top_va == thread.meta["top_slot_va"]
    assert arena.region_vas == (thread.base_va,)
    assert arena.extra == {"heaps": 1, "discovery": "ring",
                           "top_chunk_va": thread.meta["top_chunk_va"],
                           "system_mem": 2 * sh.PAGE}
    assert not any("implausible" in d for d in layout.diagnostics)
    assert pointer_size != 4 or pa.heap_max_size(4) == 1 << 20


def test_two_thread_arenas_get_ids_one_and_two(load):
    main, libc, threads = _process({}, {"base_va": SECOND_BASE})
    layout = _parse(load, main, libc, threads)
    assert layout.coverage["thread_arenas"] == 2
    assert [(a.arena_id, a.va) for a in layout.arenas] == [
        (0, libc.meta["arena_va"]), (1, threads[0].meta["arena_va"]),
        (2, threads[1].meta["arena_va"])]
    for arena_id, thread in enumerate(threads, start=1):
        assert _rows(layout.chunks, arena_id) == _expected_rows(thread)
    assert [(r.kind, r.arena_id) for r in layout.regions] == [
        (REGION_MAIN_HEAP, 0), (REGION_THREAD_HEAP, 1), (REGION_THREAD_HEAP, 2)]
    assert layout.coverage["arenas"] == 3
    assert layout.confidence == 1.0


def test_top_off_is_derived_from_the_ring_closing():
    ptr, main_base, arena = 8, 0x7000_0100, 0x7FFF_E400_0030
    top_off = sh.glibc_top_off(ptr)
    words = _Words({main_base + top_off + 256 * ptr + 16: arena,
                    arena + top_off + 256 * ptr + 16: main_base})
    assert pa.ring_arenas(words, main_base + top_off, ptr, []) == (top_off, [arena], [])
    words[main_base + top_off + 256 * ptr + 16] = main_base      # self ring
    assert pa.ring_arenas(words, main_base + top_off, ptr, []) == (top_off, [], [])


def test_self_ring_has_no_thread_arenas_but_names_main_arena(load):
    main, libc, _ = _process()
    layout = _parse(load, main, libc, [])
    assert layout.coverage["arena_discovery"] == "ring"
    assert layout.coverage["thread_arenas"] == 0
    assert layout.arenas[0].va == libc.meta["arena_va"]
    assert not any("arena_flags" == e.source for e in layout.evidence)


# -- tcache / bins / flags ------------------------------------------------------------


@pytest.mark.parametrize("safe_linking", [True, False])
def test_thread_tcache_is_decoded_per_arena(load, safe_linking):
    main, libc, (thread,) = _process({"safe_linking": safe_linking})
    layout = _parse(load, main, libc, [thread])
    tcache = [f for f in layout.free_lists if f.kind == "tcache" and f.arena_id == 1]
    assert [f.chunk_vas for f in tcache] == [(thread.meta["cached_chunk_va"],)]
    assert tcache[0].decoded is safe_linking
    main_tcache = [f for f in layout.free_lists if f.kind == "tcache" and f.arena_id == 0]
    assert main_tcache and all(f.head_va < thread.base_va for f in main_tcache)
    assert layout.to_dict()["free_lists"][-1]["arena_id"] in (0, 1)


def _cross_thread_tcache(main, thread):
    """Main tcache bin 3 (0x50) holds the thread arena's in-use 0x50 chunk."""
    chunk = [c for c in thread.chunks if c.size == 0x50 and c.bin is None][-1]
    mem, struct_mem = chunk.va + 16, main.base_va + 16
    main = _with_word(main, struct_mem + 2 * sh.TCACHE_BINS + 3 * 8, mem)
    buf = bytearray(main.data)
    struct.pack_into("<H", buf, 16 + 2 * 3, 1)                        # counts[3]
    main = dataclasses.replace(main, data=bytes(buf))
    thread = _with_word(thread, mem, mem >> 12)                       # safe-linked NULL
    return main, _with_word(thread, mem + 8, struct_mem), chunk.va


def test_main_tcache_entry_in_a_thread_heap_is_decoded(load):
    """A cross-thread free: main tcache -> chunk inside a thread arena's heap."""
    main, libc, (thread,) = _process({})
    main, thread, chunk_va = _cross_thread_tcache(main, thread)
    layout = _parse(load, main, libc, [thread])
    (entry,) = [f for f in layout.free_lists
                if f.kind == "tcache" and f.arena_id == 0 and f.index == 3]
    assert entry.chunk_vas == (chunk_va,) and entry.decoded is True
    chunk = layout.chunk_at(chunk_va)
    assert (chunk.state, chunk.bin, chunk.arena_id) == (ChunkState.CACHED, "tcache[3]", 1)
    assert not any(d.startswith("tcache[3]") for d in layout.diagnostics)
    assert layout.coverage["safe_linking"] is True


def test_thread_arena_verdict_does_not_override_main_safe_linking(load):
    main, libc, (thread,) = _process({"safe_linking": False})
    layout = _parse(load, main, libc, [thread])
    assert layout.coverage["safe_linking"] is True
    assert layout.version_hint == "glibc>=2.32"
    (tcache,) = [f for f in layout.free_lists if f.kind == "tcache" and f.arena_id == 1]
    assert tcache.decoded is False and tcache.chunk_vas == (thread.meta["cached_chunk_va"],)


def test_thread_smallbin_is_decoded(load):
    main, libc, (thread,) = _process({})
    layout = _parse(load, main, libc, [thread])
    (small,) = [f for f in layout.free_lists if f.kind == "smallbin"]
    assert (small.arena_id, small.index) == (1, 9)
    assert small.head_va == thread.meta["smallbin_header_va"]
    assert small.chunk_vas == (thread.meta["smallbin_chunk_va"],)
    chunk = layout.chunk_at(thread.meta["smallbin_chunk_va"])
    assert (chunk.state, chunk.bin, chunk.arena_id) == (ChunkState.FREE, "smallbin[9]", 1)


def test_key_chunk_is_attributed_to_its_thread_arena(load):
    main, libc, (thread,) = _process({})
    layout = _parse(load, main, libc, [thread])
    chunk = layout.chunk_at(thread.meta["key_va"])
    assert chunk.arena_id == 1 and chunk.state is ChunkState.IN_USE
    assert chunk.user_va == thread.meta["key_va"]


def test_non_main_arena_flags_are_evidence(load):
    main, libc, (thread,) = _process({})
    layout = _parse(load, main, libc, [thread])
    (evidence,) = [e for e in layout.evidence if e.source == "arena_flags"]
    assert evidence.weight == 1.0
    assert OLD_NON_MAIN not in layout.diagnostics
    assert not any("disagrees" in d for d in layout.diagnostics)


def test_flag_mismatch_is_diagnosed(load):
    main, libc, (thread,) = _process({})
    victim = thread.chunks[1]
    thread = _with_word(thread, victim.va + 8, victim.size | sh.PREV_INUSE)
    layout = _parse(load, main, libc, [thread])
    (evidence,) = [e for e in layout.evidence if e.source == "arena_flags"]
    assert evidence.weight < 1.0
    assert any(d.startswith("1 chunk(s) whose NON_MAIN_ARENA flag disagrees")
               for d in layout.diagnostics)


# -- sub-heaps and fenceposts -----------------------------------------------------------


def test_sub_heap_is_reached_through_prev(load):
    main, libc, (thread,) = _process({"extra_heap": True})
    layout = _parse(load, main, libc, [thread])
    (arena,) = layout.arenas[1:]
    second = thread.meta["second_heap_va"]
    assert arena.region_vas == (thread.base_va, second)
    assert arena.extra["heaps"] == 2
    assert arena.extra["top_chunk_va"] == thread.meta["top_chunk_va"] > second
    assert _rows(layout.chunks, 1) == _expected_rows(thread)
    fence = layout.chunk_at(second - pa.heap_max_size(8) + 2 * sh.PAGE - 32)
    assert fence.bin == "fencepost" and fence.extra["meta"] is True
    assert not any("implausible" in d for d in layout.diagnostics)


@pytest.mark.parametrize("ptr", [8, 4])
def test_freed_old_top_before_a_fencepost_is_free(load, ptr):
    """sysmalloc ``_int_free``s the old top: the fencepost loses PREV_INUSE."""
    main, libc, (thread,) = _process({"extra_heap": True, "free_old_top": True},
                                     pointer_size=ptr)
    layout = _parse(load, main, libc, [thread], pointer_size=ptr)
    assert _rows(layout.chunks, 1) == _expected_rows(thread)
    fence = next(c for c in layout.chunks if c.bin == "fencepost")
    assert fence.flags & sh.PREV_INUSE == 0 and fence.extra["meta"] is True
    old_top = layout.chunk_at(fence.va - 1)
    assert (old_top.state, old_top.bin) == (ChunkState.FREE, "unsorted")
    assert [f.chunk_vas for f in layout.free_lists
            if f.kind == "unsorted" and f.arena_id == 1] == [(old_top.va,)]
    assert not any("implausible" in d or "resync" in d for d in layout.diagnostics)


# -- heap_info scan fallback ----------------------------------------------------------


def test_heap_info_scan_without_main_arena(load):
    main, _libc, (thread,) = _process({}, with_libc=False)
    layout = _parse(load, main, None, [thread])
    assert layout.coverage["arena_discovery"] == "heap_info_scan"
    assert pa.SCAN_DIAGNOSTIC in layout.diagnostics
    assert any("main_arena not found" in d for d in layout.diagnostics)
    (arena,) = layout.arenas[1:]
    assert (arena.va, arena.top_va) == (thread.meta["arena_va"], None)
    assert arena.extra["top_chunk_va"] == thread.meta["top_chunk_va"]
    assert arena.extra["discovery"] == "heap_info_scan"
    assert [f.chunk_vas for f in layout.free_lists
            if f.kind == "tcache" and f.arena_id == 1] == [(thread.meta["cached_chunk_va"],)]
    small = layout.chunk_at(thread.meta["smallbin_chunk_va"])
    assert (small.state, small.bin) == (ChunkState.FREE, None)
    assert not any(f.kind == "smallbin" for f in layout.free_lists)


def test_heap_info_scan_without_a_main_heap(load):
    _main, _libc, (thread,) = _process({}, with_libc=False)
    memory, ctx = load(thread)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert _rows(layout.chunks) == _scan_rows(thread)
    assert layout.version_hint == "glibc>=2.32"


def test_scan_fallback_32bit_with_sub_heap(load):
    _main, _libc, (thread,) = _process({"extra_heap": True}, pointer_size=4,
                                       with_libc=False)
    memory, ctx = load(thread, pointer_size=4)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert _rows(layout.chunks) == _scan_rows(thread)
    assert layout.arenas[1].region_vas == (thread.base_va, thread.meta["second_heap_va"])


# -- negative controls ------------------------------------------------------------------


def test_random_bytes_in_an_aligned_anonymous_region_are_not_an_arena(load):
    noise = sh.random_region(seed=3, base_va=0x7FFF_E400_0000)
    main, libc, _ = _process()
    layout = _parse(load, main, libc, [noise])
    assert layout.coverage["thread_arenas"] == 0
    assert len(layout.arenas) == 1
    memory, ctx = load(main, noise)
    assert parse_ptmalloc2(memory, ctx, ParseOptions()).coverage["thread_arenas"] == 0


def test_ring_cycle_is_guarded_and_main_arena_survives(load):
    main, libc, (thread,) = _process({})
    cyclic = _with_word(thread, thread.meta["top_slot_va"] + 256 * 8 + 16,
                        thread.meta["arena_va"])
    layout = _parse(load, main, libc, [cyclic])
    assert any("does not lead back to main_arena" in d for d in layout.diagnostics)
    assert layout.coverage["main_arena_top_va"] == libc.meta["top_slot_va"]
    assert layout.coverage["arena_discovery"] == "heap_info_scan"   # still found
    assert layout.arenas[0].va is None


def test_ring_garbage_pointer_is_guarded(load):
    main, libc, _ = _process()
    libc = _with_word(libc, libc.meta["next_slot_va"], 0x4141_4141_4141_4141)
    layout = _parse(load, main, libc, [])
    assert any("does not lead back to main_arena" in d for d in layout.diagnostics)
    assert layout.coverage["thread_arenas"] == 0
    assert [c.va for c in layout.chunks] == [c.va for c in main.chunks]


def test_ring_unit_guards():
    ptr, main_base, a1, a2 = 8, 0x7000_0100, 0x7FFF_E400_0030, 0x7FFF_EC00_0030
    nxt = 256 * ptr + 16
    for top_off in range(ptr, pa.MAX_TOP_OFF + 1, ptr):
        words = _Words({main_base + 0x60 + nxt: a1, a1 + top_off + nxt: a2,
                        a2 + top_off + nxt: a1})
        top, arenas, diags = pa.ring_arenas(words, main_base + 0x60, ptr, [])
        assert (top, arenas) == (None, []) and diags
    words = _Words({main_base + 0x60 + nxt: a1 + 3})
    assert pa.ring_arenas(words, main_base + 0x60, ptr, [])[0] is None
    assert pa.ring_arenas(_Words(), main_base + 0x60, ptr, []) == (None, [], [])


# -- heap_info validation ---------------------------------------------------------------


@pytest.mark.parametrize("field,value,ok", [
    (None, None, True),
    (2, 0x1234, False),                 # size not a page multiple
    (2, 0, False),                      # empty heap
    (3, 0x1000, False),                 # mprotect_size < size
    (1, 0x7FFF_E000_1000, False),       # prev not HEAP_MAX_SIZE aligned
    (0, 0x7FFF_E400_0031, False),       # ar_ptr misaligned
    (0, 0x1000, False),                 # ar_ptr unreadable
])
def test_heap_info_validation(field, value, ok):
    va = 0x7FFF_E400_0000
    fields = [va + 0x30, 0, 0x2000, 0x2000]
    if field is not None:
        fields[field] = value
    words = _Words({va + 8 * i: w for i, w in enumerate(fields)})
    words[va + 0x30] = 0
    words[0x7FFF_E400_0031] = 0
    assert (pa.heap_info_at(words, va, 8) is not None) is ok
    assert pa.heap_info_at(words, va + 0x1000, 8) is None      # not aligned


# -- unchanged behaviour ------------------------------------------------------------------


def test_existing_glibc_fixture_has_no_thread_arenas(load):
    memory, ctx = load(sh.glibc_heap())
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert layout.coverage["thread_arenas"] == 0
    assert layout.coverage["arena_discovery"] is None
    assert len(layout.arenas) == 1 and layout.arenas[0].va is None
    assert [e.source for e in layout.evidence] == ["walk"]
    assert "arena_id" not in layout.to_dict()["free_lists"][0] or \
        layout.to_dict()["free_lists"][0]["arena_id"] == 0


def test_arena_fixture_without_ring_is_unchanged(load):
    heap, libc, top_slot = _arena_fixture()
    memory, ctx = load(heap, libc)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert layout.coverage["main_arena_top_va"] == top_slot
    assert layout.coverage["thread_arenas"] == 0
    assert not any("arena ring" in d for d in layout.diagnostics)


def test_original_non_main_diagnostic_without_thread_arenas(load):
    heap = sh.glibc_heap()
    victim = heap.chunks[1]
    heap = _with_word(heap, victim.va + 8, victim.size | sh.PREV_INUSE | sh.NON_MAIN_ARENA)
    memory, ctx = load(heap)
    layout = parse_ptmalloc2(memory, ctx, ParseOptions())
    assert OLD_NON_MAIN in layout.diagnostics


# -- options ------------------------------------------------------------------------------


def test_explicit_regions_exclude_unselected_thread_heaps(load):
    main, libc, (thread,) = _process({})
    layout = _parse(load, main, libc, [thread], opts=ParseOptions(regions=("[heap]",)))
    assert layout.coverage["thread_arenas"] == 0
    assert all(c.arena_id == 0 for c in layout.chunks)
    layout = _parse(load, main, libc, [thread], opts=ParseOptions(regions=("[heap]", "")))
    assert layout.coverage["thread_arenas"] == 1
    assert _rows(layout.chunks, 1) == _expected_rows(thread)
    assert [(r.kind, r.va) for r in layout.regions] == [
        (REGION_MAIN_HEAP, main.base_va), (REGION_THREAD_HEAP, thread.base_va)]


def test_max_chunks_budget_is_shared_with_thread_heaps(load):
    main, libc, (thread,) = _process({})
    layout = _parse(load, main, libc, [thread],
                    opts=ParseOptions(max_chunks=len(main.chunks) + 2))
    assert len(layout.chunks) == len(main.chunks) + 2
    assert layout.coverage["truncated"] is True
    assert sum("max_chunks" in d for d in layout.diagnostics) == 1


# -- geometry & region helpers ------------------------------------------------------------


@pytest.mark.parametrize("ptr,top_off,sizes", [(8, 88, (32, 48)), (4, 48, (16, 24))])
def test_geometry_helpers(ptr, top_off, sizes):
    geo = _Geometry(ptr, "little")
    assert pa.min_top_off(geo) == 8 + 10 * ptr == top_off      # NFASTBINS == 10
    assert pa.heap_info_sizes(geo) == sizes


@pytest.mark.parametrize("name,ok", [
    ("", True), ("[anon:glibc big buffer]", True), ("[anon:.bss]", True),
    ("[anon: glibc: malloc arena]", True), ("[anon: glibc: malloc]", True),
    ("[anon:scudo:primary]", False), ("[anon:libc_malloc]", False),
    ("[anon:jemalloc]", False), ("[anon:dalvik-main space]", False),
    ("[anon:stack_and_tls:123]", False), ("[anon:cfi shadow]", False),
    ("[anon_shmem:x]", False), ("[heap]", False), ("[stack]", False),
    ("[vvar]", False), ("/usr/lib/libc.so.6", False),
])
def test_is_anonymous_name(name, ok):
    assert pa.is_anonymous_name(name) is ok


def test_thread_heap_info_needs_an_anonymous_region():
    va, arena = 0x7FFF_E400_0000, 0x7FFF_E400_0030
    words = _Words({va: arena, va + 8: 0, va + 16: 0x2000, va + 24: 0x2000, arena: 0})
    region = MappedRegion(va, 0x2000, "rw-p", "", None, True)
    info = pa.thread_heap_info(words, region, 8)
    assert info is not None and (info.ar_ptr, info.size) == (arena, 0x2000)
    assert pa.is_thread_heap_region(words, region, 8)
    named = dataclasses.replace(region, name="[anon:scudo:primary]")
    assert pa.thread_heap_info(words, named, 8) is None
