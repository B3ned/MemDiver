"""glibc ptmalloc2 mmapped chunks: page-granular scan of anonymous mappings."""

import dataclasses
import random
import struct

import numpy as np
import pytest

from memdiver.engine import consensus_heap as ch
from memdiver.heap.allocators import ptmalloc2_mmapped as pm
from memdiver.heap.allocators.ptmalloc2 import parse_dlmalloc, parse_ptmalloc2
from memdiver.heap.allocators.ptmalloc2_walk import _Geometry, _PagedReader
from memdiver.heap.memory import VaMemory
from memdiver.heap.model import (ARENA_MMAP, REGION_MAIN_HEAP, REGION_MMAPPED_CHUNK,
                                 HeapRole)
from memdiver.heap.platform import MappedRegion
from memdiver.heap.registry import DetectContext, ParseOptions
from memdiver.heap.segments import ChunkBudget
from tests.fixtures import synth_heap as sh
from tests.test_heap_ptmalloc2 import _platform
from tests.test_heap_ptmalloc2_arenas import _process

VA32 = 0xB700_0000
KEY = bytes(range(0xA0, 0xC0))


@pytest.fixture
def load(tmp_path):
    """Open synthetic heaps as a regioned raw dump -> (memory, ctx)."""
    opened = []

    def _load(*heaps, pointer_size=8, modules=()):
        path = tmp_path / str(len(opened))
        source = sh.open_regioned(sh.as_regioned_raw(path, heaps, modules))
        opened.append(source)
        platform = _platform(pointer_size)
        return VaMemory(source, platform), DetectContext(source, platform=platform)

    yield _load
    for source in opened:
        source.close()


def _parse(load, *heaps, pointer_size=8, opts=None, modules=()):
    memory, ctx = load(*heaps, pointer_size=pointer_size, modules=modules)
    return parse_ptmalloc2(memory, ctx, opts or ParseOptions())


def _parse_with_main(load, *heaps, pointer_size=8):
    """Parse *heaps* next to a main ``[heap]`` (the ptmalloc2 evidence the scan needs)."""
    return _parse(load, sh.glibc_heap(pointer_size=pointer_size), *heaps,
                  pointer_size=pointer_size)


def _mmapped(layout):
    return [c for c in layout.chunks if c.bin == pm.MMAPPED_BIN]


def _rows(chunks):
    return [(c.va, c.size, c.state, c.bin, c.flags) for c in chunks]


def _expected(heap):
    return [(c.va, c.size, c.state, c.bin, c.flags) for c in heap.chunks]


def _with_word(heap, va, value):
    buf = bytearray(heap.data)
    fmt = "<Q" if heap.pointer_size == 8 else "<I"
    struct.pack_into(fmt, buf, va - heap.base_va, value)
    return dataclasses.replace(heap, data=bytes(buf))


# -- the validator -------------------------------------------------------------------


@pytest.mark.parametrize("prev, word, corr, ok", [
    (0, 0x21000 | 2, 0, True),
    (16, (0x21000 - 16) | 2, 16, True),
    (0, 0x21000 | 3, 0, False),             # PREV_INUSE
    (0, 0x21000 | 6, 0, False),             # NON_MAIN_ARENA
    (0, 0x21000, 0, False),                 # IS_MMAPPED clear
    (0, 0x800 | 2, 0, False),               # below one page
    (0, 0x21010 | 2, 0, False),             # mapping not page-rounded
    (8, 0x21000 | 2, 16, False),            # prev_size != correction
    (8, (0x21000 - 8) | 2, 8, False),       # correction not aligned
])
def test_valid_mmapped_header(prev, word, corr, ok):
    assert pm.valid_mmapped_header(prev, word, corr, 16) is ok


# -- hits ------------------------------------------------------------------------------


@pytest.mark.parametrize("pointer_size, va", [(8, sh.MMAPPED_VA), (4, VA32)])
def test_single_mmapped_chunk(load, pointer_size, va):
    heap = sh.glibc_mmapped_chunk(va, pointer_size=pointer_size)
    layout = _parse_with_main(load, heap, pointer_size=pointer_size)
    chunks = _mmapped(layout)
    assert _rows(chunks) == _expected(heap)
    chunk = chunks[0]
    assert chunk.header_len == 2 * pointer_size
    assert chunk.user_va == va + 2 * pointer_size
    assert chunk.user_len == 0x21000 - 2 * pointer_size
    assert chunk.confidence == pm.HIT_CONFIDENCE
    assert chunk.extra == {"prev_size": 0, "size_word": 0x21002, "mmapped": True}
    assert layout.coverage["mmapped_chunks"] == 1


def test_correction_hit(load):
    heap = sh.glibc_mmapped_chunk(correction=16)
    chunk, = _mmapped(_parse_with_main(load, heap))
    assert (chunk.va, chunk.size) == (sh.MMAPPED_VA + 16, 0x21000 - 16)
    assert chunk.extra["prev_size"] == 16


def test_back_to_back_chunks_in_one_region(load):
    heap = sh.glibc_mmapped_chunks(sizes=(0x21000, 0x30000))
    layout = _parse_with_main(load, heap)
    assert _rows(_mmapped(layout)) == _expected(heap)
    region, = [r for r in layout.regions if r.kind == REGION_MMAPPED_CHUNK]
    assert (region.va, region.size) == (sh.MMAPPED_VA, 0x51000)


def test_arena_and_region_stamping(load):
    main, libc, threads = _process({})
    mmapped = sh.glibc_mmapped_chunk()
    layout = _parse(load, main, libc, *threads, mmapped)
    arena = layout.arenas[-1]
    assert arena.kind == ARENA_MMAP and arena.arena_id == len(layout.arenas) - 1 == 2
    assert arena.extra == {"chunks": 1} and arena.region_vas == (sh.MMAPPED_VA,)
    region = next(r for r in layout.regions if r.kind == REGION_MMAPPED_CHUNK)
    assert region.arena_id == arena.arena_id
    assert {c.arena_id for c in _mmapped(layout)} == {arena.arena_id}
    assert any(e.detail == "mmap: 1 mmapped chunks" for e in layout.evidence)


def test_mmapped_bytes_do_not_lower_confidence(load):
    main = sh.glibc_heap()
    alone = _parse(load, main)
    both = _parse(load, main, sh.glibc_mmapped_chunk())
    assert both.confidence >= alone.confidence
    cov = both.coverage
    assert cov["bytes_total"] == alone.coverage["bytes_total"] + 0x21000
    assert cov["bytes_walked"] == alone.coverage["bytes_walked"] + 0x21000
    assert cov["chunk_count"] == len(both.chunks)


def test_existing_layouts_unchanged_without_hits(load):
    main, libc, threads = _process({})
    layout = _parse(load, main, libc, *threads)
    assert ARENA_MMAP not in {a.kind for a in layout.arenas}
    assert REGION_MMAPPED_CHUNK not in {r.kind for r in layout.regions}
    assert layout.coverage["mmapped_chunks"] == 0
    assert not _mmapped(layout)


def test_dlmalloc_does_not_scan(load):
    memory, ctx = load(sh.dlmalloc_heap(), sh.glibc_mmapped_chunk())
    layout = parse_dlmalloc(memory, ctx, ParseOptions())
    assert not _mmapped(layout) and layout.coverage["mmapped_chunks"] == 0


@pytest.mark.parametrize("pointer_size, va", [(8, sh.MMAPPED_VA), (4, VA32)])
def test_mmapped_header_alone_is_not_a_ptmalloc2_heap(load, pointer_size, va):
    """No ``[heap]`` and no thread arena: the scan alone proves nothing."""
    layout = _parse(load, sh.glibc_mmapped_chunk(va, pointer_size=pointer_size),
                    pointer_size=pointer_size)
    assert layout.chunks == () and not layout.arenas
    assert layout.diagnostics == ("no captured ptmalloc2 heap region (looked for [heap])",)
    assert layout.coverage == {"regions": [], "bytes_total": 0, "chunk_count": 0}


def test_scanned_thread_arena_without_main_heap_still_scans(load):
    """Static binary: heap_info-scan thread arenas are evidence enough."""
    _main, _libc, (thread,) = _process({}, with_libc=False)
    mmapped = sh.glibc_mmapped_chunk()
    layout = _parse(load, thread, mmapped)
    assert layout.coverage["arena_discovery"] == "heap_info_scan"
    assert _rows(_mmapped(layout)) == _expected(mmapped)


# -- rejections -----------------------------------------------------------------------


def test_prev_inuse_rejected(load):
    heap = _with_word(sh.glibc_mmapped_chunk(), sh.MMAPPED_VA + 8, 0x21000 | 3)
    assert not _mmapped(_parse_with_main(load, heap))


def test_size_overrunning_region_rejected(load):
    heap = _with_word(sh.glibc_mmapped_chunk(), sh.MMAPPED_VA + 8, 0x22000 | 2)
    assert not _mmapped(_parse_with_main(load, heap))


@pytest.mark.parametrize("name", ["[heap]", "[stack]", "[anon:scudo:primary]",
                                  "[anon:stack_and_tls:123]", "[vvar]"])
def test_named_regions_ignored(load, name):
    heap = sh.glibc_mmapped_chunks(region_name=name)
    assert not _mmapped(_parse(load, heap, opts=ParseOptions(regions=(name,))))
    assert not _mmapped(_parse(load, heap))


def test_unknown_anon_label_scanned(load):
    heap = sh.glibc_mmapped_chunks(region_name="[anon:glibc big buffer]")
    assert len(_mmapped(_parse_with_main(load, heap))) == 1


def test_module_backed_region_ignored():
    region = sh.glibc_mmapped_chunk()
    mapped = MappedRegion(region.base_va, 0x21000, "rw-p", "/usr/lib/libx.so",
                             "/usr/lib/libx.so", True)
    assert not pm.is_candidate_region(mapped)
    assert pm.is_candidate_region(dataclasses.replace(mapped, name="", module_path=None))


def test_region_in_thread_heap_reservation_ignored(load):
    main, libc, threads = _process({})
    base = threads[0].base_va
    inside = sh.glibc_mmapped_chunk(base + 0x100000)
    layout = _parse(load, main, libc, *threads, inside)
    assert not _mmapped(layout)
    assert layout.coverage["thread_arenas"] == 1


def test_claimed_main_region_ignored(load):
    heap = sh.glibc_mmapped_chunk()
    memory, ctx = load(heap)
    region = next(r for r in ctx.regions if r.va == heap.base_va)
    scan = pm.scan_mmapped_chunks(_PagedReader(memory, _Geometry(8, "little")),
                                  ctx.regions, arena_id=1, budget=ChunkBudget(10),
                                  claimed=[(region.va, region.end)],
                                  selects=lambda r: True)
    assert not scan.chunks and not scan.arenas()


def test_explicit_region_selection(load):
    heap = sh.glibc_mmapped_chunk()
    assert not _mmapped(_parse(load, sh.glibc_heap(), heap,
                               opts=ParseOptions(regions=("[heap]",))))
    layout = _parse(load, sh.glibc_heap(), heap, opts=ParseOptions(regions=("[heap]", "")))
    assert _rows(_mmapped(layout)) == _expected(heap)
    assert REGION_MAIN_HEAP in {r.kind for r in layout.regions}


def test_max_chunks_budget_is_shared(load):
    main = sh.glibc_heap()
    heap = sh.glibc_mmapped_chunks(sizes=(0x2000, 0x3000, 0x4000))
    layout = _parse(load, main, heap, opts=ParseOptions(max_chunks=len(main.chunks) + 2))
    assert len(layout.chunks) == len(main.chunks) + 2
    assert len(_mmapped(layout)) == 2
    assert layout.coverage["truncated"] is True
    assert sum("max_chunks" in d for d in layout.diagnostics) == 1


def test_uncaptured_tail_lowers_confidence():
    heap = sh.glibc_mmapped_chunk(size=0x3000)

    class Holey:
        def read(self, va, n):
            if va >= heap.base_va + 0x2000:
                return None
            return heap.read(va, n)

    region = MappedRegion(heap.base_va, 0x3000, "rw-p", "", None, True)
    chunk, = pm.scan_region(_PagedReader(Holey(), _Geometry(8, "little")), region, 3,
                            ChunkBudget(10))
    assert chunk.confidence == pm.TAIL_UNCAPTURED_CONFIDENCE and chunk.arena_id == 3


# -- false-positive control ----------------------------------------------------------


@pytest.mark.parametrize("pointer_size", [8, 4])
def test_random_and_zero_pages_yield_no_hits(load, pointer_size):
    base = 0x7F00_0100_0000 if pointer_size == 8 else 0xB000_0000
    rand = sh.random_region(seed=1234, base_va=base, region_size=512 * sh.PAGE)
    zero = dataclasses.replace(sh.random_region(base_va=base + 0x1000000,
                                                region_size=64 * sh.PAGE),
                               data=bytes(64 * sh.PAGE))
    layout = _parse(load, rand, zero, pointer_size=pointer_size)
    assert not _mmapped(layout)
    assert ARENA_MMAP not in {a.kind for a in layout.arenas}


def test_random_pages_scan_directly_has_no_hits():
    rng = random.Random(20261109)
    hits = 0
    for _ in range(4096):
        words = [rng.getrandbits(64) for _ in range(8)]
        hits += any(pm.valid_mmapped_header(words[2 * k], words[2 * k + 1], 16 * k, 16)
                    for k in range(pm.MAX_CORRECTION_SLOTS))
    assert hits == 0


# -- integration: consensus projection ----------------------------------------------


def test_key_in_mmapped_chunk_projects_to_user_data(tmp_path):
    main = sh.glibc_heap()
    mmapped = sh.glibc_mmapped_chunk(size=0x3000, payload=KEY)
    path = sh.as_regioned_raw(tmp_path, [main, mmapped])
    source = sh.open_regioned(path)
    try:
        regions = sorted(main.regions + mmapped.regions)
        slab = sum(size for _va, size, _name in regions)
        proj, record = ch.project_dump_heap(source, slab, "ptmalloc2")
    finally:
        source.close()
    assert record["status"] == ch.STATUS_OK
    flat = 0
    for va, size, _name in regions:
        if va == mmapped.base_va:
            break
        flat += size
    key_off = flat + mmapped.meta["user_va"] - mmapped.base_va
    starts, lengths, roles = proj.pieces
    covering = np.nonzero((starts <= key_off) & (key_off + len(KEY) <= starts + lengths))[0]
    assert covering.size == 1
    assert HeapRole(int(roles[covering[0]])) is HeapRole.USER_DATA
