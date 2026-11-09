"""End-to-end heap analysis of ``.msl`` dumps built with :class:`MslWriter`.

MSL is MemDiver's primary dump format, so the heap layer must see the
VAS_MAP mapping names (``[heap]``, ``[anon:scudo:primary]``, module paths)
even when the file is IMPORTED without a ``region_names=1`` provenance note
(the writer default), where region classification ignores them.
"""

import pytest

from memdiver.core.dump_source import open_dump
from memdiver.heap.analyze import analyze_heap
from memdiver.heap.model import AllocatorKind
from memdiver.heap.platform import memory_map_of, module_paths
from memdiver.msl.enums import ArchType, OSType
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import ModuleEntrySpec, MslWriter
from tests.fixtures import synth_heap as sh

LIBC_VA = 0x7F00_0000_0000
LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"
_RW, _RX = 0x03, 0x05


def _write_msl(path, heap, os_type, module_path, *, imported=True):
    """MSL holding every region of *heap* plus a VAS-only *module_path*."""
    writer = MslWriter(path, os_type=os_type, arch_type=ArchType.X86_64,
                       imported=imported)
    vas = []
    for idx, (va, size, name) in enumerate(heap.regions):
        writer.add_memory_region(va, heap.region_bytes(idx), protection=_RW)
        vas.append(MslVasEntry(va, size, _RW, 0, name))
    writer.add_module_list_index([ModuleEntrySpec(LIBC_VA, 0x1000, module_path)])
    vas.append(MslVasEntry(LIBC_VA, 0x1000, _RX, 0, module_path))
    writer.add_vas_map(vas)
    writer.write()
    return path


def _chunk_triples(chunks):
    return [(c.va, c.size, c.state) for c in chunks]


@pytest.mark.parametrize("imported", [True, False])
def test_memory_map_carries_vas_names(tmp_path, imported):
    heap = sh.glibc_heap()
    path = _write_msl(tmp_path / "h.msl", heap, OSType.LINUX, LIBC_PATH,
                      imported=imported)
    with open_dump(path) as src:
        regions = memory_map_of(src)
        assert [(r.va, r.name, r.captured) for r in regions] == [
            (heap.base_va, "[heap]", True)]
        assert LIBC_PATH in module_paths(src)


def test_split_region_blocks_all_named(tmp_path):
    heap = sh.glibc_heap(region_size=4 * sh.PAGE)
    path = tmp_path / "h.msl"
    writer = MslWriter(path, os_type=OSType.LINUX, arch_type=ArchType.X86_64,
                       region_block_cap=sh.PAGE)
    writer.add_memory_region(heap.base_va, heap.data, protection=_RW)
    writer.add_vas_map([MslVasEntry(heap.base_va, len(heap.data), _RW, 0,
                                    "[heap]")])
    writer.write()
    with open_dump(path) as src:
        names = {r.name for r in memory_map_of(src)}
    assert names == {"[heap]"}


def test_analyze_glibc_heap_msl(tmp_path):
    heap = sh.glibc_heap()
    path = _write_msl(tmp_path / "glibc.msl", heap, OSType.LINUX, LIBC_PATH)
    with open_dump(path) as src:
        layout = analyze_heap(src)
    assert layout.allocator is AllocatorKind.PTMALLOC2
    assert _chunk_triples(layout.chunks) == _chunk_triples(heap.chunks)


def test_analyze_scudo_primary_msl(tmp_path):
    heap = sh.scudo_primary()
    path = _write_msl(tmp_path / "scudo.msl", heap, OSType.ANDROID,
                      "/apex/com.android.runtime/lib64/bionic/libc.so")
    with open_dump(path) as src:
        layout = analyze_heap(src)
    assert layout.allocator is AllocatorKind.SCUDO
    assert _chunk_triples(layout.chunks) == _chunk_triples(heap.chunks)


# -- VAS-map-only libc (non-imported .msl, no module list) -------------------------


def arena_process_heaps(seed: int = 0):
    """``(heaps, meta)``: main heap, libc ``main_arena`` page, thread arena, mmapped chunk.

    The thread arena's key slot and the mmapped chunk's payload hold 32
    random bytes seeded by *seed*; ``meta`` has ``thread_key_va`` and
    ``mmap_key_va``. Heaps are sorted by base VA (= flat-view order).
    """
    import random

    rng = random.Random(1000 + seed)
    main = sh.glibc_heap()
    libc = sh.glibc_main_arena_page(
        main.chunks[-1].va, next_arena=sh.thread_arena_va(0x7FFF_E400_0000))
    thread = sh.glibc_thread_arena(next_arena=libc.meta["arena_va"])
    key_off = thread.meta["key_va"] - thread.base_va
    data = bytearray(thread.data)
    data[key_off:key_off + 32] = bytes(rng.randrange(256) for _ in range(32))
    thread.data = bytes(data)
    mmapped = sh.glibc_mmapped_chunk(payload=bytes(rng.randrange(256) for _ in range(32)))
    meta = {"thread_key_va": thread.meta["key_va"], "mmap_key_va": mmapped.meta["user_va"]}
    return sorted((main, libc, thread, mmapped), key=lambda h: h.base_va), meta


def write_vas_only_msl(path, heaps):
    """Non-imported ``.msl`` naming libc only in the VAS map (no module list)."""
    writer = MslWriter(path, os_type=OSType.LINUX, arch_type=ArchType.X86_64,
                       imported=False)
    vas = []
    for heap in heaps:
        writer.add_memory_region(heap.base_va, heap.data, protection=_RW)
        vas.append(MslVasEntry(heap.base_va, len(heap.data), _RW, 0,
                               heap.regions[0][2]))
    writer.add_vas_map(vas)
    writer.write()
    return path


def test_vas_named_libc_gets_module_path(tmp_path):
    heaps, _meta = arena_process_heaps()
    libc = next(h for h in heaps if h.allocator == "libc")
    path = write_vas_only_msl(tmp_path / "p.msl", heaps)
    with open_dump(path) as src:
        regions = {r.va: r for r in memory_map_of(src)}
    libc_path = libc.regions[0][2]
    assert regions[libc.base_va].name == libc_path
    assert regions[libc.base_va].module_path == libc_path
    assert all(r.module_path is None for va, r in regions.items() if va != libc.base_va)


def test_vas_named_libc_finds_main_arena_ring(tmp_path):
    heaps, _meta = arena_process_heaps()
    path = write_vas_only_msl(tmp_path / "p.msl", heaps)
    with open_dump(path) as src:
        layout = analyze_heap(src)
    assert layout.allocator is AllocatorKind.PTMALLOC2
    assert layout.coverage.get("arena_discovery") == "ring"
    assert "main_arena_top_va" in layout.coverage
    assert sorted(a.kind for a in layout.arenas) == ["main", "mmap", "thread"]
