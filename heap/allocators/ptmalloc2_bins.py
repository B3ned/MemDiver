"""ptmalloc2 free-list decoding: tcache, fastbins, unsorted / small / large bins
and locating ``main_arena`` in glibc's writable data.

Split out of :mod:`.ptmalloc2`, which documents the algorithm and limitations.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from memdiver.heap.allocators.ptmalloc2_segments import MAIN_ARENA_ID
from memdiver.heap.allocators.ptmalloc2_walk import (_TCACHE_BINS, _NBINS,
                                                     _FIRST_LARGE_BIN, _MAX_LIST_LEN,
                                                     _MAX_ARENA_SCAN, _GLIBC_MODULES,
                                                     _Roles, _Geometry, _PagedReader,
                                                     _Slot, _link_roles, _Heap)
from memdiver.heap.memory import VaMemory
from memdiver.heap.model import ChunkState, FreeList
from memdiver.heap.platform import MappedRegion
from memdiver.heap.registry import DetectContext


# -- free-list walks ------------------------------------------------------------------


@dataclass(frozen=True)
class _Chain:
    nodes: Tuple[int, ...]
    cycle: bool = False
    broken: bool = False


def _reveal(pos: int, stored: int) -> int:
    """glibc >= 2.32 ``REVEAL_PTR``: ``(pos >> 12) ^ stored``."""
    return (pos >> 12) ^ stored


def _walk_singly(reader: _PagedReader, first: int, link_offset: int, safe: bool,
                 to_chunk: Callable[[int], Optional[int]]) -> _Chain:
    """Follow a NULL-terminated list whose link sits at ``node + link_offset``."""
    nodes: List[int] = []
    node = first
    while node:
        chunk_va = to_chunk(node)
        if chunk_va is None or len(nodes) >= _MAX_LIST_LEN:
            return _Chain(tuple(nodes), broken=True)
        if chunk_va in nodes:
            return _Chain(tuple(nodes), cycle=True)
        nodes.append(chunk_va)
        stored = reader.word(node + link_offset)
        if stored is None:
            return _Chain(tuple(nodes), broken=True)
        node = _reveal(node + link_offset, stored) if safe else stored
    return _Chain(tuple(nodes))


def _walk_double(reader: _PagedReader, header_va: int, geo: _Geometry,
                 to_chunk: Callable[[int], Optional[int]]) -> _Chain:
    """Follow ``fd`` from a circular bin header back to itself."""
    nodes: List[int] = []
    node = reader.word(header_va + geo.header)
    while node is not None and node != header_va:
        if to_chunk(node) is None or len(nodes) >= _MAX_LIST_LEN:
            return _Chain(tuple(nodes), broken=True)
        if node in nodes:
            return _Chain(tuple(nodes), cycle=True)
        nodes.append(node)
        node = reader.word(node + geo.header)
    return _Chain(tuple(nodes), broken=node is None)


def _chains_badness(chains: Sequence[_Chain]) -> Tuple[int, int]:
    return (sum(c.broken or c.cycle for c in chains), -sum(len(c.nodes) for c in chains))


def _pick_decoding(walk: Callable[[bool], List[_Chain]],
                   hint: Optional[bool]) -> Tuple[Optional[bool], List[_Chain]]:
    """Decode plain and safe-linked; keep whichever forms in-heap chains.

    Returns ``(safe, chains)``; ``safe`` is ``None`` when neither wins.
    """
    if hint is not None:
        return hint, walk(hint)
    plain, safe = walk(False), walk(True)
    if _chains_badness(safe) < _chains_badness(plain):
        return True, safe
    if _chains_badness(plain) < _chains_badness(safe):
        return False, plain
    return None, plain


@dataclass
class _Lists:
    """Free lists found so far, their diagnostics and the safe-linking verdict.

    ``safe`` is the process-wide verdict: the main arena's, or the first
    decided thread arena's when the main tcache gave none. ``arena_safe``
    keeps each arena's own tcache verdict (its fastbins are decoded with it).
    """

    free_lists: List[FreeList] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    safe: Optional[bool] = None
    arena_safe: Dict[int, Optional[bool]] = field(default_factory=dict)

    def record_safe(self, arena_id: int, safe: Optional[bool]) -> None:
        """Record *arena_id*'s verdict; only the main arena may override ``safe``."""
        self.arena_safe[arena_id] = safe
        if arena_id == MAIN_ARENA_ID or self.safe is None:
            self.safe = safe

    def safe_hint(self, arena_id: int) -> Optional[bool]:
        """*arena_id*'s own verdict, else the process-wide one."""
        own = self.arena_safe.get(arena_id)
        return self.safe if own is None else own


def _record(lists: _Lists, kind: str, index: int, head_va: int, chain: _Chain,
            decoded: bool, arena_id: int = MAIN_ARENA_ID) -> None:
    lists.free_lists.append(FreeList(kind, index, head_va, chain.nodes, decoded,
                                     chain.cycle, arena_id))
    name = f"{kind}[{index}]"
    if arena_id != MAIN_ARENA_ID:
        name = f"arena {arena_id} {name}"
    if chain.cycle:
        lists.diagnostics.append(f"{name} contains a cycle")
    elif chain.broken:
        lists.diagnostics.append(
            f"{name} ends at an invalid or uncaptured pointer "
            f"after {len(chain.nodes)} chunk(s)")


def _mark(heap: _Heap, chain: _Chain, state: ChunkState, label: str,
          roles: _Roles) -> None:
    for chunk_va in chain.nodes:
        slot = heap.by_va[chunk_va]
        slot.state, slot.bin, slot.roles = state, label, roles


# -- tcache ---------------------------------------------------------------------------


def _tcache_struct_sizes(geo: _Geometry) -> Dict[int, int]:
    """Chunk size of ``tcache_perthread_struct`` -> width of ``counts[]``."""
    sizes: Dict[int, int] = {}
    for width in (2, 1):
        request = width * _TCACHE_BINS + geo.ptr * _TCACHE_BINS
        sizes[(request + geo.ptr + geo.align - 1) & ~(geo.align - 1)] = width
    return sizes


_VERSION_BY_WIDTH = {2: "glibc>=2.30", 1: "glibc 2.26-2.29"}


def _mark_tcache_struct(heap: _Heap, geo: _Geometry) -> Optional[_Slot]:
    """Flag the heap's first chunk as ``tcache_perthread_struct`` when it fits."""
    if not heap.slots:
        return None
    return _mark_tcache_struct_at(heap.slots[0], geo)


def _mark_tcache_struct_at(first: Optional[_Slot], geo: _Geometry) -> Optional[_Slot]:
    """Flag *first* (an arena's first chunk) as ``tcache_perthread_struct``."""
    if first is None:
        return None
    width = _tcache_struct_sizes(geo).get(first.raw.size)
    if width is None or first.bin == "top":
        return None
    first.state, first.bin, first.roles = (ChunkState.IN_USE,
                                           "tcache_perthread_struct", None)
    first.extra = {"meta": True, "struct": "tcache_perthread_struct",
                   "counts_width": width}
    return first


def _tcache_heads(reader: _PagedReader, struct_slot: _Slot,
                  geo: _Geometry) -> Iterator[Tuple[int, int, int, int]]:
    """``(index, count, entry_slot_va, head)`` for every non-empty bin."""
    width = struct_slot.extra["counts_width"]
    counts_va = struct_slot.raw.va + geo.header
    entries_va = counts_va + width * _TCACHE_BINS
    for idx in range(_TCACHE_BINS):
        head = reader.word(entries_va + idx * geo.ptr)
        if head:
            count = reader.uint(counts_va + idx * width, width) or 0
            yield idx, count, entries_va + idx * geo.ptr, head


def _decode_tcache(reader: _PagedReader, heap: _Heap, struct_slot: _Slot,
                   geo: _Geometry, lists: _Lists, arena_id: int = MAIN_ARENA_ID) -> None:
    heads = list(_tcache_heads(reader, struct_slot, geo))

    def user_to_chunk(mem: int) -> Optional[int]:
        return heap.free_candidate(mem - geo.header) if mem % geo.align == 0 else None

    def walk(safe: bool) -> List[_Chain]:
        return [_walk_singly(reader, head, 0, safe, user_to_chunk)
                for _i, _c, _s, head in heads]

    safe, chains = _pick_decoding(walk, None)
    lists.record_safe(arena_id, safe)
    for (idx, count, slot_va, _head), chain in zip(heads, chains):
        _record(lists, "tcache", idx, slot_va, chain, bool(safe), arena_id)
        _mark(heap, chain, ChunkState.CACHED, f"tcache[{idx}]", _link_roles(geo, 2))
        if count != len(chain.nodes):
            lists.diagnostics.append(
                f"tcache[{idx}] count {count} != walked length {len(chain.nodes)}")


def _version_hint(struct_slot: Optional[_Slot], safe: Optional[bool]) -> str:
    if struct_slot is None:
        return "glibc<2.26 or tcache disabled"
    width = struct_slot.extra["counts_width"]
    if width == 2 and safe is True:
        return "glibc>=2.32"
    if width == 2 and safe is False:
        return "glibc 2.30-2.31"
    return _VERSION_BY_WIDTH[width]


# -- main_arena -----------------------------------------------------------------------


def _libc_data_regions(regions: Sequence[MappedRegion]) -> List[MappedRegion]:
    return [r for r in regions
            if "w" in r.perms and r.captured and r.size <= _MAX_ARENA_SCAN
            and r.module_path
            and any(fnmatch(os.path.basename(r.module_path), p) for p in _GLIBC_MODULES)]


def _aligned_hits(data: bytes, needle: bytes, step: int) -> Iterator[int]:
    pos = data.find(needle)
    while pos >= 0:
        if pos % step == 0:
            yield pos
        pos = data.find(needle, pos + 1)


def _bins_consistent(reader: _PagedReader, top_slot_va: int, geo: _Geometry,
                     heap: _Heap) -> bool:
    """Every ``bins[]`` pair is self-linked (empty) or points into the heap."""
    words = [reader.word(top_slot_va + (2 + i) * geo.ptr) for i in range(2 * _NBINS - 2)]
    empty = 0
    for pair in range(_NBINS - 1):
        header_va = top_slot_va + 2 * pair * geo.ptr
        fd, bk = words[2 * pair], words[2 * pair + 1]
        if fd is None or bk is None:
            return False
        if fd == bk == header_va:
            empty += 1
        elif not (heap.contains(fd) and heap.contains(bk)):
            return False
    return empty > 0


def _find_main_arena(memory: VaMemory, reader: _PagedReader, regions: Sequence[MappedRegion],
                     geo: _Geometry, heap: _Heap, top_va: int) -> Optional[int]:
    """VA of ``main_arena.top`` inside glibc's writable data, or ``None``."""
    needle = geo.pack(top_va)
    for region in _libc_data_regions(regions):
        data = memory.read(region.va, region.size)
        if data is None:
            continue
        for offset in _aligned_hits(data, needle, geo.ptr):
            if _bins_consistent(reader, region.va + offset, geo, heap):
                return region.va + offset
    return None


def _nfastbins(geo: _Geometry) -> int:
    """``NFASTBINS = fastbin_index(request2size(MAX_FAST_SIZE)) + 1``."""
    max_fast = 80 * geo.ptr // 4
    request = max(geo.min_chunk, (max_fast + geo.ptr + geo.align - 1) & ~(geo.align - 1))
    return (request >> (4 if geo.ptr == 8 else 3)) - 2 + 1


def _decode_fastbins(reader: _PagedReader, heap: _Heap, top_slot_va: int,
                     geo: _Geometry, lists: _Lists, arena_id: int = MAIN_ARENA_ID) -> None:
    base = top_slot_va - _nfastbins(geo) * geo.ptr
    heads = [(i, base + i * geo.ptr, reader.word(base + i * geo.ptr))
             for i in range(_nfastbins(geo))]
    present = [(i, slot_va, head) for i, slot_va, head in heads if head]

    def walk(safe: bool) -> List[_Chain]:
        return [_walk_singly(reader, head, geo.header, safe, heap.free_candidate)
                for _i, _s, head in present]

    safe, chains = _pick_decoding(walk, lists.safe_hint(arena_id))
    for (idx, slot_va, _head), chain in zip(present, chains):
        _record(lists, "fastbin", idx, slot_va, chain, bool(safe), arena_id)
        _mark(heap, chain, ChunkState.CACHED, f"fastbin[{idx}]", _link_roles(geo, 1))


def _bin_label(index: int) -> Tuple[str, str, int]:
    """``(kind, label, link words)`` of ``bin_at(index)``."""
    if index == 1:
        return "unsorted", "unsorted", 2
    if index < _FIRST_LARGE_BIN:
        return "smallbin", f"smallbin[{index}]", 2
    return "largebin", f"largebin[{index}]", 4


def _decode_bins(reader: _PagedReader, heap: _Heap, top_slot_va: int,
                 geo: _Geometry, lists: _Lists, arena_id: int = MAIN_ARENA_ID) -> None:
    for index in range(1, _NBINS - 1):
        header_va = top_slot_va + 2 * (index - 1) * geo.ptr
        chain = _walk_double(reader, header_va, geo, heap.free_candidate)
        if not chain.nodes and not chain.broken:
            continue
        kind, label, words = _bin_label(index)
        _record(lists, kind, index, header_va, chain, False, arena_id)
        _mark(heap, chain, ChunkState.FREE, label, _link_roles(geo, words))


def _decode_arena(memory: VaMemory, reader: _PagedReader, ctx: DetectContext,
                  heap: _Heap, geo: _Geometry, lists: _Lists) -> Optional[int]:
    arena_top = _locate_main_arena(memory, reader, ctx, heap, geo)
    _decode_main_arena(reader, heap, arena_top, geo, lists)
    return arena_top


def _locate_main_arena(memory: VaMemory, reader: _PagedReader, ctx: DetectContext,
                       heap: _Heap, geo: _Geometry) -> Optional[int]:
    """``&main_arena.top`` for the walked main heap's top chunk, or ``None``."""
    top = heap.top()
    return (None if top is None else
            _find_main_arena(memory, reader, ctx.regions, geo, heap, top.raw.va))


def _decode_main_arena(reader: _PagedReader, heap: _Heap, arena_top: Optional[int],
                       geo: _Geometry, lists: _Lists) -> None:
    """Decode ``main_arena``'s bins, or say why they could not be decoded."""
    if arena_top is None:
        lists.diagnostics.append(
            "main_arena not found (no captured glibc data mapping referencing the "
            "top chunk): fastbin/unsorted/small/large bins not decoded, fastbin "
            "chunks appear in use")
        return
    _decode_arena_at(reader, heap, arena_top, geo, lists)


def _decode_arena_at(reader: _PagedReader, heap: _Heap, top_slot_va: int,
                     geo: _Geometry, lists: _Lists, arena_id: int = MAIN_ARENA_ID) -> None:
    """Fastbins + unsorted/small/large bins of the arena whose ``top`` is at *top_slot_va*."""
    _decode_fastbins(reader, heap, top_slot_va, geo, lists, arena_id)
    _decode_bins(reader, heap, top_slot_va, geo, lists, arena_id)
