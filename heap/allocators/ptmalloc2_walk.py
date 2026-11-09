"""ptmalloc2 / dlmalloc boundary-tag walker: geometry, flavours, paged reads,
the chunk-header walk with resync and fencepost detection, and the slot model.

Split out of :mod:`.ptmalloc2`, which documents the algorithm and limitations.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence, Tuple

from memdiver.heap.memory import VaMemory
from memdiver.heap.model import AllocatorKind, ChunkState, HeapRole
from memdiver.heap.platform import MappedRegion, TargetPlatform
from memdiver.heap.segments import HeapSegment

if TYPE_CHECKING:  # ptmalloc2_segments re-exports is_fencepost from here
    from memdiver.heap.allocators.ptmalloc2_segments import WalkSpan

_PREV_INUSE = 0x1
_IS_MMAPPED = 0x2        # dlmalloc: CINUSE_BIT
_NON_MAIN_ARENA = 0x4
_FLAG_BITS = 0x7
_TCACHE_BINS = 64
_NBINS = 128
_FIRST_LARGE_BIN = 64
_DL_MIN_LARGE_SIZE = 0x100
_PAGE = 0x1000
_PROBE_HEADERS = 32
_PROBE_REGIONS = 4
_MAX_LIST_LEN = 4096
_MAX_ARENA_SCAN = 8 << 20
_CACHE_PAGES = 256
_GLIBC_MODULES = ("libc.so.6", "libc-2.*.so", "libc.so")

_Roles = Tuple[Tuple[int, int, HeapRole], ...]


# -- geometry & flavours ----------------------------------------------------------


def _align_up(va: int, align: int) -> int:
    """*va* rounded up to a multiple of *align* (a power of two)."""
    return (va + align - 1) & ~(align - 1)


@dataclass(frozen=True)
class _Geometry:
    """Word size, endianness and the alignment derived from them."""

    ptr: int
    endian: str

    @property
    def align(self) -> int:
        return 2 * self.ptr

    @property
    def header(self) -> int:
        return 2 * self.ptr

    @property
    def min_chunk(self) -> int:
        return 4 * self.ptr

    def align_up(self, va: int) -> int:
        return _align_up(va, self.align)

    def pack(self, value: int) -> bytes:
        return value.to_bytes(self.ptr, "big" if self.endian == "big" else "little")


def _geometry(platform: TargetPlatform) -> _Geometry:
    return _Geometry(platform.pointer_size, platform.endianness)


@dataclass(frozen=True)
class _Flavor:
    kind: AllocatorKind
    region_patterns: Tuple[str, ...]
    dlmalloc: bool


_PTMALLOC2 = _Flavor(AllocatorKind.PTMALLOC2, ("[heap]",), False)
_DLMALLOC = _Flavor(AllocatorKind.DLMALLOC,
                    ("[heap]", "[anon:libc_malloc]", "*dlmalloc*"), True)


# -- paged reads --------------------------------------------------------------------


class _PagedReader:
    """Word reads by VA through a small LRU cache of page-sized reads."""

    def __init__(self, memory: VaMemory, geo: _Geometry):
        self._memory = memory
        self._geo = geo
        self._pages: "OrderedDict[int, Optional[bytes]]" = OrderedDict()

    def read(self, va: int, n: int) -> Optional[bytes]:
        page_va = va & ~(_PAGE - 1)
        page = self._page(page_va) if va + n <= page_va + _PAGE else None
        if page is None:
            return self._memory.read(va, n)
        return page[va - page_va:va - page_va + n]

    def _page(self, page_va: int) -> Optional[bytes]:
        if page_va in self._pages:
            self._pages.move_to_end(page_va)
            return self._pages[page_va]
        data = self._memory.read(page_va, _PAGE)
        self._pages[page_va] = data
        if len(self._pages) > _CACHE_PAGES:
            self._pages.popitem(last=False)
        return data

    def uint(self, va: int, width: int) -> Optional[int]:
        data = self.read(va, width)
        if data is None:
            return None
        return int.from_bytes(data, "big" if self._geo.endian == "big" else "little")

    def word(self, va: int) -> Optional[int]:
        return self.uint(va, self._geo.ptr)

    def words(self, va: int, count: int) -> Optional[List[int]]:
        """*count* consecutive words at *va* (``None`` unless all captured)."""
        data = self.read(va, count * self._geo.ptr)
        if data is None:
            return None
        big = self._geo.endian == "big"
        return [int.from_bytes(data[i:i + self._geo.ptr], "big" if big else "little")
                for i in range(0, len(data), self._geo.ptr)]

    @property
    def geo(self) -> _Geometry:
        return self._geo


# -- boundary-tag walk --------------------------------------------------------------


@dataclass(frozen=True)
class _Raw:
    """One walked chunk header. ``after_gap``: a resync/hole precedes it.

    ``fencepost``: glibc's end-of-heap marker (see :func:`is_fencepost`).
    """

    va: int
    size: int
    flags: int
    after_gap: bool
    region_end: int
    fencepost: bool = False

    @property
    def end(self) -> int:
        return self.va + self.size


@dataclass
class _Walk:
    raws: List[_Raw] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    skipped: int = 0
    uncaptured: int = 0
    truncated: bool = False
    spans: List[WalkSpan] = field(default_factory=list)


def _plausible(word: int, va: int, end: int, geo: _Geometry, flavor: _Flavor) -> bool:
    size = word & ~_FLAG_BITS
    if size < geo.min_chunk or size % geo.align or va + size > end:
        return False
    return flavor.dlmalloc or not word & _IS_MMAPPED


def _header_word(reader: _PagedReader, va: int, end: int, geo: _Geometry,
                 flavor: _Flavor) -> Optional[int]:
    """The size word at *va* when it forms a plausible header, else ``None``."""
    word = reader.word(va + geo.ptr)
    if word is None or not _plausible(word, va, end, geo, flavor):
        return None
    return word


def _resync(reader: _PagedReader, start: int, end: int, geo: _Geometry,
            flavor: _Flavor) -> int:
    """First aligned VA >= *start* whose header and successor are plausible."""
    va = geo.align_up(start)
    while va + geo.header <= end:
        word = _header_word(reader, va, end, geo, flavor)
        if word is not None:
            nxt = va + (word & ~_FLAG_BITS)
            if nxt == end or _header_word(reader, nxt, end, geo, flavor) is not None:
                return va
        va += geo.align
    return end


def _walk_region(reader: _PagedReader, region: MappedRegion, geo: _Geometry,
                 flavor: _Flavor, budget: int, walk: _Walk,
                 start: Optional[int] = None, end: Optional[int] = None) -> None:
    """Walk ``[start, end)`` (default: the whole *region*) into *walk*.

    A glibc fencepost right after a walked chunk ends the walk cleanly.
    """
    va = geo.align_up(region.va if start is None else start)
    end = region.end if end is None else end
    gap = False
    while va + geo.header <= end:
        if len(walk.raws) >= budget:
            walk.truncated = True
            return
        word = reader.word(va + geo.ptr)
        if word is not None and _plausible(word, va, end, geo, flavor):
            walk.raws.append(_Raw(va, word & ~_FLAG_BITS, word & _FLAG_BITS, gap, end))
            va, gap = va + (word & ~_FLAG_BITS), False
            continue
        if _ends_with_fencepost(reader, va, word, end, geo, flavor, walk):
            return
        va, gap = _skip_bad_header(reader, va, word, end, geo, flavor, walk), True


def is_fencepost(word_at: Callable[[int], Optional[int]], va: int, word: int,
                 end: int, ptr: int) -> bool:
    """``True`` when *word* (the size word at *va*) starts a glibc fencepost.

    glibc (``malloc/malloc.c`` ``sysmalloc``): when a non-main heap (or a
    non-contiguous main heap) is abandoned, the old top is followed by a
    chunk of size ``CHUNK_HDR_SZ`` (``2 * SIZE_SZ``) with PREV_INUSE and then
    a header whose size is ``0 | PREV_INUSE``; nothing valid follows it.
    The old top is then ``_int_free``d; unless it lands in a tcache or
    fastbin that clears the first fencepost's PREV_INUSE (``set_foot`` also
    stores the old top's size in its ``prev_size``). So *word* must have
    size ``2 * ptr`` (any flag bits) and the following header, which must
    lie inside ``[va, end)``, must have size 0 with PREV_INUSE set.
    """
    header = 2 * ptr
    if word & ~_FLAG_BITS != header:
        return False
    if va + header + 2 * ptr > end:
        return False
    trailer = word_at(va + header + ptr)
    return trailer is not None and trailer & ~_FLAG_BITS == 0 and bool(
        trailer & _PREV_INUSE)


def _ends_with_fencepost(reader: _PagedReader, va: int, word: Optional[int], end: int,
                         geo: _Geometry, flavor: _Flavor, walk: _Walk) -> bool:
    """Record a ptmalloc2 fencepost directly after the last walked chunk."""
    if word is None or flavor.dlmalloc or not walk.raws:
        return False
    last = walk.raws[-1]
    if last.end != va or last.region_end != end:
        return False
    if not is_fencepost(reader.word, va, word, end, geo.ptr):
        return False
    walk.raws.append(_Raw(va, word & ~_FLAG_BITS, word & _FLAG_BITS, False, end,
                          fencepost=True))
    return True


def _skip_bad_header(reader: _PagedReader, va: int, word: Optional[int], end: int,
                     geo: _Geometry, flavor: _Flavor, walk: _Walk) -> int:
    """Record why *va* is unusable and return where the walk resumes."""
    if word is None:
        hole_end = min((va & ~(_PAGE - 1)) + _PAGE, end)
        walk.uncaptured += hole_end - va
        resume = _resync(reader, hole_end, end, geo, flavor)
        walk.skipped += resume - hole_end
        return resume
    walk.diagnostics.append(
        f"implausible chunk header at {va:#x} (size word {word:#x}); resyncing")
    resume = _resync(reader, va + geo.align, end, geo, flavor)
    walk.skipped += resume - va
    if resume < end:
        walk.diagnostics.append(f"resynced at {resume:#x}")
    return resume


# -- chunk classification -------------------------------------------------------------


@dataclass
class _Slot:
    """A walked chunk plus the state/bin/roles the overlays assign to it."""

    raw: _Raw
    state: ChunkState
    bin: Optional[str] = None
    roles: Optional[_Roles] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def reserved(self) -> bool:
        """Top chunk or allocator metadata: never a free-list member."""
        return self.bin == "top" or bool(self.extra.get("meta"))


def _link_roles(geo: _Geometry, words: int) -> _Roles:
    return tuple((geo.header + i * geo.ptr, geo.ptr, HeapRole.FREE_LINK)
                 for i in range(words))


def _successor(raws: Sequence[_Raw], idx: int) -> Optional[_Raw]:
    if idx + 1 >= len(raws):
        return None
    nxt = raws[idx + 1]
    return nxt if nxt.va == raws[idx].end and not nxt.after_gap else None


def _base_state(raw: _Raw, nxt: Optional[_Raw], flavor: _Flavor) -> ChunkState:
    if flavor.dlmalloc:
        return ChunkState.IN_USE if raw.flags & _IS_MMAPPED else ChunkState.FREE
    if nxt is None:
        return ChunkState.UNKNOWN
    return ChunkState.IN_USE if nxt.flags & _PREV_INUSE else ChunkState.FREE


def _is_top(raw: _Raw, flavor: _Flavor) -> bool:
    if raw.end != raw.region_end:
        return False
    return not (flavor.dlmalloc and raw.flags & _IS_MMAPPED)


def _initial_slot(raws: Sequence[_Raw], idx: int, geo: _Geometry,
                  flavor: _Flavor) -> _Slot:
    raw = raws[idx]
    if raw.fencepost:
        return _Slot(raw, ChunkState.IN_USE, "fencepost",
                     extra={"meta": True, "fencepost": True})
    if _is_top(raw, flavor):
        return _Slot(raw, ChunkState.FREE, "top")
    slot = _Slot(raw, _base_state(raw, _successor(raws, idx), flavor))
    if slot.state is ChunkState.FREE:
        slot.roles = _link_roles(geo, 2)
        if flavor.dlmalloc:
            slot.bin = "smallbin" if raw.size < _DL_MIN_LARGE_SIZE else "treebin"
    return slot


class _Heap:
    """Walked slots indexed by chunk VA, plus the heap regions' extents."""

    def __init__(self, slots: List[_Slot], regions: Sequence[MappedRegion]):
        self.slots = slots
        self.by_va = {slot.raw.va: slot for slot in slots}
        self._extents = [(r.va, r.end) for r in regions]

    def free_candidate(self, chunk_va: int) -> Optional[int]:
        slot = self.by_va.get(chunk_va)
        return chunk_va if slot is not None and not slot.reserved else None

    def contains(self, va: int) -> bool:
        return any(lo <= va < hi for lo, hi in self._extents)

    def top(self) -> Optional[_Slot]:
        return next((s for s in self.slots if s.bin == "top"), None)

    def first_slot_in(self, lo: int, hi: int) -> Optional[_Slot]:
        """The first walked slot whose chunk starts in ``[lo, hi)``."""
        return next((s for s in self.slots if lo <= s.raw.va < hi), None)

    def top_of(self, spans: Sequence[WalkSpan]) -> Optional[_Slot]:
        """The first top chunk among *spans* (slot ``i`` is walked chunk ``i``)."""
        return next((s for span in spans for s in self.slots[span.first:span.stop]
                     if s.bin == "top"), None)

    def extend(self, slots: Sequence[_Slot], segments: Sequence[HeapSegment]) -> None:
        """Add the slots and extents of newly walked segments."""
        self.slots.extend(slots)
        self.by_va.update((slot.raw.va, slot) for slot in slots)
        self._extents.extend((seg.va, seg.end) for seg in segments)
