"""Heap roles projected onto a consensus slab.

A :class:`~memdiver.engine.consensus.ConsensusVector` indexes every byte by a
*slab offset*; the heap layer (:mod:`memdiver.heap`) describes every heap byte
by a *virtual address* in one dump. This module puts the two together: each
dump's :meth:`HeapLayout.role_runs` is projected into slab coordinates and the
N projections are merged into one run list, :class:`HeapRoleRuns`.

Projection
    * Aligned builds (MSL module+offset, or VA) carry ``cm.msl_layout`` rows
      ``(slab_offset, page_size, [va_per_dump])``; each dump's rows become a
      sorted VA -> slab map.
    * Flat builds index the sources' flat (``"vas"``) view, so a dump that has
      a VA map projects through its captured runs ``(va, length, vas_offset)``
      clipped to the slab. A dump without one is not projected.
    * Pure raw corpora (no dump has a VA map) yield an empty result whose
      report status is ``"no_va_coordinate"``.

Merge rule
    A slab byte takes role *R* when every dump that has a heap role there
    (anything but ``NONE``) says *R*; when they disagree it is ``MIXED``.
    ``agree`` counts the dumps whose role there (``NONE`` included) equals the
    anchor dump's — the first projected dump, normally dump 0 — so it doubles
    as a per-byte layout-stability metric. Bytes no dump assigns a role are not
    stored; :meth:`HeapRoleRuns.window` paints them with ``runs.fill``.

Fill
    ``fill`` is ``HeapRole.NONE`` for a computed result ("analysed, no chunk
    here") and ``HeapRole.UNCOVERED`` for an unavailable one (no VA
    coordinate, error, empty consensus) — "nothing is known here".

Everything is run-based numpy interval arithmetic; nothing loops per byte.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any, Dict, FrozenSet, Iterable, Iterator, List, Optional, Sequence, Tuple,
    Union,
)

import numpy as np

from memdiver.heap.model import (ARENA_KIND_CODES, ChunkState, HeapLayout,
                                 HeapRole, arena_entry)

logger = logging.getLogger("memdiver.engine.consensus_heap")

__all__ = [
    "HeapRoleRuns", "HeapChunkIndex", "ConsensusHeap", "compute_consensus_heap",
    "save_heap_npz", "load_heap_npz", "FREED_STATE_VALUES",
    "STATUS_OK", "STATUS_NO_VA", "STATUS_EMPTY", "STATUS_ERROR",
    "STATUS_UNSUPPORTED", "DumpHeapProjection", "project_dump_heap",
    "assemble_heap", "has_va_map",
]

STATUS_OK = "ok"
STATUS_NO_VA = "no_va_coordinate"
STATUS_EMPTY = "empty_consensus"
STATUS_ERROR = "error"
STATUS_UNSUPPORTED = "unsupported_allocator"

COORDINATE_ALIGNED = "aligned"
COORDINATE_FLAT_VIEW = "flat_view"

#: ``ChunkState`` <-> uint8 code used by :class:`HeapChunkIndex`.
_STATE_ORDER: Tuple[ChunkState, ...] = tuple(ChunkState)
_STATE_CODE: Dict[ChunkState, int] = {s: i for i, s in enumerate(_STATE_ORDER)}

#: ``ChunkState`` values of a freed chunk (stale bytes there are *residual*).
FREED_STATE_VALUES: FrozenSet[str] = frozenset(
    s.value for s in (ChunkState.FREE, ChunkState.CACHED, ChunkState.QUARANTINED))

#: Key prefix of the chunk-index arrays inside ``heap_roles.npz``.
_CHUNK_NPZ_PREFIX = "chunk_"
_CHUNK_NPZ_FIELDS = ("slab_starts", "sizes", "states", "agree")
#: Optional chunk-index array (absent from files written before it existed).
_CHUNK_NPZ_ARENA_KINDS = _CHUNK_NPZ_PREFIX + "arena_kinds"

#: Per-chunk arena-kind codes: :data:`memdiver.heap.model.ARENA_KIND_CODES`
#: (re-exported here, where the npz codecs use them).
_ARENA_KIND_OTHER = ARENA_KIND_CODES.index("other")


def arena_kind_code(kind: Optional[str]) -> int:
    """uint8 code of arena *kind* (``0`` for ``None``/empty)."""
    if not kind:
        return 0
    try:
        return ARENA_KIND_CODES.index(kind)
    except ValueError:
        return _ARENA_KIND_OTHER


def arena_kind_name(code: int) -> str:
    """Inverse of :func:`arena_kind_code` (``""`` = unknown)."""
    code = int(code)
    return ARENA_KIND_CODES[code] if 0 <= code < len(ARENA_KIND_CODES) else ""


def _arena_kinds_or_zeros(arena_kinds: Optional[np.ndarray], count: int) -> np.ndarray:
    if arena_kinds is None:
        return np.zeros(count, dtype=np.uint8)
    return np.asarray(arena_kinds, dtype=np.uint8)

#: ``(starts, lengths, roles)`` — one dump's pieces in slab coordinates.
_Pieces = Tuple[np.ndarray, np.ndarray, np.ndarray]


def _i64(values: Iterable[int] = ()) -> np.ndarray:
    return np.asarray(list(values), dtype=np.int64)


# -- run helpers ------------------------------------------------------------------


def _group_starts(breaks: np.ndarray) -> np.ndarray:
    """Indices where a new group begins, given a per-element break flag."""
    if breaks.size == 0:
        return np.zeros(0, dtype=np.int64)
    breaks = breaks.copy()
    breaks[0] = True
    return np.flatnonzero(breaks)


def _coalesce(starts: np.ndarray, lengths: np.ndarray,
              *keys: np.ndarray) -> Tuple[np.ndarray, ...]:
    """Merge touching runs whose *keys* are all equal (input sorted, disjoint)."""
    if starts.size == 0:
        return (starts, lengths) + keys
    breaks = np.ones(starts.size, dtype=bool)
    breaks[1:] = starts[1:] != starts[:-1] + lengths[:-1]
    for key in keys:
        breaks[1:] |= key[1:] != key[:-1]
    first = _group_starts(breaks)
    merged_lengths = np.add.reduceat(lengths, first)
    return (starts[first], merged_lengths) + tuple(k[first] for k in keys)


def _containing(starts: np.ndarray, ends: np.ndarray,
                points: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """``(index, valid)``: the sorted disjoint run holding each point."""
    idx = np.searchsorted(starts, points, side="right") - 1
    safe = np.clip(idx, 0, max(starts.size - 1, 0))
    valid = (idx >= 0) & (starts.size > 0)
    if starts.size:
        valid &= points < ends[safe]
    return safe, valid


# -- role runs --------------------------------------------------------------------


@dataclass(eq=False)  # numpy fields: no elementwise __eq__
class HeapRoleRuns:
    """Sorted, non-overlapping heap-role runs in slab coordinates.

    ``starts``/``lengths`` are int64, ``roles`` uint8 (:class:`HeapRole`
    values, ``MIXED`` where dumps disagree) and ``agree`` uint16 (dumps that
    agree with the anchor's role). Bytes outside every run read as ``fill``.
    """

    starts: np.ndarray
    lengths: np.ndarray
    roles: np.ndarray
    agree: np.ndarray
    fill: int = int(HeapRole.NONE)
    _mask_cache: Dict[Tuple[FrozenSet[int], int], np.ndarray] = field(
        default_factory=dict, repr=False, compare=False)

    @classmethod
    def empty(cls, fill: int = int(HeapRole.UNCOVERED)) -> "HeapRoleRuns":
        return cls(_i64(), _i64(), np.zeros(0, dtype=np.uint8),
                   np.zeros(0, dtype=np.uint16), int(fill))

    def __len__(self) -> int:
        return int(self.starts.size)

    @property
    def ends(self) -> np.ndarray:
        return self.starts + self.lengths

    def _span(self, start: int, end: int) -> Tuple[int, int]:
        """Index range ``[i0, i1)`` of runs overlapping ``[start, end)``."""
        i0 = int(np.searchsorted(self.ends, start, side="right"))
        i1 = int(np.searchsorted(self.starts, end, side="left"))
        return i0, max(i0, i1)

    def runs_in(self, start: int, n: int) -> Iterator[Tuple[int, int, HeapRole, int]]:
        """Yield ``(slab_offset, length, role, agree)`` clipped to the window."""
        end = int(start) + max(0, int(n))
        i0, i1 = self._span(int(start), end)
        for i in range(i0, i1):
            lo = max(int(self.starts[i]), int(start))
            hi = min(int(self.starts[i] + self.lengths[i]), end)
            yield lo, hi - lo, HeapRole(int(self.roles[i])), int(self.agree[i])

    def window(self, start: int, n: int) -> np.ndarray:
        """Dense uint8 roles for slab bytes ``[start, start + n)``."""
        out = np.full(max(0, int(n)), self.fill, dtype=np.uint8)
        for lo, length, role, _agree in self.runs_in(start, n):
            out[lo - start:lo - start + length] = int(role)
        return out

    def role_at(self, offset: int) -> HeapRole:
        """Role of one slab byte (``fill`` when no run covers it)."""
        idx, valid = _containing(self.starts, self.ends,
                                 np.asarray([int(offset)], dtype=np.int64))
        return HeapRole(int(self.roles[idx[0]]) if valid[0] else self.fill)

    def mask(self, roles: Iterable[Union[HeapRole, int]], size: int) -> np.ndarray:
        """Bool array of length *size*: True where the role is in *roles*.

        Built from the runs with one cumulative sum and cached per
        ``(roles, size)``; treat the returned array as read-only.
        """
        wanted = frozenset(int(r) for r in roles)
        key = (wanted, int(size))
        cached = self._mask_cache.get(key)
        if cached is None:
            cached = self._build_mask(wanted, int(size))
            self._mask_cache[key] = cached
        return cached

    def _build_mask(self, wanted: FrozenSet[int], size: int) -> np.ndarray:
        hit = np.isin(self.roles, np.asarray(sorted(wanted), dtype=np.uint8))
        if self.fill in wanted:
            hit = ~hit  # paint the complement: fill bytes plus unwanted runs
        starts = np.clip(self.starts[hit], 0, size)
        ends = np.clip(self.ends[hit], 0, size)
        # Runs are disjoint, so starts (and ends) are each unique: plain fancy
        # assignment is enough, and the running sum only ever holds 0 or 1.
        nonempty = ends > starts
        delta = np.zeros(size + 1, dtype=np.int8)
        delta[starts[nonempty]] += 1
        delta[ends[nonempty]] -= 1
        painted = np.cumsum(delta[:-1], dtype=np.int8).view(np.bool_)
        return ~painted if self.fill in wanted else painted

    def role_counts(self) -> Dict[str, int]:
        """Bytes per role name (lower-case) over the stored runs."""
        counts: Dict[str, int] = {}
        for role in np.unique(self.roles):
            name = HeapRole(int(role)).name.lower()
            counts[name] = int(self.lengths[self.roles == role].sum())
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe summary (not the runs themselves)."""
        counts = self.role_counts()
        return {
            "run_count": len(self),
            "covered_bytes": int(self.lengths.sum()),
            "mixed_bytes": counts.get("mixed", 0),
            "role_counts": counts,
            "fill": HeapRole(self.fill).name.lower(),
            "min_agree": int(self.agree.min()) if len(self) else None,
        }

    def to_npz(self, path: Union[str, Path]) -> None:
        np.savez_compressed(
            Path(path), starts=self.starts, lengths=self.lengths,
            roles=self.roles, agree=self.agree,
            fill=np.asarray([self.fill], dtype=np.uint8))

    @classmethod
    def from_npz(cls, path: Union[str, Path]) -> "HeapRoleRuns":
        with np.load(Path(path)) as data:
            return cls(data["starts"].astype(np.int64),
                       data["lengths"].astype(np.int64),
                       data["roles"].astype(np.uint8),
                       data["agree"].astype(np.uint16),
                       int(data["fill"][0]))


# -- chunk index ------------------------------------------------------------------


@dataclass(eq=False)  # numpy fields: no elementwise __eq__
class HeapChunkIndex:
    """The anchor dump's chunks in slab coordinates, sorted by ``slab_starts``.

    ``states`` holds codes into ``tuple(ChunkState)``; ``agree`` counts dumps
    with a chunk at the same slab offset and of the same size. A chunk whose
    start is outside the slab is dropped. ``chunk_at`` assumes the chunk is
    slab-contiguous from its start (true unless it straddles an alignment gap).
    """

    slab_starts: np.ndarray
    sizes: np.ndarray
    states: np.ndarray
    agree: np.ndarray
    arena_kinds: Optional[np.ndarray] = None  # ARENA_KIND_CODES; None = all unknown

    def __post_init__(self) -> None:
        self.arena_kinds = _arena_kinds_or_zeros(self.arena_kinds,
                                                 int(self.slab_starts.size))

    @classmethod
    def empty(cls) -> "HeapChunkIndex":
        return cls(_i64(), _i64(), np.zeros(0, dtype=np.uint8),
                   np.zeros(0, dtype=np.uint16))

    def __len__(self) -> int:
        return int(self.slab_starts.size)

    def chunk_at(self, slab_offset: int) -> Optional[Dict[str, Any]]:
        """The chunk containing *slab_offset*, or ``None``."""
        idx, valid = _containing(self.slab_starts, self.slab_starts + self.sizes,
                                 np.asarray([int(slab_offset)], dtype=np.int64))
        if not valid[0]:
            return None
        i = int(idx[0])
        start = int(self.slab_starts[i])
        hit: Dict[str, Any] = {
            "slab_start": start, "size": int(self.sizes[i]),
            "state": _STATE_ORDER[int(self.states[i])].value,
            "agree": int(self.agree[i]),
            "offset_in_chunk": int(slab_offset) - start,
        }
        return {**hit, **self._arena_entry(i)}

    def _arena_entry(self, i: int) -> Dict[str, str]:
        """``{"arena": kind}`` when the chunk's arena kind is known, else ``{}``."""
        assert self.arena_kinds is not None  # set by __post_init__
        return arena_entry(arena_kind_name(self.arena_kinds[i]))

    def to_arrays(self) -> Dict[str, np.ndarray]:
        """The index as ``chunk_*``-prefixed arrays (for ``heap_roles.npz``)."""
        arrays = {_CHUNK_NPZ_PREFIX + name: getattr(self, name)
                  for name in _CHUNK_NPZ_FIELDS}
        arrays[_CHUNK_NPZ_ARENA_KINDS] = self.arena_kinds
        return arrays

    @classmethod
    def from_arrays(cls, data: Any) -> "HeapChunkIndex":
        """Inverse of :meth:`to_arrays`; empty when the arrays are absent."""
        keys = [_CHUNK_NPZ_PREFIX + name for name in _CHUNK_NPZ_FIELDS]
        if not all(key in data for key in keys):
            return cls.empty()
        kinds = (data[_CHUNK_NPZ_ARENA_KINDS] if _CHUNK_NPZ_ARENA_KINDS in data
                 else None)  # files written before arena kinds: all unknown
        return cls(data[keys[0]].astype(np.int64), data[keys[1]].astype(np.int64),
                   data[keys[2]].astype(np.uint8), data[keys[3]].astype(np.uint16),
                   kinds)

    def to_dict(self) -> Dict[str, Any]:
        by_state: Dict[str, int] = {}
        for code in np.unique(self.states):
            by_state[_STATE_ORDER[int(code)].value] = int((self.states == code).sum())
        return {"chunk_count": len(self), "by_state": by_state}


# -- result -----------------------------------------------------------------------


@dataclass(eq=False)  # numpy fields: no elementwise __eq__
class ConsensusHeap:
    """Heap annotation of a consensus: merged runs, anchor chunks, provenance."""

    runs: HeapRoleRuns
    chunks: HeapChunkIndex = field(default_factory=HeapChunkIndex.empty)
    per_dump: List[Dict[str, Any]] = field(default_factory=list)
    report: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def unavailable(cls, status: str, **extra: Any) -> "ConsensusHeap":
        """An empty result (``fill=UNCOVERED``) whose report says why."""
        return cls(HeapRoleRuns.empty(), report={"status": status, **extra})

    @property
    def status(self) -> str:
        return str(self.report.get("status", STATUS_OK))

    def to_dict(self) -> Dict[str, Any]:
        return {"report": dict(self.report), "runs": self.runs.to_dict(),
                "chunks": self.chunks.to_dict(),
                "per_dump": [dict(d) for d in self.per_dump]}


def save_heap_npz(heap: ConsensusHeap, path: Union[str, Path]) -> None:
    """Write *heap*'s runs and chunk index to one ``heap_roles.npz``.

    The run arrays keep :meth:`HeapRoleRuns.to_npz`'s key names, so
    :meth:`HeapRoleRuns.from_npz` still reads the file on its own.
    """
    runs = heap.runs
    arrays: Dict[str, Any] = {
        "starts": runs.starts, "lengths": runs.lengths, "roles": runs.roles,
        "agree": runs.agree, "fill": np.asarray([runs.fill], dtype=np.uint8),
        **heap.chunks.to_arrays()}
    np.savez_compressed(Path(path), **arrays)


def load_heap_npz(path: Union[str, Path]) -> Tuple[HeapRoleRuns, HeapChunkIndex]:
    """Read ``(runs, chunks)`` back from a :func:`save_heap_npz` file."""
    runs = HeapRoleRuns.from_npz(path)
    with np.load(Path(path)) as data:
        chunks = HeapChunkIndex.from_arrays(data)
    return runs, chunks


# -- VA -> slab maps --------------------------------------------------------------


@dataclass(frozen=True, eq=False)
class _SlabMap:
    """One dump's VA -> slab correspondence: sorted, disjoint VA runs."""

    va_starts: np.ndarray   # uint64
    va_ends: np.ndarray     # uint64
    slab_starts: np.ndarray  # int64

    @classmethod
    def build(cls, vas: Sequence[int], slabs: Sequence[int],
              lengths: Sequence[int]) -> "_SlabMap":
        va = np.asarray(vas, dtype=np.uint64)
        slab = np.asarray(slabs, dtype=np.int64)
        length = np.asarray(lengths, dtype=np.int64)
        order = np.lexsort((slab, va))
        va, slab, length = va[order], slab[order], length[order]
        keep = length > 0
        va, slab, length = va[keep], slab[keep], length[keep]
        va, slab, length = _drop_va_overlaps(va, slab, length)
        va, slab, length = _merge_contiguous(va, slab, length)
        return cls(va, va + length.astype(np.uint64), slab)

    @property
    def is_empty(self) -> bool:
        return self.va_starts.size == 0

    @property
    def va_bounds(self) -> Tuple[int, int]:
        return int(self.va_starts[0]), int(self.va_ends.max())

    def project_points(self, vas: np.ndarray) -> np.ndarray:
        """Slab offset per VA, ``-1`` where unmapped."""
        idx, valid = _containing(self.va_starts, self.va_ends, vas)
        delta = (vas - self.va_starts[idx]).astype(np.int64)
        return np.where(valid, self.slab_starts[idx] + delta, -1)

    def project_runs(self, vas: np.ndarray, lengths: np.ndarray,
                     roles: np.ndarray) -> _Pieces:
        """Intersect VA runs with the map; return slab-sorted pieces."""
        ends = vas + lengths.astype(np.uint64)
        first = np.searchsorted(self.va_ends, vas, side="right")
        last = np.searchsorted(self.va_starts, ends, side="left")
        counts = np.clip(last - first, 0, None).astype(np.int64)
        run_idx = np.repeat(np.arange(vas.size), counts)
        offsets = np.arange(int(counts.sum())) - np.repeat(
            np.cumsum(counts) - counts, counts)
        row_idx = np.repeat(first, counts) + offsets
        lo = np.maximum(vas[run_idx], self.va_starts[row_idx])
        hi = np.minimum(ends[run_idx], self.va_ends[row_idx])
        keep = hi > lo
        slab = (self.slab_starts[row_idx]
                + (lo - self.va_starts[row_idx]).astype(np.int64))[keep]
        piece_len = (hi - lo).astype(np.int64)[keep]
        piece_roles = roles[run_idx][keep]
        order = np.argsort(slab, kind="stable")
        return slab[order], piece_len[order], piece_roles[order]


def _drop_va_overlaps(va: np.ndarray, slab: np.ndarray,
                      length: np.ndarray) -> Tuple[np.ndarray, ...]:
    """Keep the first of rows resolving to the same VA (overlapping modules)."""
    if va.size < 2:
        return va, slab, length
    ends = va + length.astype(np.uint64)
    reach = np.maximum.accumulate(ends)
    keep = np.ones(va.size, dtype=bool)
    keep[1:] = va[1:] >= reach[:-1]
    return va[keep], slab[keep], length[keep]


def _merge_contiguous(va: np.ndarray, slab: np.ndarray,
                      length: np.ndarray) -> Tuple[np.ndarray, ...]:
    """Coalesce rows contiguous in BOTH VA and slab (one row per page -> runs)."""
    if va.size == 0:
        return va, slab, length
    breaks = np.ones(va.size, dtype=bool)
    breaks[1:] = ((va[1:] != va[:-1] + length[:-1].astype(np.uint64))
                  | (slab[1:] != slab[:-1] + length[:-1]))
    first = _group_starts(breaks)
    return va[first], slab[first], np.add.reduceat(length, first)


def _aligned_maps(cm: Any, n_dumps: int) -> List[Optional[_SlabMap]]:
    """Per-dump maps from ``cm.msl_layout`` rows ``(slab, page, [va...])``."""
    rows = cm.msl_layout or []
    slabs = [int(r[0]) for r in rows]
    pages = [int(r[1]) for r in rows]
    maps: List[Optional[_SlabMap]] = []
    for d in range(n_dumps):
        vas = [int(r[2][d]) for r in rows]
        maps.append(_SlabMap.build(vas, slabs, pages))
    return maps


def _has_va_map(source: Any) -> bool:
    return (callable(getattr(source, "captured_runs", None))
            or callable(getattr(source, "va_to_vas_offset", None)))


def has_va_map(source: Any) -> bool:
    """True when *source* carries a VA map (a heap can be projected at all)."""
    return _has_va_map(source)


def _flat_view_runs(source: Any) -> List[Tuple[int, int, int]]:
    """``(va, length, vas_offset)`` of the flat ``"vas"`` view.

    Mirrors ``heap.memory.VaMemory._vas_runs``: ``.msl`` sources publish
    ``captured_runs``; gcore / regioned sources concatenate ``iter_ranges``.
    """
    captured = getattr(source, "captured_runs", None)
    if callable(captured):
        return [(int(va), int(n), int(off)) for va, n, off in captured()]
    runs, cursor = [], 0
    for start, end, _file_offset in source.iter_ranges():
        runs.append((int(start), int(end) - int(start), cursor))
        cursor += int(end) - int(start)
    return runs


def _flat_map(source: Any, slab_size: int) -> Optional[_SlabMap]:
    """Map through the source's flat view, clipped to the slab; None if no VA."""
    if not _has_va_map(source):
        return None
    runs = [(va, min(n, slab_size - off), off)
            for va, n, off in _flat_view_runs(source) if off < slab_size]
    return _SlabMap.build([r[0] for r in runs], [r[2] for r in runs],
                          [r[1] for r in runs])


# -- per-dump analysis ------------------------------------------------------------


#: ``DumpHeapProjection`` npz key -> dtype (order = save order).
_PROJECTION_NPZ_DTYPES: Tuple[Tuple[str, Any], ...] = (
    ("pieces_starts", np.int64), ("pieces_lengths", np.int64),
    ("pieces_roles", np.uint8), ("chunk_slabs", np.int64),
    ("chunk_sizes", np.int64), ("chunk_states", np.uint8))
#: Optional projection key (absent from npz files written before it existed).
_PROJECTION_NPZ_ARENA_KINDS = "chunk_arena_kinds"


@dataclass(eq=False)  # numpy fields: no elementwise __eq__
class DumpHeapProjection:
    """One dump's heap, projected: role pieces plus chunk starts in slab coords.

    ``pieces`` is ``(starts int64, lengths int64, roles uint8)``; the chunk
    arrays are ``slabs int64`` (``-1`` = outside the slab), ``sizes int64``
    and ``states uint8`` (:class:`ChunkState` codes); ``chunk_arena_kinds``
    holds :data:`ARENA_KIND_CODES` codes (zeros = unknown when not given).
    """

    pieces: _Pieces
    chunk_slabs: np.ndarray
    chunk_sizes: np.ndarray
    chunk_states: np.ndarray
    chunk_arena_kinds: Optional[np.ndarray] = None

    def __post_init__(self) -> None:
        self.chunk_arena_kinds = _arena_kinds_or_zeros(
            self.chunk_arena_kinds, int(np.asarray(self.chunk_slabs).size))

    @property
    def is_empty(self) -> bool:
        """True when the dump contributes neither role pieces nor chunks."""
        return self.pieces[0].size == 0 and self.chunk_slabs.size == 0

    def _arrays(self) -> Tuple[np.ndarray, ...]:
        return (*self.pieces, self.chunk_slabs, self.chunk_sizes,
                self.chunk_states)

    def to_npz(self, path: Union[str, Path]) -> None:
        """Write the arrays to one compressed ``.npz`` (dtypes kept)."""
        arrays: Dict[str, Any] = {
            key: np.asarray(arr, dtype=dtype) for (key, dtype), arr
            in zip(_PROJECTION_NPZ_DTYPES, self._arrays())}
        arrays[_PROJECTION_NPZ_ARENA_KINDS] = self.chunk_arena_kinds
        np.savez_compressed(Path(path), **arrays)

    @classmethod
    def from_npz(cls, path: Union[str, Path]) -> "DumpHeapProjection":
        """Read a :meth:`to_npz` file back (older files lack arena kinds)."""
        with np.load(Path(path)) as data:
            a = [data[key].astype(dtype, copy=False)
                 for key, dtype in _PROJECTION_NPZ_DTYPES]
            kinds = (data[_PROJECTION_NPZ_ARENA_KINDS].astype(np.uint8, copy=False)
                     if _PROJECTION_NPZ_ARENA_KINDS in data else None)
        return cls((a[0], a[1], a[2]), a[3], a[4], a[5], kinds)


#: Backwards-compatible private name.
_DumpProjection = DumpHeapProjection


def _layout_runs(layout: HeapLayout, smap: _SlabMap) -> Tuple[np.ndarray, ...]:
    lo, hi = smap.va_bounds
    runs = list(layout.role_runs(lo, hi))
    vas = np.fromiter((r[0] for r in runs), dtype=np.uint64, count=len(runs))
    lengths = np.fromiter((r[1] for r in runs), dtype=np.int64, count=len(runs))
    roles = np.fromiter((int(r[2]) for r in runs), dtype=np.uint8, count=len(runs))
    return vas, lengths, roles


def _arena_codes_by_id(layout: HeapLayout) -> Dict[Optional[int], int]:
    """``{arena_id: arena kind code}`` (first arena wins, as ``arena_kind``)."""
    return {a.arena_id: arena_kind_code(a.kind) for a in reversed(layout.arenas)}


def _project_dump(layout: HeapLayout, smap: _SlabMap) -> DumpHeapProjection:
    chunks = layout.chunks
    vas = np.fromiter((c.va for c in chunks), dtype=np.uint64, count=len(chunks))
    sizes = np.fromiter((c.size for c in chunks), dtype=np.int64, count=len(chunks))
    states = np.fromiter((_STATE_CODE[c.state] for c in chunks),
                         dtype=np.uint8, count=len(chunks))
    codes = _arena_codes_by_id(layout)
    kinds = np.fromiter((codes.get(c.arena_id, 0) for c in chunks),
                        dtype=np.uint8, count=len(chunks))
    return DumpHeapProjection(smap.project_runs(*_layout_runs(layout, smap)),
                           smap.project_points(vas), sizes, states, kinds)


def _dump_record(index: int, source: Any,
                 layout: Optional[HeapLayout]) -> Dict[str, Any]:
    record: Dict[str, Any] = {"index": index,
                              "path": str(getattr(source, "path", "") or ""),
                              "projected": layout is not None}
    if layout is None:
        record["reason"] = "no_va_map"
        return record
    record.update(allocator=layout.allocator.value,
                  confidence=float(layout.confidence),
                  chunk_count=len(layout.chunks))
    return record


# -- merge ------------------------------------------------------------------------


def _roles_at(pieces: _Pieces, points: np.ndarray) -> np.ndarray:
    starts, lengths, roles = pieces
    idx, valid = _containing(starts, starts + lengths, points)
    if roles.size == 0:
        return np.zeros(points.size, dtype=np.uint8)
    return np.where(valid, roles[idx], int(HeapRole.NONE)).astype(np.uint8)


def merge_role_pieces(pieces: Sequence[_Pieces], anchor: int = 0) -> HeapRoleRuns:
    """Merge per-dump slab pieces into consensus runs (see module docstring)."""
    bounds = [np.concatenate((s, s + n)) for s, n, _r in pieces]
    edges = np.unique(np.concatenate(bounds)) if bounds else _i64()
    if edges.size < 2:
        return HeapRoleRuns.empty(fill=int(HeapRole.NONE))
    lefts, widths = edges[:-1], np.diff(edges)
    matrix = np.stack([_roles_at(p, lefts) for p in pieces])
    covered = matrix != int(HeapRole.NONE)
    sample = matrix.max(axis=0)
    uniform = ((matrix == sample) | ~covered).all(axis=0)
    merged = np.where(uniform, sample, int(HeapRole.MIXED)).astype(np.uint8)
    agree = (matrix == matrix[anchor]).sum(axis=0).astype(np.uint16)
    keep = covered.any(axis=0)
    starts, lengths, roles, agrees = _coalesce(
        lefts[keep], widths[keep], merged[keep], agree[keep])
    return HeapRoleRuns(starts, lengths, roles, agrees, int(HeapRole.NONE))


def _chunk_agreement(anchor: DumpHeapProjection,
                     others: Sequence[DumpHeapProjection]) -> np.ndarray:
    """Per anchor chunk: dumps with a chunk at the same slab start and size."""
    agree = np.zeros(anchor.chunk_slabs.size, dtype=np.uint16)
    for other in others:
        order = np.argsort(other.chunk_slabs, kind="stable")
        slabs, sizes = other.chunk_slabs[order], other.chunk_sizes[order]
        if slabs.size == 0:
            continue
        idx = np.clip(np.searchsorted(slabs, anchor.chunk_slabs), 0, slabs.size - 1)
        agree += ((slabs[idx] == anchor.chunk_slabs)
                  & (sizes[idx] == anchor.chunk_sizes)).astype(np.uint16)
    return agree


def _chunk_index(anchor: DumpHeapProjection,
                 projections: Sequence[DumpHeapProjection]) -> HeapChunkIndex:
    agree = _chunk_agreement(anchor, projections)
    keep = anchor.chunk_slabs >= 0
    order = np.argsort(anchor.chunk_slabs[keep], kind="stable")
    assert anchor.chunk_arena_kinds is not None  # set by __post_init__
    return HeapChunkIndex(anchor.chunk_slabs[keep][order],
                          anchor.chunk_sizes[keep][order],
                          anchor.chunk_states[keep][order],
                          agree[keep][order],
                          anchor.chunk_arena_kinds[keep][order])


# -- entry point ------------------------------------------------------------------


def _slab_maps(cm: Any, sources: Sequence[Any]) -> Tuple[str, List[Optional[_SlabMap]]]:
    if cm.msl_layout is not None:
        return COORDINATE_ALIGNED, _aligned_maps(cm, len(sources))
    return COORDINATE_FLAT_VIEW, [_flat_map(s, int(cm.size)) for s in sources]


def _analyze_all(sources: Sequence[Any], maps: Sequence[Optional[_SlabMap]],
                 allocator: str) -> Tuple[List[Optional[HeapLayout]],
                                          List[Optional[DumpHeapProjection]]]:
    from memdiver.heap.analyze import analyze_heap

    layouts: List[Optional[HeapLayout]] = []
    projections: List[Optional[DumpHeapProjection]] = []
    for source, smap in zip(sources, maps):
        if smap is None or smap.is_empty:
            layouts.append(None)
            projections.append(None)
            continue
        layout = analyze_heap(source, allocator)
        layouts.append(layout)
        projections.append(_project_dump(layout, smap))
    return layouts, projections


def compute_consensus_heap(cm: Any, sources: Sequence[Any],
                           allocator: str = "auto") -> ConsensusHeap:
    """Project every dump's heap roles onto *cm*'s slab and merge them.

    *sources* must be the OPEN sources *cm* was built from, in build order.
    Analysis errors propagate; :func:`build_consensus` turns them into an
    ``"error"`` report so the consensus itself is never affected.
    """
    if int(getattr(cm, "size", 0) or 0) == 0 or len(sources) < 2:
        return ConsensusHeap.unavailable(STATUS_EMPTY, allocator=allocator)
    coordinate, maps = _slab_maps(cm, sources)
    if all(m is None for m in maps):
        return ConsensusHeap.unavailable(STATUS_NO_VA, allocator=allocator,
                                         coordinate=coordinate)
    layouts, projections = _analyze_all(sources, maps, allocator)
    per_dump = [_dump_record(i, s, lay)
                for i, (s, lay) in enumerate(zip(sources, layouts))]
    done = [(i, p) for i, p in enumerate(projections) if p is not None]
    return assemble_heap(done, per_dump, allocator, coordinate)


def project_dump_heap(source: Any, slab_size: int, allocator: str, *,
                      index: int = 0) -> Tuple[Optional[DumpHeapProjection],
                                               Dict[str, Any]]:
    """Analyse ONE dump and project it onto a flat-view slab of *slab_size*.

    Returns ``(projection, record)``; *record* is the ``per_dump`` entry
    (``_dump_record`` plus ``"status"``). A source without a VA map yields
    ``(None, {..., "status": "no_va_coordinate", "reason": "no_va_map"})``.
    *allocator* is anything :func:`memdiver.heap.analyze.analyze_heap`
    accepts (a concrete name or ``"auto"``). Analysis errors propagate; the
    caller decides how to report them.
    """
    smap = _flat_map(source, int(slab_size))
    if smap is None or smap.is_empty:
        record = _dump_record(index, source, None)
        record["status"] = STATUS_NO_VA
        return None, record
    from memdiver.heap.analyze import analyze_heap

    layout = analyze_heap(source, allocator)
    record = _dump_record(index, source, layout)
    record["status"] = STATUS_OK
    return _project_dump(layout, smap), record


def assemble_heap(projections: Sequence[Tuple[int, DumpHeapProjection]],
                  per_dump: List[Dict[str, Any]], allocator: str,
                  coordinate: str, *, empty_status: str = STATUS_NO_VA,
                  **empty_extra: Any) -> ConsensusHeap:
    """Merge ``(dump_index, projection)`` pairs into one :class:`ConsensusHeap`.

    The first pair is the anchor. A single projection is valid (every
    ``agree`` is then 1); no projections yields an unavailable result with
    status *empty_status* (default ``"no_va_coordinate"``), carrying
    *per_dump* and any *empty_extra* report fields.
    """
    if not projections:
        return ConsensusHeap(HeapRoleRuns.empty(), per_dump=per_dump,
                             report={"status": empty_status, "allocator": allocator,
                                     "coordinate": coordinate, **empty_extra})
    return _assemble(projections, per_dump, allocator, coordinate)


def _assemble(done: Sequence[Tuple[int, DumpHeapProjection]],
              per_dump: List[Dict[str, Any]], allocator: str,
              coordinate: str) -> ConsensusHeap:
    anchor_index, anchor = done[0]
    projections = [p for _i, p in done]
    runs = merge_role_pieces([p.pieces for p in projections], anchor=0)
    chunks = _chunk_index(anchor, projections)
    report = {"status": STATUS_OK, "allocator": allocator,
              "coordinate": coordinate, "anchor_index": anchor_index,
              "dumps_projected": len(done), **runs.to_dict(),
              "chunk_count": len(chunks)}
    logger.info("Consensus heap: %d runs over %d dumps (%s)",
                len(runs), len(done), coordinate)
    return ConsensusHeap(runs, chunks, per_dump, report)
