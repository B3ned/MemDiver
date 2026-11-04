"""Heap producers: allocator detection, summary, chunk table, chunk lookup,
free lists, byte roles — the ``heap.*`` capabilities.

Each producer opens the dump exactly like the inspect producers
(:func:`~memdiver.app.key_material.open_dump_source`, so an encrypted
``.msl`` honours ``key_file`` / ``passphrase`` / ``kem_key_file``), runs the
one heap facade :func:`memdiver.heap.analyze.analyze_heap`, and returns a
:class:`~memdiver.core.service_result.ServiceResult` whose status block
carries the key state. Bad input (unknown allocator, state or view, a VA
and an offset window at once, …) is RAISED as a :class:`CapabilityError`.

``view_offset`` columns locate a chunk in the requested byte view
(``"vas"`` — the dense captured-memory view, ``"raw"`` — the file, ``"va"``
— the sparse VA view of an ``.msl``) so a row can be opened in the hex view.
"""

from __future__ import annotations

import bisect
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import (TYPE_CHECKING, Any, Dict, Iterator, List, Optional,
                    Sequence, Tuple)

from memdiver.core.image.view_descriptor import ViewKind
from memdiver.core.service_errors import (CapabilityError, ErrorCategory,
                                          FileNotFoundServiceError,
                                          OffsetOutOfRangeError)
from memdiver.heap.analyze import (DEFAULT_MAX_CHUNKS, analyze_heap,
                                   parse_allocator_hint)
from memdiver.heap.detect import _platform_dict, detect_allocator
from memdiver.heap.memory import VaMemory
from memdiver.heap.model import (ChunkState, FreeList, HeapChunk, HeapLayout,
                                 HeapRole)
from memdiver.heap.registry import get_allocator

from .key_material import key_material_kwargs, open_dump_source
from .session import ToolSession
from .tools_inspect import _finalize_inspect, _require_supported_view

if TYPE_CHECKING:
    from memdiver.core.service_result import ServiceResult

MAX_CHUNK_PAGE_SIZE = 2000
DEFAULT_CHUNK_PAGE_SIZE = 200
HEAP_VIEWS = ("vas", "raw", "va")
DEFAULT_ROLES_LENGTH = 65536
MAX_ROLES_LENGTH = 1 << 20  # 1 MiB
_METADATA_ROLES = ("chunk_header", "allocator_meta")


# -- shared helpers ---------------------------------------------------------------


def _invalid(message: str, **details: Any) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT,
                           details=details or None)


def _checked_allocator(allocator: str) -> str:
    try:
        hint = parse_allocator_hint(allocator)
    except ValueError as exc:
        raise _invalid(str(exc), allocator=allocator) from exc
    return hint.value if hint is not None else "auto"


def _checked_view(view: str) -> str:
    if view not in HEAP_VIEWS:
        raise _invalid(f"unknown view {view!r}; expected one of "
                       f"{', '.join(HEAP_VIEWS)}", view=view)
    return view


def _checked_state(state: Optional[str]) -> Optional[ChunkState]:
    if state is None:
        return None
    try:
        return ChunkState(state.strip().lower())
    except ValueError:
        valid = ", ".join(s.value for s in ChunkState)
        raise _invalid(f"unknown chunk state {state!r}; expected one of {valid}",
                       state=state) from None


def _require_file(dump_path: str) -> None:
    if not Path(dump_path).is_file():
        raise FileNotFoundServiceError(f"File not found: {dump_path}")


@contextmanager
def _opened(dump_path: str, key_file: Optional[str], passphrase: Optional[str],
            kem_key_file: Optional[str]) -> Iterator[Any]:
    """The opened DumpSource; a vanished file becomes FileNotFoundServiceError."""
    _require_file(dump_path)
    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    try:
        with open_dump_source(dump_path, km) as source:
            _refuse_physical_view(source)
            yield source
    except FileNotFoundError:
        raise FileNotFoundServiceError(f"File not found: {dump_path}") from None


def _refuse_physical_view(source: Any) -> None:
    """A PHYSICAL ``.mdview`` reports a "va" map whose addresses are physical.

    The allocator walkers follow virtual pointers, so walking a physical view would
    chase process VAs through physical frames. Process and kernel views carry
    genuine virtual addresses and are analysed as usual.
    """
    descriptor = getattr(source, "descriptor", None)
    view = getattr(descriptor, "view", None)
    if view is not ViewKind.PHYSICAL:
        return
    raise CapabilityError(
        "heap analysis needs a virtual address space; a physical image view "
        "addresses physical frames. Open a process view of the image instead.",
        category=ErrorCategory.UNSUPPORTED, code="heap.physical_view_unsupported",
        details={"view_kind": view.value})


def _layout_of(source: Any, allocator: str, base_va: Optional[int],
               max_chunks: int, regions: Optional[Sequence[str]]) -> HeapLayout:
    return analyze_heap(source, allocator, base_va=base_va,
                        max_chunks=max_chunks,
                        regions=list(regions) if regions else None)


def _memory_of(source: Any, layout: HeapLayout,
               base_va: Optional[int]) -> VaMemory:
    return VaMemory(source, layout.platform, base_va=base_va)


def _chunk_row(chunk: HeapChunk, memory: VaMemory, view: str) -> Dict[str, Any]:
    row = chunk.to_dict()
    row.pop("roles", None)
    row["view_offset"] = memory.va_to_view_offset(chunk.va, view)
    return row


# -- heap.detect ------------------------------------------------------------------


def heap_detect_result(
    session: ToolSession,
    dump_path: str,
    allocator: str = "auto",
    *,
    base_va: Optional[int] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """Ranked allocator candidates for *dump_path*, each with its evidence.

    ``allocator`` other than ``"auto"`` is echoed back as the verdict
    (``hinted: true``), exactly as :func:`memdiver.heap.detect_allocator`.
    """
    hint = _checked_allocator(allocator)
    with _opened(dump_path, key_file, passphrase, kem_key_file) as source:
        detection = detect_allocator(source, hint, base_va=base_va)
        payload = detection.to_dict()
        payload["format"] = source.format_name
        return _finalize_inspect(payload, source, view=None)


# -- heap.summary -----------------------------------------------------------------


def heap_summary_result(
    session: ToolSession,
    dump_path: str,
    allocator: str = "auto",
    *,
    base_va: Optional[int] = None,
    max_chunks: int = DEFAULT_MAX_CHUNKS,
    regions: Optional[Sequence[str]] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """Whole-heap overview: allocator, regions, state counts, size histogram,
    per-role byte counts, metadata bytes, coverage and diagnostics."""
    hint = _checked_allocator(allocator)
    with _opened(dump_path, key_file, passphrase, kem_key_file) as source:
        layout = _layout_of(source, hint, base_va, max_chunks, regions)
        payload = _summary_payload(layout)
        payload["format"] = source.format_name
        return _finalize_inspect(payload, source, view=None)


def _summary_payload(layout: HeapLayout) -> Dict[str, Any]:
    role_bytes = _role_bytes(layout)
    overview = layout.to_dict(limit=0)
    return {
        **_allocator_block(layout),
        "platform": _platform_dict(layout.platform),
        "regions": [{"va": r.va, "size": r.size, "name": r.name, "kind": r.kind}
                    for r in layout.regions],
        "chunk_count": len(layout.chunks),
        "counts_by_state": _counts_by_state(layout.chunks),
        "bytes_by_state": _bytes_by_state(layout.chunks),
        "size_histogram": _size_histogram(layout.chunks),
        "role_bytes": role_bytes,
        "metadata_bytes": sum(role_bytes.get(r, 0) for r in _METADATA_ROLES),
        "free_list_count": len(layout.free_lists),
        "evidence": overview["evidence"],
        "coverage": overview["coverage"],
        "diagnostics": list(layout.diagnostics),
    }


def _allocator_block(layout: HeapLayout) -> Dict[str, Any]:
    desc = get_allocator(layout.allocator)
    return {
        "allocator": layout.allocator.value,
        "confidence": round(layout.confidence, 4),
        "version_hint": layout.version_hint,
        "partial": bool(desc and desc.partial),
        "heuristic": bool(desc and desc.heuristic),
        "levels": sorted(desc.levels) if desc else [],
    }


def _counts_by_state(chunks: Sequence[HeapChunk]) -> Dict[str, int]:
    return dict(Counter(chunk.state.value for chunk in chunks))


def _bytes_by_state(chunks: Sequence[HeapChunk]) -> Dict[str, int]:
    totals: Counter[str] = Counter()
    for chunk in chunks:
        totals[chunk.state.value] += chunk.size
    return dict(totals)


def _size_histogram(chunks: Sequence[HeapChunk]) -> List[Dict[str, int]]:
    """Power-of-two buckets ``[2**k, 2**(k+1))``, ascending, empty ones omitted."""
    buckets = Counter(max(chunk.size, 1).bit_length() - 1 for chunk in chunks)
    return [{"min_size": 1 << k, "max_size": (1 << (k + 1)) - 1, "count": n}
            for k, n in sorted(buckets.items())]


def _role_bytes(layout: HeapLayout) -> Dict[str, int]:
    if not layout.chunks:
        return {}
    end = max(chunk.end for chunk in layout.chunks)
    return layout.role_counts(layout.chunks[0].va, end)


# -- heap.chunks ------------------------------------------------------------------


def heap_chunks_result(
    session: ToolSession,
    dump_path: str,
    allocator: str = "auto",
    *,
    state: Optional[str] = None,
    min_size: Optional[int] = None,
    max_size: Optional[int] = None,
    va_start: Optional[int] = None,
    va_end: Optional[int] = None,
    offset: Optional[int] = None,
    length: Optional[int] = None,
    view: str = "vas",
    page: int = 0,
    page_size: int = DEFAULT_CHUNK_PAGE_SIZE,
    base_va: Optional[int] = None,
    max_chunks: int = DEFAULT_MAX_CHUNKS,
    regions: Optional[Sequence[str]] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """One page of the chunk table, filtered by state, size and a window.

    The window is EITHER ``va_start``/``va_end`` (half-open VAs) OR
    ``offset``/``length`` in ``view``; a chunk matches when it overlaps the
    window. ``page`` is 0-based; ``page_size`` is capped at
    :data:`MAX_CHUNK_PAGE_SIZE`.
    """
    hint = _checked_allocator(allocator)
    view = _checked_view(view)
    wanted_state = _checked_state(state)
    _check_window(va_start, va_end, offset, length)
    _check_paging(page, page_size)
    with _opened(dump_path, key_file, passphrase, kem_key_file) as source:
        _require_supported_view(source, view)
        layout = _layout_of(source, hint, base_va, max_chunks, regions)
        memory = _memory_of(source, layout, base_va)
        matches = [c for c in layout.chunks
                   if _chunk_passes(c, wanted_state, min_size, max_size)]
        matches = _in_window(matches, memory, view, va_start, va_end,
                             offset, length)
        payload = _chunk_page(layout, matches, memory, view, page, page_size)
        payload["filters"] = {
            "state": wanted_state.value if wanted_state else None,
            "min_size": min_size, "max_size": max_size,
            "va_start": va_start, "va_end": va_end,
            "offset": offset, "length": length,
        }
        return _finalize_inspect(payload, source, view=None)


def _check_window(va_start: Optional[int], va_end: Optional[int],
                  offset: Optional[int], length: Optional[int]) -> None:
    has_va = va_start is not None or va_end is not None
    has_offset = offset is not None or length is not None
    if has_va and has_offset:
        raise _invalid("give either va_start/va_end or offset/length, not both")
    if has_offset and (offset is None or length is None or offset < 0
                       or length <= 0):
        raise _invalid("offset/length window needs offset >= 0 and length > 0",
                       offset=offset, length=length)
    if va_start is not None and va_end is not None and va_end <= va_start:
        raise _invalid("va_end must be greater than va_start",
                       va_start=va_start, va_end=va_end)


def _check_paging(page: int, page_size: int) -> None:
    if page < 0:
        raise _invalid("page must be >= 0", page=page)
    if not 1 <= page_size <= MAX_CHUNK_PAGE_SIZE:
        raise _invalid(f"page_size must be between 1 and {MAX_CHUNK_PAGE_SIZE}",
                       page_size=page_size)


def _chunk_passes(chunk: HeapChunk, state: Optional[ChunkState],
                  min_size: Optional[int], max_size: Optional[int]) -> bool:
    if state is not None and chunk.state is not state:
        return False
    if min_size is not None and chunk.size < min_size:
        return False
    return max_size is None or chunk.size <= max_size


def _in_window(chunks: List[HeapChunk], memory: VaMemory, view: str,
               va_start: Optional[int], va_end: Optional[int],
               offset: Optional[int], length: Optional[int]) -> List[HeapChunk]:
    if offset is not None and length is not None:
        return [c for c in chunks
                if _overlaps_view_window(c, memory, view, offset, length)]
    lo = va_start if va_start is not None else 0
    hi = va_end if va_end is not None else None
    return [c for c in chunks if c.end > lo and (hi is None or c.va < hi)]


def _overlaps_view_window(chunk: HeapChunk, memory: VaMemory, view: str,
                          offset: int, length: int) -> bool:
    start = memory.va_to_view_offset(chunk.va, view)
    if start is None:
        return False
    return start < offset + length and start + chunk.size > offset


def _chunk_page(layout: HeapLayout, matches: List[HeapChunk], memory: VaMemory,
                view: str, page: int, page_size: int) -> Dict[str, Any]:
    first = page * page_size
    shown = matches[first:first + page_size]
    return {
        "allocator": layout.allocator.value,
        "view": view,
        "total": len(matches),
        "chunk_count": len(layout.chunks),
        "page": page,
        "page_size": page_size,
        "pages": -(-len(matches) // page_size),
        "chunks": [_chunk_row(c, memory, view) for c in shown],
        "diagnostics": list(layout.diagnostics),
    }


# -- heap.chunk_at ----------------------------------------------------------------


def heap_chunk_at_result(
    session: ToolSession,
    dump_path: str,
    allocator: str = "auto",
    *,
    va: Optional[int] = None,
    offset: Optional[int] = None,
    view: str = "vas",
    base_va: Optional[int] = None,
    max_chunks: int = DEFAULT_MAX_CHUNKS,
    regions: Optional[Sequence[str]] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """The chunk containing a VA (or a ``view`` offset), the role of that
    byte, and the chunks either side of it.

    ``found`` is False when the address lies in no chunk; ``prev`` / ``next``
    are then the nearest chunks below and above it.
    """
    hint = _checked_allocator(allocator)
    view = _checked_view(view)
    if (va is None) == (offset is None):
        raise _invalid("give exactly one of va or offset")
    with _opened(dump_path, key_file, passphrase, kem_key_file) as source:
        _require_supported_view(source, view)
        layout = _layout_of(source, hint, base_va, max_chunks, regions)
        memory = _memory_of(source, layout, base_va)
        target = va if va is not None else _offset_to_va(memory, offset, view)
        payload = _chunk_at_payload(layout, memory, view, target)
        return _finalize_inspect(payload, source, view=None)


def _offset_to_va(memory: VaMemory, offset: Optional[int], view: str) -> int:
    target = memory.view_offset_to_va(offset or 0, view)
    if target is None:
        raise OffsetOutOfRangeError(
            "offset does not map to a captured virtual address",
            details={"offset": offset, "view": view})
    return target


def _chunk_at_payload(layout: HeapLayout, memory: VaMemory, view: str,
                      va: int) -> Dict[str, Any]:
    chunk = layout.chunk_at(va)
    prev_chunk, next_chunk = _neighbours(layout.chunks, va, chunk)
    return {
        "allocator": layout.allocator.value,
        "va": va,
        "view": view,
        "view_offset": memory.va_to_view_offset(va, view),
        "found": chunk is not None,
        "chunk": _chunk_row(chunk, memory, view) if chunk else None,
        "role": _role_at(layout, va),
        "offset_in_chunk": va - chunk.va if chunk else None,
        "offset_in_user": _offset_in_user(chunk, va),
        "prev": _chunk_row(prev_chunk, memory, view) if prev_chunk else None,
        "next": _chunk_row(next_chunk, memory, view) if next_chunk else None,
    }


def _neighbours(chunks: Tuple[HeapChunk, ...], va: int,
                containing: Optional[HeapChunk]
                ) -> Tuple[Optional[HeapChunk], Optional[HeapChunk]]:
    """Chunks just below and just above *va* (excluding the containing one)."""
    idx = bisect.bisect_right(chunks, va, key=lambda c: c.va)
    below = idx - 2 if containing is not None else idx - 1
    prev_chunk = chunks[below] if below >= 0 else None
    next_chunk = chunks[idx] if idx < len(chunks) else None
    return prev_chunk, next_chunk


def _role_at(layout: HeapLayout, va: int) -> str:
    for _start, _length, role in layout.role_runs(va, va + 1):
        return role.name.lower()
    return HeapRole.NONE.name.lower()


def _offset_in_user(chunk: Optional[HeapChunk], va: int) -> Optional[int]:
    if chunk is None or not chunk.user_va <= va < chunk.user_va + chunk.user_len:
        return None
    return va - chunk.user_va


# -- heap.free_lists --------------------------------------------------------------


def heap_free_lists_result(
    session: ToolSession,
    dump_path: str,
    allocator: str = "auto",
    *,
    kind: Optional[str] = None,
    base_va: Optional[int] = None,
    max_chunks: int = DEFAULT_MAX_CHUNKS,
    regions: Optional[Sequence[str]] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """Every walked free list (tcache bins, fastbins, …), optionally only
    those of one ``kind``, with cycle and corruption flags.

    A list is ``corrupt`` when an entry is not the start of a parsed chunk
    (listed in ``unresolved_vas``) — a smashed link or an uncaptured page.
    """
    hint = _checked_allocator(allocator)
    with _opened(dump_path, key_file, passphrase, kem_key_file) as source:
        layout = _layout_of(source, hint, base_va, max_chunks, regions)
        lists = [_free_list_row(layout, fl) for fl in layout.free_lists
                 if kind is None or fl.kind == kind]
        payload = {
            "allocator": layout.allocator.value,
            "kinds": sorted({fl.kind for fl in layout.free_lists}),
            "list_count": len(lists),
            "cycle_count": sum(1 for row in lists if row["cycle"]),
            "corrupt_count": sum(1 for row in lists if row["corrupt"]),
            "lists": lists,
            "diagnostics": list(layout.diagnostics),
        }
        return _finalize_inspect(payload, source, view=None)


def _free_list_row(layout: HeapLayout, free_list: FreeList) -> Dict[str, Any]:
    unresolved = [va for va in free_list.chunk_vas
                  if not _is_chunk_start(layout, va)]
    return {
        "kind": free_list.kind,
        "index": free_list.index,
        "head_va": free_list.head_va,
        "length": len(free_list.chunk_vas),
        "chunk_vas": list(free_list.chunk_vas),
        "decoded": free_list.decoded,
        "cycle": free_list.cycle,
        "corrupt": bool(unresolved),
        "unresolved_vas": unresolved,
    }


def _is_chunk_start(layout: HeapLayout, va: int) -> bool:
    chunk = layout.chunk_at(va)
    return chunk is not None and chunk.va == va


# -- heap.roles -------------------------------------------------------------------


def heap_roles_result(
    session: ToolSession,
    dump_path: str,
    allocator: str = "auto",
    *,
    view: str = "vas",
    offset: int = 0,
    length: int = DEFAULT_ROLES_LENGTH,
    base_va: Optional[int] = None,
    max_chunks: int = DEFAULT_MAX_CHUNKS,
    regions: Optional[Sequence[str]] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> "ServiceResult":
    """The role of every heap byte in a ``view`` window, as coalesced runs.

    ``runs`` are ``{offset, length, role}`` in ``view`` offsets, clipped to
    ``[offset, offset + length)``, sorted and non-overlapping; bytes in no
    chunk (role ``none``) are omitted. ``chunk_starts`` are the view offsets
    of the chunk starts inside the window. ``length`` is capped at
    :data:`MAX_ROLES_LENGTH`.
    """
    hint = _checked_allocator(allocator)
    view = _checked_view(view)
    _check_roles_window(offset, length)
    with _opened(dump_path, key_file, passphrase, kem_key_file) as source:
        _require_supported_view(source, view)
        layout = _layout_of(source, hint, base_va, max_chunks, regions)
        memory = _memory_of(source, layout, base_va)
        segments = memory.view_window_segments(offset, length, view)
        allocator_block = _allocator_block(layout)
        payload = {
            "allocator": layout.allocator.value,
            "view": view,
            "offset": offset,
            "length": length,
            "runs": _view_role_runs(layout, segments),
            "chunk_starts": _view_chunk_starts(layout, segments),
            "partial": allocator_block["partial"],
            "heuristic": allocator_block["heuristic"],
        }
        return _finalize_inspect(payload, source, view=None)


def _check_roles_window(offset: int, length: int) -> None:
    if offset < 0 or length <= 0:
        raise _invalid("roles window needs offset >= 0 and length > 0",
                       offset=offset, length=length)
    if length > MAX_ROLES_LENGTH:
        raise _invalid(f"length must be at most {MAX_ROLES_LENGTH} bytes",
                       length=length, max_length=MAX_ROLES_LENGTH)


def _view_role_runs(layout: HeapLayout,
                    segments: Sequence[Tuple[int, int, int]]
                    ) -> List[Dict[str, Any]]:
    """VA role runs of each contiguous window piece, in view offsets,
    sorted and coalesced across piece boundaries."""
    runs: List[Tuple[int, int, HeapRole]] = []
    for seg_offset, seg_va, seg_len in segments:
        for run_va, run_len, role in layout.role_runs(seg_va, seg_va + seg_len):
            runs.append((seg_offset + (run_va - seg_va), run_len, role))
    return [{"offset": start, "length": run_len, "role": role.name.lower()}
            for start, run_len, role in _coalesced(sorted(runs))]


def _coalesced(runs: Sequence[Tuple[int, int, HeapRole]]
               ) -> List[Tuple[int, int, HeapRole]]:
    merged: List[Tuple[int, int, HeapRole]] = []
    for start, run_len, role in runs:
        if merged:
            last_start, last_len, last_role = merged[-1]
            last_end = last_start + last_len
            if start < last_end:  # defensive: never emit overlapping runs
                start, run_len = last_end, start + run_len - last_end
                if run_len <= 0:
                    continue
            if start == last_end and role == last_role:
                merged[-1] = (last_start, last_len + run_len, role)
                continue
        merged.append((start, run_len, role))
    return merged


def _view_chunk_starts(layout: HeapLayout,
                       segments: Sequence[Tuple[int, int, int]]) -> List[int]:
    starts: List[int] = []
    for seg_offset, seg_va, seg_len in segments:
        first = bisect.bisect_left(layout.chunks, seg_va, key=lambda c: c.va)
        for chunk in layout.chunks[first:]:
            if chunk.va >= seg_va + seg_len:
                break
            starts.append(seg_offset + (chunk.va - seg_va))
    return sorted(starts)
