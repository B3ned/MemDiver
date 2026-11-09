"""Heap-role projections persisted in an incremental (Welford) consensus session.

``consensus-begin`` opts a session in (``state["heap"]``); every
``consensus-add`` then projects the dump's heap onto the flat-view slab while
the dump is open and writes ``<state stem>.heap/<index:04d>.npz`` plus one
record in ``state["heap"]["dumps"]``. A later reduce merges the stored
projections with :func:`load_session_heap` (or, for a session without them,
analyses the reference dump alone via :func:`reference_heap`).

Recording a heap never breaks the fold: every failure becomes a record with
``status == "error"``. A session begun with allocator ``"off"`` carries no
``"heap"`` key at all, so its state JSON is byte-identical to the historical
one. Engine / heap imports stay function-local, as everywhere in ``app``
(only the shared ``ALLOCATOR_OFF`` constant is imported at module level).
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from memdiver.app._pipeline_heap import reduce_ready_allocators
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine.consensus_service import ALLOCATOR_OFF

logger = logging.getLogger("memdiver.app.welford_heap")

ALLOCATOR_AUTO = "auto"

#: Key of the heap block inside the session state JSON.
STATE_HEAP_KEY = "heap"

#: Suffix of the projection directory beside the state file.
HEAP_DIR_SUFFIX = ".heap"

#: File names :func:`record_dump_heap` writes (``<index:04d>.npz``; an index
#: of 10000 or more has five or more digits).
_PROJECTION_NAME = re.compile(r"^\d{4,}\.npz$")

#: Why ``search-reduce`` falls back to the reference dump.
NO_SESSION_HEAP_REASON = ("session has no heap roles (begun before heap "
                          "support or with --allocator off)")

Resolved = Tuple[Optional[str], Dict[str, Any]]


# -- allocator resolution ----------------------------------------------------------


def _check_allocator(allocator: str) -> None:
    """Reject a name that is neither off/auto nor reduce-ready (INVALID_INPUT)."""
    allowed = (ALLOCATOR_AUTO, ALLOCATOR_OFF, *reduce_ready_allocators())
    if allocator not in allowed:
        raise CapabilityError(
            f"allocator={allocator!r} cannot feed a candidate reduction; "
            f"choose one of {allowed}",
            category=ErrorCategory.INVALID_INPUT)


def _heap_enabled(allocator: str) -> bool:
    """Validate *allocator* (:func:`_check_allocator`); False for ``"off"``."""
    _check_allocator(allocator)
    return allocator != ALLOCATOR_OFF


def _detect(source: Any) -> Dict[str, Any]:
    """``{"best", "confidence"}`` of the auto-detector on *source*."""
    from memdiver.heap.detect import detect_allocator

    result = detect_allocator(source, ALLOCATOR_AUTO)
    return {"best": result.best.value,
            "confidence": round(float(result.confidence), 4)}


def _resolve_auto(source: Any) -> Resolved:
    detected = _detect(source)
    if detected["best"] in reduce_ready_allocators():
        return detected["best"], {"detected": detected}
    from memdiver.engine.consensus_heap import STATUS_UNSUPPORTED

    return None, {"status": STATUS_UNSUPPORTED, "detected": detected}


def _resolve_explicit(source: Any, allocator: str) -> Resolved:
    # Detection runs separately on purpose: with an explicit hint,
    # ``analyze_heap`` records the hint itself as ``coverage["analysis"]
    # ["detected"]`` (no ranking happens), so it cannot tell us whether the
    # dump disagrees with the forced allocator.
    info: Dict[str, Any] = {"detected": None}
    try:
        info["detected"] = _detect(source)
    except Exception as exc:  # noqa: BLE001 — detection is advisory here
        logger.debug("Allocator detection failed: %s", exc)
        return allocator, info
    best = info["detected"]["best"]
    if best != allocator:
        info["warning"] = (f"allocator {allocator!r} forced but detection "
                           f"suggests {best!r}")
    return allocator, info


def resolve_allocator(source: Any, allocator: str) -> Resolved:
    """``(concrete allocator or None, info)`` for a reduce-ready projection.

    ``"off"`` -> ``(None, {})``. ``"auto"`` accepts the detector's verdict
    only when it is reduce-ready; otherwise ``(None, {"status":
    "unsupported_allocator", "detected": {...}})``. An explicit name must be
    reduce-ready (``CapabilityError`` INVALID_INPUT otherwise); detection still
    runs and a disagreeing verdict adds a ``warning``.
    """
    if not _heap_enabled(allocator):
        return None, {}
    if allocator == ALLOCATOR_AUTO:
        return _resolve_auto(source)
    return _resolve_explicit(source, allocator)


# -- session state -----------------------------------------------------------------


def session_heap_dir(state_path: Path) -> Path:
    """``<stem>.heap/`` beside the session state file."""
    state_path = Path(state_path)
    return state_path.with_name(state_path.with_suffix("").name + HEAP_DIR_SUFFIX)


def begin_session_heap(state: Dict[str, Any], allocator: str) -> None:
    """Opt a new session into heap recording (no-op for ``"off"``)."""
    if _heap_enabled(allocator):
        state[STATE_HEAP_KEY] = {"allocator": allocator, "dumps": []}


def reset_session_heap_dir(state_path: Path) -> List[Path]:
    """Remove stale ``<index:04d>.npz`` projections left by an earlier session.

    A (re)begun session reusing *state_path* must not merge projections of a
    previous run. Only files named like a projection are removed; the
    directory and anything else in it stay. Returns the removed paths.
    """
    directory = session_heap_dir(state_path)
    if not directory.is_dir():
        return []
    stale = [p for p in sorted(directory.iterdir())
             if p.is_file() and _PROJECTION_NAME.match(p.name)]
    for path in stale:
        path.unlink()
    return stale


def _base_record(index: int, source: Any) -> Dict[str, Any]:
    return {"index": index, "path": str(getattr(source, "path", "") or ""),
            "status": None, "allocator": None, "detected": None,
            "confidence": None, "chunk_count": None, "file": None}


def _project(source: Any, size: int, allocator: str,
             record: Dict[str, Any]) -> Optional[Any]:
    """Resolve + project *source*, filling *record*; the projection or None."""
    from memdiver.engine.consensus_heap import (STATUS_NO_VA, has_va_map,
                                                project_dump_heap)

    if not has_va_map(source):   # nothing to detect on or project
        record["status"] = STATUS_NO_VA
        return None
    kind, info = resolve_allocator(source, allocator)
    record.update(info)
    if kind is None:
        return None
    projection, engine_record = project_dump_heap(source, size, kind)
    for key in ("status", "allocator", "confidence", "chunk_count"):
        record[key] = engine_record.get(key)
    return projection


def _record_error(record: Dict[str, Any], exc: Exception) -> None:
    from memdiver.engine.consensus_heap import STATUS_ERROR

    logger.warning("Session heap projection failed for %s", record["path"],
                   exc_info=True)
    record["status"] = STATUS_ERROR
    record["error"] = f"{type(exc).__name__}: {exc}"


def _save_projection(projection: Any, state_path: Path, index: int) -> str:
    """Write the projection; its ABSOLUTE path (never cwd-relative)."""
    directory = session_heap_dir(state_path)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{index:04d}.npz"
    projection.to_npz(path)
    return str(path.absolute())


def record_dump_heap(state: Dict[str, Any], state_path: Path, source: Any,
                     size: int, *, index: int) -> Optional[Dict[str, Any]]:
    """Project one OPEN dump into the session; the appended record or None.

    No-op (``None``) for a session without a ``"heap"`` block. Never raises:
    any failure is recorded as ``status == "error"`` with an ``error`` text.
    """
    block = state.get(STATE_HEAP_KEY)
    if block is None:
        return None
    record = _base_record(index, source)
    try:
        projection = _project(source, int(size), block["allocator"], record)
        if projection is not None:
            record["file"] = _save_projection(projection, Path(state_path), index)
    except Exception as exc:  # noqa: BLE001 — heap recording must never break the fold
        _record_error(record, exc)
    block.setdefault("dumps", []).append(record)
    return record


# -- merge ---------------------------------------------------------------------------


def _projection_file(stored: str, state_path: Optional[Path]) -> Path:
    """The session's own copy of *stored*, else *stored* as recorded.

    :func:`record_dump_heap` always writes into ``session_heap_dir(state_path)``,
    so that directory is tried FIRST: a legacy session (relative ``--state``)
    recorded cwd-relative paths, which from another working directory could
    name a different session's same-named file. The recorded path is the
    fallback (no *state_path*, or a state whose heap dir lacks the file).
    """
    path = Path(stored)
    if state_path is None:
        return path
    beside = session_heap_dir(Path(state_path)) / path.name
    return beside if beside.is_file() else path


Loaded = Tuple[List[Tuple[int, Any]], List[int]]


def _load_projections(records: Sequence[Dict[str, Any]],
                      state_path: Optional[Path] = None) -> Loaded:
    """``([(index, DumpHeapProjection)], [missing indices])`` in add order."""
    from memdiver.engine.consensus_heap import DumpHeapProjection

    loaded, missing = [], []
    for record in records:
        if not record.get("file"):
            continue
        path = _projection_file(record["file"], state_path)
        if not path.is_file():
            logger.warning("Session heap projection %s is missing; skipped", path)
            missing.append(int(record["index"]))
            continue
        loaded.append((int(record["index"]), DumpHeapProjection.from_npz(path)))
    return loaded, missing


def _report_allocator(records: Sequence[Dict[str, Any]], fallback: str) -> str:
    resolved = {r["allocator"] for r in records if r.get("file") and r.get("allocator")}
    return resolved.pop() if len(resolved) == 1 else fallback


def _status_counts(records: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    return dict(Counter(str(r.get("status")) for r in records))


def _status_by_precedence(statuses: Dict[str, int]) -> str:
    """``error`` > ``unsupported_allocator`` > ``no_va_coordinate``.

    An ``ok`` record counts as an error here: it promised a projection file
    that did not load.
    """
    from memdiver.engine.consensus_heap import (STATUS_ERROR, STATUS_NO_VA, STATUS_OK,
                                                STATUS_UNSUPPORTED)

    if STATUS_ERROR in statuses or STATUS_OK in statuses:
        return STATUS_ERROR
    return STATUS_UNSUPPORTED if STATUS_UNSUPPORTED in statuses else STATUS_NO_VA


def _status_without_projections(records: Sequence[Dict[str, Any]]
                                ) -> Tuple[str, Dict[str, Any]]:
    """``(status, extra report fields)`` of a merge that loaded no projection.

    No records: ``empty_consensus``. Otherwise the status follows
    :func:`_status_by_precedence` and the report carries ``status_counts``.
    ``ok`` records whose files are gone (moved or deleted session directory)
    must not report a usable, empty heap: that is an ``error`` naming the
    missing files.
    """
    from memdiver.engine.consensus_heap import STATUS_EMPTY, STATUS_OK

    if not records:
        return STATUS_EMPTY, {}
    counts = _status_counts(records)
    extra: Dict[str, Any] = {"status_counts": counts}
    if STATUS_OK in counts:
        extra["error"] = "stored heap projection files are missing"
    return _status_by_precedence(counts), extra


def _missing_projection_fields(missing: Sequence[int]) -> Dict[str, Any]:
    """Report fields for a merge that loaded only SOME projections."""
    if not missing:
        return {}
    return {"missing_projections": list(missing),
            "warning": (f"stored heap projection files are missing for dump "
                        f"indices {list(missing)}; merged without them")}


def load_session_heap(state: Dict[str, Any],
                      state_path: Optional[Path] = None) -> Optional[Any]:
    """Merge the session's stored projections into one ``ConsensusHeap``.

    ``None`` for a session without a ``"heap"`` block. Without any stored
    projection the result is unavailable, with the status picked by
    precedence (``error`` > ``unsupported_allocator`` >
    ``no_va_coordinate``) and per-status ``status_counts`` in the report.
    When only SOME projection files are missing the result stays ``ok`` and
    the report gains ``missing_projections`` (dump indices) and a
    ``warning``. The report always gains ``source="session"``,
    ``dumps_recorded`` and ``dumps_folded``. *state_path* (optional) makes
    projections resolve in the session's own heap directory first.
    """
    from memdiver.engine.consensus_heap import COORDINATE_FLAT_VIEW, assemble_heap

    block = state.get(STATE_HEAP_KEY)
    if block is None:
        return None
    records = [dict(r) for r in block.get("dumps", [])]
    projections, missing = _load_projections(records, state_path)
    allocator = _report_allocator(records, block["allocator"])
    empty_status, empty_extra = _status_without_projections(records)
    heap = assemble_heap(projections, records, allocator, COORDINATE_FLAT_VIEW,
                         empty_status=empty_status, **empty_extra)
    if projections:
        heap.report.update(_missing_projection_fields(missing))
    heap.report.update(source="session", dumps_recorded=len(records),
                       dumps_folded=int(state.get("num_dumps", 0)))
    return heap


def _reference_projection(reference_path: str, slab_size: int, allocator: str,
                          key_material: Dict[str, Any]) -> Any:
    from memdiver.app.composition import open_dump
    from memdiver.engine.consensus_heap import (COORDINATE_FLAT_VIEW, STATUS_NO_VA,
                                                assemble_heap)

    with open_dump(Path(reference_path), **key_material) as source:  # opens it
        record = _base_record(0, source)
        projection = _project(source, int(slab_size), allocator, record)
    pairs = [(0, projection)] if projection is not None else []
    return assemble_heap(pairs, [record], record.get("allocator") or allocator,
                         COORDINATE_FLAT_VIEW,
                         empty_status=record.get("status") or STATUS_NO_VA)


def reference_heap(reference_path: str, slab_size: int, allocator: str,
                   key_material: Optional[Dict[str, Any]] = None) -> Optional[Any]:
    """Single-dump heap roles of the reference (fallback without a session).

    ``None`` for ``"off"``. Failures become an unavailable ``"error"``
    result; the report carries ``source="reference"``.
    """
    if not _heap_enabled(allocator):
        return None
    return _reference_heap(reference_path, slab_size, allocator, key_material)


def _reference_heap(reference_path: str, slab_size: int, allocator: str,
                    key_material: Optional[Dict[str, Any]]) -> Any:
    """:func:`reference_heap` for an already validated, enabled *allocator*."""
    from memdiver.engine.consensus_heap import STATUS_ERROR, ConsensusHeap

    try:
        heap = _reference_projection(reference_path, slab_size, allocator,
                                     dict(key_material or {}))
    except Exception as exc:  # noqa: BLE001 — annotation must never break a reduce
        logger.warning("Reference heap annotation failed", exc_info=True)
        heap = ConsensusHeap.unavailable(STATUS_ERROR, allocator=allocator,
                                         error=f"{type(exc).__name__}: {exc}")
    heap.report["source"] = "reference"
    return heap


def _session_allocator_compatible(session_allocator: str, requested: str) -> bool:
    return ALLOCATOR_AUTO in (session_allocator, requested) or (
        session_allocator == requested)


def _guarded_session_heap(state: Dict[str, Any],
                          state_path: Optional[Path]) -> Any:
    """:func:`load_session_heap`, with a failure as an ``error`` result."""
    from memdiver.engine.consensus_heap import STATUS_ERROR, ConsensusHeap

    try:
        return load_session_heap(state, state_path)
    except Exception as exc:  # noqa: BLE001 — annotation must never break a reduce
        logger.warning("Session heap merge failed", exc_info=True)
        return ConsensusHeap.unavailable(
            STATUS_ERROR, allocator=state[STATE_HEAP_KEY]["allocator"],
            source="session", error=f"{type(exc).__name__}: {exc}")


def _session_fallback_reason(state: Dict[str, Any], allocator: str) -> Optional[str]:
    """Why the session heap cannot serve *allocator* (``None``: it can)."""
    block = state.get(STATE_HEAP_KEY)
    if block is None:
        return NO_SESSION_HEAP_REASON
    if not _session_allocator_compatible(block["allocator"], allocator):
        return (f"session heap was recorded with allocator "
                f"{block['allocator']!r}, not {allocator!r}")
    return None


def select_reduce_heap(state: Dict[str, Any], reference_path: str,
                       slab_size: int, allocator: str, *,
                       state_path: Optional[Path] = None,
                       key_material: Optional[Dict[str, Any]] = None,
                       ) -> Optional[Any]:
    """Heap roles for a reduce over a Welford session's variance.

    ``None`` for ``"off"``. The session's merged projections
    (``source="session"``) when it recorded them with a compatible
    allocator; otherwise the reference dump alone (``source="reference"``,
    with ``fallback_reason`` in the report). Never raises for a failed
    analysis: that is an unavailable result whose status says why.
    """
    if not _heap_enabled(allocator):
        return None
    reason = _session_fallback_reason(state, allocator)
    if reason is None:
        return _guarded_session_heap(state, state_path)
    heap = _reference_heap(reference_path, slab_size, allocator, key_material)
    heap.report["fallback_reason"] = reason
    return heap


def session_heap_summary(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Allocator, recorded dump count and per-status counts (finalize output)."""
    block = state.get(STATE_HEAP_KEY)
    if block is None:
        return None
    records = block.get("dumps", [])
    return {"allocator": block["allocator"], "dumps_recorded": len(records),
            "status_counts": _status_counts(records)}
