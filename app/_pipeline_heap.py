"""Heap-role plumbing shared by the pipeline producers in ``tools_pipeline``.

The consensus stage persists ``cm.heap`` as ``heap_roles.npz`` beside
``variance.npy`` plus a ``"heap"`` block in ``consensus.json``; the reduce
stages (``search_reduce`` / ``analyze_candidates``) read it back and hand it to
:func:`memdiver.engine.candidate_pipeline.reduce_search_space` under a
``heap_policy``. Engine imports stay function-local, as everywhere in ``app``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: Artifact the consensus stage writes beside ``variance.npy``.
HEAP_ROLES_FILENAME = "heap_roles.npz"

#: ``(heap_runs, heap_chunks)`` as ``reduce_search_space`` takes them.
HeapInputs = Tuple[Optional[Any], Optional[Any]]

_NO_HEAP: HeapInputs = (None, None)


def checked_heap_policy(heap_policy: str) -> str:
    """Reject an unknown ``heap_policy`` as INVALID_INPUT."""
    from memdiver.engine.candidate_pipeline import HEAP_POLICIES

    if heap_policy not in HEAP_POLICIES:
        raise CapabilityError(
            f"heap_policy={heap_policy!r} is not one of {HEAP_POLICIES}",
            category=ErrorCategory.INVALID_INPUT,
        )
    return heap_policy


def _mask_unavailable(reason: str, *, reduce_ready: bool = False) -> CapabilityError:
    """PRECONDITION error for ``mask`` without usable heap roles.

    Only paths that enforce a reduce-ready allocator (the ``search-reduce``
    session / reference heap) pass ``reduce_ready=True``; the batch consensus
    paths do not, so their message must not claim that requirement.
    """
    allocator_clause = (f" whose heap allocator is reduce-ready "
                        f"({', '.join(reduce_ready_allocators())})"
                        if reduce_ready else "")
    return CapabilityError(
        f"heap_policy='mask' needs consensus heap roles, but {reason}. "
        f"Masking needs dumps with a VA map (.msl / core){allocator_clause} "
        f"and heap analysis enabled (an allocator other than 'off'); "
        f"otherwise use heap_policy='annotate' / 'off'.",
        category=ErrorCategory.PRECONDITION,
    )


def _detected_allocator(heap: Any) -> Optional[Dict[str, Any]]:
    """The detector verdict in the report, else the first per-dump one."""
    detected = heap.report.get("detected")
    for record in heap.per_dump:
        detected = detected or record.get("detected")
    return detected


def _first_error(heap: Any) -> Optional[str]:
    errors = [heap.report.get("error")] + [r.get("error") for r in heap.per_dump]
    return next((e for e in errors if e), None)


def heap_unavailable_reason(heap: Optional[Any]) -> str:
    """``"<status>: <cause>"`` for a heap annotation that is not ``ok``."""
    from memdiver.engine.consensus_heap import STATUS_EMPTY, STATUS_NO_VA, STATUS_UNSUPPORTED

    if heap is None:
        return "allocator='off': heap analysis is disabled"
    status = heap.status
    source = heap.report.get("source", "consensus")
    if status == STATUS_NO_VA:
        return f"{status}: {source} dump has no VA map (raw dump)"
    if status == STATUS_UNSUPPORTED:
        found = _detected_allocator(heap) or {}
        return (f"{status}: detected {found.get('best', '?')} "
                f"({found.get('confidence', '?')}); the reduction supports "
                f"{', '.join(reduce_ready_allocators())}")
    if status == STATUS_EMPTY:
        return f"{status}: no heap projection was recorded"
    return f"{status}: {_first_error(heap) or 'heap analysis failed'}"


def require_heap_for_mask(heap: Optional[Any], heap_policy: str) -> None:
    """PRECONDITION error when ``mask`` meets a missing / unusable heap."""
    from memdiver.engine.consensus_heap import STATUS_OK

    if heap_policy == "mask" and (heap is None or heap.status != STATUS_OK):
        raise _mask_unavailable(
            f"the heap annotation is unavailable ({heap_unavailable_reason(heap)})",
            reduce_ready=True)


def reduce_heap_block(heap: Any) -> Dict[str, Any]:
    """Compact payload block: status, report fields and per-dump records.

    Unlike :func:`write_consensus_heap`'s block it carries no run / chunk
    summaries and no ``heap_roles_path`` (the reduce's npz is scratch).
    """
    return {"status": heap.status, **heap.report,
            "per_dump": [dict(r) for r in heap.per_dump]}


def write_consensus_heap(heap: Optional[Any], out_dir: Path) -> Optional[Dict[str, Any]]:
    """Persist ``cm.heap``; return the ``"heap"`` block for ``consensus.json``.

    ``heap_roles.npz`` is written only for a usable (``status == "ok"``)
    annotation, so a later ``mask`` never silently masks with an empty map.
    Otherwise a ``heap_roles.npz`` left by an earlier build in *out_dir* is
    removed: it would describe a different consensus. ``None`` (allocator
    "off") returns ``None`` — no block.
    """
    from memdiver.engine.consensus_heap import STATUS_OK, save_heap_npz

    path = out_dir / HEAP_ROLES_FILENAME
    if heap is None or heap.status != STATUS_OK:
        path.unlink(missing_ok=True)
    if heap is None:
        return None
    block: Dict[str, Any] = {"status": heap.status, **heap.to_dict(),
                             "heap_roles_path": None}
    if heap.status == STATUS_OK:
        save_heap_npz(heap, path)
        block["heap_roles_path"] = str(path)
    return block


def load_heap_beside(variance_path: str, heap_policy: str) -> HeapInputs:
    """Heap inputs for a reduce over ``variance_path`` (its sibling npz).

    No npz: ``(None, None)`` — the reduction then behaves as ``"off"`` — except
    under an explicit ``"mask"``, which is a PRECONDITION error.
    """
    if heap_policy == "off":
        return _NO_HEAP
    path = Path(variance_path).parent / HEAP_ROLES_FILENAME
    if not path.is_file():
        if heap_policy == "mask":
            raise _mask_unavailable(f"no {HEAP_ROLES_FILENAME} beside {variance_path}")
        return _NO_HEAP
    from memdiver.engine.consensus_heap import load_heap_npz

    return load_heap_npz(path)


def heap_inputs_from_consensus(cm: Any, heap_policy: str) -> HeapInputs:
    """Heap inputs from an in-memory consensus (same rules as the npz path)."""
    if heap_policy == "off":
        return _NO_HEAP
    from memdiver.engine.consensus_heap import STATUS_OK

    heap = getattr(cm, "heap", None)
    if heap is None or heap.status != STATUS_OK:
        if heap_policy == "mask":
            status = "allocator='off'" if heap is None else f"status={heap.status!r}"
            raise _mask_unavailable(f"the consensus heap annotation is unavailable ({status})")
        return _NO_HEAP
    return heap.runs, heap.chunks


def allocator_for_policy(allocator: str, heap_policy: str) -> str:
    """``"off"`` when the policy ignores heap roles (skip the analysis cost)."""
    return "off" if heap_policy == "off" else allocator


def reduce_ready_allocators() -> Tuple[str, ...]:
    """Allocator names whose heap roles may feed a candidate reduction."""
    from memdiver.heap.registry import reduce_ready_kinds

    return tuple(kind.value for kind in reduce_ready_kinds())
