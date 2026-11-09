"""Heap roles for ``search-reduce`` (``--allocator`` x ``--heap-policy``).

The producer (``app.tools_pipeline.search_reduce``) reads heap roles from a
``heap_roles.npz`` beside the variance it reduces. The CLI materialises that
variance into a scratch directory, so this module selects the heap for the
Welford session (its merged per-dump projections, else the reference dump
alone), writes the npz into the same scratch directory, and afterwards adds
the compact ``heap`` block to the payload. With ``--allocator off`` (or
``--heap-policy off``) nothing here touches the payload.
"""

import argparse
from pathlib import Path
from typing import Any, Dict, Optional

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine.consensus_service import ALLOCATOR_OFF

from ._shared import _key_material_from_args
from .heap_report import report_reduce_heap

def heap_policy_of(args: argparse.Namespace) -> str:
    """``--heap-policy`` (hand-built Namespaces default to ``annotate``)."""
    return getattr(args, "heap_policy", "annotate")


def effective_allocator(args: argparse.Namespace) -> str:
    """``--allocator`` after the policy; ``off`` for pre-flag Namespaces.

    ``--allocator off --heap-policy mask`` is contradictory (nothing to mask
    with) and is refused as INVALID_INPUT (exit 2) before any work.
    """
    from memdiver.app._pipeline_heap import allocator_for_policy

    allocator = getattr(args, "allocator", ALLOCATOR_OFF)
    policy = heap_policy_of(args)
    if allocator == ALLOCATOR_OFF and policy == "mask":
        raise CapabilityError(
            "--heap-policy mask needs heap roles, but --allocator off disables "
            "heap analysis; use --allocator auto|ptmalloc2 or --heap-policy "
            "annotate|off",
            category=ErrorCategory.INVALID_INPUT)
    return allocator_for_policy(allocator, policy)


def prepare_reduce_heap(args: argparse.Namespace, state: Dict[str, Any],
                        slab_size: int, allocator: str,
                        scratch: Path) -> Optional[Any]:
    """Select, report and persist the heap beside the scratch variance.

    Returns the ``ConsensusHeap`` (``None`` for ``off``). Under ``mask`` an
    unusable heap is a PRECONDITION error naming its status.
    """
    from memdiver.app._pipeline_heap import require_heap_for_mask
    from memdiver.app.welford_heap import select_reduce_heap

    if allocator == ALLOCATOR_OFF:
        return None
    heap = select_reduce_heap(
        state, args.reference_dump, slab_size, allocator,
        state_path=Path(args.state), key_material=_key_material_from_args(args))
    report_reduce_heap(heap)
    require_heap_for_mask(heap, heap_policy_of(args))
    _save_heap_roles(heap, scratch)
    return heap


def _save_heap_roles(heap: Any, scratch: Path) -> None:
    """``heap_roles.npz`` in the fresh *scratch* dir, only for a usable heap.

    Unlike ``write_consensus_heap`` no ``consensus.json`` block is built and
    no stale npz needs removing: nothing else ever wrote to *scratch*.
    """
    from memdiver.app._pipeline_heap import HEAP_ROLES_FILENAME
    from memdiver.engine.consensus_heap import STATUS_OK, save_heap_npz

    if heap.status == STATUS_OK:
        save_heap_npz(heap, scratch / HEAP_ROLES_FILENAME)


def attach_reduce_heap(payload: Dict[str, Any], heap: Optional[Any],
                       allocator: str) -> None:
    """Add ``heap`` / ``heap_status`` / ``thresholds.allocator`` (not for off).

    ``thresholds.allocator`` records the REQUESTED allocator (``auto`` stays
    ``auto``); the resolved one is ``heap.allocator``.
    """
    from memdiver.app._pipeline_heap import reduce_heap_block

    if heap is None:
        return
    payload["heap"] = reduce_heap_block(heap)
    payload["heap_status"] = heap.status
    payload.setdefault("thresholds", {})["allocator"] = allocator
