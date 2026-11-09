"""Heap-role awareness for the search-space reduction (``heap_policy``).

:func:`memdiver.engine.candidate_pipeline.reduce_search_space` takes the
consensus heap annotation (:mod:`memdiver.engine.consensus_heap`) as two
optional inputs — merged role runs and the anchor's chunk index, both in slab
coordinates — and a ``heap_policy``:

``"off"``
    Ignore them; the reduction is exactly what it was before heap roles.
``"annotate"`` (default)
    Every region gets a :func:`region_heap_annotation` dict. The candidate set
    and every score are untouched.
``"mask"``
    Additionally drop bytes whose consensus role is allocator metadata
    (:data:`METADATA_ROLES`) before the reduction, and adjust each region's
    score by :func:`heap_score_adjustment`.

Kept out of ``candidate_pipeline`` so the reduction itself never imports the
heap layer unless a caller hands it heap runs.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, Optional

import numpy as np

from memdiver.engine.consensus_heap import (
    FREED_STATE_VALUES,
    HeapChunkIndex,
    HeapRoleRuns,
)
from memdiver.heap.model import HeapRole, arena_entry

#: Roles the ``"mask"`` policy removes: bytes the allocator owns, which vary
#: across dumps (pointers, sizes, safe-linked next fields) without ever being
#: key material. ``MIXED`` is deliberately absent — "dumps disagree" is not
#: evidence that a byte is metadata.
METADATA_ROLES: FrozenSet[HeapRole] = frozenset({
    HeapRole.CHUNK_HEADER, HeapRole.FREE_LINK,
    HeapRole.ALLOCATOR_META, HeapRole.TOP,
})

_METADATA_NAMES = frozenset(r.name.lower() for r in METADATA_ROLES)
_USER_DATA_NAME = HeapRole.USER_DATA.name.lower()

#: ``CandidateScore.heap`` under ``"mask"``: a region touching allocator
#: metadata is demoted hard, one lying wholly in live user data nudged up.
METADATA_PENALTY = -0.5
USER_DATA_BONUS = 0.1


def metadata_mask(runs: HeapRoleRuns, size: int) -> np.ndarray:
    """Bool mask of length *size*: True on allocator-metadata bytes."""
    return runs.mask(METADATA_ROLES, size)


def _role_counts(runs: HeapRoleRuns, start: int, length: int) -> Dict[str, int]:
    """Bytes per role name inside ``[start, start + length)``, fill included."""
    counts: Dict[str, int] = {}
    covered = 0
    for _lo, n, role, _agree in runs.runs_in(start, length):
        name = role.name.lower()
        counts[name] = counts.get(name, 0) + n
        covered += n
    if covered < length:
        fill = HeapRole(runs.fill).name.lower()
        counts[fill] = counts.get(fill, 0) + length - covered
    return counts


def _agreement(runs: HeapRoleRuns, start: int, length: int) -> Optional[int]:
    """Fewest agreeing dumps over the region's role runs (None: no runs)."""
    agrees = [agree for *_rest, agree in runs.runs_in(start, length)]
    return min(agrees) if agrees else None


def _chunk_dict(chunks: Optional[HeapChunkIndex],
                start: int) -> Optional[Dict[str, Any]]:
    """The anchor chunk holding the region's first byte, or ``None``."""
    hit = chunks.chunk_at(start) if chunks is not None else None
    if hit is None:
        return None
    return {"start": hit["slab_start"], "size": hit["size"],
            "state": hit["state"], "offset_in_chunk": hit["offset_in_chunk"],
            "agree": hit["agree"],
            **arena_entry(hit.get("arena"))}


def region_heap_annotation(runs: HeapRoleRuns,
                           chunks: Optional[HeapChunkIndex],
                           start: int, length: int) -> Dict[str, Any]:
    """The ``CandidateRegion.heap`` dict for one region.

    ``residual`` is True when the region starts in a freed chunk (free,
    cached or quarantined): bytes there are stale, not live state.
    """
    chunk = _chunk_dict(chunks, start)
    return {
        "role_counts": _role_counts(runs, start, length),
        "chunk": chunk,
        "residual": bool(chunk and chunk["state"] in FREED_STATE_VALUES),
        "agreement": _agreement(runs, start, length),
    }


def heap_score_adjustment(annotation: Dict[str, Any], length: int) -> float:
    """``CandidateScore.heap`` for one annotated region (``"mask"`` only)."""
    counts = annotation["role_counts"]
    if any(counts.get(name) for name in _METADATA_NAMES):
        return METADATA_PENALTY
    if length > 0 and counts.get(_USER_DATA_NAME, 0) == length:
        return USER_DATA_BONUS
    return 0.0
