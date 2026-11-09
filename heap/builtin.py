"""Built-in allocator descriptors, registered on first registry use.

Every descriptor detects by the name / module / OS signals of
:mod:`.detect`, combined with the content probe of its parser module in
``heap/allocators/``. Each parser module exports ``DESCRIPTOR_OVERRIDES``,
a ``{kind: (probe, parse)}`` map that :data:`BUILTIN_SPECS` draws from.
``levels`` lists the analysis levels each parser reaches (L0 detection,
L1 region attribution, L2 chunk walk, L3 free-list walk).
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, FrozenSet, List, NamedTuple, Optional, Tuple

from memdiver.heap.allocators import (generic, jemalloc, mallocng, ptmalloc2,
                                      scudo)
from memdiver.heap.detect import evidence_score, name_signals
from memdiver.heap.model import AllocatorKind, Evidence
from memdiver.heap.registry import (AllocatorDescriptor, DetectContext,
                                    DetectFn, DetectScore, ParseFn,
                                    register_allocator)

ProbeFn = Callable[[DetectContext], DetectScore]

logger = logging.getLogger("memdiver.heap.builtin")


def _levels(*names: str) -> FrozenSet[str]:
    return frozenset(names)


def name_detector(kind: AllocatorKind,
                  probe: Optional[ProbeFn] = None) -> DetectFn:
    """A detect function scoring *kind*'s name signals, plus *probe*'s bytes.

    The two scores combine as independent evidence:
    ``1 - (1 - names) * (1 - probe)``. A probe that raises (e.g. no readable
    memory behind the context) only loses its own contribution; the name
    evidence still stands.
    """

    def detect(ctx: DetectContext) -> DetectScore:
        evidence = name_signals(kind, ctx)
        score = evidence_score(evidence)
        if probe is None:
            return DetectScore(score, evidence)
        probed = _run_probe(kind, probe, ctx)
        combined = 1.0 - (1.0 - score) * (1.0 - probed.score)
        return DetectScore(combined, evidence + list(probed.evidence))

    detect.__name__ = f"detect_{kind.value}"
    return detect


def _run_probe(kind: AllocatorKind, probe: ProbeFn,
               ctx: DetectContext) -> DetectScore:
    try:
        return probe(ctx)
    except Exception as exc:  # noqa: BLE001 — keep the name evidence alive
        logger.debug("Allocator probe %s failed", kind.value, exc_info=True)
        return DetectScore(0.0, [Evidence(
            "probe_error", f"{kind.value} content probe raised {exc!r}", 0.0)])


class BuiltinSpec(NamedTuple):
    kind: AllocatorKind
    priority: int
    levels: FrozenSet[str]
    partial: bool = False
    heuristic: bool = False
    parse: Optional[ParseFn] = None
    probe: Optional[ProbeFn] = None
    reduce_ready: bool = False


def _parser_overrides() -> Dict[AllocatorKind, Tuple[ProbeFn, ParseFn]]:
    """Collect ``(probe, parse)`` pairs from every allocator parser module."""
    overrides: Dict[AllocatorKind, Tuple[ProbeFn, ParseFn]] = {}
    for module in (ptmalloc2, scudo, mallocng, jemalloc, generic):
        overrides.update(module.DESCRIPTOR_OVERRIDES)
    return overrides


_OVERRIDES = _parser_overrides()


def _spec(kind: AllocatorKind, priority: int, levels: FrozenSet[str],
          *, partial: bool = False, heuristic: bool = False,
          reduce_ready: bool = False) -> BuiltinSpec:
    probe, parse = _OVERRIDES[kind]
    return BuiltinSpec(kind, priority, levels, partial, heuristic,
                       parse=parse, probe=probe, reduce_ready=reduce_ready)


BUILTIN_SPECS: List[BuiltinSpec] = [
    _spec(AllocatorKind.PTMALLOC2, 50, _levels("L0", "L1", "L2", "L3"),
          reduce_ready=True),
    _spec(AllocatorKind.SCUDO, 50, _levels("L0", "L1", "L2"), partial=True),
    _spec(AllocatorKind.MALLOCNG, 50, _levels("L0", "L1", "L2")),
    _spec(AllocatorKind.DLMALLOC, 40, _levels("L0", "L1", "L2")),
    _spec(AllocatorKind.JEMALLOC, 30, _levels("L0", "L1"), partial=True),
    _spec(AllocatorKind.GENERIC, 0, _levels("L0", "L1"), heuristic=True),
]


def builtin_descriptor(spec: BuiltinSpec) -> AllocatorDescriptor:
    return AllocatorDescriptor(
        kind=spec.kind, detect=name_detector(spec.kind, spec.probe),
        parse=spec.parse, priority=spec.priority, levels=spec.levels,
        partial=spec.partial, heuristic=spec.heuristic,
        reduce_ready=spec.reduce_ready,
    )


def register_builtin_allocators() -> None:
    """Register every built-in; an earlier (plugin) registration wins."""
    for spec in BUILTIN_SPECS:
        register_allocator(builtin_descriptor(spec), replace=False)
