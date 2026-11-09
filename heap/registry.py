"""Allocator registry: one :class:`AllocatorDescriptor` per allocator kind.

Mirrors :func:`memdiver.core.dump_source.register_dump_source`: a descriptor
pairs a ``detect`` function (how much does this dump look like my
allocator?) with an optional ``parse`` function (walk its heap), plus a
dispatch ``priority``. The built-in descriptors live in :mod:`.builtin`;
out-of-tree packages add their own through the ``memdiver.allocators``
entry-point group (a module that calls :func:`register_allocator` on import,
or a callable that does so when invoked).

Registering a kind that is already registered replaces it, so a plugin can
override a built-in allocator. Detectors are isolated: one that raises (or
returns garbage) scores 0 with a diagnostic :class:`Evidence` instead of
breaking detection of every other allocator — see :func:`run_detector`.
"""

from __future__ import annotations

import itertools
import logging
import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from functools import cached_property
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

from memdiver.heap.memory import VaMemory
from memdiver.heap.model import AllocatorKind, Evidence, HeapLayout
from memdiver.heap.platform import (MappedRegion, TargetPlatform,
                                    memory_map_of, module_paths, platform_of)

logger = logging.getLogger("memdiver.heap.registry")

ALLOCATOR_ENTRY_POINT_GROUP = "memdiver.allocators"


def name_matches(name: str, pattern: str) -> bool:
    """fnmatch with ``*``/``?`` wildcards but a literal ``[`` (``[heap]``)."""
    return fnmatch(name, pattern.replace("[", "[[]"))


class DetectContext:
    """What a detector may look at; every field is computed on first use.

    Pass ``platform`` / ``regions`` / ``modules`` to skip the source probes
    (tests, or a caller that already has them).
    """

    def __init__(self, source: Any, *, platform: Optional[TargetPlatform] = None,
                 regions: Optional[List[MappedRegion]] = None,
                 modules: Optional[List[str]] = None,
                 base_va: Optional[int] = None):
        self.source = source
        self.base_va = base_va
        if platform is not None:
            self.__dict__["platform"] = platform
        if regions is not None:
            self.__dict__["regions"] = list(regions)
        if modules is not None:
            self.__dict__["modules"] = list(modules)

    @cached_property
    def platform(self) -> TargetPlatform:
        return platform_of(self.source)

    @cached_property
    def regions(self) -> List[MappedRegion]:
        return memory_map_of(self.source)

    @cached_property
    def modules(self) -> List[str]:
        from_regions = [r.module_path for r in self.regions if r.module_path]
        return list(dict.fromkeys(module_paths(self.source) + from_regions))

    @cached_property
    def memory(self) -> VaMemory:
        return VaMemory(self.source, self.platform, base_va=self.base_va)

    @cached_property
    def region_names(self) -> List[str]:
        return [r.name for r in self.regions if r.name]

    @cached_property
    def module_basenames(self) -> List[str]:
        return [os.path.basename(path) for path in self.modules]

    def has_region(self, pattern: str) -> bool:
        """True when a region name matches *pattern* (see :func:`name_matches`)."""
        return any(name_matches(name, pattern) for name in self.region_names)

    def matching_modules(self, *patterns: str) -> List[str]:
        """Module basenames matching any of the fnmatch *patterns*."""
        return [name for name in self.module_basenames
                if any(fnmatch(name, p) for p in patterns)]


@dataclass(frozen=True)
class DetectScore:
    """A detector's verdict: ``score`` in ``[0, 1]`` and why."""

    score: float
    evidence: List[Evidence] = field(default_factory=list)


@dataclass(frozen=True)
class ParseOptions:
    """Knobs every parser honours.

    ``regions`` restricts parsing to mappings whose name matches one of the
    given patterns (:func:`name_matches`; ``None`` = every region the parser
    owns).
    """

    max_chunks: int = 200_000
    regions: Optional[Tuple[str, ...]] = None

    def selects(self, region: MappedRegion) -> bool:
        if self.regions is None:
            return True
        return any(name_matches(region.name, p) for p in self.regions)


DetectFn = Callable[[DetectContext], DetectScore]
ParseFn = Callable[[VaMemory, DetectContext, ParseOptions], HeapLayout]


@dataclass(frozen=True)
class AllocatorDescriptor:
    """One allocator: how to detect it, how to parse it, what it covers.

    ``levels`` names the analysis levels the parser reaches (``"L0"``
    detection … ``"L3"`` free-list walk); ``partial`` marks a parser that
    covers only part of the allocator, ``heuristic`` one that guesses
    structure instead of reading it. ``parse=None`` means detect-only.
    ``reduce_ready`` opts the allocator in to heap-aware candidate
    reduction: set it only once the parser is validated for that use.
    """

    kind: AllocatorKind
    detect: DetectFn
    parse: Optional[ParseFn] = None
    priority: int = 0
    levels: FrozenSet[str] = frozenset({"L0"})
    partial: bool = False
    heuristic: bool = False
    reduce_ready: bool = False


@dataclass(frozen=True)
class _RegistryEntry:
    order: int  # registration sequence; tie-breaker within a priority
    descriptor: AllocatorDescriptor


_ALLOCATOR_REGISTRY: Dict[AllocatorKind, _RegistryEntry] = {}
_registration_counter = itertools.count()
_LOADED = False


def register_allocator(desc: AllocatorDescriptor, *, replace: bool = True) -> None:
    """Register *desc*, replacing any descriptor of the same kind.

    With ``replace=False`` an existing registration wins (how the built-ins
    register, so a plugin registered earlier is never overwritten).
    """
    if not replace and desc.kind in _ALLOCATOR_REGISTRY:
        return
    _ALLOCATOR_REGISTRY[desc.kind] = _RegistryEntry(
        order=next(_registration_counter), descriptor=desc)


def unregister_allocator(kind: AllocatorKind) -> Optional[AllocatorDescriptor]:
    """Remove and return the descriptor of *kind* (``None`` if absent)."""
    entry = _ALLOCATOR_REGISTRY.pop(AllocatorKind(kind), None)
    return entry.descriptor if entry is not None else None


def registered_allocators() -> List[AllocatorDescriptor]:
    """Every descriptor, highest priority first (ties: registration order)."""
    _ensure_loaded()
    entries = sorted(_ALLOCATOR_REGISTRY.values(),
                     key=lambda e: (-e.descriptor.priority, e.order))
    return [entry.descriptor for entry in entries]


def get_allocator(kind: AllocatorKind | str) -> Optional[AllocatorDescriptor]:
    """The descriptor registered for *kind*, or ``None``."""
    _ensure_loaded()
    entry = _ALLOCATOR_REGISTRY.get(AllocatorKind(kind))
    return entry.descriptor if entry is not None else None


def reduce_ready_kinds() -> Tuple[AllocatorKind, ...]:
    """Kinds whose descriptor opted in to candidate reduction (priority order)."""
    return tuple(desc.kind for desc in registered_allocators()
                 if desc.reduce_ready)


def run_detector(desc: AllocatorDescriptor, ctx: DetectContext) -> DetectScore:
    """``desc.detect(ctx)`` clamped to ``[0, 1]``; failures score 0."""
    try:
        result = desc.detect(ctx)
        score = float(result.score)
        evidence = list(result.evidence)
    except Exception as exc:  # noqa: BLE001 — one bad plugin must not break the rest
        logger.warning("Allocator detector %s failed", desc.kind.value,
                       exc_info=True)
        return DetectScore(0.0, [Evidence(
            "detector_error", f"{desc.kind.value} detector raised {exc!r}", 0.0)])
    return DetectScore(min(1.0, max(0.0, score)), evidence)


def _ensure_loaded() -> None:
    """Register built-ins, then out-of-tree plugins, exactly once."""
    global _LOADED  # noqa: PLW0603
    if _LOADED:
        return
    _LOADED = True
    from memdiver.core.plugin_discovery import load_entry_point_registrations
    from memdiver.heap.builtin import register_builtin_allocators

    register_builtin_allocators()
    load_entry_point_registrations(ALLOCATOR_ENTRY_POINT_GROUP)
