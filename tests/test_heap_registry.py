"""Tests for heap/registry.py: descriptors, plugins, detector isolation."""

import pytest

from memdiver.heap import builtin, registry
from memdiver.heap.detect import detect_allocator
from memdiver.heap.model import AllocatorKind, Evidence
from memdiver.heap.platform import MappedRegion
from memdiver.heap.registry import (AllocatorDescriptor, DetectContext,
                                    DetectScore, ParseOptions, get_allocator,
                                    register_allocator, registered_allocators,
                                    run_detector, unregister_allocator)
from tests.fixtures import synth_raw_regions


@pytest.fixture
def restore_registry():
    """Snapshot the registry and put it back after the test."""
    registered_allocators()  # make sure built-ins are loaded first
    saved = dict(registry._ALLOCATOR_REGISTRY)  # noqa: SLF001
    yield
    registry._ALLOCATOR_REGISTRY.clear()  # noqa: SLF001
    registry._ALLOCATOR_REGISTRY.update(saved)  # noqa: SLF001


def _fixed(score, detail="plugin"):
    return lambda ctx: DetectScore(score, [Evidence("plugin", detail, score)])


def _raise(ctx):
    raise RuntimeError("boom")


def test_builtins_cover_six_kinds_sorted_by_priority():
    descs = registered_allocators()
    kinds = {d.kind for d in descs}
    assert kinds == set(AllocatorKind) - {AllocatorKind.UNKNOWN}
    priorities = [d.priority for d in descs]
    assert priorities == sorted(priorities, reverse=True)
    assert descs[-1].kind is AllocatorKind.GENERIC


def test_builtin_flags_and_wired_parsers():
    assert get_allocator("jemalloc").partial
    assert get_allocator(AllocatorKind.GENERIC).heuristic
    assert "L3" in get_allocator(AllocatorKind.PTMALLOC2).levels
    assert all(d.parse is not None for d in registered_allocators())


def test_get_allocator_rejects_unknown_name():
    with pytest.raises(ValueError):
        get_allocator("tcmalloc")


def test_register_replaces_and_unregister_removes(restore_registry):
    plugin = AllocatorDescriptor(AllocatorKind.JEMALLOC, _fixed(0.9),
                                 priority=99)
    register_allocator(plugin)
    assert get_allocator(AllocatorKind.JEMALLOC) is plugin
    assert registered_allocators()[0] is plugin
    assert unregister_allocator(AllocatorKind.JEMALLOC) is plugin
    assert get_allocator(AllocatorKind.JEMALLOC) is None
    assert unregister_allocator(AllocatorKind.JEMALLOC) is None


def test_register_without_replace_keeps_existing(restore_registry):
    original = get_allocator(AllocatorKind.SCUDO)
    register_allocator(AllocatorDescriptor(AllocatorKind.SCUDO, _fixed(1.0)),
                       replace=False)
    assert get_allocator(AllocatorKind.SCUDO) is original


def test_plugin_detector_wins_detection(restore_registry, tmp_path):
    register_allocator(AllocatorDescriptor(AllocatorKind.DLMALLOC,
                                           _fixed(0.99, "embedded dlmalloc")))
    run = synth_raw_regions.build(tmp_path)
    from memdiver.core.dump_sources.gdb_raw import GdbRawDumpSource
    with GdbRawDumpSource(run / "gdb_raw.bin", run / "gdb_raw.maps") as src:
        result = detect_allocator(src)
    assert result.best is AllocatorKind.DLMALLOC
    assert result.candidates[0].evidence[0].detail == "embedded dlmalloc"


def test_faulty_detector_is_isolated(restore_registry, tmp_path):
    register_allocator(AllocatorDescriptor(AllocatorKind.MALLOCNG, _raise,
                                           priority=100))
    run = synth_raw_regions.build(tmp_path)
    from memdiver.core.dump_sources.gdb_raw import GdbRawDumpSource
    with GdbRawDumpSource(run / "gdb_raw.bin", run / "gdb_raw.maps") as src:
        result = detect_allocator(src)
    assert result.best is AllocatorKind.PTMALLOC2
    broken = next(c for c in result.candidates
                  if c.kind is AllocatorKind.MALLOCNG)
    assert broken.score == 0.0
    assert broken.evidence[0].source == "detector_error"
    assert "boom" in broken.evidence[0].detail


def test_run_detector_clamps_and_rejects_garbage():
    ctx = DetectContext(None, regions=[])
    high = AllocatorDescriptor(AllocatorKind.GENERIC, _fixed(7.0))
    garbage = AllocatorDescriptor(AllocatorKind.GENERIC, lambda c: "nope")
    assert run_detector(high, ctx).score == 1.0
    assert run_detector(garbage, ctx).evidence[0].source == "detector_error"


def test_name_detector_combines_probe():
    probe = _fixed(0.5, "content probe")
    detect = builtin.name_detector(AllocatorKind.MALLOCNG, probe)
    region = MappedRegion(0, 0x1000, "r-x", "/lib/ld-musl-aarch64.so.1",
                          "/lib/ld-musl-aarch64.so.1", True)
    result = detect(DetectContext(None, regions=[region]))
    assert result.score == pytest.approx(1 - 0.2 * 0.5)
    assert [e.detail for e in result.evidence][-1] == "content probe"


def test_entry_points_loaded_once(monkeypatch):
    calls = []
    monkeypatch.setattr(registry, "_LOADED", False)
    monkeypatch.setattr("memdiver.core.plugin_discovery."
                        "load_entry_point_registrations",
                        lambda group: calls.append(group) or 0)
    registered_allocators()
    get_allocator(AllocatorKind.SCUDO)
    assert calls == [registry.ALLOCATOR_ENTRY_POINT_GROUP]


def test_parse_options_region_filter():
    region = MappedRegion(0, 0x1000, "rw-", "[anon:scudo:primary]", None, True)
    assert ParseOptions().selects(region)
    assert ParseOptions(regions=("[anon:scudo:*",)).selects(region)
    assert not ParseOptions(regions=("[heap]",)).selects(region)


def test_detect_context_is_lazy():
    ctx = DetectContext(object())
    assert "regions" not in ctx.__dict__
    assert ctx.regions == [] and ctx.modules == []


def test_reduce_ready_kinds_is_ptmalloc2_only():
    assert registry.reduce_ready_kinds() == (AllocatorKind.PTMALLOC2,)


def test_third_party_descriptor_defaults_not_reduce_ready(restore_registry):
    desc = AllocatorDescriptor(AllocatorKind.SCUDO, _fixed(0.5))
    assert desc.reduce_ready is False
    register_allocator(desc)
    assert AllocatorKind.SCUDO not in registry.reduce_ready_kinds()
    register_allocator(AllocatorDescriptor(AllocatorKind.SCUDO, _fixed(0.5),
                                           reduce_ready=True))
    assert AllocatorKind.SCUDO in registry.reduce_ready_kinds()
