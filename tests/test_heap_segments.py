"""Tests for heap/segments.py: segments, chunk budget, layout assembler."""

import json

from memdiver.heap.model import (ARENA_MAIN, ARENA_THREAD, REGION_MAIN_HEAP,
                                 REGION_THREAD_HEAP, AllocatorKind, ChunkState,
                                 Evidence, FreeList, HeapArena, HeapChunk)
from memdiver.heap.platform import ASSUMED_PLATFORM
from memdiver.heap.segments import (ChunkBudget, HeapSegment, LayoutAssembler,
                                    truncation_diagnostic)

BASE = 0x5555_0000
THREAD = 0x7F00_0000


def _chunk(va, size=0x20, **kw):
    return HeapChunk(va=va, size=size, state=ChunkState.IN_USE, header_len=16,
                     user_va=va + 16, user_len=size - 16, **kw)


def _main_segment():
    return HeapSegment(BASE, BASE + 0x1000, BASE, 0, REGION_MAIN_HEAP, "[heap]")


def _thread_segment():
    return HeapSegment(THREAD, THREAD + 0x800, THREAD + 0x10, 1,
                       REGION_THREAD_HEAP)


def _two_arena_assembler():
    asm = LayoutAssembler(AllocatorKind.PTMALLOC2, ASSUMED_PLATFORM)
    asm.add_arena(HeapArena(0, ARENA_MAIN))
    asm.add_arena(HeapArena(1, ARENA_THREAD))
    asm.add_segment(_main_segment(), [_chunk(BASE), _chunk(BASE + 0x20)],
                    walked=0x800, skipped=0x100, uncaptured=0x700)
    asm.add_segment(_thread_segment(), [_chunk(THREAD + 0x10)], walked=0x800)
    return asm


# -- HeapSegment -----------------------------------------------------------------


def test_segment_size_and_label():
    assert _main_segment().size == 0x1000
    assert _main_segment().label == "[heap]"
    assert _thread_segment().label == hex(THREAD)
    assert HeapSegment(10, 5, 10, 0, "x").size == 0


# -- ChunkBudget -------------------------------------------------------------------


def test_budget_take_until_exhausted():
    budget = ChunkBudget(3)
    assert budget.take() and budget.take(2)
    assert budget.exhausted and budget.remaining == 0
    assert not budget.truncated
    assert not budget.take()
    assert budget.truncated


def test_budget_refuses_oversized_take_without_consuming():
    budget = ChunkBudget(2)
    assert not budget.take(3)
    assert budget.remaining == 2 and budget.truncated
    assert budget.diagnostic() == truncation_diagnostic(2)
    assert "max_chunks=2" in budget.diagnostic()


# -- LayoutAssembler ---------------------------------------------------------------


def test_coverage_keys_and_values():
    layout = _two_arena_assembler().build(version_hint="2.35")
    assert layout.coverage == {
        "regions": ["[heap]", hex(THREAD)], "arenas": 2,
        "bytes_total": 0x1800, "bytes_walked": 0x1000,
        "bytes_skipped": 0x100, "bytes_uncaptured": 0x700,
        "chunk_count": 3, "truncated": False,
    }
    assert layout.version_hint == "2.35"
    assert layout.platform == ASSUMED_PLATFORM
    json.dumps(layout.to_dict())


def test_arena_id_stamped_on_chunks_and_regions():
    layout = _two_arena_assembler().build()
    assert [c.arena_id for c in layout.chunks] == [0, 0, 1]
    assert [(r.kind, r.arena_id) for r in layout.regions] == [
        (REGION_MAIN_HEAP, 0), (REGION_THREAD_HEAP, 1)]
    assert [a.arena_id for a in layout.arenas] == [0, 1]


def test_existing_arena_id_is_not_overwritten():
    asm = LayoutAssembler(AllocatorKind.PTMALLOC2)
    asm.add_segment(_main_segment(), [_chunk(BASE, arena_id=7)])
    assert asm.build().chunks[0].arena_id == 7


def test_mark_truncated_adds_shared_diagnostic_once():
    asm = LayoutAssembler(AllocatorKind.SCUDO)
    asm.mark_truncated(5)
    asm.mark_truncated(5)
    layout = asm.build()
    assert layout.coverage["truncated"] is True
    assert layout.diagnostics == (truncation_diagnostic(5),)


def test_mark_truncated_keeps_a_diagnostic_the_parser_already_reported():
    asm = LayoutAssembler(AllocatorKind.PTMALLOC2)
    asm.diagnose(truncation_diagnostic(5))
    asm.diagnose("later")
    asm.mark_truncated(5)
    assert asm.build().diagnostics == (truncation_diagnostic(5), "later")


def test_truncation_diagnostic_wording():
    assert truncation_diagnostic(7) == "stopped after max_chunks=7 chunks"
    assert "max_chunks" in truncation_diagnostic()


def test_add_segment_total_overrides_segment_size():
    asm = LayoutAssembler(AllocatorKind.PTMALLOC2)
    asm.add_segment(_main_segment(), [_chunk(BASE)], walked=0x300, total=0x300)
    layout = asm.build()
    assert layout.coverage["bytes_total"] == 0x300
    assert layout.regions[0].size == 0x1000
    assert layout.confidence == 1.0


def test_default_and_explicit_confidence():
    assert _two_arena_assembler().build().confidence == 0x1000 / 0x1800
    assert _two_arena_assembler().build(confidence=0.25).confidence == 0.25


def test_extra_coverage_overrides_and_evidence_merges():
    asm = _two_arena_assembler()
    asm.evidence(Evidence("probe", "a", 0.5))
    asm.add_free_list(FreeList("tcache", 0, BASE))
    asm.diagnose("note")
    layout = asm.build(extra_coverage={"arenas": 9, "tcache": True},
                       extra_evidence=(Evidence("probe", "b", 0.1),))
    assert layout.coverage["arenas"] == 9 and layout.coverage["tcache"] is True
    assert [e.detail for e in layout.evidence] == ["a", "b"]
    assert len(layout.free_lists) == 1 and layout.diagnostics == ("note",)


def test_build_with_no_segments():
    layout = LayoutAssembler(AllocatorKind.GENERIC).build()
    assert layout.allocator is AllocatorKind.GENERIC
    assert layout.chunks == () and layout.regions == () and layout.arenas == ()
    assert layout.confidence == 0.0
    assert layout.coverage["bytes_total"] == 0
    assert layout.coverage["chunk_count"] == 0
    assert layout.to_dict()["arenas"] == []
