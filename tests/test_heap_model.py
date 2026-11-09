"""Tests for heap/model.py: chunk lookup, role projection, serialization."""

import json

import pytest

from memdiver.heap.model import (AllocatorKind, ChunkState, Evidence, FreeList,
                                 HeapChunk, HeapLayout, HeapRegion, HeapRole)
from memdiver.heap.platform import ASSUMED_PLATFORM

BASE = 0x5555_0000


def _chunk(va, size, state=ChunkState.IN_USE, user_len=None, **kw):
    """ptmalloc-like chunk: 16-byte header, user data right after it."""
    user_len = size - 16 if user_len is None else user_len
    return HeapChunk(va=va, size=size, state=state, header_len=16,
                     user_va=va + 16, user_len=user_len, **kw)


def _layout(*chunks):
    return HeapLayout(allocator=AllocatorKind.PTMALLOC2, chunks=chunks)


# -- enums ------------------------------------------------------------------


def test_enum_values_are_stable():
    assert [k.value for k in AllocatorKind] == [
        "ptmalloc2", "dlmalloc", "scudo", "mallocng", "jemalloc", "generic",
        "unknown"]
    assert [s.value for s in ChunkState] == [
        "in_use", "free", "cached", "quarantined", "unknown"]
    assert {r.name: int(r) for r in HeapRole} == {
        "NONE": 0, "CHUNK_HEADER": 1, "USER_DATA": 2, "FREE_LINK": 3,
        "FREE_DATA": 4, "ALLOCATOR_META": 5, "TOP": 6, "SLACK": 7,
        "MIXED": 254, "UNCOVERED": 255}


def test_heap_chunk_is_frozen():
    chunk = _chunk(BASE, 0x20)
    with pytest.raises(AttributeError):
        chunk.size = 0x40  # type: ignore[misc]


# -- chunk_at -------------------------------------------------------------------


def test_chunks_sorted_on_construction():
    layout = _layout(_chunk(BASE + 0x40, 0x20), _chunk(BASE, 0x40))
    assert [c.va for c in layout.chunks] == [BASE, BASE + 0x40]


@pytest.mark.parametrize("va,expected", [
    (BASE - 1, None),
    (BASE, BASE),
    (BASE + 0x3F, BASE),
    (BASE + 0x40, BASE + 0x40),
    (BASE + 0x5F, BASE + 0x40),
    (BASE + 0x60, None),           # gap between chunks
    (BASE + 0x80, BASE + 0x80),
    (BASE + 0xA0, None),           # one past the last chunk
    (-5, None),
])
def test_chunk_at_bisect_edges(va, expected):
    layout = _layout(_chunk(BASE, 0x40), _chunk(BASE + 0x40, 0x20),
                     _chunk(BASE + 0x80, 0x20))
    found = layout.chunk_at(va)
    assert (found.va if found else None) == expected


def test_chunk_at_empty_layout_and_kernel_half_va():
    assert _layout().chunk_at(BASE) is None
    high = 0xFFFF_8000_0000_0000
    layout = _layout(_chunk(high, 0x20))
    assert layout.chunk_at(high + 0x10).va == high
    assert layout.chunk_at(high - 1) is None


# -- role_runs ------------------------------------------------------------------


def test_role_runs_in_use_and_free_defaults():
    layout = _layout(_chunk(BASE, 0x20), _chunk(BASE + 0x20, 0x30, ChunkState.FREE))
    assert list(layout.role_runs(BASE, BASE + 0x50)) == [
        (BASE, 16, HeapRole.CHUNK_HEADER),
        (BASE + 0x10, 16, HeapRole.USER_DATA),
        (BASE + 0x20, 16, HeapRole.CHUNK_HEADER),
        (BASE + 0x30, 0x20, HeapRole.FREE_DATA),
    ]


@pytest.mark.parametrize("state", [ChunkState.CACHED, ChunkState.QUARANTINED])
def test_role_runs_cached_and_quarantined_are_free_data(state):
    runs = list(_layout(_chunk(BASE, 0x20, state)).role_runs(BASE, BASE + 0x20))
    assert runs[1] == (BASE + 0x10, 16, HeapRole.FREE_DATA)


def test_role_runs_unknown_state_is_user_data():
    runs = list(_layout(_chunk(BASE, 0x20, ChunkState.UNKNOWN)).role_runs(BASE, BASE + 0x20))
    assert runs[1][2] == HeapRole.USER_DATA


def test_role_runs_coalesce_adjacent_same_role():
    """Header-only chunks back to back merge into one CHUNK_HEADER run."""
    a = _chunk(BASE, 0x10, user_len=0)
    b = _chunk(BASE + 0x10, 0x10, user_len=0)
    assert list(_layout(a, b).role_runs(BASE, BASE + 0x20)) == [
        (BASE, 0x20, HeapRole.CHUNK_HEADER)]


def test_role_runs_clip_to_window():
    layout = _layout(_chunk(BASE, 0x40))
    assert list(layout.role_runs(BASE + 8, BASE + 0x18)) == [
        (BASE + 8, 8, HeapRole.CHUNK_HEADER),
        (BASE + 0x10, 8, HeapRole.USER_DATA),
    ]


def test_role_runs_gaps_are_omitted():
    layout = _layout(_chunk(BASE, 0x20), _chunk(BASE + 0x40, 0x20))
    runs = list(layout.role_runs(BASE - 0x100, BASE + 0x100))
    assert [r[0] for r in runs] == [BASE, BASE + 0x10, BASE + 0x40, BASE + 0x50]
    assert all(r[2] != HeapRole.NONE for r in runs)


def test_role_runs_empty_window():
    layout = _layout(_chunk(BASE, 0x20))
    assert list(layout.role_runs(BASE + 0x10, BASE + 0x10)) == []
    assert list(layout.role_runs(BASE + 0x100, BASE + 0x200)) == []


def test_role_runs_slack_after_short_user_data():
    layout = _layout(_chunk(BASE, 0x30, user_len=0x18))
    assert list(layout.role_runs(BASE, BASE + 0x30)) == [
        (BASE, 0x10, HeapRole.CHUNK_HEADER),
        (BASE + 0x10, 0x18, HeapRole.USER_DATA),
        (BASE + 0x28, 0x08, HeapRole.SLACK),
    ]


def test_role_runs_tcache_override():
    """tcache next/key at user+0/+8 are FREE_LINK; the rest stays FREE_DATA."""
    chunk = _chunk(BASE, 0x40, ChunkState.CACHED,
                   roles=((0x10, 8, HeapRole.FREE_LINK), (0x18, 8, HeapRole.FREE_LINK)))
    assert list(_layout(chunk).role_runs(BASE, BASE + 0x40)) == [
        (BASE, 0x10, HeapRole.CHUNK_HEADER),
        (BASE + 0x10, 0x10, HeapRole.FREE_LINK),
        (BASE + 0x20, 0x20, HeapRole.FREE_DATA),
    ]


def test_role_runs_override_is_clipped_to_chunk():
    chunk = _chunk(BASE, 0x20, roles=((0x18, 0x100, HeapRole.FREE_LINK),))
    runs = list(_layout(chunk).role_runs(BASE, BASE + 0x200))
    assert runs[-1] == (BASE + 0x18, 8, HeapRole.FREE_LINK)


def test_role_runs_top_and_meta_chunks():
    top = _chunk(BASE + 0x100, 0x1000, bin="top")
    meta = _chunk(BASE, 0x100, extra={"meta": True})
    assert list(_layout(meta, top).role_runs(BASE, BASE + 0x1100)) == [
        (BASE, 0x100, HeapRole.ALLOCATOR_META),
        (BASE + 0x100, 0x1000, HeapRole.TOP),
    ]


def test_role_runs_overlapping_chunks_never_overlap():
    layout = _layout(_chunk(BASE, 0x40), _chunk(BASE + 0x20, 0x40))
    runs = list(layout.role_runs(BASE, BASE + 0x60))
    for (va, length, _), (next_va, _, _) in zip(runs, runs[1:]):
        assert va + length <= next_va


def test_role_counts():
    layout = _layout(_chunk(BASE, 0x20), _chunk(BASE + 0x20, 0x30, ChunkState.FREE))
    assert layout.role_counts(BASE, BASE + 0x50) == {
        "chunk_header": 32, "user_data": 16, "free_data": 32}


# -- to_dict --------------------------------------------------------------------


def test_to_dict_is_json_safe_and_limited():
    chunks = [_chunk(BASE + i * 0x20, 0x20, extra={"arena": AllocatorKind.SCUDO})
              for i in range(5)]
    layout = HeapLayout(
        allocator=AllocatorKind.PTMALLOC2, version_hint="2.35",
        platform=ASSUMED_PLATFORM,
        regions=(HeapRegion(BASE, 0x1000, "[heap]", "arena"),),
        chunks=tuple(chunks),
        free_lists=(FreeList("tcache", 0, BASE, (BASE, BASE + 0x20), True),),
        evidence=(Evidence("region_names", "[heap]", 0.5),),
        confidence=0.9, diagnostics=("ok",), coverage={"chunks": 5})
    data = layout.to_dict(limit=2)
    json.dumps(data)
    assert data["allocator"] == "ptmalloc2"
    assert data["chunk_count"] == 5 and len(data["chunks"]) == 2
    assert data["chunks_truncated"] is True
    assert data["chunks"][0]["state"] == "in_use"
    assert data["chunks"][0]["va"] == BASE
    assert data["chunks"][0]["extra"] == {"arena": "scudo"}
    assert data["free_lists"][0]["chunk_vas"] == [BASE, BASE + 0x20]
    assert data["platform"]["arch"] == "x86_64"
    assert layout.to_dict()["chunks_truncated"] is False


def test_to_dict_roles_serialized_as_ints():
    chunk = _chunk(BASE, 0x20, roles=((0x10, 8, HeapRole.FREE_LINK),))
    assert _layout(chunk).to_dict()["chunks"][0]["roles"] == [[0x10, 8, 3]]


# -- arenas -------------------------------------------------------------------


def test_heap_arena_to_dict_is_json_safe():
    from memdiver.heap.model import ARENA_MAIN, HeapArena
    arena = HeapArena(0, ARENA_MAIN, va=0x7000, top_va=BASE + 0x100,
                      region_vas=(BASE,), extra={"kind": AllocatorKind.SCUDO})
    data = arena.to_dict()
    json.dumps(data)
    assert data == {"arena_id": 0, "kind": "main", "va": 0x7000,
                    "top_va": BASE + 0x100, "region_vas": [BASE],
                    "extra": {"kind": "scudo"}}


def test_layout_to_dict_carries_arenas_and_arena_ids():
    from memdiver.heap.model import ARENA_THREAD, REGION_THREAD_HEAP, HeapArena
    layout = HeapLayout(
        allocator=AllocatorKind.PTMALLOC2,
        regions=(HeapRegion(BASE, 0x1000, "t", REGION_THREAD_HEAP, 1),),
        chunks=(_chunk(BASE, 0x20, arena_id=1), _chunk(BASE + 0x20, 0x20)),
        arenas=(HeapArena(1, ARENA_THREAD),))
    data = layout.to_dict()
    json.dumps(data)
    assert [a["arena_id"] for a in data["arenas"]] == [1]
    assert data["regions"][0]["arena_id"] == 1
    assert data["chunks"][0]["arena_id"] == 1
    assert "arena_id" not in data["chunks"][1]


def test_unset_arena_id_keeps_legacy_dict_shape():
    region = HeapRegion(BASE, 0x1000, "[heap]", "heap")
    assert region.to_dict() == {"va": BASE, "size": 0x1000,
                                "name": "[heap]", "kind": "heap"}
    assert "arena_id" not in _chunk(BASE, 0x20).to_dict()
    assert _layout().to_dict()["arenas"] == []
