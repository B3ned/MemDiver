"""Heap context on located-key hits (``locate_key(..., allocator=...)``)."""

import pytest

from memdiver.app.tools_pipeline import locate_key
from memdiver.core.service_errors import CapabilityError
from memdiver.engine import heap_hits
from memdiver.engine.key_location import (
    DumpKeyLocation,
    locate_key_across_dumps,
)
from memdiver.heap import analyze as heap_analyze
from memdiver.heap.model import ChunkState
from tests.test_candidate_pipeline_heap import KEY_LEN, _spans, write_corpus


@pytest.fixture(autouse=True)
def _fresh_heap_cache():
    heap_analyze.clear_heap_cache()
    yield
    heap_analyze.clear_heap_cache()


@pytest.fixture
def planted(tmp_path):
    paths, heap = write_corpus(tmp_path)
    va, _n = _spans(heap)["key"]
    # Dumps 0 and 2 hold the unflipped bytes; 1 and 3 the flipped copy.
    return paths, heap, va, heap.read(va, KEY_LEN)


def test_hits_carry_chunk_context(planted):
    paths, heap, va, key = planted
    payload = locate_key(dump_paths=paths, key_hex=key.hex())
    chunk = next(c for c in heap.chunks if c.size == 0x100)
    rows = payload["dumps"]
    assert [r["present"] for r in rows] == [True, False, True, False]
    for row in rows:
        if not row["present"]:
            assert "heap" not in row
            continue
        (hit,) = row["heap"]
        assert hit == {
            "allocator": "ptmalloc2", "chunk_va": chunk.va,
            "chunk_size": chunk.size, "state": ChunkState.IN_USE.value,
            "offset_in_chunk": va - chunk.va, "role": "user_data",
            "arena": "main",
        }


def test_allocator_off_leaves_rows_unchanged(planted):
    paths, _heap, _va, key = planted
    on = locate_key(dump_paths=paths, key_hex=key.hex())
    off = locate_key(dump_paths=paths, key_hex=key.hex(), allocator="off")
    assert all("heap" not in r for r in off["dumps"])
    stripped = [{k: v for k, v in r.items() if k != "heap"} for r in on["dumps"]]
    assert stripped == off["dumps"]


def test_hit_outside_any_chunk_is_null(tmp_path):
    # A flat raw dump with no heap: the hit exists, the chunk does not.
    path = tmp_path / "flat.dump"
    path.write_bytes(bytes(4096) + b"SECRETSECRETSECR" + bytes(64))
    result = locate_key_across_dumps([path], b"SECRETSECRETSECR")
    (row,) = result.dumps
    assert row.present and row.heap == (None,)
    assert row.to_dict()["heap"] == [None]


def test_heap_parsed_only_for_dumps_with_hits(planted, monkeypatch):
    paths, _heap, _va, key = planted
    calls = []
    real = heap_hits.heap_hit_annotations

    def spy(source, offsets, view, allocator):
        calls.append(len(offsets))
        return real(source, offsets, view, allocator)

    monkeypatch.setattr("memdiver.engine.key_location.heap_hit_annotations", spy)
    locate_key_across_dumps(paths, key)
    assert calls == [1, 1]   # dumps 1 and 3 have no hits: never parsed


def test_annotation_failure_is_soft(planted, monkeypatch):
    paths, _heap, _va, key = planted

    def boom(*_a, **_k):
        raise RuntimeError("parser exploded")

    monkeypatch.setattr(heap_analyze, "analyze_heap", boom)
    result = locate_key_across_dumps(paths, key)
    assert result.verdict == "found"
    assert [r.heap for r in result.dumps if r.present] == [(None,), (None,)]


def test_unknown_allocator_rejected(planted):
    paths, _heap, _va, key = planted
    with pytest.raises(CapabilityError, match="unknown allocator"):
        locate_key(dump_paths=paths, key_hex=key.hex(), allocator="nope")


def test_heap_must_parallel_offsets():
    with pytest.raises(ValueError, match="parallel"):
        DumpKeyLocation(dump_path="x", present=True, first_offset=0,
                        hit_count=1, offsets=(0,), heap=(None, None))


def test_hit_carries_arena_kind_when_known(tmp_path):
    from tests.fixtures import synth_heap as sh
    from tests.test_heap_msl import arena_process_heaps

    heaps, meta = arena_process_heaps()
    path = sh.as_regioned_raw(tmp_path / "proc", heaps, stem="proc")
    offsets = [_concat_offset(heaps, meta["thread_key_va"]),
               _concat_offset(heaps, meta["mmap_key_va"])]
    source = sh.open_regioned(path)
    try:
        hits = heap_hits.heap_hit_annotations(source, offsets, "raw", "auto")
    finally:
        source.close()
    assert [hit["arena"] for hit in hits] == ["thread", "mmap"]


def _concat_offset(heaps, va):
    """Offset of *va* in the byte concatenation of *heaps* (sorted by VA)."""
    offset = 0
    for heap in heaps:
        if heap.base_va <= va < heap.base_va + len(heap.data):
            return offset + va - heap.base_va
        offset += len(heap.data)
    raise AssertionError(f"{va:#x} not mapped")
