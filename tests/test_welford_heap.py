"""Heap projections persisted in the incremental (Welford) consensus session.

N synthetic glibc ``.msl`` dumps are folded with ``consensus-begin`` /
``consensus-add``; every add stores a per-dump projection beside the state,
and :func:`app.welford_heap.load_session_heap` merges them like the batch
consensus does. Recording must never break the fold, and a session begun
with ``--allocator off`` (or predating heap recording) keeps the historical
state JSON.
"""

import argparse
import json
from contextlib import contextmanager

import pytest

from memdiver.app import welford_heap as wh
from memdiver.app.composition import open_dump
from memdiver.cli.consensus import (
    _cmd_consensus_add,
    _cmd_consensus_begin,
    _cmd_consensus_finalize,
)
from memdiver.core.service_errors import CapabilityError
from memdiver.engine import consensus_heap as ch
from memdiver.heap import analyze as heap_analyze
from memdiver.heap.model import HeapRole
from tests.fixtures import synth_heap as sh
from tests.test_consensus_heap import _variant, _write_msl

N_DUMPS = 3
LEGACY_STATE_KEYS = {"size", "num_dumps", "mean_path", "m2_path"}


@pytest.fixture(autouse=True)
def _fresh_heap_cache():
    heap_analyze.clear_heap_cache()
    yield
    heap_analyze.clear_heap_cache()


# -- helpers --------------------------------------------------------------------------


def _msl_dumps(tmp_path, *, jitter_last=False):
    heaps = [_variant(i, jitter=jitter_last and i == N_DUMPS - 1)
             for i in range(N_DUMPS)]
    return [_write_msl(tmp_path / f"d{i}.msl", h) for i, h in enumerate(heaps)]


def _view_size(path):
    with open_dump(path) as source:
        return len(source.read_all())


def _begin(state_path, size, **extra):
    args = argparse.Namespace(state=str(state_path), size=size, **extra)
    assert _cmd_consensus_begin(args) == 0


def _add(state_path, dump):
    args = argparse.Namespace(state=str(state_path), dump=str(dump))
    assert _cmd_consensus_add(args) == 0


def _state(state_path):
    return json.loads(state_path.read_text())


def _session(tmp_path, dumps, allocator="auto", size=None):
    state_path = tmp_path / "session" / "s.json"
    _begin(state_path, size or _view_size(dumps[0]), allocator=allocator)
    for dump in dumps:
        _add(state_path, dump)
    return state_path


def _records(state_path):
    return _state(state_path)["heap"]["dumps"]


# -- happy path -----------------------------------------------------------------------


def test_session_heap_merges_stable_runs(tmp_path):
    state_path = _session(tmp_path, _msl_dumps(tmp_path))
    heap = wh.load_session_heap(_state(state_path))
    assert heap.status == ch.STATUS_OK
    assert heap.report["source"] == "session"
    assert heap.report["dumps_recorded"] == N_DUMPS
    assert heap.report["dumps_folded"] == N_DUMPS
    assert heap.report["dumps_projected"] == N_DUMPS
    assert heap.report["allocator"] == "ptmalloc2"
    assert heap.report["mixed_bytes"] == 0
    assert set(heap.chunks.agree.tolist()) == {N_DUMPS}


def test_jittered_chunk_is_mixed(tmp_path):
    heap_ = sh.glibc_heap()
    chunk = heap_.chunks[1]
    state_path = _session(tmp_path, _msl_dumps(tmp_path, jitter_last=True))
    heap = wh.load_session_heap(_state(state_path))
    assert heap.status == ch.STATUS_OK
    assert heap.report["mixed_bytes"] > 0
    header_slab = chunk.va - heap_.base_va + 0x30   # next (swallowed) chunk
    assert heap.runs.role_at(header_slab) == HeapRole.MIXED


def test_projection_files_exist_per_index(tmp_path):
    state_path = _session(tmp_path, _msl_dumps(tmp_path))
    heap_dir = wh.session_heap_dir(state_path)
    assert heap_dir == state_path.parent / "s.heap"
    for index, record in enumerate(_records(state_path)):
        assert record["index"] == index
        assert record["status"] == ch.STATUS_OK
        assert record["allocator"] == "ptmalloc2"
        assert record["detected"]["best"] == "ptmalloc2"
        assert record["chunk_count"] > 0
        assert record["file"] == str(heap_dir / f"{index:04d}.npz")
        assert (heap_dir / f"{index:04d}.npz").is_file()


def test_finalize_reports_heap_summary(tmp_path, capsys):
    state_path = _session(tmp_path, _msl_dumps(tmp_path))
    out = tmp_path / "final.json"
    args = argparse.Namespace(state=str(state_path), output=str(out))
    assert _cmd_consensus_finalize(args) == 0
    summary = json.loads(out.read_text())["heap"]
    assert summary == {"allocator": "auto", "dumps_recorded": N_DUMPS,
                       "status_counts": {"ok": N_DUMPS}}


def test_add_prints_one_heap_line_per_dump(tmp_path, capsys):
    _session(tmp_path, _msl_dumps(tmp_path))
    err = capsys.readouterr().err
    assert err.count("heap dump[") == N_DUMPS
    assert "status=ok allocator=ptmalloc2 chunks=" in err


# -- opt-out / legacy -------------------------------------------------------------------


def test_off_keeps_the_historical_state(tmp_path, capsys):
    state_path = _session(tmp_path, _msl_dumps(tmp_path), allocator="off")
    assert set(_state(state_path)) == LEGACY_STATE_KEYS
    assert not wh.session_heap_dir(state_path).exists()
    assert wh.load_session_heap(_state(state_path)) is None
    assert "heap dump[" not in capsys.readouterr().err


def test_legacy_namespace_without_allocator_is_off(tmp_path):
    dumps = _msl_dumps(tmp_path)
    state_path = tmp_path / "s.json"
    _begin(state_path, _view_size(dumps[0]))
    _add(state_path, dumps[0])
    assert set(_state(state_path)) == LEGACY_STATE_KEYS
    assert not wh.session_heap_dir(state_path).exists()


def test_finalize_without_heap_has_no_heap_key(tmp_path):
    state_path = _session(tmp_path, _msl_dumps(tmp_path), allocator="off")
    out = tmp_path / "final.json"
    assert _cmd_consensus_finalize(
        argparse.Namespace(state=str(state_path), output=str(out))) == 0
    assert "heap" not in json.loads(out.read_text())


# -- degraded paths ---------------------------------------------------------------------


def test_raw_dump_records_no_va(tmp_path):
    raw = tmp_path / "flat.dump"
    raw.write_bytes(sh.glibc_heap().data)
    state_path = _session(tmp_path, [raw], size=len(raw.read_bytes()))
    (record,) = _records(state_path)
    assert record["status"] == ch.STATUS_NO_VA
    assert record["file"] is None
    assert _state(state_path)["num_dumps"] == 1
    heap = wh.load_session_heap(_state(state_path))
    assert heap.status == ch.STATUS_NO_VA


def test_projection_error_is_recorded_and_add_succeeds(tmp_path, monkeypatch):
    def _boom(*_a, **_k):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(ch, "project_dump_heap", _boom)
    state_path = _session(tmp_path, _msl_dumps(tmp_path)[:1])
    (record,) = _records(state_path)
    assert record["status"] == ch.STATUS_ERROR
    assert "synthetic failure" in record["error"]
    assert _state(state_path)["num_dumps"] == 1
    assert wh.load_session_heap(_state(state_path)).status == ch.STATUS_ERROR


def test_auto_on_scudo_is_unsupported(tmp_path):
    dump = sh.as_regioned_raw(tmp_path / "scudo", [sh.scudo_primary()], stem="sc")
    state_path = _session(tmp_path, [dump], size=_view_size(dump))
    (record,) = _records(state_path)
    assert record["status"] == ch.STATUS_UNSUPPORTED
    assert record["detected"]["best"] == "scudo"
    assert record["allocator"] is None and record["file"] is None
    heap = wh.load_session_heap(_state(state_path))
    assert heap.status == ch.STATUS_UNSUPPORTED


def test_short_dump_records_nothing(tmp_path):
    dumps = _msl_dumps(tmp_path)
    state_path = tmp_path / "s.json"
    _begin(state_path, _view_size(dumps[0]) + 1, allocator="auto")
    args = argparse.Namespace(state=str(state_path), dump=str(dumps[0]))
    assert _cmd_consensus_add(args) == 1
    assert _records(state_path) == []


# -- allocator resolution -----------------------------------------------------------------


def test_resolve_allocator_variants(tmp_path):
    dump = _msl_dumps(tmp_path)[0]
    with open_dump(dump) as source:
        assert wh.resolve_allocator(source, "off") == (None, {})
        kind, info = wh.resolve_allocator(source, "auto")
        assert kind == "ptmalloc2" and info["detected"]["best"] == "ptmalloc2"
        kind, info = wh.resolve_allocator(source, "ptmalloc2")
        assert kind == "ptmalloc2" and "warning" not in info
        with pytest.raises(CapabilityError):
            wh.resolve_allocator(source, "scudo")


def test_explicit_allocator_warns_on_disagreement(tmp_path):
    dump = sh.as_regioned_raw(tmp_path / "scudo", [sh.scudo_primary()], stem="sc")
    with open_dump(dump) as source:
        kind, info = wh.resolve_allocator(source, "ptmalloc2")
    assert kind == "ptmalloc2"
    assert "scudo" in info["warning"]


def test_explicit_allocator_survives_detection_failure(tmp_path, monkeypatch):
    def _boom(*_a, **_k):
        raise RuntimeError("detector down")

    monkeypatch.setattr(wh, "_detect", _boom)
    kind, info = wh.resolve_allocator(object(), "ptmalloc2")
    assert (kind, info) == ("ptmalloc2", {"detected": None})


def test_begin_rejects_a_non_reduce_ready_allocator():
    with pytest.raises(CapabilityError):
        wh.begin_session_heap({}, "scudo")


# -- reference fallback -----------------------------------------------------------------


def test_reference_heap_single_dump(tmp_path):
    dump = _msl_dumps(tmp_path)[0]
    heap = wh.reference_heap(str(dump), _view_size(dump), "auto")
    assert heap.status == ch.STATUS_OK
    assert heap.report["source"] == "reference"
    assert heap.report["dumps_projected"] == 1
    assert heap.report["allocator"] == "ptmalloc2"
    assert set(heap.chunks.agree.tolist()) == {1}


def test_reference_heap_opens_the_dump_once(tmp_path, monkeypatch):
    """``open_dump`` already opens the source; no second reader is acquired."""
    import memdiver.app.composition as composition

    real_open_dump = composition.open_dump
    reopened = []

    @contextmanager
    def _spying_open_dump(path, **kwargs):
        with real_open_dump(path, **kwargs) as source:
            monkeypatch.setattr(source, "open", lambda: reopened.append(path))
            yield source

    monkeypatch.setattr(composition, "open_dump", _spying_open_dump)
    dump = _msl_dumps(tmp_path)[0]
    heap = wh.reference_heap(str(dump), _view_size(dump), "auto")
    assert heap.status == ch.STATUS_OK
    assert reopened == []


def test_reference_heap_off_and_error(tmp_path):
    assert wh.reference_heap(str(tmp_path / "x.msl"), 16, "off") is None
    heap = wh.reference_heap(str(tmp_path / "missing.msl"), 16, "auto")
    assert heap.status == ch.STATUS_ERROR
    assert heap.report["source"] == "reference"
    assert "error" in heap.report


def test_session_heap_summary_none_without_heap():
    assert wh.session_heap_summary({"num_dumps": 0}) is None


# -- projection paths (review fixes) ------------------------------------------------------


def _relative_legacy_records(state_path):
    """The session's state with cwd-relative ``s.heap/<index>.npz`` records,
    as a session begun with ``--state s.json`` from its own directory wrote."""
    state = _state(state_path)
    for record in state["heap"]["dumps"]:
        record["file"] = f"s.heap/{record['index']:04d}.npz"
    return state


def test_relative_paths_resolve_against_the_state_dir_first(tmp_path, monkeypatch):
    """Reducing session B from inside session A's directory must load B's
    projections, not A's same-named files under the cwd."""
    dumps = _msl_dumps(tmp_path)
    state_a = _session(tmp_path / "A", dumps)
    state_b = _session(tmp_path / "B", dumps)
    loaded = []
    real_from_npz = ch.DumpHeapProjection.from_npz

    def _spy(path):
        loaded.append(path.resolve())
        return real_from_npz(path)

    monkeypatch.setattr(ch.DumpHeapProjection, "from_npz", staticmethod(_spy))
    monkeypatch.chdir(state_a.parent)
    heap = wh.load_session_heap(_relative_legacy_records(state_b), state_b)
    assert heap.status == ch.STATUS_OK
    heap_dir_b = wh.session_heap_dir(state_b).resolve()
    assert loaded and all(p.parent == heap_dir_b for p in loaded)


def test_new_projection_paths_are_absolute(tmp_path, monkeypatch):
    """A relative ``--state`` no longer records cwd-relative npz paths."""
    from pathlib import Path

    (tmp_path / "work").mkdir()
    monkeypatch.chdir(tmp_path / "work")
    dumps = _msl_dumps(tmp_path)
    _begin(Path("s.json"), _view_size(dumps[0]), allocator="auto")
    _add(Path("s.json"), dumps[0])
    (record,) = _records(Path("s.json"))
    assert Path(record["file"]).is_absolute()
    assert Path(record["file"]) == (tmp_path / "work" / "s.heap" / "0000.npz")


# -- status without projections (review fixes) -------------------------------------------


def _heap_state(*statuses):
    dumps = [{"index": i, "status": s, "allocator": None, "file": None}
             for i, s in enumerate(statuses)]
    return {"num_dumps": len(dumps), "heap": {"allocator": "auto", "dumps": dumps}}


@pytest.mark.parametrize("statuses, expected", [
    ((ch.STATUS_NO_VA, ch.STATUS_UNSUPPORTED), ch.STATUS_UNSUPPORTED),
    ((ch.STATUS_NO_VA, ch.STATUS_ERROR), ch.STATUS_ERROR),
    ((ch.STATUS_UNSUPPORTED, ch.STATUS_ERROR, ch.STATUS_NO_VA), ch.STATUS_ERROR),
    ((ch.STATUS_NO_VA, ch.STATUS_NO_VA), ch.STATUS_NO_VA),
])
def test_mixed_statuses_pick_by_precedence(statuses, expected):
    heap = wh.load_session_heap(_heap_state(*statuses))
    assert heap.status == expected
    assert heap.report["status_counts"] == dict(
        __import__("collections").Counter(statuses))


def test_ok_record_with_missing_file_among_mixed_is_error(tmp_path):
    state = _heap_state(ch.STATUS_NO_VA, ch.STATUS_OK)
    state["heap"]["dumps"][1]["file"] = str(tmp_path / "gone.npz")
    heap = wh.load_session_heap(state, tmp_path / "s.json")
    assert heap.status == ch.STATUS_ERROR
    assert "missing" in heap.report["error"]
    assert heap.report["status_counts"] == {ch.STATUS_NO_VA: 1, ch.STATUS_OK: 1}


def test_partially_missing_projections_are_reported(tmp_path):
    state_path = _session(tmp_path, _msl_dumps(tmp_path))
    (wh.session_heap_dir(state_path) / "0001.npz").unlink()
    heap = wh.load_session_heap(_state(state_path), state_path)
    assert heap.status == ch.STATUS_OK
    assert heap.report["dumps_projected"] == N_DUMPS - 1
    assert heap.report["missing_projections"] == [1]
    assert "missing" in heap.report["warning"]


def test_complete_session_reports_no_missing_projections(tmp_path):
    state_path = _session(tmp_path, _msl_dumps(tmp_path))
    heap = wh.load_session_heap(_state(state_path), state_path)
    assert "missing_projections" not in heap.report
    assert "warning" not in heap.report


# -- stale projection names (review fixes) -----------------------------------------------


def test_reset_removes_five_digit_projection_files(tmp_path):
    state_path = tmp_path / "s.json"
    heap_dir = wh.session_heap_dir(state_path)
    heap_dir.mkdir()
    for name in ("0000.npz", "10000.npz", "123456.npz", "12.npz", "notes.npz"):
        (heap_dir / name).write_bytes(b"x")
    removed = sorted(p.name for p in wh.reset_session_heap_dir(state_path))
    assert removed == ["0000.npz", "10000.npz", "123456.npz"]
    assert sorted(p.name for p in heap_dir.iterdir()) == ["12.npz", "notes.npz"]
