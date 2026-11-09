"""``search-reduce --allocator`` on a Welford (``--state``) session.

The CLI reduces a scratch ``variance.npy``; heap roles come from the session's
per-dump projections (``consensus-begin --allocator auto``) or, for a session
without them, from the reference dump alone. Four synthetic glibc ``.msl``
dumps differ only in the user data of one in-use chunk (the planted secret)
and in the tcache ``key`` word of the freed chunk right after it (allocator
metadata), so ``--heap-policy mask`` has something to remove.
"""

import argparse
import json
import random
import sys

import pytest

from memdiver.app import welford_heap as wh
from memdiver.cli import _build_parser, main
from memdiver.cli._shared import SEARCH_REDUCE_ALLOCATOR_CHOICES
from memdiver.cli.pipeline import _cmd_search_reduce
from memdiver.core.service_errors import CapabilityError
from memdiver.heap import analyze as heap_analyze
from memdiver.msl.enums import ArchType, OSType
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import MslWriter
from tests.fixtures import synth_heap as sh
from tests.test_consensus_heap import _write_msl

N_DUMPS = 4
#: The planted chunk (64-byte user area) and the cached chunk after it.
PLANT_CHUNK, KEY_CHUNK = 3, 4
#: Thresholds at which the planted 64 random bytes form one region.
REDUCE_FLAGS = ["--min-variance", "100", "--entropy-threshold", "3"]


@pytest.fixture(autouse=True)
def _fresh_heap_cache():
    heap_analyze.clear_heap_cache()
    yield
    heap_analyze.clear_heap_cache()


# -- fixtures ---------------------------------------------------------------------------


def _randomise(data, offset, length, rng):
    data[offset:offset + length] = bytes(rng.randrange(256) for _ in range(length))


def _planted_heap(seed):
    heap = sh.glibc_heap()
    data = bytearray(heap.data)
    rng = random.Random(seed)
    plant, cached = heap.chunks[PLANT_CHUNK], heap.chunks[KEY_CHUNK]
    _randomise(data, plant.va - heap.base_va + plant.header_len, plant.user_len, rng)
    key_word = cached.va - heap.base_va + cached.header_len + 8
    _randomise(data, key_word, 8, rng)
    heap.data = bytes(data)
    return heap


def _planted_user_span():
    chunk = sh.glibc_heap().chunks[PLANT_CHUNK]
    start = chunk.va - sh.glibc_heap().base_va + chunk.header_len
    return start, start + chunk.user_len


@pytest.fixture
def msl_dumps(tmp_path):
    return [_write_msl(tmp_path / f"d{i}.msl", _planted_heap(i))
            for i in range(N_DUMPS)]


@pytest.fixture
def raw_dumps(tmp_path):
    paths = []
    for i in range(N_DUMPS):
        path = tmp_path / f"flat{i}.dump"
        path.write_bytes(_planted_heap(i).data)
        paths.append(path)
    return paths


def _write_named_msl(path, heap):
    """``.msl`` keeping the fixture's region name (``[anon:scudo:primary]``)."""
    base_va, size, name = heap.regions[0]
    writer = MslWriter(path, os_type=OSType.LINUX, arch_type=ArchType.X86_64,
                       imported=False)
    writer.add_memory_region(base_va, heap.data, protection=0x03)
    writer.add_vas_map([MslVasEntry(base_va, size, 0x03, 0, name)])
    writer.write()
    return path


@pytest.fixture
def scudo_dumps(tmp_path):
    paths = []
    for i in range(N_DUMPS):
        heap = sh.scudo_primary()
        data = bytearray(heap.data)
        _randomise(data, 0x210, 64, random.Random(i))
        heap.data = bytes(data)
        paths.append(_write_named_msl(tmp_path / f"scudo{i}.msl", heap))
    return paths


# -- helpers ----------------------------------------------------------------------------


def _run(monkeypatch, capsys, argv):
    monkeypatch.setattr(sys, "argv", ["memdiver", *argv])
    with pytest.raises(SystemExit) as exc:
        main()
    return exc.value.code, capsys.readouterr()


def _session(monkeypatch, capsys, tmp_path, dumps, allocator="auto"):
    state = tmp_path / "session" / "s.json"
    size = str(len(sh.glibc_heap().data))
    code, _ = _run(monkeypatch, capsys, ["consensus-begin", "--state", str(state),
                                         "--size", size, "--allocator", allocator])
    assert code == 0
    for dump in dumps:
        assert _run(monkeypatch, capsys,
                    ["consensus-add", "--state", str(state), str(dump)])[0] == 0
    return state


def _reduce(monkeypatch, capsys, state, dumps, out, *extra):
    argv = ["search-reduce", "--state", str(state), "--reference-dump",
            str(dumps[0]), "-o", str(out), *REDUCE_FLAGS, *extra]
    return _run(monkeypatch, capsys, argv)


def _payload(monkeypatch, capsys, state, dumps, out, *extra):
    code, captured = _reduce(monkeypatch, capsys, state, dumps, out, *extra)
    assert code == 0, captured.err
    return json.loads(out.read_text()), captured.err


def _overlaps_plant(region):
    start, end = _planted_user_span()
    return region["offset"] < end and region["offset"] + region["length"] > start


# -- parser -----------------------------------------------------------------------------


def test_parser_allocator_choices_and_default():
    parser = _build_parser()
    args = parser.parse_args(["search-reduce", "--state", "s", "--reference-dump",
                              "r", "-o", "o"])
    assert args.allocator == "auto"
    sub = parser._subparsers._group_actions[0].choices["search-reduce"]
    action = next(a for a in sub._actions if a.dest == "allocator")
    assert tuple(action.choices) == SEARCH_REDUCE_ALLOCATOR_CHOICES


# -- heap sources -----------------------------------------------------------------------


def test_session_source_annotates_the_planted_region(msl_dumps, tmp_path,
                                                      monkeypatch, capsys):
    state = _session(monkeypatch, capsys, tmp_path, msl_dumps)
    payload, err = _payload(monkeypatch, capsys, state, msl_dumps,
                            tmp_path / "c.json", "--allocator", "auto")
    heap = payload["heap"]
    assert heap["status"] == "ok" and heap["source"] == "session"
    assert heap["dumps_recorded"] == heap["dumps_folded"] == N_DUMPS
    assert len(heap["per_dump"]) == N_DUMPS
    assert "heap_roles_path" not in heap and "runs" not in heap
    assert payload["heap_status"] == "ok"
    assert payload["thresholds"]["allocator"] == "auto"
    planted = [r for r in payload["regions"] if _overlaps_plant(r)]
    assert planted and all(r["heap"]["chunk"] for r in planted)
    assert "heap source=session" in err
    assert "chunk=0x" in err


@pytest.mark.parametrize("session_allocator", ["off", None])
def test_session_without_heap_falls_back_to_reference(
        session_allocator, msl_dumps, tmp_path, monkeypatch, capsys):
    if session_allocator is None:   # a session from before heap recording
        state = tmp_path / "legacy.json"
        size = len(sh.glibc_heap().data)
        wh_args = argparse.Namespace(state=str(state), size=size)
        from memdiver.cli.consensus import _cmd_consensus_begin
        assert _cmd_consensus_begin(wh_args) == 0
        for dump in msl_dumps:
            assert _run(monkeypatch, capsys,
                        ["consensus-add", "--state", str(state), str(dump)])[0] == 0
    else:
        state = _session(monkeypatch, capsys, tmp_path, msl_dumps, session_allocator)
    payload, err = _payload(monkeypatch, capsys, state, msl_dumps,
                            tmp_path / "c.json")
    assert payload["heap"]["status"] == "ok"
    assert payload["heap"]["source"] == "reference"
    assert payload["heap"]["fallback_reason"] == wh.NO_SESSION_HEAP_REASON
    assert "heap source=reference" in err and "session has no heap roles" in err


def test_relative_projection_paths_resolve_beside_the_state(
        msl_dumps, tmp_path, monkeypatch, capsys):
    """A legacy session (relative --state) recorded cwd-relative npz paths;
    the merge still finds them beside the state file from another working
    directory. New sessions record absolute paths."""
    monkeypatch.chdir(tmp_path)
    state = _session(monkeypatch, capsys, tmp_path.relative_to(tmp_path), msl_dumps)
    session = json.loads(state.read_text())
    assert session["heap"]["dumps"][0]["file"].startswith("/")
    for record in session["heap"]["dumps"]:   # rewrite as a legacy session
        record["file"] = str(wh.session_heap_dir(state) / f"{record['index']:04d}.npz")
    assert not session["heap"]["dumps"][0]["file"].startswith("/")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert wh.load_session_heap(session).status != "ok"
    heap = wh.load_session_heap(session, tmp_path / state)
    assert heap.status == "ok" and heap.report["dumps_projected"] == N_DUMPS


# -- off is the historical payload ----------------------------------------------------


def test_allocator_off_payload_matches_the_pre_flag_handler(
        msl_dumps, tmp_path, monkeypatch, capsys):
    state = _session(monkeypatch, capsys, tmp_path, msl_dumps)
    off, _ = _payload(monkeypatch, capsys, state, msl_dumps,
                      tmp_path / "off.json", "--allocator", "off")
    policy_off, _ = _payload(monkeypatch, capsys, state, msl_dumps,
                             tmp_path / "policy_off.json", "--heap-policy", "off")
    args = _build_parser().parse_args(
        ["search-reduce", "--state", str(state), "--reference-dump",
         str(msl_dumps[0]), "-o", str(tmp_path / "legacy.json"), *REDUCE_FLAGS])
    del args.allocator
    args.heap_policy = "off"
    assert _cmd_search_reduce(args) == 0
    legacy = json.loads((tmp_path / "legacy.json").read_text())
    assert off == policy_off == legacy
    assert "heap" not in off and "heap_status" not in off
    assert "allocator" not in off["thresholds"]


# -- mask -------------------------------------------------------------------------------


def test_mask_with_session_heap_masks_metadata(msl_dumps, tmp_path,
                                               monkeypatch, capsys):
    state = _session(monkeypatch, capsys, tmp_path, msl_dumps)
    payload, err = _payload(monkeypatch, capsys, state, msl_dumps,
                            tmp_path / "c.json", "--heap-policy", "mask")
    assert payload["stages"]["heap_masked"] > 0
    assert "heap_masked=" in err


def test_mask_on_raw_dumps_names_the_status(raw_dumps, tmp_path,
                                            monkeypatch, capsys):
    state = _session(monkeypatch, capsys, tmp_path, raw_dumps)
    code, captured = _reduce(monkeypatch, capsys, state, raw_dumps,
                             tmp_path / "c.json", "--heap-policy", "mask")
    assert code != 0
    assert "no_va_coordinate" in captured.err
    assert not (tmp_path / "c.json").exists()


def test_mask_with_allocator_off_is_an_argument_error(msl_dumps, tmp_path,
                                                      monkeypatch, capsys):
    state = _session(monkeypatch, capsys, tmp_path, msl_dumps)
    code, captured = _reduce(monkeypatch, capsys, state, msl_dumps,
                             tmp_path / "c.json", "--heap-policy", "mask",
                             "--allocator", "off")
    assert code == 2
    assert "--allocator off" in captured.err


def test_mask_with_allocator_off_raises_before_loading_the_session(tmp_path):
    args = argparse.Namespace(state=str(tmp_path / "missing.json"),
                              heap_policy="mask", allocator="off")
    with pytest.raises(CapabilityError, match="--allocator off"):
        _cmd_search_reduce(args)


# -- unsupported allocator ------------------------------------------------------------


def test_scudo_session_is_unsupported_but_annotate_succeeds(
        scudo_dumps, tmp_path, monkeypatch, capsys):
    state = _session(monkeypatch, capsys, tmp_path, scudo_dumps)
    payload, err = _payload(monkeypatch, capsys, state, scudo_dumps,
                            tmp_path / "c.json")
    assert payload["heap"]["status"] == "unsupported_allocator"
    assert "warning: heap annotation unavailable" in err
    assert all("heap" not in r for r in payload["regions"])


# -- session restart ------------------------------------------------------------------


def test_rebegin_removes_stale_projections_only(msl_dumps, tmp_path,
                                                monkeypatch, capsys):
    state = _session(monkeypatch, capsys, tmp_path, msl_dumps[:2])
    heap_dir = wh.session_heap_dir(state)
    keep = heap_dir / "notes.txt"
    keep.write_text("mine")
    assert sorted(p.name for p in heap_dir.glob("*.npz")) == ["0000.npz", "0001.npz"]
    _session(monkeypatch, capsys, tmp_path, [])
    assert not list(heap_dir.glob("*.npz"))
    assert keep.read_text() == "mine"


def test_reset_session_heap_dir_without_directory(tmp_path):
    assert wh.reset_session_heap_dir(tmp_path / "s.json") == []


# -- arena kinds ------------------------------------------------------------------------


def _flat_offset(heaps, va):
    """View offset of *va* when *heaps* (sorted by VA) are concatenated."""
    offset = 0
    for heap in heaps:
        if heap.base_va <= va < heap.base_va + len(heap.data):
            return offset + va - heap.base_va
        offset += len(heap.data)
    raise AssertionError(f"{va:#x} not mapped")


def test_session_regions_carry_thread_and_mmap_arena(tmp_path, monkeypatch, capsys):
    from tests.test_heap_msl import arena_process_heaps, write_vas_only_msl

    processes = [arena_process_heaps(seed) for seed in range(N_DUMPS)]
    dumps = [write_vas_only_msl(tmp_path / f"p{i}.msl", heaps)
             for i, (heaps, _meta) in enumerate(processes)]
    heaps, meta = processes[0]
    state = tmp_path / "session" / "s.json"
    size = str(sum(len(h.data) for h in heaps))
    assert _run(monkeypatch, capsys, ["consensus-begin", "--state", str(state),
                                      "--size", size, "--allocator", "auto"])[0] == 0
    for dump in dumps:
        assert _run(monkeypatch, capsys,
                    ["consensus-add", "--state", str(state), str(dump)])[0] == 0
    payload, err = _payload(monkeypatch, capsys, state, dumps, tmp_path / "c.json",
                            "--allocator", "auto")
    assert payload["heap"]["source"] == "session"

    def arena_at(va):
        offset = _flat_offset(heaps, va)
        region = next(r for r in payload["regions"]
                      if r["offset"] <= offset < r["offset"] + r["length"])
        return region["heap"]["chunk"].get("arena")

    assert arena_at(meta["thread_key_va"]) == "thread"
    assert arena_at(meta["mmap_key_va"]) == "mmap"
    assert "arena=thread" in err and "arena=mmap" in err


# -- stderr heap lines (review fixes) ---------------------------------------------------


def test_search_reduce_prints_one_heap_status_line(msl_dumps, tmp_path,
                                                    monkeypatch, capsys):
    state = _session(monkeypatch, capsys, tmp_path, msl_dumps)
    _payload_, err = _payload(monkeypatch, capsys, state, msl_dumps,
                              tmp_path / "c.json", "--heap-policy", "mask")
    status_lines = [ln for ln in err.splitlines() if "heap status=" in ln]
    assert len(status_lines) == 1, err
    (line,) = status_lines
    assert "status=ok allocator=ptmalloc2 chunks=" in line
    assert " residual=" in line and " heap_masked=" in line
    assert err.count("heap source=session") == 1
    assert "chunk=0x" in err


def test_search_reduce_warns_about_missing_projections(msl_dumps, tmp_path,
                                                        monkeypatch, capsys):
    state = _session(monkeypatch, capsys, tmp_path, msl_dumps)
    (wh.session_heap_dir(state) / "0002.npz").unlink()
    payload, err = _payload(monkeypatch, capsys, state, msl_dumps,
                            tmp_path / "c.json")
    assert payload["heap"]["status"] == "ok"
    assert payload["heap"]["missing_projections"] == [2]
    assert "warning:" in err and "missing" in err and "[2]" in err
