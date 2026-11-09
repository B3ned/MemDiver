"""CLI ``--allocator`` / ``--heap-policy`` on the consensus-backed commands.

Two layers:

* flag parsing -> producer kwarg, with the producer replaced by a spy that
  records its kwargs and stops the handler (no compute);
* end to end on the synthetic heap corpus: ``analyze-candidates --heap-policy
  mask`` really changes ``stages.heap_masked``, and the human-readable heap
  lines reach stderr.
"""

import argparse
import json
import sys

import pytest

from memdiver.app import tools_consensus, tools_pipeline
from memdiver.cli import _build_parser, main
from memdiver.cli._shared import (
    ALLOCATOR_CHOICES,
    HEAP_POLICY_CHOICES,
    PIPELINE_ALLOCATOR_CHOICES,
    SEARCH_REDUCE_ALLOCATOR_CHOICES,
)
from memdiver.cli.consensus import (
    _cmd_consensus,
    _cmd_consensus_begin,
    _cmd_consensus_regions,
    _cmd_consensus_window,
)
from memdiver.cli.heap_report import (
    candidate_heap_lines,
    consensus_heap_line,
    locate_key_heap_lines,
)
from memdiver.cli.pipeline import (
    _cmd_analyze_candidates,
    _cmd_locate_key,
    _cmd_search_reduce,
)
from memdiver.engine import consensus_service
from memdiver.heap import analyze as heap_analyze
from tests.test_candidate_pipeline_heap import KEY_LEN, _spans, write_corpus


class _Stop(Exception):
    """Raised by the spies once the producer kwargs are captured."""


@pytest.fixture
def spy(monkeypatch):
    """``spy(module, name)`` -> dict filled with the replaced callable's kwargs."""
    def install(module, name):
        captured = {}

        def fake(*_args, **kwargs):
            captured.update(kwargs)
            raise _Stop

        monkeypatch.setattr(module, name, fake)
        return captured
    return install


@pytest.fixture
def two_dumps(tmp_path):
    paths = []
    for i in range(2):
        path = tmp_path / f"d{i}.dump"
        path.write_bytes(bytes([i]) * 256)
        paths.append(str(path))
    return paths


def _parse(argv):
    return _build_parser().parse_args(argv)


# -- choices ----------------------------------------------------------------------


def test_choice_tuples_match_the_engine():
    from memdiver.engine.candidate_pipeline import HEAP_POLICIES
    from memdiver.heap.analyze import parse_allocator_hint

    assert set(HEAP_POLICY_CHOICES) == set(HEAP_POLICIES)
    assert PIPELINE_ALLOCATOR_CHOICES == ALLOCATOR_CHOICES + ("off",)
    for name in ALLOCATOR_CHOICES:
        parse_allocator_hint(name)   # every CLI choice is a valid hint


def test_search_reduce_allocator_choices_match_reduce_ready_kinds():
    from memdiver.app._pipeline_heap import reduce_ready_allocators

    concrete = tuple(c for c in SEARCH_REDUCE_ALLOCATOR_CHOICES
                     if c not in ("auto", "off"))
    assert concrete == reduce_ready_allocators()
    assert set(SEARCH_REDUCE_ALLOCATOR_CHOICES) <= set(PIPELINE_ALLOCATOR_CHOICES)


def test_consensus_begin_allocator_choices(capsys):
    base = ["consensus-begin", "--state", "s.json", "--size", "16"]
    # None = omitted; the handler records heap roles as auto for a --size session.
    assert _parse(base).allocator is None
    assert _parse([*base, "--allocator", "off"]).allocator == "off"
    # 'scudo' parses because it selects the Scudo session; the handler refuses it
    # next to --size. Other names that are not reduce-ready stop at the parser.
    assert _parse([*base, "--allocator", "scudo"]).allocator == "scudo"
    with pytest.raises(SystemExit):
        _parse([*base, "--allocator", "dlmalloc"])
    capsys.readouterr()


@pytest.mark.parametrize("command", [
    "consensus", "consensus-window", "consensus-regions",
    "analyze-candidates", "locate-key",
])
def test_allocator_defaults_to_auto_and_rejects_unknown(command, two_dumps, capsys):
    extra = ["--key-hex", "aa"] if command == "locate-key" else []
    assert _parse([command, *two_dumps, *extra]).allocator == "auto"
    assert _parse([command, *two_dumps, *extra, "--allocator", "off"]).allocator == "off"
    with pytest.raises(SystemExit):
        _parse([command, *two_dumps, *extra, "--allocator", "tcmalloc"])
    capsys.readouterr()


@pytest.mark.parametrize("command", ["analyze-candidates", "search-reduce"])
def test_heap_policy_defaults_to_annotate_and_rejects_unknown(command, two_dumps, capsys):
    base = ([command, *two_dumps] if command == "analyze-candidates" else
            [command, "--state", "s.json", "--reference-dump", "r", "-o", "c.json"])
    assert _parse(base).heap_policy == "annotate"
    assert _parse([*base, "--heap-policy", "mask"]).heap_policy == "mask"
    with pytest.raises(SystemExit):
        _parse([*base, "--heap-policy", "drop"])
    capsys.readouterr()


# -- flag -> producer kwarg ----------------------------------------------------------


def test_consensus_forwards_allocator(spy, two_dumps):
    captured = spy(consensus_service, "build_consensus")
    with pytest.raises(_Stop):
        _cmd_consensus(_parse(["consensus", *two_dumps, "--allocator", "scudo"]))
    assert captured["allocator"] == "scudo"


@pytest.mark.parametrize("command, handler, producer", [
    ("consensus-window", _cmd_consensus_window, "aligned_window_result"),
    ("consensus-regions", _cmd_consensus_regions, "class_regions_result"),
])
def test_consensus_views_forward_allocator(spy, two_dumps, command, handler, producer):
    captured = spy(tools_consensus, producer)
    with pytest.raises(_Stop):
        handler(_parse([command, *two_dumps, "--allocator", "jemalloc"]))
    assert captured["allocator"] == "jemalloc"


def test_analyze_candidates_forwards_both(spy, two_dumps):
    captured = spy(tools_pipeline, "analyze_candidates")
    with pytest.raises(_Stop):
        _cmd_analyze_candidates(_parse([
            "analyze-candidates", *two_dumps,
            "--heap-policy", "mask", "--allocator", "ptmalloc2"]))
    assert captured["heap_policy"] == "mask"
    assert captured["allocator"] == "ptmalloc2"


def test_locate_key_forwards_allocator(spy, two_dumps):
    captured = spy(tools_pipeline, "locate_key")
    with pytest.raises(_Stop):
        _cmd_locate_key(_parse([
            "locate-key", *two_dumps, "--key-hex", "aabb", "--allocator", "off"]))
    assert captured["allocator"] == "off"


def test_search_reduce_forwards_heap_policy(spy, tmp_path):
    state = tmp_path / "state.json"
    _cmd_consensus_begin(argparse.Namespace(state=str(state), size=64))
    captured = spy(tools_pipeline, "search_reduce")
    with pytest.raises(_Stop):
        _cmd_search_reduce(_parse([
            "search-reduce", "--state", str(state), "--reference-dump", "r",
            "-o", str(tmp_path / "c.json"), "--heap-policy", "off"]))
    assert captured["heap_policy"] == "off"


def test_handlers_tolerate_namespaces_without_the_new_flags(spy, two_dumps):
    """Hand-built Namespaces that predate the flags keep the producer defaults."""
    captured = spy(tools_pipeline, "analyze_candidates")
    args = _parse(["analyze-candidates", *two_dumps])
    del args.heap_policy, args.allocator
    with pytest.raises(_Stop):
        _cmd_analyze_candidates(args)
    assert captured["heap_policy"] == "annotate"
    assert captured["allocator"] == "auto"


# -- human-readable lines ------------------------------------------------------------


def test_candidate_lines_mark_residual_chunks():
    regions = [
        {"rank": 1, "offset": 0x40, "length": 32,
         "heap": {"chunk": {"start": 0x20, "size": 64, "state": "cached",
                            "offset_in_chunk": 0x20, "agree": 4},
                  "residual": True}},
        {"rank": 2, "offset": 0x100, "length": 16,
         "heap": {"chunk": None, "residual": False}},
        {"rank": 3, "offset": 0x200, "length": 16},
    ]
    (line,) = candidate_heap_lines(regions)
    assert "chunk=0x20+0x20" in line and line.endswith("state=cached residual")


def test_candidate_lines_show_arena_only_when_known():
    chunk = {"start": 0x20, "size": 64, "state": "in_use",
             "offset_in_chunk": 0x20, "agree": 4}
    regions = [
        {"rank": 1, "offset": 0x40, "length": 32,
         "heap": {"chunk": {**chunk, "arena": "thread"}, "residual": False}},
        {"rank": 2, "offset": 0x40, "length": 32,
         "heap": {"chunk": chunk, "residual": False}},
    ]
    known, unknown = candidate_heap_lines(regions)
    assert known.endswith("state=in_use arena=thread")
    assert "arena=" not in unknown


def test_locate_key_lines_mark_freed_hits_only():
    rows = [{"dump_path": "d0", "offsets": [0x10, 0x20, 0x30], "heap": [
        {"allocator": "ptmalloc2", "chunk_va": 0x1000, "chunk_size": 64,
         "state": "free", "offset_in_chunk": 16, "role": "free_data"},
        {"allocator": "ptmalloc2", "chunk_va": 0x2000, "chunk_size": 64,
         "state": "in_use", "offset_in_chunk": 16, "role": "user_data"},
        None]}]
    first, second = locate_key_heap_lines(rows)
    assert first.endswith("residual")
    assert not second.endswith("residual")


def test_consensus_line_is_none_when_heap_is_off():
    assert consensus_heap_line(None) is None


# -- end to end on the synthetic heap corpus -----------------------------------------


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    from memdiver.app import composition

    heap_analyze.clear_heap_cache()
    monkeypatch.setattr(composition, "resolve_project_db", lambda *a, **k: None)
    paths, heap = write_corpus(tmp_path / "dumps")
    yield paths, heap
    heap_analyze.clear_heap_cache()


def _run(monkeypatch, capsys, argv):
    monkeypatch.setattr(sys, "argv", ["memdiver", *argv])
    with pytest.raises(SystemExit) as exc:
        main()
    return exc.value.code, capsys.readouterr()


def test_heap_policy_mask_changes_heap_masked_end_to_end(corpus, tmp_path,
                                                         monkeypatch, capsys):
    paths, _heap = corpus
    outputs = {}
    for policy in ("annotate", "mask"):
        out = tmp_path / f"{policy}.json"
        code, streams = _run(monkeypatch, capsys, [
            "analyze-candidates", *paths, "--max-returned", "0",
            "--heap-policy", policy, "-o", str(out)])
        assert code in (0, None)
        assert "heap status=ok" in streams.err
        status_lines = [ln for ln in streams.err.splitlines() if "heap status=" in ln]
        assert len(status_lines) == 1
        assert status_lines[0].startswith("memdiver: heap status=ok residual=")
        assert "allocator=" not in status_lines[0]   # unchanged format
        outputs[policy] = json.loads(out.read_text())
    assert "heap_masked" not in outputs["annotate"]["stages"]
    assert outputs["mask"]["stages"]["heap_masked"] > 0
    assert any(r["heap"]["residual"] for r in outputs["annotate"]["regions"])


def test_heap_policy_off_drops_the_annotation_end_to_end(corpus, tmp_path,
                                                         monkeypatch, capsys):
    paths, _heap = corpus
    out = tmp_path / "off.json"
    _run(monkeypatch, capsys, [
        "analyze-candidates", *paths, "--heap-policy", "off", "-o", str(out)])
    payload = json.loads(out.read_text())
    assert "heap_status" not in payload
    assert all("heap" not in r for r in payload["regions"])


def test_consensus_prints_heap_status_and_honours_off(corpus, tmp_path,
                                                      monkeypatch, capsys):
    paths, _heap = corpus
    out = tmp_path / "cons.json"
    _run(monkeypatch, capsys, ["consensus", *paths, "-o", str(out)])
    assert json.loads(out.read_text())["heap"]["status"] == "ok"
    _run(monkeypatch, capsys, ["consensus", *paths, "--allocator", "off",
                               "-o", str(out)])
    assert "heap" not in json.loads(out.read_text())


def test_locate_key_prints_chunk_lines(corpus, tmp_path, monkeypatch, capsys):
    paths, heap = corpus
    va, _n = _spans(heap)["key"]
    key = heap.read(va, KEY_LEN)
    out = tmp_path / "loc.json"
    code, streams = _run(monkeypatch, capsys, [
        "locate-key", *paths, "--key-hex", key.hex(), "-o", str(out)])
    assert code in (0, None)
    assert "allocator=ptmalloc2" in streams.err and "chunk=0x" in streams.err
    code, streams = _run(monkeypatch, capsys, [
        "locate-key", *paths, "--key-hex", key.hex(), "--allocator", "off",
        "-o", str(out)])
    assert "chunk=0x" not in streams.err
    assert all("heap" not in r for r in json.loads(out.read_text())["dumps"])


# -- mask precondition wording (review fixes) -----------------------------------------


def test_batch_mask_error_does_not_claim_a_reduce_ready_requirement(tmp_path):
    from memdiver.app._pipeline_heap import heap_inputs_from_consensus, load_heap_beside
    from memdiver.core.service_errors import CapabilityError

    with pytest.raises(CapabilityError) as by_consensus:
        heap_inputs_from_consensus(argparse.Namespace(heap=None), "mask")
    with pytest.raises(CapabilityError) as beside:
        load_heap_beside(str(tmp_path / "variance.npy"), "mask")
    for exc in (by_consensus, beside):
        assert "reduce-ready" not in str(exc.value)
        assert "VA map" in str(exc.value)


def test_search_reduce_mask_error_names_the_reduce_ready_allocators():
    from memdiver.app._pipeline_heap import reduce_ready_allocators, require_heap_for_mask
    from memdiver.core.service_errors import CapabilityError

    with pytest.raises(CapabilityError) as exc:
        require_heap_for_mask(None, "mask")
    assert "reduce-ready" in str(exc.value)
    assert all(name in str(exc.value) for name in reduce_ready_allocators())
