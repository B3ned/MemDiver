"""The web pipeline runner's Android Scudo method.

``run_pipeline`` with a ``scudo`` block must be the CLI's Scudo chain under
another front end: same producer, same regions, the same run's own secret for
every choice of reference. Around that it is held to what the wizard relies on:
no positional consensus is built, the artifacts keep their usual names, the
hits carry no variance the method does not have, and the memory guard and the
cooperative cancel work as they do for the positional pipeline.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import pytest

import memdiver.app.pipeline.pipeline_runner as pr
from memdiver.core.dump_source import open_dump
from memdiver.core.service_errors import CapabilityError
from tests.fixtures.generate_scudo_msl_fixtures import (
    SECRET_SIZE,
    secret_user_va,
    secret_value,
    write_scudo_msl_fixtures,
)

N_RUNS = 3


@dataclass
class _FakeCtx:
    task_id: str = "scudo"
    cancel: bool = False
    cancel_on_stage: str = ""
    events: List[Dict[str, Any]] = field(default_factory=list)

    def emit(self, event_type: str, **fields: Any) -> None:
        self.events.append({"type": event_type, **fields})
        if fields.get("stage") == self.cancel_on_stage:
            self.cancel = True

    def is_cancelled(self) -> bool:
        return self.cancel

    def stages(self, event_type: str) -> List[str]:
        return [e["stage"] for e in self.events if e["type"] == event_type]


@pytest.fixture
def scudo_runs(tmp_path) -> List[str]:
    return [str(p) for p in write_scudo_msl_fixtures(tmp_path / "runs", N_RUNS)]


def _oracle(tmp_path: Path, target: bytes) -> Path:
    path = tmp_path / "oracle.py"
    path.write_text(f"TARGET = bytes.fromhex({target.hex()!r})\n"
                    "def verify(candidate):\n"
                    "    return candidate == TARGET\n")
    os.chmod(path, 0o600)
    return path


def _params(tmp_path: Path, sources: List[str], target: bytes,
            allocator: str = "scudo", **extra: Any) -> Dict[str, Any]:
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir(exist_ok=True)
    return {
        "artifact_dir": str(artifact_dir),
        "source_paths": sources,
        "oracle_path": str(_oracle(tmp_path, target)),
        "brute_force": {"key_sizes": [SECRET_SIZE], "stride": 1, "jobs": 1},
        "scudo": {"allocator": allocator},
        **extra,
    }


def _reordered(paths: List[str], first: int) -> List[str]:
    return [paths[first], *[p for i, p in enumerate(paths) if i != first]]


def _hits(params: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(
        (Path(params["artifact_dir"]) / "brute_force" / "hits.json").read_text())


def _candidates(params: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(
        (Path(params["artifact_dir"]) / "search_reduce" / "candidates.json").read_text())


def _state(tmp_path: Path, sources: List[str], **kw: Any) -> pr.PipelineState:
    return pr.PipelineState(
        ctx=_FakeCtx(), artifact_dir=tmp_path, reduce_kwargs={}, oracle_path=tmp_path / "o.py",
        bf_kwargs={"key_sizes": [48]}, nsweep_params=None, emit_params=None,
        source_paths=sources, scudo_params={"allocator": "auto"}, **kw)


# ---------------------------------------------------------------------------
# The chain
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ref", range(N_RUNS))
def test_every_reference_finds_its_own_runs_secret(scudo_runs, tmp_path, ref):
    sources = _reordered(scudo_runs, ref)
    params = _params(tmp_path, sources, secret_value(ref))

    run_pipeline_result = pr.run_pipeline(params, _FakeCtx())

    (region,) = _candidates(params)["regions"]
    assert int(region["va"], 16) == secret_user_va(ref)
    (hit,) = _hits(params)["hits"]
    assert hit["offset"] == region["offset"]
    assert hit["confirmed_by"] == "oracle"
    with open_dump(Path(sources[0])) as source:
        source.open()
        assert source.read_all()[hit["offset"]:hit["offset"] + SECRET_SIZE] == secret_value(ref)
    assert run_pipeline_result["summary"]["hits_path"].endswith("brute_force/hits.json")


def test_the_regions_are_the_ones_the_cli_chain_writes(scudo_runs, tmp_path):
    """One implementation: the web run and the CLI chain agree region for region."""
    from memdiver.cli.consensus import _cmd_consensus_add, _cmd_consensus_begin
    from memdiver.cli.main import _build_parser
    from memdiver.cli.pipeline import _cmd_search_reduce

    parse = _build_parser().parse_args
    state, out = tmp_path / "s.json", tmp_path / "cli.json"
    assert _cmd_consensus_begin(parse([
        "consensus-begin", "--state", str(state), "--allocator", "scudo"])) == 0
    for path in scudo_runs:
        assert _cmd_consensus_add(parse(["consensus-add", "--state", str(state), path])) == 0
    assert _cmd_search_reduce(parse([
        "search-reduce", "--state", str(state), "--reference-dump", scudo_runs[0],
        "--key-sizes", str(SECRET_SIZE), "-o", str(out)])) == 0

    params = _params(tmp_path, scudo_runs, secret_value(0))
    pr.run_pipeline(params, _FakeCtx())

    web, cli = _candidates(params), json.loads(out.read_text())
    assert web["regions"] == cli["regions"]
    assert web["funnel"] == cli["funnel"]
    assert web["source"] == cli["source"] == "search-reduce:scudo"


def test_no_positional_consensus_is_built(scudo_runs, tmp_path):
    params = _params(tmp_path, scudo_runs, secret_value(0))
    ctx = _FakeCtx()

    result = pr.run_pipeline(params, ctx)

    assert not (Path(params["artifact_dir"]) / "consensus").exists()
    assert "consensus" not in ctx.stages("stage_start")
    assert ctx.stages("stage_start") == ["search_reduce", "brute_force"]
    assert {a["name"] for a in result["artifacts"]} == {"candidates", "hits"}
    relpaths = {a["relpath"] for a in result["artifacts"]}
    assert relpaths == {"search_reduce/candidates.json", "brute_force/hits.json"}


def test_a_hit_carries_no_neighborhood_variance(scudo_runs, tmp_path):
    """The method has no per-byte variance around a hit, so none is invented."""
    params = _params(tmp_path, scudo_runs, secret_value(0))
    pr.run_pipeline(params, _FakeCtx())
    (hit,) = _hits(params)["hits"]
    assert hit["neighborhood_variance"] == []


def test_the_stage_stream_carries_the_verdict_funnel(scudo_runs, tmp_path):
    params = _params(tmp_path, scudo_runs, secret_value(0))
    ctx = _FakeCtx()
    pr.run_pipeline(params, ctx)

    progress = ctx.stages("progress")
    assert progress.count("search_reduce:chunk_consensus") == N_RUNS
    assert "search_reduce:classify" in progress
    assert "search_reduce:regions" in progress
    end = next(e for e in ctx.events
               if e["type"] == "stage_end" and e["stage"] == "search_reduce")
    assert end["extra"]["source"] == "search-reduce:scudo"
    assert end["extra"]["funnel"]["signature_unique"]["chunks"] == 1
    assert end["extra"]["reference_dump"] == scudo_runs[0]


# ---------------------------------------------------------------------------
# Allocator selection
# ---------------------------------------------------------------------------


def _fake_detection(best):
    from memdiver.heap.detect import DetectionResult

    def _detect(*_args, **_kwargs):
        return DetectionResult(candidates=[], best=best, confidence=1.0)
    return _detect


def test_auto_runs_when_detection_finds_scudo(scudo_runs, tmp_path, monkeypatch):
    import memdiver.heap.detect as detect
    from memdiver.heap.model import AllocatorKind

    monkeypatch.setattr(detect, "detect_allocator", _fake_detection(AllocatorKind.SCUDO))
    params = _params(tmp_path, scudo_runs, secret_value(0), allocator="auto")
    pr.run_pipeline(params, _FakeCtx())
    assert len(_hits(params)["hits"]) == 1


def test_auto_refuses_a_heap_detection_calls_something_else(scudo_runs, tmp_path, monkeypatch):
    import memdiver.heap.detect as detect
    from memdiver.heap.model import AllocatorKind

    monkeypatch.setattr(detect, "detect_allocator", _fake_detection(AllocatorKind.PTMALLOC2))
    params = _params(tmp_path, scudo_runs, secret_value(0), allocator="auto")
    with pytest.raises(CapabilityError) as refused:
        pr.run_pipeline(params, _FakeCtx())
    assert refused.value.code == "scudo.wrong_allocator"


def test_forcing_scudo_skips_detection(scudo_runs, tmp_path, monkeypatch):
    import memdiver.heap.detect as detect

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("detection ran although the allocator was forced")

    monkeypatch.setattr(detect, "detect_allocator", _forbidden)
    params = _params(tmp_path, scudo_runs, secret_value(0), allocator="scudo")
    pr.run_pipeline(params, _FakeCtx())
    assert len(_hits(params)["hits"]) == 1


# ---------------------------------------------------------------------------
# Cancel, memory guard and what the stages hand over
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cancel_on_stage", ["", "search_reduce:chunk_consensus"])
def test_a_cancel_ends_the_run_with_exactly_one_terminal_event(
    scudo_runs, tmp_path, cancel_on_stage,
):
    params = _params(tmp_path, scudo_runs, secret_value(0))
    ctx = _FakeCtx(cancel=not cancel_on_stage, cancel_on_stage=cancel_on_stage)

    with pytest.raises(RuntimeError, match="pipeline cancelled"):
        pr.run_pipeline(params, ctx)

    assert [e["error"] for e in ctx.events if e["type"] == "error"] == ["cancelled"]
    assert not (Path(params["artifact_dir"]) / "search_reduce" / "candidates.json").exists()


def test_an_over_budget_run_is_refused_for_the_forced_rerun_dialog(
    scudo_runs, tmp_path, monkeypatch,
):
    import memdiver.engine.scudo_chunk_consensus as scc
    from memdiver.core.memory_budget import MemoryEstimate

    monkeypatch.setattr(scc, "chunk_consensus_estimate",
                        lambda *_a, **_k: MemoryEstimate(1 << 60, "test"))
    params = _params(tmp_path, scudo_runs, secret_value(0))
    with pytest.raises(CapabilityError) as refused:
        pr.run_pipeline(params, _FakeCtx())
    assert refused.value.code == "memory_budget_exceeded"

    pr.run_pipeline({**params, "force_memory": True}, _FakeCtx())
    assert len(_hits(params)["hits"]) == 1


def test_the_reduce_stage_hands_the_request_to_the_producer(tmp_path, monkeypatch):
    import memdiver.app.tools_pipeline_android as android

    captured: Dict[str, Any] = {}
    monkeypatch.setattr(android, "search_reduce_android",
                        lambda **kw: captured.update(kw) or {})
    state = _state(tmp_path, ["/d/a.msl", "/d/b.msl"], mixed_ok=True, force_memory=True)

    pr._stage_reduce(state)

    assert captured["dump_paths"] == ["/d/a.msl", "/d/b.msl"]
    assert captured["reference_path"] == "/d/a.msl"
    assert captured["key_sizes"] == [48]
    assert captured["allocator"] == "auto"
    assert captured["mixed_ok"] is True
    assert captured["force_memory"] is True
    assert captured["output_dir"] == str(tmp_path / "search_reduce")
    assert state.candidates_path == tmp_path / "search_reduce" / "candidates.json"


def test_brute_force_reads_the_first_dump_without_a_welford_state(tmp_path, monkeypatch):
    from memdiver.app import tools_pipeline

    captured: Dict[str, Any] = {}
    monkeypatch.setattr(tools_pipeline, "brute_force", lambda **kw: captured.update(kw) or {})
    state = _state(tmp_path, ["/d/a.msl", "/d/b.msl"])
    state.candidates_path = tmp_path / "candidates.json"

    pr._stage_brute_force(state)

    assert captured["reference_path"] == "/d/a.msl"
    assert captured["state_path"] is None
    assert state.consensus is None
