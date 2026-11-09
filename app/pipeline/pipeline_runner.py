"""Phase 25 end-to-end pipeline orchestrator.

Runs ``consensus → search-reduce → brute-force → n-sweep → emit-plugin``
inside a worker process dispatched by :class:`api.services.task_manager.TaskManager`.
The entry point :func:`run_pipeline` is deliberately top-level so it
pickles cleanly under ``mp_context="spawn"`` (closures, lambdas, and
instance methods do not).

Contract:

* ``params`` is a JSON-friendly dict built from the Pydantic
  ``PipelineRunRequest`` in ``api/routers/pipeline.py``. The router is
  the only authoritative place parameters are validated.
* ``ctx`` is the :class:`api.services.task_manager.WorkerContext`
  passed in by ``_worker_entry``; it exposes ``emit`` (put a dict on
  the progress mp.Queue) and ``is_cancelled`` (read the Manager
  cancel Event).
* Every stage is wrapped in ``stage_start`` / ``stage_end`` emits so
  the TaskManager can maintain per-stage records. Engine functions
  themselves emit fine-grained progress via the ``progress_callback``
  bridge installed here.

Artifacts written per stage (relative to ``artifact_dir``):

    consensus/variance.npy
    consensus/reference.bin
    search_reduce/candidates.json
    brute_force/hits.json
    nsweep/report.json
    nsweep/report.html
    nsweep/report.md
    emit_plugin/<name>.py

The orchestrator never touches ``task_manager`` or ``progress_bus``
directly — it only emits dicts onto ``ctx.progress_queue`` and relies
on the drain task in the parent process to translate them into bus
events. This keeps the worker stdlib-only beyond engine/.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, TYPE_CHECKING

from memdiver.app.pipeline.artifact_paths import resolve_artifact_dir
from memdiver.app.pipeline.artifact_events import EmittingArtifactList

from memdiver.core.artifact_util import register_artifact, sha256_streamed

if TYPE_CHECKING:
    from memdiver.engine.auto_floor import AutoFloorResult

logger = logging.getLogger("memdiver.app.pipeline.pipeline_runner")

# Default oracle probe config for Shape-2 oracles at pipeline time.
_EMPTY_CONFIG: Dict[str, Any] = {}


class _CancelledByContext(Exception):
    """Raised internally when ctx.is_cancelled() flips mid-stage."""


def _bridge(ctx, stage_prefix: str) -> Callable:
    """Return a ``progress_callback`` forwarding engine events to ctx.emit.

    Adapts the :class:`engine.progress.ProgressEvent` signature to the
    TaskManager worker-side JSON contract (plain dicts on an mp.Queue).
    The ``event.extra`` dict is passed by reference — it gets pickled
    across the queue boundary, so the child never mutates the original.

    NOTE(single-source): the default pipeline stages no longer call this — they
    delegate to the ``app.tools_pipeline`` producers, which build their own
    identical ``_progress_bridge`` from the ``on_progress`` sink. This function
    is retained (repo policy) as the reference adapter and for out-of-tree stages
    that may still import it; its behaviour is mirrored 1:1 by
    ``tools_pipeline._progress_bridge``.
    """
    def _fn(event) -> None:
        stage = event.stage
        if ":" not in stage:
            stage = f"{stage_prefix}:{stage}"
        ctx.emit(
            "progress",
            stage=stage,
            pct=event.pct if event.pct >= 0 else None,
            msg=event.msg,
            extra=event.extra or None,
        )
    return _fn


def _producer_sink(ctx) -> Callable[..., None]:
    """An ``on_progress(event, **fields)`` sink handing producer events to ctx.

    The ``app.tools_pipeline`` producers own their own ``stage_start`` /
    ``progress`` / ``stage_end`` bracketing (byte-identical to the pre-refactor
    inline emits, same stage names + ``extra`` field names) and stream it through
    this sink, so the stage wrappers no longer emit those themselves.

    The one event this sink DROPS is the cancel ``error``: a producer that
    observes ``ctx.is_cancelled()`` emits ``("error", error="cancelled")`` AND
    raises ``CapabilityError(code="cancelled")``. We swallow that ``error`` here
    because :func:`run_pipeline` re-emits exactly one ``("error", "cancelled")``
    when it catches the translated :class:`_CancelledByContext` — preserving the
    single terminal cancel-error the pre-refactor path produced. The pipeline
    producers only ever emit ``error`` for cancellation (genuine compute failures
    raise), so swallowing it here is safe.
    """
    def _sink(event: str, **fields: Any) -> None:
        if event == "error":
            return
        ctx.emit(event, **fields)
    return _sink


def _run_producer(fn: Callable, /, **kwargs: Any) -> Any:
    """Call a ``tools_pipeline`` producer, translating its cancel signal.

    The producers raise :class:`CapabilityError` with ``code="cancelled"`` on
    cooperative cancellation; the pipeline expresses cancellation as
    :class:`_CancelledByContext` (which :func:`run_pipeline` catches to emit the
    single terminal cancel event and raise the ``RuntimeError`` the TaskManager
    treats as an aborted task). Every other exception propagates unchanged.
    """
    from memdiver.core.service_errors import CapabilityError

    try:
        return fn(**kwargs)
    except CapabilityError as exc:
        if getattr(exc, "code", None) == "cancelled":
            raise _CancelledByContext() from exc
        raise


# MOVED to memdiver.core.artifact_util (P3.2 dedup)
# def _sha256_streamed(path: Path) -> str:
#     """Return the hex sha256 of ``path``, read incrementally.
#
#     ``hashlib.file_digest`` (Python 3.11+, the project's floor) streams the file
#     through a bounded internal buffer, so peak memory stays bounded and
#     full-dump-scale artifacts never load whole into RAM. Byte-identical to
#     hashing the whole file at once.
#     """
#     with path.open("rb") as f:
#         return hashlib.file_digest(f, "sha256").hexdigest()
#
#
# def _register_artifact(
#     artifacts: List[Dict[str, Any]],
#     artifact_dir: Path,
#     *,
#     name: str,
#     relpath: str,
#     media_type: str = "application/octet-stream",
# ) -> Dict[str, Any]:
#     """Compute size + sha256 of a written artifact and append a record."""
#     full = artifact_dir / relpath
#     try:
#         size = full.stat().st_size
#     except OSError:
#         size = 0
#     sha = _sha256_streamed(full) if full.is_file() else None
#     spec = {
#         "name": name,
#         "relpath": relpath,
#         "media_type": media_type,
#         "size": size,
#         "sha256": sha,
#     }
#     artifacts.append(spec)
#     return spec


def _is_msl(source) -> bool:
    return getattr(source, "format_name", "") == "msl"


def _persist_welford_state(
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
    *,
    mean_arr,
    m2_arr,
    total: int,
    n_welford: int,
    region_filter: Optional[str] = None,
) -> Path:
    """Persist the Welford accumulators + a state.json pointer, register it.

    Extracted verbatim from :func:`_build_consensus`; brute-force reads
    these to compute ``neighborhood_variance`` and the refine workflow
    folds more dumps on top of them. Callers must have created the
    ``consensus`` subdirectory first.
    """
    import numpy as np

    mean_path = artifact_dir / "consensus" / "mean.npy"
    m2_path = artifact_dir / "consensus" / "m2.npy"
    state_json_path = artifact_dir / "consensus" / "state.json"
    np.save(mean_path, mean_arr)
    np.save(m2_path, m2_arr)
    state = {
        "size": int(total),
        "num_dumps": int(n_welford),
        "mean_path": str(mean_path),
        "m2_path": str(m2_path),
    }
    if region_filter is not None:
        # ``/refine`` must fold later dumps through the same view filter.
        state["region_filter"] = region_filter
    state_json_path.write_text(json.dumps(state, indent=2))
    register_artifact(
        artifacts, artifact_dir,
        name="consensus_state",
        relpath="consensus/state.json",
        media_type="application/json",
    )
    return state_json_path


def _build_consensus(
    sources: List,
    *,
    ctx,
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
    region_filter: Optional[Any] = None,
) -> Dict[str, Any]:
    """Fold N sources into a variance matrix + reference slab.

    ``region_filter`` (``RegionSelection`` / spec / note; ``.msl`` only) folds
    through the region view filter; ``None`` uses whatever filter the sources
    were opened with. An active filter is recorded in ``state.json``.

    Emits progress per-fold so the UI sees the matrix accumulating.

    NOTE(single-source): the ``consensus`` pipeline stage now delegates to
    :func:`memdiver.app.tools_pipeline.consensus` (``persist_welford=True``),
    which mirrors this fold + Welford-persist byte-for-byte (validated for the
    raw path by ``test_consensus_persist_matches_direct_welford``). This function
    is retained (repo policy + still directly exercised by
    ``test_build_consensus_reads_each_raw_source_once``, which asserts the
    read-each-source-once invariant on already-open sources — a guarantee the
    path-taking producer cannot express). It is no longer on the production
    pipeline path.
    """
    from memdiver.engine.consensus_msl import MslIncrementalBuilder, build_msl_consensus
    from memdiver.engine.consensus import ConsensusVector

    import numpy as np

    n = len(sources)
    if n == 0:
        raise ValueError("pipeline: no consensus sources provided")

    ctx.emit("stage_start", stage="consensus", pct=0.0,
             msg=f"folding {n} dumps")

    from memdiver.core.region_view_filter import (
        coerce_region_filter,
        region_filter_note,
    )
    from memdiver.engine.consensus import sources_region_filter_note

    selection = coerce_region_filter(region_filter)
    if all(_is_msl(s) for s in sources):
        # ASLR-aware incremental path for native MSL sources.
        # ``builder.diagnostics`` (e.g. ``classification_basis_mixed``) is
        # logged by the builder but not threaded into this legacy helper's
        # return: it is off the production path (see the docstring), and the
        # producer it was replaced by, ``tools_pipeline._consensus_incremental``,
        # does surface it.
        builder = MslIncrementalBuilder.from_sources(
            sources, region_filter=selection)
        for i in range(n):
            if ctx.is_cancelled():
                raise _CancelledByContext()
            builder.fold_next(i)
            ctx.emit(
                "progress",
                stage="consensus",
                pct=(i + 1) / n,
                msg=f"folded {i + 1}/{n}",
                extra={"dumps_folded": i + 1, "total_dumps": n},
            )
        variance = builder.get_live_variance()
        reference = builder.get_reference()
        total = builder.total_bytes
        mean_arr, m2_arr, n_welford = builder.welford_state()
    else:
        # Raw .dump path: use the flat ConsensusVector incremental API. Stream
        # the fold — hand each source to add_source one at a time so only ONE
        # dump is resident at a time (peak ~O(dump size)) rather than
        # materializing all N up front (~O(N * dump size), which OOM'd on large
        # multi-dump runs). add_source reads each dump internally, trims to
        # min_size, folds it, and caches reference_bytes on the first.
        min_size = min(s.size for s in sources)
        matrix = ConsensusVector()
        matrix.build_incremental(min_size)
        for i, s in enumerate(sources):
            if ctx.is_cancelled():
                raise _CancelledByContext()
            matrix.add_source(s)
            ctx.emit(
                "progress",
                stage="consensus",
                pct=(i + 1) / n,
                msg=f"folded {i + 1}/{n}",
                extra={"dumps_folded": i + 1, "total_dumps": n},
            )
        # Extract Welford state BEFORE finalize() destroys it.
        mean_arr, m2_arr, n_welford = matrix.welford_state()
        matrix.finalize()
        variance = matrix.variance
        reference = matrix.reference_bytes
        total = min_size

    # Persist consensus artifacts.
    (artifact_dir / "consensus").mkdir(parents=True, exist_ok=True)
    variance_path = artifact_dir / "consensus" / "variance.npy"
    ref_path = artifact_dir / "consensus" / "reference.bin"
    np.save(variance_path, variance)
    ref_path.write_bytes(reference)
    register_artifact(
        artifacts, artifact_dir,
        name="consensus_variance",
        relpath="consensus/variance.npy",
        media_type="application/octet-stream",
    )
    register_artifact(
        artifacts, artifact_dir,
        name="consensus_reference",
        relpath="consensus/reference.bin",
        media_type="application/octet-stream",
    )
    # Persist Welford accumulators so brute-force can compute
    # neighborhood_variance and the refine workflow can fold more dumps.
    state_json_path = _persist_welford_state(
        artifact_dir, artifacts,
        mean_arr=mean_arr, m2_arr=m2_arr, total=total, n_welford=n_welford,
        region_filter=(region_filter_note(selection)
                       or sources_region_filter_note(sources)),
    )
    ctx.emit(
        "stage_end", stage="consensus", pct=1.0,
        msg=f"variance ready ({total} bytes)",
        extra={"total_bytes": total, "num_dumps": n},
    )
    return {
        "variance_path": str(variance_path),
        "reference_path": str(ref_path),
        "state_path": str(state_json_path),
        "total_bytes": int(total),
        "num_dumps": int(n),
    }


def _reduce_kwargs_without_heap(
    reduce_kwargs: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Copy of ``reduce_kwargs`` minus ``heap_policy``.

    Only the reduce stage (``tools_pipeline.search_reduce``) loads the heap
    roles the consensus stage wrote. The nsweep fold (fresh Welford per N) and
    the auto-floor / escalate sweep reduce with no heap annotation, so a
    ``heap_policy`` there would either be rejected as an unknown keyword or be
    a silent no-op ("mask" quietly behaving as "off"). Dropping it keeps those
    stages exactly as they were before the reduce stage honoured the policy.
    """
    stripped = dict(reduce_kwargs or {})
    stripped.pop("heap_policy", None)
    return stripped


def _run_reduce(
    variance_path: Path,
    reference_path: Path,
    num_dumps: int,
    reduce_kwargs: Dict[str, Any],
    *,
    ctx,
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
) -> Path:
    """Run search-reduce and persist the resulting candidates.json.

    Delegates the compute + stage bracketing to
    :func:`memdiver.app.tools_pipeline.search_reduce` (the single implementation
    shared with the CLI/MCP). The producer emits the identical ``search_reduce``
    stage_start/progress/stage_end stream (sub-stages ``variance`` / ``aligned``
    / ``entropy``) and writes ``candidates.json`` with the same
    ``ReductionResult.to_dict()`` body PLUS an additive ``recommended_floor`` key
    (an advisory the frontend ignores as an unknown key; the rest of the file is
    byte-identical). This wrapper keeps the artifact registration + cancel
    translation.
    """
    from memdiver.app import tools_pipeline

    out_dir = artifact_dir / "search_reduce"
    _run_producer(
        tools_pipeline.search_reduce,
        variance_path=str(variance_path),
        reference_path=str(reference_path),
        num_dumps=num_dumps,
        output_dir=str(out_dir),
        on_progress=_producer_sink(ctx),
        is_cancelled=ctx.is_cancelled,
        **reduce_kwargs,
    )
    candidates_path = out_dir / "candidates.json"
    register_artifact(
        artifacts, artifact_dir,
        name="candidates",
        relpath="search_reduce/candidates.json",
        media_type="application/json",
    )
    return candidates_path


def _run_reduce_scudo(
    source_paths: Sequence[str],
    scudo_params: Dict[str, Any],
    *,
    key_sizes: Sequence[int],
    mixed_ok: bool,
    force_memory: bool,
    ctx,
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
) -> Path:
    """Run the Android Scudo reduction and persist the resulting candidates.json.

    Scudo alignment needs every dump at once, so the chunk consensus is built
    here and not in a consensus stage. The artifact keeps the positional stage's
    name and path because it is the same contract for ``brute_force``.
    """
    from memdiver.app.tools_pipeline_android import search_reduce_android

    out_dir = artifact_dir / "search_reduce"
    _run_producer(
        search_reduce_android,
        dump_paths=list(source_paths),
        reference_path=source_paths[0],
        output_dir=str(out_dir),
        key_sizes=key_sizes,
        allocator=scudo_params["allocator"],
        mixed_ok=mixed_ok,
        force_memory=force_memory,
        on_progress=_producer_sink(ctx),
        is_cancelled=ctx.is_cancelled,
    )
    register_artifact(
        artifacts, artifact_dir,
        name="candidates",
        relpath="search_reduce/candidates.json",
        media_type="application/json",
    )
    return out_dir / "candidates.json"


def _run_brute_force(
    candidates_path: Path,
    reference_path: Path,
    oracle_path: Optional[Path],
    bf_kwargs: Dict[str, Any],
    *,
    oracle_config: Optional[Dict[str, Any]] = None,
    pcap_path: Optional[str] = None,
    tls_client_random: Optional[str] = None,
    pcap_max_records: Optional[int] = None,
    pcap_max_challenges: Optional[int] = None,
    state_path: Optional[Path] = None,
    variance_threshold: Optional[float] = None,
    ctx,
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
) -> Path:
    """Run the BYO oracle against surviving candidates and persist hits.json.

    Delegates to :func:`memdiver.app.tools_pipeline.brute_force`; the producer
    emits the identical ``brute_force`` stage stream + stage_end extra
    (``verified_count`` / ``total_candidates`` / ``hits[]`` with each hit's
    ``offset`` / ``size`` / ``region_index`` / ``key_hex`` /
    ``neighborhood_start`` / ``neighborhood_variance``) and writes the same
    ``hits.json`` (``BruteForceResult.to_dict()``). This wrapper wires the
    ``state_path`` (so the Welford ``neighborhood_variance`` slice is attached to
    each hit), registers the artifact, and translates cancellation.

    ``oracle_config`` is the armed BYO oracle's already-parsed configuration; it
    is threaded as a dict (no temporary TOML) and the producer prefers it over
    ``oracle_config_path``. ``None`` for a pcap run or an oracle needing none.
    """
    from memdiver.app import tools_pipeline

    out_dir = artifact_dir / "brute_force"
    _run_producer(
        tools_pipeline.brute_force,
        candidates_path=str(candidates_path),
        reference_path=str(reference_path),
        # Exactly one oracle source — the producer routes ``pcap_path`` through
        # the first-party trusted pcap oracle and raises if both/neither given.
        oracle_path=str(oracle_path) if oracle_path is not None else None,
        oracle_config=oracle_config,
        pcap_path=pcap_path,
        tls_client_random=tls_client_random,
        pcap_max_records=pcap_max_records,
        pcap_max_challenges=pcap_max_challenges,
        output_dir=str(out_dir),
        state_path=str(state_path) if state_path else None,
        variance_threshold=variance_threshold,
        on_progress=_producer_sink(ctx),
        is_cancelled=ctx.is_cancelled,
        **bf_kwargs,
    )
    hits_path = out_dir / "hits.json"
    register_artifact(
        artifacts, artifact_dir,
        name="hits",
        relpath="brute_force/hits.json",
        media_type="application/json",
    )
    return hits_path


def _run_nsweep(
    source_paths: List[str],
    oracle_path: Optional[Path],
    nsweep_params: Dict[str, Any],
    *,
    oracle_config: Optional[Dict[str, Any]] = None,
    pcap_path: Optional[str] = None,
    tls_client_random: Optional[str] = None,
    pcap_max_records: Optional[int] = None,
    pcap_max_challenges: Optional[int] = None,
    ctx,
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
    region_filter: Optional[str] = None,
    mixed_ok: bool = False,
) -> Dict[str, Any]:
    """Run the N-sweep harness and persist report.{json,md,html}.

    ``region_filter`` is the run's region view filter, so the sweep folds the
    same filtered view the consensus stage did.

    Delegates to :func:`memdiver.app.tools_pipeline.n_sweep`, which opens the
    sources itself from ``source_paths`` — the harness re-folds a fresh
    consensus at each N, so it cannot reuse the single already-open source set
    the other stages share. The producer emits the identical ``nsweep`` stage
    stream + stage_end extra (``first_hit_n`` / ``first_hit_offset`` /
    ``total_dumps``) and writes the same ``report.{json,md,html}`` via
    ``app.reports.write_nsweep_artifacts``.

    Both oracle sources are forwarded verbatim, exactly as
    :func:`_run_brute_force` forwards them: a pcap run passes ``oracle_path``
    as ``None`` and the producer routes the sweep through the first-party
    trusted pcap oracle instead. The producer raises if both or neither is
    given.

    The per-stage summary is read back from ``report.json`` (which
    ``write_nsweep_artifacts`` fills with ``NSweepResult.to_dict()`` plus the
    injected ``headline``) so it stays equal to the pre-refactor
    ``result.to_dict()`` the frontend consumes — the producer's own trimmed
    return payload does not carry the full dict.
    """
    from memdiver.app import tools_pipeline

    out_dir = artifact_dir / "nsweep"
    _run_producer(
        tools_pipeline.n_sweep,
        source_paths=list(source_paths),
        # Exactly one oracle source — mirrors _run_brute_force's forwarding so
        # both stages of a pcap run verify against the same capture.
        oracle_path=str(oracle_path) if oracle_path is not None else None,
        # Same armed-oracle config the brute_force stage ran with, so the two
        # stages of one run can never be configured differently.
        oracle_config=oracle_config,
        pcap_path=pcap_path,
        tls_client_random=tls_client_random,
        pcap_max_records=pcap_max_records,
        pcap_max_challenges=pcap_max_challenges,
        output_dir=str(out_dir),
        n_values=list(nsweep_params["n_values"]),
        reduce_kwargs=_reduce_kwargs_without_heap(nsweep_params.get("reduce_kwargs")),
        key_sizes=tuple(nsweep_params.get("key_sizes", (32,))),
        stride=nsweep_params.get("stride", 1),
        exhaustive=nsweep_params.get("exhaustive", True),
        on_progress=_producer_sink(ctx),
        is_cancelled=ctx.is_cancelled,
        region_filter=region_filter,
        mixed_ok=mixed_ok,
    )
    # Register in the same order the pre-refactor write_nsweep_artifacts dict
    # yielded (json, html, md); the filenames are fixed by the writer.
    for name, media_type in (("json", "application/json"),
                             ("html", "text/html"),
                             ("md", "text/markdown")):
        register_artifact(
            artifacts, artifact_dir,
            name=f"nsweep_{name}",
            relpath=f"nsweep/report.{name}",
            media_type=media_type,
        )
    return json.loads((out_dir / "report.json").read_text())


def _run_emit_plugin(
    hits_path: Path,
    reference_path: Path,
    emit_params: Dict[str, Any],
    *,
    ctx,
    artifact_dir: Path,
    artifacts: List[Dict[str, Any]],
) -> Optional[Path]:
    """Emit a Vol3 plugin from the first hit, or return None if hits empty.

    The empty-hits graceful skip (emit a ``skipped`` stage_end and return
    ``None`` WITHOUT running the generator) and the ``hit_index`` clamp stay in
    this wrapper — the path-taking producer would instead RAISE on an empty /
    out-of-range hits file, which would fail the whole run. For a non-empty hits
    file the compute + stage bracketing + the ``inferred_fields`` artifact are
    delegated to :func:`memdiver.app.tools_pipeline.emit_plugin`
    (``write_fields=True``): it emits the identical ``emit_plugin`` stage stream
    + stage_end extra (``plugin_path`` / ``fields`` / ``variance_threshold``),
    writes ``<name>.py`` + ``<name>_fields.json``, and the generated plugin is
    byte-identical to the previous inline path. This wrapper keeps the artifact
    registration + cancel translation.
    """
    from memdiver.app import tools_pipeline

    payload = json.loads(Path(hits_path).read_text())
    hits = payload.get("hits", [])
    if not hits:
        ctx.emit(
            "stage_end", stage="emit_plugin", pct=1.0,
            msg="no hits to emit",
            extra={"skipped": True},
        )
        return None
    hit_index = int(emit_params.get("hit_index", 0))
    hit_index = max(0, min(hit_index, len(hits) - 1))
    name = emit_params.get("name", "memdiver_plugin")
    description = emit_params.get("description")
    v_thresh = emit_params.get("variance_threshold")

    output_dir = artifact_dir / "emit_plugin"
    _run_producer(
        tools_pipeline.emit_plugin,
        hits_path=str(hits_path),
        reference_path=str(reference_path),
        name=name,
        output_dir=str(output_dir),
        description=description,
        hit_index=hit_index,
        variance_threshold=float(v_thresh) if v_thresh is not None else None,
        min_static_ratio=float(emit_params.get("min_static_ratio", 0.3)),
        write_fields=True,
        on_progress=_producer_sink(ctx),
        is_cancelled=ctx.is_cancelled,
    )
    output_path = output_dir / f"{name}.py"
    register_artifact(
        artifacts, artifact_dir,
        name="vol3_plugin",
        relpath=f"emit_plugin/{output_path.name}",
        media_type="text/x-python",
    )
    register_artifact(
        artifacts, artifact_dir,
        name="inferred_fields",
        relpath=f"emit_plugin/{name}_fields.json",
        media_type="application/json",
    )
    # The standalone YARA rule the emitter now writes beside the plugin
    # (``engine.vol3_emit.emit_plugin_for_hit``). Registered rather than merely
    # left on disk: the artifact store is the ONLY way a web-UI run's output
    # leaves the worker's artifact_dir (the download route resolves a
    # registered name), so an unregistered file would be a rule the user
    # cannot get at -- the same "emitted but unusable" shape the sidecar was
    # written to fix. Registration also gets it sized + sha256'd and streamed
    # as a live ``artifact`` event like every other output. It is deliberately
    # NOT in the frontend's PRIMARY_ARTIFACT_NAMES, so it lands in the Raw
    # download list instead of claiming a result tab of its own.
    register_artifact(
        artifacts, artifact_dir,
        name="vol3_yara_rule",
        relpath=f"emit_plugin/{output_path.stem}.yar",
        media_type="text/plain",
    )
    return output_path


def run_auto_floor_stage(
    *,
    variance_path: str,
    reference_path: str,
    num_dumps: int,
    oracle_path: str,
    oracle_config: Optional[Dict[str, Any]] = None,
    reduce_kwargs: Optional[Dict[str, Any]] = None,
    key_sizes: Sequence[int] = (32,),
    stride: int = 1,
    coverage: Optional[float] = None,
    correspondence: Optional[float] = None,
    filter_recall: Optional[float] = None,
    min_coverage: float = 0.80,
    phi0_method: str = "pmin",
    p_min: float = 0.35,
    oracle_budget: Optional[int] = None,
    positive_control: Optional[bytes] = None,
    key_material: Optional[Dict[str, Any]] = None,
    progress_callback: Optional[Callable] = None,
    region_filter: Optional[str] = None,
) -> "AutoFloorResult":
    """Ground-truth-free variance-floor selection for the pipeline / API.

    Mirrors the CLI ``_cmd_auto_floor`` assembly so the two transports
    cannot drift: it loads the persisted variance array (``.npy`` written
    by the consensus stage), reads the reference dump through a proper
    ``open_dump`` lifecycle (with optional ``key_material`` so an encrypted
    ``.msl`` reference can be decrypted, spec §10), loads the armed BYO
    oracle, then delegates the verdict to
    :func:`engine.auto_floor.run_auto_floor` — the single source of truth
    for the oracle-arbitrated sweep.

    ``reference_data`` is truncated to the variance length so the two arrays
    are index-aligned, exactly as the CLI does. ``region_filter`` reads an
    ``.msl`` reference through the region view filter; ``None`` reuses the one
    the consensus stage recorded beside ``variance_path`` (if any).
    """
    import numpy as np

    from memdiver.app.composition import open_dump
    from memdiver.app.tools_pipeline import _consensus_region_filter
    from memdiver.engine.auto_floor import run_auto_floor
    from memdiver.engine.oracle import load_oracle

    variance = np.load(variance_path)
    region_filter = _consensus_region_filter(variance_path, region_filter)
    with open_dump(Path(reference_path), region_filter=region_filter,
                   **(key_material or {})) as source:
        reference_data = source.read_all()[: len(variance)]

    oracle = load_oracle(Path(oracle_path), config=oracle_config or {})

    extra: Dict[str, Any] = {}
    if progress_callback is not None:
        extra["progress_callback"] = progress_callback

    return run_auto_floor(
        variance,
        reference_data,
        int(num_dumps),
        oracle,
        reduce_kwargs=_reduce_kwargs_without_heap(reduce_kwargs),
        key_sizes=tuple(key_sizes),
        stride=stride,
        coverage=coverage,
        correspondence=correspondence,
        filter_recall=filter_recall,
        min_coverage=min_coverage,
        positive_control=positive_control,
        phi0_method=phi0_method,
        p_min=p_min,
        oracle_budget=oracle_budget,
        **extra,
    )


# ---------------------------------------------------------------------------
# Stage abstraction + ordered registry.
#
# Historically :func:`run_pipeline` inlined a hardcoded 5-stage sequence.
# The abstraction below composes that same sequence from a module-level
# ordered registry so a new stage can be registered/inserted without editing
# ``run_pipeline``'s body. It is intentionally thin: each default stage is a
# wrapper delegating to the existing ``_build_consensus`` / ``_run_*``
# functions unchanged, so the default pipeline's ordering, optional gating,
# artifacts, emits and return value are byte-for-byte preserved.
#
# Pickle/spawn note: the registry is a module global rebuilt at import time in
# each worker (spawn re-imports the module). Neither ``Stage`` objects nor the
# wrapper functions are pickled — only ``run_pipeline`` and ``params``/``ctx``
# cross the process boundary — and every wrapper is a top-level function that
# captures no state, so the fragile spawn contract is upheld.
# ---------------------------------------------------------------------------


@dataclass
class PipelineState:
    """Mutable state threaded through the composed pipeline stages.

    Stages read the parsed request fields + upstream results and write their
    own outputs back onto the same instance. This replaces the ad-hoc local
    variables the inline sequence used (``consensus``/``candidates_path``/
    ``hits_path``) without changing what flows between stages.
    """

    ctx: Any
    artifact_dir: Path
    reduce_kwargs: Dict[str, Any]
    # ``None`` for a pcap-oracle run: the brute_force and nsweep stages both
    # route through the first-party trusted pcap oracle (``pcap_path`` /
    # ``tls_client_random``) instead of a BYO oracle file. Only the ``escalate``
    # stage still requires an oracle FILE and stays off on a pcap run.
    oracle_path: Optional[Path]
    bf_kwargs: Dict[str, Any]
    nsweep_params: Optional[Dict[str, Any]]
    emit_params: Optional[Dict[str, Any]]
    # The armed BYO oracle's configuration, already parsed. Held once on the
    # state rather than per stage because it belongs to the ORACLE, and
    # brute_force / nsweep / escalate all load that same oracle file — three
    # copies could drift apart within one run. ``None`` for a pcap run (which
    # builds its own config) or for an oracle that needs no configuration.
    oracle_config: Optional[Dict[str, Any]] = None
    # Pcap-oracle source (mutually exclusive with ``oracle_path``).
    pcap_path: Optional[str] = None
    tls_client_random: Optional[str] = None
    # Optional pcap-oracle work caps; ``None`` keeps the resource/oracle
    # defaults (16 records per direction, no total challenge cap).
    pcap_max_records: Optional[int] = None
    pcap_max_challenges: Optional[int] = None
    # Static/dynamic variance cutoff (from the emit request) forwarded to the
    # brute_force stage so its stage_end preview matches the emit stage. ``None``
    # resolves to the producer default (``PLUGIN_STATIC_THRESHOLD``).
    variance_threshold: Optional[float] = None
    # Dump paths the path-taking producers (consensus / n_sweep) open + close
    # themselves; stages consume ``source_paths``, never a shared open handle.
    source_paths: List[str] = field(default_factory=list)
    # Analysis-time region view filter (``RegionSelection.to_note()`` string
    # or ``"heap,stack"`` spec) forwarded to the consensus stage; ``None``
    # analyses every region. Honoured by ``.msl`` sources only.
    region_filter: Optional[str] = None
    # Memory-guard override (params key ``force_memory``) forwarded to the
    # budget-gated consensus stage as ``force=``.
    force_memory: bool = False
    # Cohort-mix override (params key ``mixed_ok``) forwarded to the consensus
    # and n-sweep stages; unset, a multi-cohort source set is refused.
    mixed_ok: bool = False
    # The router refuses every option the Scudo method cannot honour, so the
    # stages below only branch on reduce and verify.
    scudo_params: Optional[Dict[str, Any]] = None
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    # Opt-in escalation (floor-free fall-through when brute-force finds no hit).
    escalate: bool = False
    escalate_oracle_budget: Optional[int] = None
    # Upstream results shared between stages.
    consensus: Optional[Dict[str, Any]] = None
    candidates_path: Optional[Path] = None
    hits_path: Optional[Path] = None


def _always_enabled(state: "PipelineState") -> bool:
    return True


def _consensus_enabled(state: "PipelineState") -> bool:
    """Off for a Scudo run, whose chunk consensus is part of ``search_reduce``.

    A positional fold of cold-boot dumps would line up unrelated bytes, and it
    would cost a full read of every dump for nothing the Scudo path consumes.
    """
    return state.scudo_params is None


def _nsweep_enabled(state: "PipelineState") -> bool:
    """Fire whenever nsweep params were supplied, on EITHER oracle source.

    Deliberately blind to which source is armed: the sweep reaches the BYO
    oracle file and the first-party pcap oracle alike, so gating it on
    ``oracle_path`` would silently drop the stage from a pcap run. A request
    carrying neither source is not skipped here either — the producer's
    exactly-one guard reports that as an error, which beats a silent no-op.
    """
    return state.nsweep_params is not None


def _emit_enabled(state: "PipelineState") -> bool:
    return state.emit_params is not None


@dataclass
class Stage:
    """A named, optionally-gated step in the pipeline.

    ``run(state)`` mutates ``state`` in place (writes artifacts/summary and any
    result other stages consume). ``enabled(state)`` decides whether the stage
    runs at all — this is where the historical optional gating for nsweep/emit
    lives. ``check_cancel_before`` mirrors the pre-refactor placement of the
    ``ctx.is_cancelled()`` guard (consensus checked cancellation only inside
    its fold loop; every later stage was guarded before it ran).
    """

    name: str
    run: Callable[["PipelineState"], None]
    enabled: Callable[["PipelineState"], bool] = _always_enabled
    check_cancel_before: bool = True


def _stage_consensus(state: "PipelineState") -> None:
    """Fold the sources into variance.npy + reference.bin (+ Welford state).

    Delegates to :func:`memdiver.app.tools_pipeline.consensus`
    (``persist_welford=True``), the incremental fold that mirrors the retained
    :func:`_build_consensus`: it emits the identical ``consensus`` stage +
    per-fold ``progress`` stream (``dumps_folded`` / ``total_dumps``) and writes
    the same ``variance.npy`` / ``reference.bin`` / ``mean.npy`` / ``m2.npy`` /
    ``state.json`` (``{size, num_dumps, mean_path, m2_path}``) that ``/refine``
    and ``/neighborhood`` read and that brute-force consumes via ``state_path``.
    This wrapper registers the three downloadable artifacts (variance / reference
    / state — mean.npy & m2.npy stay unregistered, referenced only by
    state.json, exactly as before) and translates cancellation.

    The producer opens its own sources from the given paths (it validates
    >= 2 dumps) and closes them when done.
    """
    from memdiver.app import tools_pipeline

    out_dir = state.artifact_dir / "consensus"
    consensus = _run_producer(
        tools_pipeline.consensus,
        dump_paths=list(state.source_paths),
        output_dir=str(out_dir),
        persist_welford=True,
        on_progress=_producer_sink(state.ctx),
        is_cancelled=state.ctx.is_cancelled,
        region_filter=state.region_filter,
        force=state.force_memory,
        mixed_ok=state.mixed_ok,
    )
    register_artifact(
        state.artifacts, state.artifact_dir,
        name="consensus_variance", relpath="consensus/variance.npy",
        media_type="application/octet-stream",
    )
    register_artifact(
        state.artifacts, state.artifact_dir,
        name="consensus_reference", relpath="consensus/reference.bin",
        media_type="application/octet-stream",
    )
    register_artifact(
        state.artifacts, state.artifact_dir,
        name="consensus_state", relpath="consensus/state.json",
        media_type="application/json",
    )
    state.consensus = consensus
    state.summary["consensus"] = consensus


def _stage_reduce(state: "PipelineState") -> None:
    if state.scudo_params is not None:
        state.candidates_path = _run_reduce_scudo(
            state.source_paths,
            state.scudo_params,
            key_sizes=state.bf_kwargs.get("key_sizes", (32,)),
            mixed_ok=state.mixed_ok,
            force_memory=state.force_memory,
            ctx=state.ctx,
            artifact_dir=state.artifact_dir,
            artifacts=state.artifacts,
        )
    else:
        consensus = state.consensus
        state.candidates_path = _run_reduce(
            Path(consensus["variance_path"]),
            Path(consensus["reference_path"]),
            consensus["num_dumps"],
            state.reduce_kwargs,
            ctx=state.ctx,
            artifact_dir=state.artifact_dir,
            artifacts=state.artifacts,
        )
    state.summary["candidates_path"] = str(state.candidates_path)


def _stage_brute_force(state: "PipelineState") -> None:
    # A Scudo run's offsets are in the first dump's own flat view and it has no
    # Welford state, so its hits carry no neighborhood variance.
    if state.scudo_params is not None:
        reference_path, consensus_state = Path(state.source_paths[0]), None
    else:
        reference_path = Path(state.consensus["reference_path"])
        consensus_state = Path(state.consensus["state_path"])
    state.hits_path = _run_brute_force(
        state.candidates_path,
        reference_path,
        state.oracle_path,
        state.bf_kwargs,
        oracle_config=state.oracle_config,
        pcap_path=state.pcap_path,
        tls_client_random=state.tls_client_random,
        pcap_max_records=state.pcap_max_records,
        pcap_max_challenges=state.pcap_max_challenges,
        state_path=consensus_state,
        variance_threshold=state.variance_threshold,
        ctx=state.ctx,
        artifact_dir=state.artifact_dir,
        artifacts=state.artifacts,
    )
    state.summary["hits_path"] = str(state.hits_path)


def _stage_nsweep(state: "PipelineState") -> None:
    state.summary["nsweep"] = _run_nsweep(
        state.source_paths,
        state.oracle_path,
        state.nsweep_params,
        oracle_config=state.oracle_config,
        pcap_path=state.pcap_path,
        tls_client_random=state.tls_client_random,
        pcap_max_records=state.pcap_max_records,
        pcap_max_challenges=state.pcap_max_challenges,
        ctx=state.ctx,
        artifact_dir=state.artifact_dir,
        artifacts=state.artifacts,
        region_filter=state.region_filter,
        mixed_ok=state.mixed_ok,
    )


def _stage_emit_plugin(state: "PipelineState") -> None:
    plugin_path = _run_emit_plugin(
        state.hits_path,
        Path(state.consensus["reference_path"]),
        state.emit_params,
        ctx=state.ctx,
        artifact_dir=state.artifact_dir,
        artifacts=state.artifacts,
    )
    state.summary["plugin_path"] = str(plugin_path) if plugin_path else None


def _escalate_enabled(state: "PipelineState") -> bool:
    """Fire only when opted-in AND brute-force produced zero verified hits.

    Short-circuits on ``state.escalate`` before any file I/O so the default
    (``escalate=False``) path is a pure no-op and stays byte-identical. Requires
    an oracle (always present in the pipeline) and a consensus result so the
    already-cached ``variance.npy`` can be reused without re-folding.
    """
    if not state.escalate:
        return False
    if state.oracle_path is None or state.consensus is None or state.hits_path is None:
        return False
    try:
        payload = json.loads(Path(state.hits_path).read_text())
    except (OSError, ValueError):
        return False
    return int(payload.get("verified_count", 0)) == 0


def _stage_escalate(state: "PipelineState") -> None:
    """Floor-free descending-variance fall-through when brute-force misses.

    Delegates to :func:`memdiver.app.tools_pipeline.auto_floor`, which
    ``np.load``s the cached ``consensus/variance.npy`` (the Theta(N*d) fold NEVER
    re-runs) and reuses the same oracle. It emits the identical ``escalate``
    stage stream + stage_end extra (``verdict`` / ``hit_tier`` / ``phi_star`` /
    ``phi0``) and writes ``verdict.json`` + ``report.md`` via
    ``app.reports.write_auto_floor_artifacts`` — the same
    ``engine.auto_floor.run_auto_floor`` compute the CLI ``auto-floor`` and
    ``POST /auto-floor`` (through :func:`run_auto_floor_stage`) use. This wrapper
    registers the two artifacts, translates cancellation, and reconstructs the
    canonical ``escalation`` summary envelope from the producer's return.
    """
    from memdiver.app import tools_pipeline

    consensus = state.consensus
    bf = state.bf_kwargs
    out_dir = state.artifact_dir / "escalate"
    verdict = _run_producer(
        tools_pipeline.auto_floor,
        variance_path=consensus["variance_path"],
        reference_path=consensus["reference_path"],
        oracle_path=str(state.oracle_path),
        # The escalate stage re-loads the SAME armed oracle the brute-force
        # stage used, so it needs the same configuration; without it a Shape-2
        # oracle would build fine in brute_force and then fail here.
        oracle_config=state.oracle_config,
        output_dir=str(out_dir),
        num_dumps=int(consensus["num_dumps"]),
        reduce_kwargs=_reduce_kwargs_without_heap(state.reduce_kwargs),
        key_sizes=tuple(bf.get("key_sizes", (32,))),
        stride=int(bf.get("stride", 1)),
        oracle_budget=state.escalate_oracle_budget,
        on_progress=_producer_sink(state.ctx),
        is_cancelled=state.ctx.is_cancelled,
    )
    register_artifact(
        state.artifacts, state.artifact_dir,
        name="escalate_verdict", relpath="escalate/verdict.json",
        media_type="application/json",
    )
    register_artifact(
        state.artifacts, state.artifact_dir,
        name="escalate_report", relpath="escalate/report.md",
        media_type="text/markdown",
    )
    # summary["escalation"] must remain the canonical escalation_verdict envelope
    # ({**AutoFloorResult.to_dict(), "hit_tier"}). The producer's return is that
    # plus an "artifacts" path map; drop it to recover the exact envelope.
    state.summary["escalation"] = {
        k: v for k, v in verdict.items() if k != "artifacts"
    }


def _default_stages() -> List[Stage]:
    """Build a fresh list of the default stages in canonical order."""
    return [
        Stage("consensus", _stage_consensus, enabled=_consensus_enabled,
              check_cancel_before=False),
        Stage("search_reduce", _stage_reduce),
        Stage("brute_force", _stage_brute_force),
        Stage("escalate", _stage_escalate, enabled=_escalate_enabled),
        Stage("nsweep", _stage_nsweep, enabled=_nsweep_enabled),
        Stage("emit_plugin", _stage_emit_plugin, enabled=_emit_enabled),
    ]


# Ordered registry the composed pipeline iterates over. Mutated by
# ``register_stage``; snapshotted by ``get_pipeline_stages``.
_STAGE_REGISTRY: List[Stage] = _default_stages()

#: Entry-point group under which out-of-tree packages advertise pipeline stages.
#: Each advertised entry point is a module (imported for its ``register_stage``
#: side effects) or a callable (invoked to self-register). See
#: ``docs/contributing/adding_pipeline_stage.md``.
STAGE_ENTRY_POINT_GROUP = "memdiver.pipeline_stages"

#: Guards one-time out-of-tree discovery so it runs at most once per process.
_ENTRY_POINTS_LOADED = False


def _load_entry_point_stages_once() -> None:
    """Load out-of-tree pipeline stages exactly once, after the defaults.

    Runs at module import so SPAWNED workers (which re-import this module under
    ``mp_context="spawn"``) also pick up out-of-tree stages — closing the known
    spawn-visibility gap where ``register_stage`` calls made only in the parent
    process never reached the workers. Additive, import-safe and
    failure-isolated: a silent no-op when nothing is installed, and a broken
    plugin can never abort import.
    """
    global _ENTRY_POINTS_LOADED  # noqa: PLW0603
    if _ENTRY_POINTS_LOADED:
        return
    _ENTRY_POINTS_LOADED = True
    try:
        from memdiver.core.plugin_discovery import load_entry_point_registrations
        load_entry_point_registrations(STAGE_ENTRY_POINT_GROUP)
    except Exception:  # noqa: BLE001 - discovery must never break module import
        logger.warning(
            "out-of-tree pipeline-stage discovery failed; using built-in "
            "stages only", exc_info=True,
        )


_load_entry_point_stages_once()


def get_pipeline_stages() -> List[Stage]:
    """Return a shallow copy of the registered stages in execution order."""
    return list(_STAGE_REGISTRY)


def register_stage(
    stage: Stage,
    *,
    index: Optional[int] = None,
    before: Optional[str] = None,
    after: Optional[str] = None,
) -> None:
    """Register ``stage`` into the ordered pipeline.

    Position may be given as an explicit ``index``, or relative to an existing
    stage's ``name`` via ``before`` / ``after``. With none supplied the stage
    is appended. At most one of ``index`` / ``before`` / ``after`` may be set.
    """
    supplied = [x for x in (index, before, after) if x is not None]
    if len(supplied) > 1:
        raise ValueError("register_stage: pass at most one of index/before/after")

    # Idempotent replace-by-name: a stage registered twice (double import,
    # plugin setup invoked twice, hot-reload) must NOT end up executing twice.
    # Drop any existing stage with the same name before (re)inserting. Mirrors
    # FormatRegistry.register()'s replace-by-name semantics.
    existing = [s for s in _STAGE_REGISTRY if s.name == stage.name]
    if existing:
        logger.debug("register_stage: replacing existing stage %r", stage.name)
        _STAGE_REGISTRY[:] = [s for s in _STAGE_REGISTRY if s.name != stage.name]

    if before is not None:
        pos = _index_of(before)
    elif after is not None:
        pos = _index_of(after) + 1
    elif index is not None:
        pos = index
    else:
        pos = len(_STAGE_REGISTRY)
    _STAGE_REGISTRY.insert(pos, stage)


def _index_of(name: str) -> int:
    for i, stage in enumerate(_STAGE_REGISTRY):
        if stage.name == name:
            return i
    raise KeyError(f"register_stage: no registered stage named {name!r}")


def _execute_stages(state: "PipelineState", stages: Sequence[Stage]) -> None:
    """Run ``stages`` in order against ``state``, preserving gating + cancel.

    A stage runs only when ``enabled(state)`` is truthy; a stage with
    ``check_cancel_before`` raises :class:`_CancelledByContext` if the context
    was cancelled before it starts. This reproduces the pre-refactor control
    flow exactly.
    """
    for stage in stages:
        if not stage.enabled(state):
            continue
        if stage.check_cancel_before and state.ctx.is_cancelled():
            raise _CancelledByContext()
        stage.run(state)


def run_pipeline(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Top-level worker entry point.

    ``params`` keys:

    * ``artifact_dir`` (str, required): per-task directory the
      TaskManager has already created for us.
    * ``source_paths`` (list[str], required): dump files to fold.
    * ``reduce_kwargs`` (dict): passed straight to
      :func:`engine.candidate_pipeline.reduce_search_space`.
    * ``oracle_path`` (str, optional): absolute path to the armed oracle
      file. ``None`` when ``pcap_path`` is supplied instead.
    * ``oracle_config`` (dict, optional): the armed oracle's already-parsed
      configuration, threaded as a dict (never a temporary TOML file). It sits
      at the top level, not inside ``brute_force``/``nsweep``, because it
      belongs to the oracle and all three oracle-loading stages (brute_force,
      nsweep, escalate) must run it with the SAME config. ``None`` for a pcap
      run or for an oracle that needs no configuration. A copy found under
      ``brute_force`` is lifted here for backward compatibility.
    * ``pcap_path`` (str, optional): pcap/pcapng of the same TLS session;
      routes the brute_force stage through the first-party trusted pcap
      oracle. Mutually exclusive with ``oracle_path``. ``tls_client_random``
      (hex) optionally restricts pcap matching to one session. The ``nsweep``
      stage runs on a pcap run too (same pcap oracle at every N); only
      ``escalate`` still needs an oracle FILE and stays off.
    * ``pcap_max_records`` / ``pcap_max_challenges`` (int, optional): pcap-oracle
      work caps (records per direction / total challenges). ``None`` keeps the
      defaults; both are silent truncations of coverage when set.
    * ``brute_force`` (dict): ``key_sizes``, ``stride``, ``jobs``,
      ``exhaustive``, ``top_k``. Splatted straight into the producer, so any
      other ``tools_pipeline.brute_force`` keyword is accepted here too.
    * ``nsweep`` (dict, optional): if present, runs the N-sweep harness
      with ``n_values``, ``reduce_kwargs``, ``key_sizes``, ``stride``,
      ``exhaustive``. The oracle config is NOT read from here — see the
      top-level ``oracle_config`` above.
    * ``emit`` (dict, optional): ``name``, ``description``, ``hit_index``,
      ``min_static_ratio``.
    * ``force_memory`` (bool, default False): bypass the consensus
      memory-budget guard (forwarded to the consensus stage as ``force=``).
      Without it an over-budget fold raises ``CapabilityError``
      ``code="memory_budget_exceeded"``, which propagates unchanged.
    * ``scudo`` (dict, optional): ``allocator`` (``"scudo"`` or ``"auto"``)
      selects the Android Scudo method instead of the positional consensus.

    Returns a dict with:

        {
          "artifacts": [<ArtifactSpec dicts>],
          "summary": { ... per-stage summary for the UI ... }
        }

    which the TaskManager reads in ``_on_success`` to publish the
    terminal ``done`` event and register artifacts onto the task record.
    """
    # The TaskManager mints a task_id inside submit() and cannot pass
    # the final artifact_dir back to the caller. The router therefore
    # passes ``task_root`` instead, and we derive the per-task dir
    # inside the worker from ``ctx.task_id``. Callers that already
    # know the absolute dir (tests) can still pass ``artifact_dir``.
    artifact_dir = resolve_artifact_dir(params, ctx)
    source_paths: List[str] = list(params["source_paths"])
    reduce_kwargs: Dict[str, Any] = dict(params.get("reduce_kwargs", {}))
    _oracle_path_raw = params.get("oracle_path")
    oracle_path = (
        Path(_oracle_path_raw).expanduser() if _oracle_path_raw else None
    )
    pcap_path = params.get("pcap_path")
    tls_client_random = params.get("tls_client_random")
    pcap_max_records = params.get("pcap_max_records")
    pcap_max_challenges = params.get("pcap_max_challenges")
    bf_kwargs: Dict[str, Any] = dict(params.get("brute_force", {}))
    # Sanitize brute_force kwargs — run_brute_force does not accept an
    # arbitrary progress_callback from params; the orchestrator supplies
    # the bridge itself.
    bf_kwargs.pop("progress_callback", None)
    bf_kwargs.pop("cancel_event", None)
    bf_kwargs.pop("state_path", None)
    # variance_threshold is threaded explicitly (from the emit params) into the
    # brute_force stage_end preview, so drop any stray copy here to avoid a
    # duplicate-keyword clash on the explicit pass.
    bf_kwargs.pop("variance_threshold", None)
    # The armed oracle's parsed configuration rides ONCE at the top level, not
    # inside a per-stage sub-dict: brute_force, nsweep and escalate all load the
    # same oracle file. A stray copy under ``brute_force`` (older callers) is
    # lifted rather than rejected, which also keeps the ``**bf_kwargs`` splat in
    # :func:`_run_brute_force` from colliding with the explicit pass.
    _bf_oracle_config = bf_kwargs.pop("oracle_config", None)
    oracle_config: Optional[Dict[str, Any]] = (
        params.get("oracle_config") or _bf_oracle_config
    )
    nsweep_params = params.get("nsweep")
    emit_params = params.get("emit")
    # Surface the emit stage's variance_threshold override (if any) so the
    # brute_force stage can emit the same resolved cutoff on its stage_end.
    _vt = (emit_params or {}).get("variance_threshold")
    variance_threshold = float(_vt) if _vt is not None else None
    escalate = bool(params.get("escalate", False))
    escalate_oracle_budget = params.get("escalate_oracle_budget")

    state = PipelineState(
        ctx=ctx,
        artifact_dir=artifact_dir,
        # An emitting list, not the plain default: every register_artifact call
        # below (there are a dozen, across every stage) then streams one live
        # ``artifact`` event to the UI instead of the artifact only surfacing in
        # the task record at completion. See app.pipeline.artifact_events.
        artifacts=EmittingArtifactList(ctx),
        source_paths=source_paths,
        region_filter=params.get("region_filter"),
        force_memory=bool(params.get("force_memory", False)),
        mixed_ok=bool(params.get("mixed_ok", False)),
        scudo_params=params.get("scudo"),
        reduce_kwargs=reduce_kwargs,
        oracle_path=oracle_path,
        oracle_config=oracle_config,
        pcap_path=pcap_path,
        tls_client_random=tls_client_random,
        pcap_max_records=pcap_max_records,
        pcap_max_challenges=pcap_max_challenges,
        bf_kwargs=bf_kwargs,
        nsweep_params=nsweep_params,
        emit_params=emit_params,
        variance_threshold=variance_threshold,
        escalate=escalate,
        escalate_oracle_budget=escalate_oracle_budget,
    )
    # A per-run reference-bytes cache so the reading stages (search_reduce /
    # brute_force / emit_plugin) share one read of the immutable consensus
    # ``reference.bin`` instead of re-opening it each. The scope drops the blob
    # on exit, so a reused pool worker never retains the previous run's bytes.
    from memdiver.app.artifact_cache import reference_cache_scope

    try:
        # Compose the registered stages (default order below) instead of an
        # inline sequence. Ordering, optional gating and per-stage cancel
        # guards are carried by the Stage objects / _execute_stages:
        #   consensus → search_reduce → brute_force
        #   → [nsweep if params.nsweep] → [emit_plugin if params.emit]
        with reference_cache_scope():
            _execute_stages(state, get_pipeline_stages())
    except _CancelledByContext:
        ctx.emit("error", error="cancelled")
        raise RuntimeError("pipeline cancelled")

    return {"artifacts": state.artifacts, "summary": state.summary}
