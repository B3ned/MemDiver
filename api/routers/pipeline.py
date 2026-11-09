"""HTTP surface for the Phase 25 end-to-end pipeline.

Single-orchestrator design: one ``POST /api/pipeline/run`` endpoint
accepts a dump list + armed oracle + reduce/brute-force/nsweep/
emit-plugin params and returns a ``task_id``. Progress streams over
``/ws/tasks/{task_id}``. Artifact metadata + stage state live on the
TaskRecord at ``GET /api/pipeline/runs/{task_id}``; individual
artifacts are downloadable at ``GET /api/pipeline/runs/{task_id}/artifacts/{name}``.

Per-stage endpoints (search-reduce / brute-force / n-sweep by
themselves) are deferred to v2 per the plan — keeping the surface
small forces the frontend to treat the pipeline as one coherent
story and avoids duplicating orchestration in TypeScript.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from memdiver.api.dependencies import (
    oracle_registry_or_503 as _oracle_registry_or_503,
    task_manager_or_503 as _task_manager_or_503,
)
from memdiver.api.services.artifact_store import (
    ArtifactNotFound,
    ArtifactStoreError,
    InvalidArtifactName,
)
from memdiver.api.services.oracle_registry import (
    OracleNotArmed,
    OracleNotFound,
    OracleRegistryError,
)
from memdiver.api.models import MemoryOverrideFields, MixedCohortFields, RegionFilterFields
from memdiver.api.region_filter_resolution import request_region_filter
from memdiver.api.services.task_manager import TERMINAL_STATUSES
from memdiver.app.pipeline.pipeline_runner import get_pipeline_stages
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine.brute_force import DEFAULT_NEIGHBORHOOD_PAD

logger = logging.getLogger("memdiver.api.routers.pipeline")

router = APIRouter()


# ------------------------------------------------------------------
# pydantic models
# ------------------------------------------------------------------


class ReduceParams(BaseModel):
    alignment: int = 8
    block_size: int = 32
    density_threshold: float = 0.5
    min_variance: float = 3000.0
    entropy_window: int = 32
    entropy_threshold: float = 4.5
    min_region: int = 16
    #: How the reduce stage treats the consensus stage's heap roles
    #: (``heap_roles.npz``; see ``engine.candidate_heap``). Forwarded to
    #: ``tools_pipeline.search_reduce``; "mask" without heap roles fails the
    #: run with a PRECONDITION error. The nsweep / escalate / auto-floor reduce
    #: paths have no heap roles and drop it (``pipeline_runner``).
    heap_policy: Literal["annotate", "mask", "off"] = "annotate"


class BruteForceParams(BaseModel):
    key_sizes: List[int] = Field(default_factory=lambda: [32])
    stride: int = 1
    # 0 = auto (engine.brute_force.resolve_jobs): serial for a small or
    # first-hit sweep, a small pool for a large exhaustive one. Explicit >0 wins.
    jobs: int = 0
    exhaustive: bool = True
    top_k: int = 10


class NSweepParams(BaseModel):
    n_values: List[int]
    reduce_kwargs: Optional[ReduceParams] = None
    key_sizes: List[int] = Field(default_factory=lambda: [32])
    stride: int = 1
    exhaustive: bool = True


class ScudoParams(BaseModel):
    """Selects the Android Scudo method for a pipeline run.

    Its own object rather than an ``allocator`` field: on the consensus routes
    ``HeapAllocatorFields.allocator="auto"`` only annotates heap roles, while
    here ``"auto"`` means the first dump must be detected as a Scudo heap.
    """

    allocator: Literal["scudo", "auto"] = "auto"


class EmitParams(BaseModel):
    name: str = "memdiver_plugin"
    description: Optional[str] = None
    hit_index: int = 0
    min_static_ratio: float = 0.3
    variance_threshold: Optional[float] = None


class RefineRequest(BaseModel):
    additional_paths: List[str] = Field(..., min_length=1)
    #: Per-side context width for the hit neighborhoods re-sliced after the
    #: fold. Imported from ``engine.brute_force`` rather than hardcoded so the
    #: web surface can never disagree with the brute-force engine about how
    #: wide an emitted window is.
    neighborhood_pad: int = Field(DEFAULT_NEIGHBORHOOD_PAD, ge=0)


class RefineResponse(BaseModel):
    num_dumps: int
    static_count: int
    dynamic_count: int
    #: The variance threshold used to classify static vs dynamic bytes
    #: (``PLUGIN_STATIC_THRESHOLD``), surfaced so callers stop hardcoding it.
    variance_threshold: float
    #: Each entry also carries a ``fields`` list (inferred field structure) so
    #: the frontend consumes it instead of recomputing ``infer_fields``.
    hit_neighborhoods: List[Dict[str, Any]]


class InferFieldsRequest(BaseModel):
    neighborhood_variance: List[float]
    neighborhood_start: int
    offset: int
    length: int
    variance_threshold: Optional[float] = None


class PipelineRunRequest(RegionFilterFields, MemoryOverrideFields, MixedCohortFields):
    source_paths: List[str] = Field(..., min_length=1)
    #: Exactly one oracle source must be supplied: an armed BYO oracle from the
    #: registry (``oracle_id``) OR a pcap/pcapng of the same TLS session
    #: (``pcap_path``), which routes the brute-force stage through MemDiver's
    #: first-party trusted pcap oracle. ``tls_client_random`` (hex) optionally
    #: restricts pcap matching to one session. ``pcap_max_records`` /
    #: ``pcap_max_challenges`` size the pcap oracle's verification work (records
    #: per direction / total challenges); ``None`` keeps the defaults, and
    #: ``POST /api/pcaps/validate`` reports the caps a capture actually loses
    #: records to (``caps`` + ``records_truncated``).
    oracle_id: Optional[str] = None
    pcap_path: Optional[str] = None
    tls_client_random: Optional[str] = None
    pcap_max_records: Optional[int] = Field(default=None, ge=1)
    pcap_max_challenges: Optional[int] = Field(default=None, ge=1)
    reduce: ReduceParams = Field(default_factory=ReduceParams)
    brute_force: BruteForceParams = Field(default_factory=BruteForceParams)
    nsweep: Optional[NSweepParams] = None
    emit: Optional[EmitParams] = None
    escalate: bool = False
    escalate_oracle_budget: Optional[int] = None
    scudo: Optional[ScudoParams] = None
    # ``region_filter`` / ``session_name`` come from ``RegionFilterFields``:
    # the analysis-time region view filter for the consensus stage
    # (``"heap,stack"``; ``.msl`` sources only), normalised to the
    # ``RegionSelection.to_note()`` form; ``None`` analyses every region, and
    # an unset field defaults to the named session's persisted filter.


class AutoFloorRunRequest(BaseModel):
    """Inputs for ``POST /api/pipeline/auto-floor`` (mirrors the CLI).

    ``variance_path`` is a ``.npy`` array (the consensus stage's
    ``consensus/variance.npy`` artifact, or any equivalent), ``reference_dump``
    is one dump whose bytes index-align with the variance, and ``oracle_id``
    names an armed BYO oracle in the registry. Optional ``passphrase`` /
    ``key_hex`` / ``kem_key_hex`` decrypt an encrypted ``.msl`` reference.
    """

    variance_path: str
    reference_dump: str
    oracle_id: str
    num_dumps: int = Field(..., ge=1)
    reduce: ReduceParams = Field(default_factory=ReduceParams)
    key_sizes: List[int] = Field(default_factory=lambda: [32])
    stride: int = 1
    coverage: Optional[float] = None
    correspondence: Optional[float] = None
    filter_recall: Optional[float] = None
    min_coverage: float = 0.80
    phi0_method: str = "pmin"
    p_min: float = 0.35
    positive_control_hex: Optional[str] = None
    passphrase: Optional[str] = None
    key_hex: Optional[str] = None
    kem_key_hex: Optional[str] = None


class PipelineRunResponse(BaseModel):
    task_id: str
    status: str
    #: ``None`` for a pcap-oracle run (there is no BYO oracle file to hash).
    oracle_sha256: Optional[str] = None


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------


def _store_task_dir(manager, task_id: str) -> Optional[Path]:
    """Return ``artifact_store.root / <task_id>`` for a task, if resolvable.

    The pipeline worker writes every stage's artifacts to
    ``artifact_store.root / <task_id>`` (see
    :func:`app.pipeline.pipeline_runner.run_pipeline`, which derives its
    ``artifact_dir`` from ``params["task_root"]`` — the artifact-store
    root — joined with ``ctx.task_id``). ``TaskRecord`` intentionally
    carries no ``artifact_dir`` field, so this is the authoritative way to
    locate a real run's output on disk. Returns ``None`` when the manager
    exposes no artifact store (e.g. a lightweight test double).
    """
    store = getattr(manager, "artifact_store", None)
    root = getattr(store, "root", None)
    if root is None:
        return None
    return Path(root) / task_id


def _task_artifact_dir_hint(task) -> Optional[Path]:
    """Extract a caller-supplied ``artifact_dir`` from the task, if any.

    Kept for backward compatibility with callers/tests that hand the
    handlers a task carrying an explicit ``artifact_dir`` (dict or object).
    Production ``TaskRecord`` objects have no such field, so this returns
    ``None`` there and the store-derived path is used instead.
    """
    if isinstance(task, dict):
        value = task.get("artifact_dir")
    else:
        value = getattr(task, "artifact_dir", None)
    return Path(value) if value else None


def _resolve_consensus_state_path(manager, task_id: str, task) -> Optional[Path]:
    """Locate the persisted ``consensus/state.json`` for a completed run.

    Resolution order:

    1. A genuine registered artifact on the ``TaskRecord`` (the consensus
       stage registers ``state.json`` under the ``consensus_state`` name /
       ``consensus/state.json`` relpath), resolved against the store's
       per-task directory.
    2. The conventional ``consensus/state.json`` under the store's per-task
       directory (``artifact_store.root / task_id``).
    3. An explicit ``artifact_dir`` hint carried on the task, for backward
       compatibility with callers that pass one directly.

    Returns ``None`` when no candidate exists on disk.
    """
    candidates: List[Path] = []

    store_dir = _store_task_dir(manager, task_id)
    if store_dir is not None:
        # 1. Derive from a registered artifact spec if present.
        for spec in getattr(task, "artifacts", []) or []:
            relpath = getattr(spec, "relpath", None)
            name = getattr(spec, "name", None)
            if name == "consensus_state" or (
                relpath
                and Path(relpath).as_posix().endswith("consensus/state.json")
            ):
                candidates.append(store_dir / relpath)
        # 2. Conventional location under the store's task dir.
        candidates.append(store_dir / "consensus" / "state.json")

    # 3. Backward-compat: an explicit artifact_dir hint on the task.
    hint = _task_artifact_dir_hint(task)
    if hint is not None:
        candidates.append(hint / "consensus" / "state.json")

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _build_worker_params(
    request: PipelineRunRequest,
    oracle_path: Optional[Path],
    task_root: Path,
    oracle_config: Optional[Dict[str, Any]] = None,
) -> dict:
    """Translate the Pydantic request into the plain-dict the worker expects.

    ``oracle_config`` is the armed registry entry's configuration, supplied by
    the caller rather than read off ``request``: it is deliberately NOT a field
    on ``PipelineRunRequest``. The config is what ``arm()`` strictly validated in
    a sandbox, so letting a client post one here would hand the worker a config
    no arm step ever checked. Taking it only from the armed entry keeps the
    arm-time validation on the path of every run.
    """
    reduce_kwargs = request.reduce.model_dump()
    bf_kwargs = request.brute_force.model_dump()
    worker: dict = {
        "task_root": str(task_root),
        "source_paths": list(request.source_paths),
        # Request value wins; otherwise the named session's persisted filter.
        "region_filter": request_region_filter(request),
        # ``oracle_path`` is ``None`` for a pcap-oracle run; the worker routes
        # the brute-force stage through the first-party trusted pcap oracle.
        "oracle_path": str(oracle_path) if oracle_path is not None else None,
        # One top-level key, not a copy inside ``brute_force`` and another
        # inside ``nsweep``: the config belongs to the oracle, and the
        # brute_force / nsweep / escalate stages all load that same oracle file.
        # ``None`` (a pcap run, or an oracle needing no config) leaves every
        # producer on its existing ``oracle_config_path`` behaviour.
        "oracle_config": dict(oracle_config) if oracle_config else None,
        "pcap_path": request.pcap_path,
        "tls_client_random": request.tls_client_random,
        "pcap_max_records": request.pcap_max_records,
        "pcap_max_challenges": request.pcap_max_challenges,
        "reduce_kwargs": reduce_kwargs,
        "brute_force": bf_kwargs,
    }
    if request.nsweep is not None:
        nsweep_dict = request.nsweep.model_dump()
        if nsweep_dict.get("reduce_kwargs") is None:
            nsweep_dict["reduce_kwargs"] = reduce_kwargs
        worker["nsweep"] = nsweep_dict
    if request.emit is not None:
        worker["emit"] = request.emit.model_dump()
    worker["escalate"] = request.escalate
    worker["escalate_oracle_budget"] = request.escalate_oracle_budget
    # Memory-budget override for the consensus stage (runner reads
    # ``params["force_memory"]`` and forwards it as the producer's ``force=``).
    worker["force_memory"] = request.force_memory
    # Cohort-mix override for the consensus + n-sweep stages (``cohort.mixed``).
    worker["mixed_ok"] = request.mixed_ok
    if request.scudo is not None:
        worker["scudo"] = request.scudo.model_dump()
    return worker


def _refuse_invalid_scudo_run(request: PipelineRunRequest) -> None:
    """Refuse a Scudo run that could not do what the request asks for.

    Everything checked here is about the positional consensus, which a Scudo
    run does not build. Silently dropping one of these options would report a
    run the caller did not ask for, so each is refused before a worker starts.
    """
    from memdiver.app.tools_pipeline_android import (
        PLUGIN_UNSUPPORTED_CODE,
        PLUGIN_UNSUPPORTED_MESSAGE,
        UNSUPPORTED_OPTION_CODE,
        _validate_scudo_dumps,
    )

    if request.emit is not None:
        raise CapabilityError(
            PLUGIN_UNSUPPORTED_MESSAGE,
            category=ErrorCategory.INVALID_INPUT,
            code=PLUGIN_UNSUPPORTED_CODE,
        )
    unsupported = [
        name
        for name, requested in (
            ("nsweep", request.nsweep is not None),
            ("escalate", request.escalate),
            ("region_filter", request_region_filter(request) is not None),
            ("reduce", bool(request.reduce.model_fields_set)),
        )
        if requested
    ]
    if unsupported:
        raise CapabilityError(
            "the Android Scudo method compares whole heap chunks and has no "
            f"positional consensus, so these options do not apply: "
            f"{', '.join(unsupported)}",
            category=ErrorCategory.INVALID_INPUT,
            code=UNSUPPORTED_OPTION_CODE,
            details={"options": unsupported},
        )
    _validate_scudo_dumps(
        request.source_paths,
        request.source_paths[0],
        request.brute_force.key_sizes,
        request.mixed_ok,
    )


# ------------------------------------------------------------------
# routes
# ------------------------------------------------------------------


@router.post("/run", response_model=PipelineRunResponse)
def run_pipeline_endpoint(request: PipelineRunRequest):
    """Submit the Phase 25 pipeline and return a task_id."""
    manager = _task_manager_or_503()

    # Exactly one oracle source: an armed BYO oracle (oracle_id) or a pcap.
    if bool(request.oracle_id) == bool(request.pcap_path):
        raise HTTPException(
            status_code=400,
            detail="provide exactly one of oracle_id or pcap_path",
        )

    oracle_path: Optional[Path] = None
    oracle_sha256: Optional[str] = None
    oracle_config: Optional[Dict[str, Any]] = None
    if request.pcap_path:
        # Existence check only, deliberately. This is a READ of a capture the
        # operator chose, which is the accepted, documented risk class for this
        # localhost API (api/main.py, handoff O-15) — and
        # docs/oracle/pcap_oracle.md documents typing a server-side path as an
        # alternative to uploading. POST /api/pcaps/validate applies the same
        # rule so the arm step and the run step cannot disagree about which
        # captures are usable. Do NOT add upload_dir containment here without
        # also changing /validate and that doc.
        if not Path(request.pcap_path).is_file():
            raise HTTPException(
                status_code=400,
                detail=f"pcap not found: {request.pcap_path}",
            )
    else:
        registry = _oracle_registry_or_503()
        try:
            entry = registry.require_armed(request.oracle_id)
        except OracleNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except OracleNotArmed as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except OracleRegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        oracle_path = entry.path
        oracle_sha256 = entry.sha256
        # The configuration the user confirmed at arm time — and that arm()
        # already replayed through the strict sandbox — travels with the run.
        # Without it a Shape-2 oracle (``build_oracle(config)`` reading a
        # required key) arms cleanly and then dies in the worker on ``{}``.
        oracle_config = entry.config

    for p in request.source_paths:
        if not Path(p).is_file():
            raise HTTPException(
                status_code=400,
                detail=f"source path not found: {p}",
            )

    if request.scudo is not None:
        _refuse_invalid_scudo_run(request)

    # Seed the UI progress stages from the real pipeline registry (in
    # execution order) rather than a hardcoded literal, so a stage added via
    # ``register_stage`` shows up in progress tracking automatically. The two
    # optional stages are gated by the same request params the runner's
    # ``Stage.enabled`` predicates check (``state.nsweep_params`` /
    # ``state.emit_params``); every other (always-enabled) stage is kept.
    optional_stage_present = {
        # A seeded stage that never runs would stay "pending" for the whole run.
        "consensus": request.scudo is None,
        "nsweep": request.nsweep is not None,
        "emit_plugin": request.emit is not None,
        "escalate": request.escalate,
    }
    stage_names = [
        stage.name
        for stage in get_pipeline_stages()
        if optional_stage_present.get(stage.name, True)
    ]

    worker_params = _build_worker_params(
        request,
        oracle_path=oracle_path,
        task_root=manager.artifact_store.root,
        oracle_config=oracle_config,
    )
    record = manager.submit(
        kind="pipeline",
        params=worker_params,
        runner_dotted="memdiver.app.pipeline.pipeline_runner.run_pipeline",
        stage_names=stage_names,
    )
    return PipelineRunResponse(
        task_id=record.task_id,
        status=record.status.value,
        oracle_sha256=oracle_sha256,
    )


@router.post("/auto-floor")
def run_auto_floor_endpoint(request: AutoFloorRunRequest):
    """Run ground-truth-free variance-floor selection and return the verdict.

    Synchronous (the oracle-arbitrated sweep is fast and single-shot): it
    resolves the armed oracle, then delegates to
    :func:`app.pipeline.pipeline_runner.run_auto_floor_stage`, which loads the
    variance ``.npy`` + reference dump and calls
    ``engine.auto_floor.run_auto_floor``. Returns the ``AutoFloorResult``
    as JSON (``verdict``, ``phi_star``, ``phi0``, ``key_hex``, sweep, …).
    """
    from memdiver.core.key_material import from_hex
    from memdiver.app.pipeline.pipeline_runner import run_auto_floor_stage

    registry = _oracle_registry_or_503()
    try:
        entry = registry.require_armed(request.oracle_id)
    except OracleNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except OracleNotArmed as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except OracleRegistryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not Path(request.variance_path).is_file():
        raise HTTPException(
            status_code=400,
            detail=f"variance array not found: {request.variance_path}",
        )
    if not Path(request.reference_dump).is_file():
        raise HTTPException(
            status_code=400,
            detail=f"reference dump not found: {request.reference_dump}",
        )

    # Mirror the CLI: auto_floor owns min_variance (it sweeps it), so pass the
    # rest of the reduce params through untouched.
    reduce_kwargs = request.reduce.model_dump()
    reduce_kwargs.pop("min_variance", None)

    try:
        positive_control = (
            bytes.fromhex(request.positive_control_hex)
            if request.positive_control_hex
            else None
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail="Invalid positive_control_hex encoding"
        ) from exc

    key_material = from_hex(
        request.passphrase, request.key_hex, request.kem_key_hex
    )

    try:
        result = run_auto_floor_stage(
            variance_path=request.variance_path,
            reference_path=request.reference_dump,
            num_dumps=request.num_dumps,
            oracle_path=str(entry.path),
            # Same gap the /run path had: ``run_auto_floor_stage`` already
            # accepts the parsed config, it was simply never handed the one the
            # arm step validated, so a Shape-2 oracle built with ``{}`` here.
            oracle_config=entry.config,
            reduce_kwargs=reduce_kwargs,
            key_sizes=request.key_sizes,
            stride=request.stride,
            coverage=request.coverage,
            correspondence=request.correspondence,
            filter_recall=request.filter_recall,
            min_coverage=request.min_coverage,
            phi0_method=request.phi0_method,
            p_min=request.p_min,
            positive_control=positive_control,
            key_material=key_material,
        )
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"oracle_sha256": entry.sha256, **result.to_dict()}


@router.get("/runs/{task_id}")
def get_run(task_id: str):
    """Return the TaskRecord for a pipeline task (stages + artifacts)."""
    manager = _task_manager_or_503()
    record = manager.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"unknown task: {task_id}")
    return record.to_dict()


@router.delete("/runs/{task_id}")
def cancel_run(task_id: str):
    """Cooperative cancel. Use DELETE for idempotent semantics."""
    manager = _task_manager_or_503()
    record = manager.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"unknown task: {task_id}")
    if record.status in TERMINAL_STATUSES:
        return {"task_id": task_id, "cancelled": False,
                "status": record.status.value}
    manager.cancel(task_id)
    return {"task_id": task_id, "cancelled": True}


@router.get("/runs/{task_id}/artifacts/{name}")
def download_artifact(task_id: str, name: str):
    """Serve a registered artifact via FileResponse, traversal-guarded."""
    manager = _task_manager_or_503()
    record = manager.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"unknown task: {task_id}")
    spec = next((a for a in record.artifacts if a.name == name), None)
    if spec is None:
        raise HTTPException(
            status_code=404,
            detail=f"artifact not found: {name}",
        )
    # Prefer the ArtifactStore's validated opener. Fall back to a
    # direct resolve against the task dir if the store does not yet
    # know about the spec (e.g. task registered artifacts via the
    # TaskManager but not the store — current worker path).
    store = manager.artifact_store
    try:
        full_path = store.open(task_id, name)
    except ArtifactNotFound:
        # Route the fallback through the store's validated resolver so it
        # enforces the same traversal *and* symlink guards as store.open()
        # — a plain resolve()+relative_to would happily serve an in-tree
        # symlink that points outside the task dir.
        try:
            full_path = store._resolve(
                task_id, spec.relpath, require_file=True
            )
        except ArtifactNotFound as exc:
            raise HTTPException(
                status_code=404, detail="artifact file missing"
            ) from exc
        except (InvalidArtifactName, ArtifactStoreError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (ArtifactStoreError, InvalidArtifactName) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return FileResponse(
        full_path,
        media_type=spec.media_type,
        filename=Path(spec.relpath).name,
    )


@router.post("/runs/{task_id}/refine", response_model=RefineResponse)
async def refine_consensus(task_id: str, body: RefineRequest):
    """Fold additional dumps into the consensus and return updated variance stats.

    Loads the persisted Welford state, folds new dumps synchronously (fast),
    saves updated state, and returns per-hit neighborhood slices.
    """
    import json

    import numpy as np

    from memdiver.app.composition import open_dump
    from memdiver.app.tools_fields import infer_fields_result
    from memdiver.core.variance import WelfordVariance
    from memdiver.engine.vol3_emit import PLUGIN_STATIC_THRESHOLD

    manager = _task_manager_or_503()
    task = manager.get(task_id)
    if task is None:
        raise HTTPException(404, f"task {task_id} not found")

    # Find the consensus state.json written by the pipeline worker under
    # the task's artifact directory (artifact_store.root / task_id).
    state_path = _resolve_consensus_state_path(manager, task_id, task)

    if state_path is None:
        raise HTTPException(
            400,
            "consensus state not found for this task "
            "— was the pipeline run completed?",
        )

    def _refine_sync() -> tuple[int, int, int, List[Dict[str, Any]]]:
        """Blocking Welford fold + numpy save I/O; run off the event loop.

        The synchronous ``np.load``/per-dump ``read_all()``/``np.save`` work
        here can take seconds on real multi-GB dumps, so it must not run inline
        in the async handler (it would stall every other request). Matches the
        ``asyncio.to_thread`` treatment already used by the dumps/consensus
        handlers. Any ``HTTPException`` raised for a bad path still propagates
        out of ``to_thread`` and is handled normally.
        """
        state = json.loads(state_path.read_text())
        mean = np.load(state["mean_path"])
        m2 = np.load(state["m2_path"])
        welford = WelfordVariance.from_state(mean, m2, int(state["num_dumps"]))

        # Validate and fold each additional dump
        for p in body.additional_paths:
            path = Path(p).expanduser()
            if not path.exists():
                raise HTTPException(400, f"dump not found: {p}")
            # A filtered consensus has filtered-view offsets: fold the new dump
            # through the SAME view filter (absent key = unfiltered, as before).
            with open_dump(path, region_filter=state.get("region_filter")) as src:
                data = src.read_all()[: welford.size]
            if len(data) < welford.size:
                continue  # skip short dumps
            welford.add_dump(data)

        # Save updated state
        new_mean, new_m2, new_n = welford.state_arrays()
        np.save(state["mean_path"], new_mean)
        np.save(state["m2_path"], new_m2)
        state["num_dumps"] = new_n
        state_path.write_text(json.dumps(state, indent=2))

        # Update variance.npy
        variance = welford.variance()
        variance_path = state_path.parent / "variance.npy"
        np.save(variance_path, variance)

        # Compute classification counts
        static_count = int(np.sum(variance <= PLUGIN_STATIC_THRESHOLD))
        dynamic_count = int(np.sum(variance > PLUGIN_STATIC_THRESHOLD))

        # Extract neighborhood slices for known hits
        hit_neighborhoods: List[Dict[str, Any]] = []
        hits_path = state_path.parent.parent / "brute_force" / "hits.json"
        if hits_path.exists():
            hits_data = json.loads(hits_path.read_text())
            for hit in hits_data.get("hits", []):
                offset = int(hit["offset"])
                length = int(hit["length"])
                nb_pad = body.neighborhood_pad
                start = max(0, offset - nb_pad)
                end = min(len(variance), offset + length + nb_pad)
                # Use the post-fold variance (welford.variance()), NOT the
                # stale pre-fold local m2 array — the new dumps were folded
                # into welford._m2, so m2[start:end]/new_n would be wrong.
                nb_var = variance[start:end].astype(np.float32).tolist()
                nb_static = sum(
                    1 for v in nb_var if v <= PLUGIN_STATIC_THRESHOLD
                )
                # Attach inferred field structure via the shared app producer so
                # the frontend consumes ``fields`` instead of recomputing it.
                fields = infer_fields_result(
                    neighborhood_variance=nb_var,
                    neighborhood_start=start,
                    offset=offset,
                    length=length,
                )
                hit_neighborhoods.append(
                    {
                        "offset": offset,
                        "neighborhood_start": start,
                        "neighborhood_variance": nb_var,
                        "static_count": nb_static,
                        "dynamic_count": len(nb_var) - nb_static,
                        "fields": fields,
                    }
                )
        return new_n, static_count, dynamic_count, hit_neighborhoods

    new_n, static_count, dynamic_count, hit_neighborhoods = await asyncio.to_thread(
        _refine_sync
    )

    return RefineResponse(
        num_dumps=new_n,
        static_count=static_count,
        dynamic_count=dynamic_count,
        variance_threshold=PLUGIN_STATIC_THRESHOLD,
        hit_neighborhoods=hit_neighborhoods,
    )


@router.post("/infer-fields")
def infer_fields_endpoint(body: InferFieldsRequest):
    """Segment an arbitrary hit's neighborhood variance into inferred fields.

    Stateless companion to the ``fields`` now embedded in ``/refine``: lets a
    caller (e.g. the hex-viewer neighborhood overlay) compute the field
    structure for any hit without a persisted run. Delegates to the shared
    ``app`` producer so the segmentation cannot fork. Also echoes the resolved
    ``variance_threshold`` so the frontend stops hardcoding
    ``PLUGIN_STATIC_THRESHOLD``.
    """
    from memdiver.app.tools_fields import infer_fields_result
    from memdiver.engine.vol3_emit import PLUGIN_STATIC_THRESHOLD

    fields = infer_fields_result(
        neighborhood_variance=body.neighborhood_variance,
        neighborhood_start=body.neighborhood_start,
        offset=body.offset,
        length=body.length,
        variance_threshold=body.variance_threshold,
    )
    threshold = (
        body.variance_threshold
        if body.variance_threshold is not None
        else PLUGIN_STATIC_THRESHOLD
    )
    return {"fields": fields, "variance_threshold": threshold}


@router.get("/runs/{task_id}/neighborhood")
async def get_neighborhood(
    task_id: str, offset: int, length: int = 32,
    neighborhood_pad: int = DEFAULT_NEIGHBORHOOD_PAD,
):
    """Return the variance slice around a specific offset from the consensus state.

    ``neighborhood_pad`` is the per-side context width; it defaults to
    ``engine.brute_force.DEFAULT_NEIGHBORHOOD_PAD`` so this endpoint returns
    exactly the window ``brute-force`` would have attached to a hit.
    """
    import json

    import numpy as np

    if neighborhood_pad < 0:
        raise HTTPException(400, "neighborhood_pad must be >= 0")

    manager = _task_manager_or_503()
    task = manager.get(task_id)
    if task is None:
        raise HTTPException(404, f"task {task_id} not found")

    state_path = _resolve_consensus_state_path(manager, task_id, task)
    if state_path is None:
        raise HTTPException(400, "consensus state not found")

    state = json.loads(state_path.read_text())
    n = int(state["num_dumps"])
    if n == 0:
        return {
            "offset": offset,
            "length": length,
            "variance": [],
            "num_dumps": 0,
        }

    m2 = np.load(state["m2_path"], mmap_mode="r")
    nb_pad = neighborhood_pad
    start = max(0, offset - nb_pad)
    end = min(len(m2), offset + length + nb_pad)
    variance_slice = (
        m2[start:end].astype(np.float32) / float(n)
    ).tolist()

    return {
        "offset": offset,
        "neighborhood_start": start,
        "num_dumps": n,
        "variance": variance_slice,
    }
