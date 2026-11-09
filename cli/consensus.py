"""Consensus (region-report + incremental Welford session) CLI commands, extracted from cli.main (P3.1)."""

import argparse
import json
import logging
import sys
from pathlib import Path

from ._shared import (
    _key_material_from_args,
    _resolve_dump_paths,
    _warn_tag_status,
    _write_output,
    force_memory_requested,
    keylog_spec_from_args,
)
from .heap_report import report_consensus_heap, report_session_heap_record

logger = logging.getLogger("memdiver.cli")


def add_region_filter_arguments(parser: argparse.ArgumentParser) -> None:
    """Register ``--regions`` / ``--exclude-regions`` on a consensus parser.

    The analysis-time region VIEW filter (non-destructive; ``.msl`` only): the
    dumps are analysed as if only the selected region categories existed.
    Offsets in the output are then FILTERED-VIEW offsets, and the output
    carries ``region_filter`` so a reader knows it.
    """
    parser.add_argument(
        "--regions", default=None,
        help="Analyse only these region categories (e.g. 'heap,stack', "
             "'all'); .msl inputs only. Offsets become filtered-view offsets.")
    parser.add_argument(
        "--exclude-regions", default=None,
        help="Exclude these region categories (e.g. 'image'); combinable "
             "with --regions.")


def region_filter_from_args(args: argparse.Namespace) -> "str | None":
    """``--regions`` / ``--exclude-regions`` -> ``to_note()`` string or None.

    Read with ``getattr`` so a parser that never registered the flags (see
    :func:`add_region_filter_arguments`) keeps the unfiltered behaviour.
    Raises ``ValueError`` on an unknown category name.
    """
    from memdiver.core.region_view_filter import region_filter_note
    from memdiver.msl.region_select import parse_selection

    selection = parse_selection(
        getattr(args, "regions", None), getattr(args, "exclude_regions", None))
    return region_filter_note(selection)


def _region_filter_or_exit(args: argparse.Namespace) -> "tuple[bool, str | None]":
    """Parse the region flags; ``(False, None)`` after printing a bad spec."""
    try:
        return True, region_filter_from_args(args)
    except ValueError as exc:
        print(f"Invalid region selection: {exc}", file=sys.stderr)
        return False, None


def _warn_alignment_diagnostics(diagnostics) -> None:
    """Print structured alignment diagnostics to stderr for a human reader.

    The JSON on stdout carries them verbatim (``diagnostics`` /
    ``alignment.diagnostics``); this is the line an operator actually sees.
    """
    for diagnostic in diagnostics or ():
        print(f"warning [{diagnostic['code']}]: {diagnostic['message']}",
              file=sys.stderr)
        remedy = (diagnostic.get("details") or {}).get("remedy")
        if remedy:
            print(f"  hint: {remedy}", file=sys.stderr)


def _payload_alignment_diagnostics(payload: dict) -> list:
    """``alignment.diagnostics`` of a producer payload (``[]`` when absent)."""
    return list((payload.get("alignment") or {}).get("diagnostics") or [])


def _cmd_consensus(args: argparse.Namespace) -> int:
    """Build consensus matrix from dump files and output region analysis.

    NOTE(single-source): the CLI ``consensus`` command is a REGION-REPORT
    surface (volatile/static/aligned regions + optional convergence), distinct
    from the pipeline-origination ``app.tools_pipeline.consensus`` producer the
    MCP ``consensus`` tool uses (which writes ``variance.npy`` / ``reference.bin``
    to feed ``search_reduce``). Both already share the ONE compute leaf,
    ``engine.consensus_service.build_consensus`` (called below with the same
    key-material + ``on_source`` contract), so there is no forked orchestration
    to collapse here — only the per-surface region/artifact shaping differs.
    """
    from memdiver.engine.cohorts import require_single_cohort
    from memdiver.engine.consensus_service import build_consensus

    dump_paths = _resolve_dump_paths(args.dumps)

    if len(dump_paths) < 2:
        print(f"Need at least 2 dumps, got {len(dump_paths)}", file=sys.stderr)
        return 1

    ok, region_filter = _region_filter_or_exit(args)
    if not ok:
        return 2
    cohort = require_single_cohort(
        [str(p) for p in dump_paths], mixed_ok=getattr(args, "mixed_ok", False))
    logger.info("Building consensus from %d dumps", len(dump_paths))
    key_material = _key_material_from_args(args)
    # build_consensus opens each dump as a context-managed source, warns on
    # tag status per source (the on_source hook, in order) while they are all
    # live, builds the vector, then closes the sources — cm retains its own
    # copies of variance/reference_bytes for the region shaping below.
    cm = build_consensus(
        dump_paths,
        normalize=args.normalize,
        key_material=key_material,
        on_source=_warn_tag_status,
        region_filter=region_filter,
        force=force_memory_requested(args),
        allocator=getattr(args, "allocator", "auto"),
    )

    min_len = args.min_length
    volatile = cm.get_volatile_regions(min_length=min_len)
    static = cm.get_static_regions(min_length=min_len)

    result = {
        "cohort": cohort,
        "num_dumps": cm.num_dumps,
        "size": cm.size,
        "classification_counts": cm.classification_counts(),
        "volatile_regions": [
            {"start": r.start, "end": r.end, "length": r.end - r.start,
             "mean_variance": round(float(r.mean_variance), 2), "classification": r.classification}
            for r in volatile
        ],
        "static_regions": [
            {"start": r.start, "end": r.end, "length": r.end - r.start,
             "mean_variance": 0.0, "classification": r.classification}
            for r in static
        ],
    }
    if cm.region_filter is not None:
        # Offsets above are filtered-view offsets; say so (additive key, so
        # an unfiltered report is byte-identical to before).
        result["region_filter"] = cm.region_filter
    # Additive: how the dumps were aligned plus its structured notes (e.g.
    # ``classification_basis_mixed``), hoisted like POST /consensus does.
    result["alignment"] = cm.alignment_report.to_dict()
    result["diagnostics"] = cm.alignment_report.diagnostic_dicts
    _warn_alignment_diagnostics(result["diagnostics"])
    if cm.heap is not None:
        # Additive, shaped like the pipeline consensus.json "heap" block; absent
        # under --allocator off so that report is byte-identical to before.
        result["heap"] = {"status": cm.heap.status, **cm.heap.to_dict()}
    report_consensus_heap(cm.heap)

    # Alignment filtering
    if args.align:
        aligned = cm.get_aligned_candidates(
            block_size=args.block_size,
            alignment=args.alignment_bytes,
            density_threshold=args.density,
        )
        result["aligned_candidates"] = [
            {"start": r.start, "end": r.end, "length": r.end - r.start,
             "mean_variance": round(float(r.mean_variance), 2)}
            for r in aligned
        ]

    # Convergence sweep
    if args.convergence:
        from memdiver.engine.convergence import run_convergence_sweep
        from memdiver.engine.serializer import serialize_convergence_result
        sweep = run_convergence_sweep(
            dump_paths,
            max_fp=args.max_fp,
            force=force_memory_requested(args),
        )
        result["convergence"] = serialize_convergence_result(sweep)

    _write_output(result, args.output)
    return 0


def _consensus_state_paths(state_path: Path) -> "tuple[Path, Path]":
    stem = state_path.with_suffix("")
    return stem.with_suffix(".mean.npy"), stem.with_suffix(".m2.npy")


def _load_welford_session(state_path: Path):
    """Load persisted incremental-consensus state from disk."""
    import numpy as np

    from memdiver.core.variance import WelfordVariance

    state = json.loads(state_path.read_text())
    mean = np.load(state["mean_path"])
    m2 = np.load(state["m2_path"])
    welford = WelfordVariance.from_state(mean, m2, int(state["num_dumps"]))
    return state, welford


# --------------------------------------------------------------------------
# Session-kind discriminant (generic Welford vs. Android Scudo collect)
# --------------------------------------------------------------------------

#: The two persisted consensus-session kinds.
STATE_MODE_WELFORD = "welford"
STATE_MODE_SCUDO = "scudo"


def _consensus_state_mode(state: dict) -> str:
    """Which pipeline a persisted consensus state belongs to.

    The generic (Welford) state carries ``mean_path``/``m2_path`` and a fixed
    ``size``; the Android Scudo collect state carries an ``allocator`` and a
    ``dump_paths`` list and no Welford arrays. Exactly one discriminator is
    present in a well-formed state.
    """
    from memdiver.core.service_errors import CapabilityError, ErrorCategory

    if "mean_path" in state:
        return STATE_MODE_WELFORD
    if state.get("allocator") or "dump_paths" in state:
        return STATE_MODE_SCUDO
    raise CapabilityError(
        "consensus state is neither a generic (Welford) session (no mean_path) "
        "nor an Android Scudo session (no allocator/dump_paths); re-create it "
        "with consensus-begin",
        category=ErrorCategory.INVALID_INPUT,
        code="consensus.state_unrecognized")


def _load_consensus_state(state_path: Path) -> "tuple[str, dict]":
    """``(mode, state)`` for a persisted consensus session.

    The ONE place that knows the state-shape discriminant; every consensus
    command dispatches on the returned mode. The Welford arrays are NOT loaded
    here (the Scudo branch never needs them) -- the Welford branch loads them
    with :func:`_load_welford_session` as before.
    """
    state = json.loads(Path(state_path).read_text())
    return _consensus_state_mode(state), state


def _cmd_consensus_begin(args: argparse.Namespace) -> int:
    """Create a new consensus session persisted on disk.

    Two session kinds, chosen at begin:

    * ``--size N`` -> the generic (Welford) session: a fixed-width variance
      accumulator folded one dump at a time by consensus-add.
    * ``--allocator scudo`` / ``--allocator auto`` (no ``--size``) -> the
      Android Scudo collect session. Scudo chunk alignment is cohort-global
      (every dump is needed at once), so it cannot be folded incrementally;
      consensus-add only records each dump's path and search-reduce aligns them.
      ``scudo`` forces the Scudo path; ``auto`` defers to memdiver's allocator
      detection on the reference at search-reduce time.

    ``--size`` and ``--allocator scudo`` are mutually exclusive (a Scudo session
    has no fixed consensus width).
    """
    from memdiver.core.service_errors import CapabilityError, ErrorCategory

    allocator = getattr(args, "allocator", None)
    size = getattr(args, "size", None)

    if size is not None:
        if allocator == "scudo":
            raise CapabilityError(
                "--size and --allocator scudo are mutually exclusive: the "
                "Scudo pipeline aligns heap chunks across all dumps at "
                "search-reduce time and has no fixed consensus width. Use "
                "--size for the generic (Welford) pipeline, or --allocator "
                "scudo on its own for the Scudo pipeline.",
                category=ErrorCategory.INVALID_INPUT,
                code="consensus.size_allocator_xor")
        return _consensus_begin_welford(args)

    # No --size: a Scudo collect session, which needs an explicit Scudo-family
    # allocator (the generic pipeline is the one that needs --size).
    if allocator in ("scudo", "auto"):
        return _consensus_begin_scudo(args, allocator)
    if allocator is None:
        raise CapabilityError(
            "consensus-begin needs either --size (the generic Welford "
            "pipeline) or --allocator scudo / --allocator auto (the Android "
            "Scudo pipeline).",
            category=ErrorCategory.INVALID_INPUT,
            code="consensus.mode_required")
    raise CapabilityError(
        f"--allocator {allocator} without --size is not a Scudo session; the "
        "Scudo pipeline reduces Scudo heaps only, so pass --allocator scudo "
        "(force) or --allocator auto (detect on the reference), or add --size "
        "for the generic (Welford) pipeline.",
        category=ErrorCategory.INVALID_INPUT,
        code="consensus.bad_scudo_allocator")


def _consensus_begin_welford(args: argparse.Namespace) -> int:
    """Create a generic (Welford) incremental consensus session on disk."""
    import numpy as np

    from memdiver.app.welford_heap import begin_session_heap, reset_session_heap_dir
    from memdiver.engine.cohorts import require_single_cohort

    state_path = Path(args.state)
    mean_path, m2_path = _consensus_state_paths(state_path)
    # Cohort guard: the dumps named at begin (optional) fix the session's cohort.
    cohort = require_single_cohort(
        [str(p) for p in (getattr(args, "dumps", None) or [])],
        mixed_ok=getattr(args, "mixed_ok", False))
    state_path.parent.mkdir(parents=True, exist_ok=True)

    mean = np.zeros(args.size, dtype=np.float32)
    m2 = np.zeros(args.size, dtype=np.float32)
    np.save(mean_path, mean)
    np.save(m2_path, m2)
    state = {
        "size": args.size,
        "num_dumps": 0,
        "mean_path": str(mean_path),
        "m2_path": str(m2_path),
    }
    if cohort is not None:
        state["cohort"] = cohort
    # Hand-built Namespaces without --allocator keep the historical state; None
    # is the parser's "flag omitted", which records heap roles as auto.
    allocator = getattr(args, "allocator", "off")
    begin_session_heap(state, "auto" if allocator is None else allocator)
    # A reused --state path must not merge projections of a previous session.
    reset_session_heap_dir(state_path)
    state_path.write_text(json.dumps(state, indent=2))
    print(f"Begun consensus session: size={args.size} state={state_path}")
    return 0


def _consensus_begin_scudo(args: argparse.Namespace, allocator: str) -> int:
    """Create an Android Scudo collect session on disk.

    Records only the cohort of any dumps named at begin (as the Welford path
    does) and an empty ``dump_paths`` list; consensus-add appends to it. No
    Welford arrays and no ``size`` -- Scudo alignment is cohort-global and
    happens at search-reduce. ``allocator`` is ``scudo`` (forced) or ``auto``
    (detected on the reference at search-reduce via memdiver's allocator
    detection).
    """
    from memdiver.engine.cohorts import require_single_cohort

    state_path = Path(args.state)
    cohort = require_single_cohort(
        [str(p) for p in (getattr(args, "dumps", None) or [])],
        mixed_ok=getattr(args, "mixed_ok", False))
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "allocator": allocator,
        "num_dumps": 0,
        "dump_paths": [],
    }
    if cohort is not None:
        state["cohort"] = cohort
    state_path.write_text(json.dumps(state, indent=2))
    print(f"Begun Scudo consensus session (allocator={allocator}): "
          f"state={state_path}")
    return 0


def _cohort_of_prefolded(state: dict, args: argparse.Namespace) -> "str | None":
    """Cohort of dumps already folded into a session that recorded no cohort.

    A session that predates cohort recording must not adopt the next dump's
    cohort silently. With listed folded paths (``dump_paths``) their cohort is
    computed (``require_single_cohort``); without them the add is refused unless
    ``--mixed-ok``. An empty session (``num_dumps == 0``) returns ``None``.
    """
    from memdiver.core.service_errors import CapabilityError, ErrorCategory
    from memdiver.engine.cohorts import require_single_cohort

    mixed_ok = getattr(args, "mixed_ok", False)
    if int(state.get("num_dumps", 0)) <= 0:
        return None
    folded = [str(p) for p in (state.get("dump_paths") or [])]
    if folded:
        return require_single_cohort(folded, mixed_ok=mixed_ok)
    if mixed_ok:
        return None
    raise CapabilityError(
        "State predates cohort recording and already folded "
        f"{int(state['num_dumps'])} dump(s) of unknown cohort; re-run "
        "consensus-begin or pass --mixed-ok.",
        category=ErrorCategory.INVALID_INPUT, code="cohort.unknown_state",
        details={"num_dumps": int(state["num_dumps"])})


def _guard_add_cohort(state: dict, args: argparse.Namespace) -> None:
    """Refuse (``cohort.mixed``) a dump whose cohort differs from the session's.

    A dump without a cohort never refuses; a session with no recorded cohort
    adopts the first known one (written into ``state``, saved by the caller).
    ``--mixed-ok`` skips the refusal but still never rewrites a recorded cohort.
    """
    from memdiver.core.service_errors import CapabilityError, ErrorCategory
    from memdiver.engine.cohorts import cohort_of

    dump_cohort = cohort_of(str(args.dump))
    if dump_cohort is None:
        return
    recorded = state.get("cohort")
    if recorded is None:
        recorded = _cohort_of_prefolded(state, args)
    if recorded is None:
        state["cohort"] = dump_cohort
    elif recorded != dump_cohort and not getattr(args, "mixed_ok", False):
        raise CapabilityError(
            f"Dump {args.dump} belongs to cohort {dump_cohort!r} but this "
            f"incremental consensus session is for cohort {recorded!r}; "
            "different conditions must not be merged into one variance "
            "accumulator. Use a dump of the same cohort, or pass --mixed-ok.",
            category=ErrorCategory.INVALID_INPUT, code="cohort.mixed",
            details={"session_cohort": recorded, "dump_cohort": dump_cohort})


def _cmd_consensus_add(args: argparse.Namespace) -> int:
    """Fold or collect one dump into an existing consensus session.

    Dispatches on the session kind: a generic (Welford) session folds the dump
    into its variance accumulator; a Scudo collect session only records the
    dump's path (Scudo alignment is cohort-global and deferred to
    search-reduce).
    """
    mode, state = _load_consensus_state(Path(args.state))
    if mode == STATE_MODE_SCUDO:
        return _consensus_add_scudo(state, Path(args.state), args)
    return _consensus_add_welford(args)


def _consensus_add_welford(args: argparse.Namespace) -> int:
    """Fold one dump into a generic (Welford) incremental consensus session."""
    import numpy as np

    from memdiver.app.composition import open_dump
    from memdiver.app.welford_heap import record_dump_heap

    state_path = Path(args.state)
    state, welford = _load_welford_session(state_path)
    size = int(state["size"])
    _guard_add_cohort(state, args)

    with open_dump(Path(args.dump), **_key_material_from_args(args)) as source:
        _warn_tag_status(source)
        data = source.read_all()[:size]
        heap_record = None
        if len(data) >= size:   # project while the dump is open
            heap_record = record_dump_heap(state, state_path, source, size,
                                           index=int(state["num_dumps"]))
    report_session_heap_record(heap_record)
    if len(data) < size:
        print(
            f"Dump shorter than consensus size ({len(data)} < {size})",
            file=sys.stderr,
        )
        return 1
    if not data.strip(b"\x00"):
        logger.warning(
            "Folded dump %s is entirely zero bytes — consensus may be meaningless",
            args.dump,
        )
    welford.add_dump(data)

    new_mean, new_m2, new_n = welford.state_arrays()
    np.save(state["mean_path"], new_mean)
    np.save(state["m2_path"], new_m2)
    state["num_dumps"] = new_n
    state_path.write_text(json.dumps(state, indent=2))

    current = welford.variance()
    print(
        f"[{new_n}] mean_var={float(current.mean()):.2f} "
        f"max_var={float(current.max()):.2f}"
    )
    return 0


def _consensus_add_scudo(state: dict, state_path: Path,
                         args: argparse.Namespace) -> int:
    """Record one dump's path in a Scudo collect session.

    No heap read and no fold: Scudo chunk alignment needs every dump at once, so
    search-reduce does the work. The cohort guard (meta.json only, no heap read)
    still runs, so a dump from another experiment cohort is refused here before
    it can silently join the set.
    """
    dump = Path(args.dump)
    if not dump.is_file():
        print(f"Dump not found: {args.dump}", file=sys.stderr)
        return 1
    _guard_add_cohort(state, args)
    state.setdefault("dump_paths", []).append(str(dump))
    state["num_dumps"] = int(state.get("num_dumps", 0)) + 1
    state_path.write_text(json.dumps(state, indent=2))
    print(f"[{state['num_dumps']}] collected {dump.name}")
    return 0


def _cmd_consensus_finalize(args: argparse.Namespace) -> int:
    """Materialize a session's summary report.

    Generic (Welford) sessions report variance + classification counts; Scudo
    collect sessions report the collected set (the candidate reduction itself is
    search-reduce's job, which needs a reference dump).
    """
    mode, state = _load_consensus_state(Path(args.state))
    if mode == STATE_MODE_SCUDO:
        return _consensus_finalize_scudo(state, args)
    return _consensus_finalize_welford(args)


def _consensus_finalize_welford(args: argparse.Namespace) -> int:
    """Materialize variance + classifications from a persisted session."""
    from memdiver.app.welford_heap import session_heap_summary
    from memdiver.core.variance import classify_variance, count_classifications

    state_path = Path(args.state)
    state, welford = _load_welford_session(state_path)
    size = int(state["size"])

    variance = welford.variance()
    classifications = classify_variance(variance)
    counts = count_classifications(classifications)

    result = {
        "num_dumps": welford.num_dumps,
        "size": size,
        "classification_counts": counts,
        "variance_summary": {
            "mean": float(variance.mean()),
            "max": float(variance.max()),
            "min": float(variance.min()),
        },
    }
    heap_summary = session_heap_summary(state)
    if heap_summary is not None:
        result["heap"] = heap_summary
    _write_output(result, args.output)
    return 0


def _consensus_finalize_scudo(state: dict, args: argparse.Namespace) -> int:
    """Report an Android Scudo collect session's contents.

    Scudo chunk alignment is cohort-global and needs a reference dump to pick
    per-run chunks, which search-reduce supplies; finalize therefore reports
    only what has been collected (allocator, cohort, the dump paths). Run
    ``search-reduce --state <this> --reference-dump <one of them> -o
    candidates.json`` to produce the candidates.
    """
    dump_paths = list(state.get("dump_paths") or [])
    result = {
        "mode": STATE_MODE_SCUDO,
        "allocator": state.get("allocator", "scudo"),
        "num_dumps": int(state.get("num_dumps", len(dump_paths))),
        "dump_paths": dump_paths,
    }
    if state.get("cohort") is not None:
        result["cohort"] = state["cohort"]
    _write_output(result, args.output)
    return 0


def _cmd_consensus_window(args: argparse.Namespace) -> int:
    """Read ONE window in every dump at the address the consensus aligned.

    The terminal sibling of ``POST /api/analysis/consensus/aligned-window`` and
    the MCP ``aligned_window`` tool — the same
    ``app.tools_consensus.aligned_window_result`` producer, so the slab -> VA ->
    navigable-offset arithmetic exists in exactly one place and the CLI cannot
    grow a second, differently-wrong copy of it.

    The decrypt flags apply to EVERY dump here (one process, one operator, one
    keyring is the terminal case); the per-dump ``key_material_by_path``
    channel the producer takes is exercised by the web and MCP surfaces, where
    a request really can mix differently-keyed containers.
    """
    from memdiver.app.composition import build_tool_session, has_key_material
    from memdiver.app.tools_consensus import aligned_window_result

    dump_paths = _resolve_dump_paths(args.dumps)
    if args.classify and len(dump_paths) < 2:
        print(f"Need at least 2 dumps, got {len(dump_paths)}", file=sys.stderr)
        return 1

    ok, region_filter = _region_filter_or_exit(args)
    if not ok:
        return 2
    key_material = _key_material_from_args(args)
    by_path = (
        {str(p): key_material for p in dump_paths}
        if has_key_material(key_material) else None
    )

    result = aligned_window_result(
        build_tool_session(),
        dump_paths=[str(p) for p in dump_paths],
        anchor_path=args.anchor_dump,
        anchor_view=args.view,
        offset=args.offset,
        slab_offset=args.slab_offset,
        length=args.length,
        normalize=args.normalize,
        classify=args.classify,
        include_bytes=not args.no_bytes,
        key_material_by_path=by_path,
        region_filter=region_filter,
        force=force_memory_requested(args),
        allocator=getattr(args, "allocator", "auto"),
        mixed_ok=getattr(args, "mixed_ok", False),
    )
    _warn_alignment_diagnostics(_payload_alignment_diagnostics(result.payload))
    _write_output(result.payload, args.output)
    return 0


def _cmd_consensus_regions(args: argparse.Namespace) -> int:
    """List EVERY occurrence of a consensus class, paginated and jumpable.

    The terminal sibling of ``POST /api/analysis/consensus/regions`` and the
    MCP ``consensus_regions`` tool — the same
    ``app.tools_consensus.class_regions_result`` producer, so the slab -> VA ->
    navigable-offset arithmetic exists in exactly one place.

    ``--classes`` omitted is the NON-INVARIANT UNION, not "key_candidate": real
    key material is class-MIXED (a measured 48-byte TLS 1.2 secret is 22
    KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL bytes), so a per-class query
    shatters a real secret into shards no ``--min-length`` keeps.

    The decrypt flags apply to the anchor dump here (one process, one operator,
    one keyring is the terminal case); the per-dump ``key_material_by_path``
    channel the producer takes is exercised by the web and MCP surfaces.
    """
    from memdiver.app.composition import build_tool_session, has_key_material
    from memdiver.app.tools_consensus import class_regions_result

    dump_paths = _resolve_dump_paths(args.dumps)
    if len(dump_paths) < 2:
        print(f"Need at least 2 dumps, got {len(dump_paths)}", file=sys.stderr)
        return 1

    ok, region_filter = _region_filter_or_exit(args)
    if not ok:
        return 2
    key_material = _key_material_from_args(args)
    by_path = (
        {str(p): key_material for p in dump_paths}
        if has_key_material(key_material) else None
    )

    result = class_regions_result(
        build_tool_session(),
        dump_paths=[str(p) for p in dump_paths],
        classes=args.classes,
        min_length=args.min_length,
        max_length=args.max_length,
        sort=args.sort,
        after=args.after,
        limit=args.limit,
        anchor_path=args.anchor_dump,
        anchor_view=args.view,
        include_anchor_offsets=not args.no_anchor_offsets,
        normalize=args.normalize,
        key_material_by_path=by_path,
        region_filter=region_filter,
        force=force_memory_requested(args),
        allocator=getattr(args, "allocator", "auto"),
        mixed_ok=getattr(args, "mixed_ok", False),
    )
    _warn_alignment_diagnostics(_payload_alignment_diagnostics(result.payload))
    _write_output(result.payload, args.output)
    return 0


def _anchor_specs_from_args(args: argparse.Namespace, dump_paths: list):
    """``(anchors, needles)`` from ``--anchor PATH=VA`` / ``--needle`` / ``--needle-file``."""
    if args.anchor:
        specs = []
        for item in args.anchor:
            path, _, va = item.rpartition("=")
            specs.append({"dump_path": path, "va": int(va, 0)})
        return specs, None
    if args.needle_file:
        raw = json.loads(Path(args.needle_file).read_text())
        return None, {str(k): str(v) for k, v in raw.items()}
    if args.needle:
        return None, {str(p): args.needle for p in dump_paths}
    return None, None


def _cmd_consensus_anchor(args: argparse.Namespace) -> int:
    """Anchor-relative consensus; the sibling of ``POST /consensus/anchor``."""
    from memdiver.app.composition import build_tool_session
    from memdiver.app.tools_consensus import anchor_consensus_result
    from memdiver.core.service_errors import CapabilityError

    dump_paths = [str(p) for p in _resolve_dump_paths(args.dumps)]
    anchors, needles = _anchor_specs_from_args(args, dump_paths)
    try:
        result = anchor_consensus_result(
            build_tool_session(), dump_paths=dump_paths, anchors=anchors,
            needles=needles, occurrence=args.occurrence,
            delta_start=args.delta_start, length=args.length,
            min_instances=args.min_instances, include_bytes=args.include_bytes,
            mixed_ok=getattr(args, "mixed_ok", False),
            keylog=keylog_spec_from_args(args),
            anchor_label=args.anchor_label, related_labels=args.related_labels)
    except (CapabilityError, OSError, ValueError) as exc:
        print(f"memdiver: {exc}", file=sys.stderr)
        return 1
    _write_output(result.payload, args.output)
    return 0
