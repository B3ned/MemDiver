"""``search-reduce`` Scudo mode -- reduce Android Scudo heap dumps.

``search-reduce`` normally turns a POSITIONAL consensus (a finalized Welford
``--state``) into ``candidates.json``, the region list ``brute-force`` walks.
Across Android cold boots a positional consensus does not line up -- Scudo
re-places every heap chunk each run (see
:mod:`memdiver.engine.scudo_candidates`) -- so this producer backs
``search-reduce`` for a Scudo session instead: it builds the chunk-signature
consensus (:func:`~memdiver.engine.scudo_chunk_consensus.build_chunk_consensus`,
content alignment on), gives every chunk of ONE reference dump a verdict
(:func:`~memdiver.engine.scudo_candidates.classify_chunks`) and writes the kept
chunks as ``candidates.json`` in the reference's flat ``"vas"`` view: the
coordinates ``brute-force --dump <reference>`` slices its windows from.

The ``search-reduce`` command reaches it through the kind of its ``--state``
session and the web pipeline through a run's ``scudo`` params; it is registered
as ``pipeline.search_reduce_android`` in :mod:`memdiver.app.capabilities`.

The chain it completes::

    memslicer <package> -U ...                                   # N cold-boot runs
    memdiver consensus-begin --state s.json --allocator scudo
    memdiver consensus-add --state s.json runs/r1.msl            # once per run
    memdiver search-reduce --state s.json --reference-dump runs/r1.msl -o c1.json
    memdiver brute-force --candidates c1.json --dump runs/r1.msl --pcap r1.pcap \\
        --key-sizes 48 --stride 1 -o hits1.json

Every emitted region is checked against the bytes the consensus judged, so an
offset can never silently name other bytes: the chunk's VA is translated with
:meth:`~memdiver.core.dump_source.MslDumpSource.va_to_vas_offset`, the chunk
must lie in the stream in one piece, and the bytes read back at that offset
must be the chunk's own. A reference whose container is truncated is refused
outright: ``brute-force`` reads the reference through ``read_all()``, which
concatenates only the bytes each captured run really holds, so behind a short
run its offsets and ``va_to_vas_offset``'s nominal ones part ways.

Inputs are refused, not guessed around, when the answer would otherwise be
silently wrong: a dump given twice (it would see its own per-run secret "in
another run" and drop it), a reference that is not one of the dumps, fewer than
two dumps, a non-``.msl`` input, a locked encrypted dump, mixed cohorts.
"""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from memdiver.core.service_errors import (
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
    UnsupportedFormatError,
)
from memdiver.core.service_result import Diagnostic, Severity

from ._progress import _emit, _experiment_check_cancelled
from .key_material import has_key_material, key_material_kwargs
from .tools_consensus import _single_cohort
from .tools_pipeline import _dump_json, _ensure_dir

logger = logging.getLogger("memdiver.app.tools_pipeline_android")

__all__ = [
    "CANDIDATES_FILENAME",
    "CANDIDATES_EMPTY_CODE",
    "CANDIDATES_SKIPPED_CODE",
    "DUMP_NOT_FOUND_CODE",
    "DUPLICATE_DUMPS_CODE",
    "INVALID_KEY_SIZES_CODE",
    "NOT_JUDGED_CODE",
    "NOT_MSL_CODE",
    "PLUGIN_UNSUPPORTED_CODE",
    "PLUGIN_UNSUPPORTED_MESSAGE",
    "REFERENCE_NOT_IN_DUMPS_CODE",
    "REFERENCE_TRUNCATED_CODE",
    "SCOPE_FALLBACK_CODE",
    "SCUDO_SOURCE",
    "TOO_FEW_DUMPS_CODE",
    "UNSUPPORTED_OPTION_CODE",
    "WRONG_ALLOCATOR_CODE",
]

#: Name of the artifact written into ``output_dir`` -- the same file name
#: ``search_reduce`` writes, because it is the same contract.
CANDIDATES_FILENAME = "candidates.json"

#: ``source`` stamped into the artifact, so a reader can tell a Scudo-mode
#: ``search-reduce`` output from a positional (Welford) ``search-reduce`` one.
SCUDO_SOURCE = "search-reduce:scudo"

# Refusals (CapabilityError.code) and diagnostics (Diagnostic.code). Stable
# strings in the ``scudo.`` namespace.
TOO_FEW_DUMPS_CODE = "scudo.too_few_dumps"
DUMP_NOT_FOUND_CODE = "scudo.dump_not_found"
DUPLICATE_DUMPS_CODE = "scudo.duplicate_dumps"
NOT_MSL_CODE = "scudo.not_msl"
REFERENCE_NOT_IN_DUMPS_CODE = "scudo.reference_not_in_dumps"
REFERENCE_TRUNCATED_CODE = "scudo.reference_truncated"
INVALID_KEY_SIZES_CODE = "scudo.invalid_key_sizes"
CANDIDATES_EMPTY_CODE = "scudo.candidates_empty"
CANDIDATES_SKIPPED_CODE = "scudo.candidates_skipped"
NOT_JUDGED_CODE = "scudo.not_judged"
SCOPE_FALLBACK_CODE = "scudo.scope_fallback"
#: The reference is not a Scudo heap (``--allocator`` named a non-Scudo
#: allocator, or ``auto`` detected one): a Scudo session reduces Scudo heaps only.
WRONG_ALLOCATOR_CODE = "scudo.wrong_allocator"
PLUGIN_UNSUPPORTED_CODE = "scudo.plugin_unsupported"
UNSUPPORTED_OPTION_CODE = "scudo.unsupported_option"

#: The web UI repeats this sentence from its locale file, because its form has
#: to say so before any request.
PLUGIN_UNSUPPORTED_MESSAGE = (
    "Volatility 3 plugin generation is not supported yet with the Android "
    "Scudo method. A plugin is built from the per-byte variance around a hit, "
    "and this method compares whole heap chunks across runs instead of byte "
    "positions, so that data is not available."
)

#: The allocator is fixed when a session begins, so both ways out start a new one.
_NEW_SESSION_HINT = (
    "begin a session with consensus-begin --size for the generic (Welford) "
    "pipeline, or with consensus-begin --allocator scudo to force the Scudo path"
)

#: No region filter among these: a Scudo run refuses one.
_BUDGET_SUGGESTIONS = (
    "use fewer dumps, raise MEMDIVER_MEMORY_BUDGET_MB / max_rss_mb, or pass "
    "force to override."
)

#: Why a kept chunk did not become a region. Each is a translation guard that
#: should never fire on an intact capture; a non-zero count is reported.
SKIP_NOT_CAPTURED = "not_captured"
SKIP_NOT_CONTIGUOUS = "not_contiguous"
SKIP_BYTES_MISMATCH = "bytes_mismatch"
_SKIP_REASONS = (SKIP_NOT_CAPTURED, SKIP_NOT_CONTIGUOUS, SKIP_BYTES_MISMATCH)

#: brute-force's grid step the window estimate is quoted for (every offset).
_ESTIMATE_STRIDE = 1


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------


def _validated_key_sizes(key_sizes: Sequence[int]) -> Tuple[int, ...]:
    try:
        sizes = tuple(int(k) for k in key_sizes)
    except (TypeError, ValueError) as exc:
        raise CapabilityError(
            f"key_sizes must be positive integers: {exc}",
            category=ErrorCategory.INVALID_INPUT, code=INVALID_KEY_SIZES_CODE,
        ) from exc
    if not sizes or any(k <= 0 for k in sizes):
        raise CapabilityError(
            f"key_sizes must be one or more positive integers, got {list(sizes)}",
            category=ErrorCategory.INVALID_INPUT, code=INVALID_KEY_SIZES_CODE)
    return tuple(sorted(set(sizes)))


def _require_distinct_msl_files(paths: Sequence[str]) -> None:
    """Every dump exists, is a native ``.msl``, and is named only once.

    A dump named twice (a directory plus one of its files, a symlink beside
    its target) would be compared with ITSELF: its per-run-unique chunks then
    occur "in another dump" and are dropped as shared -- the secret of that
    very run lost without a word. So it is refused on resolved paths.
    """
    from memdiver.core.dump_source import open_dump

    seen: Dict[Path, str] = {}
    for raw in paths:
        path = Path(raw)
        if not path.is_file():
            raise FileNotFoundServiceError(f"dump not found: {raw}",
                                           code=DUMP_NOT_FOUND_CODE)
        resolved = path.resolve()
        if resolved in seen:
            raise CapabilityError(
                f"the same dump is named twice ({seen[resolved]} and {raw}); "
                "a dump compared with itself makes its own per-run values look "
                "shared, so they would be dropped. Name every run once.",
                category=ErrorCategory.INVALID_INPUT, code=DUPLICATE_DUMPS_CODE)
        seen[resolved] = raw
        # Constructing a source only probes the magic; nothing is opened.
        fmt = getattr(open_dump(path), "format_name", "")
        if fmt != "msl":
            raise UnsupportedFormatError(
                f"{raw} is a {fmt or 'unrecognised'} dump; the Scudo method "
                "reads native .msl dumps only (the Scudo scan needs their "
                "region table and VAS map)", code=NOT_MSL_CODE)


def _reference_index(paths: Sequence[str], reference_path: str) -> int:
    """Position of ``reference_path`` among ``paths``, compared on resolved paths.

    Checked BEFORE the consensus is built, so a typo costs nothing. The paths
    are distinct (:func:`_require_distinct_msl_files`), so at most one matches.
    """
    target = Path(reference_path).resolve()
    for i, raw in enumerate(paths):
        if Path(raw).resolve() == target:
            return i
    raise FileNotFoundServiceError(
        f"reference dump is not one of the named dumps: {reference_path}; "
        "the reference must be part of the consensus it is reduced against",
        code=REFERENCE_NOT_IN_DUMPS_CODE)


def _validate_scudo_dumps(
    dump_paths: Sequence[str],
    reference_path: str,
    key_sizes: Sequence[int],
    mixed_ok: bool = False,
) -> Tuple[Tuple[int, ...], int, Optional[str]]:
    """Every refusal that needs no heap read, as ``(sizes, ref_index, cohort)``.

    Shared by the producer and the web router: the web answers a bad request
    before it starts a worker, and both give the same refusal codes.

    :raises CapabilityError: on the refusals named in the module docstring.
    """
    paths = [str(p) for p in dump_paths]
    if len(paths) < 2:
        raise CapabilityError(
            f"Need at least 2 dumps to build a consensus, got {len(paths)}",
            category=ErrorCategory.INVALID_INPUT, code=TOO_FEW_DUMPS_CODE)
    sizes = _validated_key_sizes(key_sizes)
    _require_distinct_msl_files(paths)
    ref_index = _reference_index(paths, reference_path)
    return sizes, ref_index, _single_cohort(paths, mixed_ok)


def _refuse_truncated(source: Any, reference_path: str) -> None:
    """Refuse a reference whose ``read_all()`` offsets drift from the VAS map.

    ``brute-force`` slices windows out of ``read_all()``, which concatenates
    :meth:`MslReader.run_span` bytes per captured run; ``va_to_vas_offset``
    advances by each run's NOMINAL length. The two agree exactly when every run
    holds all its bytes. A container truncated mid-payload breaks that, and
    every region behind the short run would point at the wrong bytes.
    """
    reader = source.get_reader()
    index = reader.captured_run_index()
    short = [run for run in index.runs if reader.run_span(run) != run.length]
    if short:
        first = min(short, key=lambda run: run.vas_offset)
        raise CapabilityError(
            f"reference dump {reference_path} is truncated: {len(short)} captured "
            f"run(s) hold fewer bytes than their pages (first at vas offset "
            f"{first.vas_offset:#x}, VA {first.va_start:#x}), so the flat offsets "
            "brute-force reads would not line up behind it; re-acquire the dump",
            category=ErrorCategory.PRECONDITION, code=REFERENCE_TRUNCATED_CODE,
            details={"short_runs": len(short), "first_vas_offset": first.vas_offset})


def _require_scudo(reference_path: str, allocator: str,
                   km: Dict[str, Any]) -> None:
    """Refuse unless the reference dump is a Scudo heap.

    A Scudo session only knows how to pair Scudo primary
    chunks across cold boots, so it is Scudo-only in this release.
    ``allocator="scudo"`` forces that path without probing; ``"auto"`` detects
    the allocator from the (decrypted) reference and requires Scudo; any other
    allocator -- or ``"off"`` -- is refused with a pointer to the two kinds of
    session. The name is validated
    the way :func:`memdiver.app.tools_heap._checked_allocator` validates it, so
    a typo is an ``INVALID_INPUT`` refusal rather than a traceback.
    """
    from memdiver.core.dump_source import open_dump
    from memdiver.heap.analyze import parse_allocator_hint
    from memdiver.heap.detect import detect_allocator
    from memdiver.heap.model import AllocatorKind

    name = str(allocator or "auto").strip().lower()

    if name not in ("auto", "scudo"):
        # A concrete non-Scudo allocator, "off", or a bad name. Surface an
        # unknown name as INVALID_INPUT (mirroring _checked_allocator); then
        # refuse the mode -- a Scudo session reduces Scudo heaps only.
        if name != "off":
            try:
                parse_allocator_hint(name)
            except ValueError as exc:
                raise CapabilityError(
                    str(exc), category=ErrorCategory.INVALID_INPUT,
                    code=WRONG_ALLOCATOR_CODE) from exc
        raise CapabilityError(
            f"a Scudo session reduces Android Scudo heaps only, but its "
            f"allocator is {name}; {_NEW_SESSION_HINT}",
            category=ErrorCategory.PRECONDITION, code=WRONG_ALLOCATOR_CODE)

    if name == "scudo":
        return  # forced: skip detection

    # name == "auto": detect from the decrypted reference dump.
    with open_dump(Path(reference_path), **km) as source:
        detected = detect_allocator(source).best
    if detected is AllocatorKind.SCUDO:
        return
    raise CapabilityError(
        f"the reference dump's heap was detected as {detected.value}, not "
        f"Scudo; a Scudo session reduces Android Scudo heaps only -- {_NEW_SESSION_HINT}",
        category=ErrorCategory.PRECONDITION, code=WRONG_ALLOCATOR_CODE,
        details={"detected": detected.value})


# --------------------------------------------------------------------------
# Regions and the report around them
# --------------------------------------------------------------------------


def _region_row(verdict: Any, offset: int) -> Dict[str, Any]:
    """One ``candidates.json`` region. ``offset``/``length`` are all brute-force needs.

    ``mean_variance`` and ``row`` are present only for a chunk paired across
    the dumps: brute-force ranks its zero-hit ``top_k`` with
    ``float(region.get("mean_variance", 0.0))``, which an explicit ``null``
    would crash, and an unpaired chunk has no cross-dump variance to report.
    """
    row: Dict[str, Any] = {
        "offset": int(offset),
        "length": verdict.length,
        "va": hex(verdict.va),
        "signature": verdict.chunk.sig,
        "selected_as": verdict.verdict,
    }
    if verdict.row_key is not None:
        row["row"] = verdict.row_key
    if verdict.mean_variance is not None:
        row["mean_variance"] = round(float(verdict.mean_variance), 2)
    return row


def _translate(source: Any, kept: Sequence[Any]) -> Tuple[List[Dict[str, Any]], Counter]:
    """``(regions, skipped)``: kept chunks as verified flat ``"vas"`` regions."""
    regions: List[Dict[str, Any]] = []
    skipped: Counter = Counter()
    for verdict in kept:
        offset = source.va_to_vas_offset(verdict.va)
        if offset is None:
            skipped[SKIP_NOT_CAPTURED] += 1
            continue
        last = source.va_to_vas_offset(verdict.va + verdict.length - 1)
        if last != offset + verdict.length - 1:
            skipped[SKIP_NOT_CONTIGUOUS] += 1
            continue
        if source.read_range(offset, verdict.length) != verdict.chunk.data:
            skipped[SKIP_BYTES_MISMATCH] += 1
            continue
        regions.append(_region_row(verdict, offset))
    regions.sort(key=lambda r: (r["offset"], r["length"]))
    return regions, skipped


def _windows(regions: Sequence[Dict[str, Any]], key_sizes: Sequence[int],
             dump_len: int) -> int:
    """Windows brute-force will test over ``regions`` at stride 1.

    The same closed form ``brute-force`` counts its own grid with, so the two
    numbers cannot drift apart.
    """
    from memdiver.engine.candidate_grid import count_region_grid

    return sum(count_region_grid(r["offset"], r["offset"] + r["length"],
                                 key_sizes, _ESTIMATE_STRIDE, dump_len)
               for r in regions)


def _empty_reason(funnel: Dict[str, Dict[str, int]], total_chunks: int,
                  skipped: Counter) -> str:
    """Say WHY the list is empty, top-down -- "0 regions" alone reads as broken."""
    from memdiver.engine.scudo_candidates import KEEP_VERDICTS

    kept = sum(funnel[v]["chunks"] for v in KEEP_VERDICTS)
    if not total_chunks:
        return ("no Scudo primary chunk was found in the reference -- is it an "
                "Android dump, and does its VAS map name [anon:scudo:primary]?")
    if kept and sum(skipped.values()) >= kept:
        return (f"all {kept} kept chunk(s) failed the offset translation "
                f"({dict(skipped)})")
    return (f"none of the reference's {total_chunks} chunk(s) can hold a per-run "
            "value: every one is invariant across the dumps, shares its content "
            "with another dump, or was not judged")


def _diagnostics(
    *, funnel: Dict[str, Dict[str, int]], total_chunks: int, num_regions: int,
    skipped: Counter, not_judged: Dict[str, Any], fallback_dumps: List[str],
) -> List[Dict[str, Any]]:
    out: List[Diagnostic] = []
    if fallback_dumps:
        out.append(Diagnostic(
            code=SCOPE_FALLBACK_CODE,
            message=(f"{len(fallback_dumps)} dump(s) carry no VAS map naming "
                     "[anon:scudo:primary], so their chunk scan covered every "
                     "read/write region: header-shaped words outside the Scudo "
                     "heap may have been taken for chunks"),
            severity=Severity.WARNING, details={"dumps": list(fallback_dumps)}))
    if sum(skipped.values()):
        out.append(Diagnostic(
            code=CANDIDATES_SKIPPED_CODE,
            message=(f"{sum(skipped.values())} kept chunk(s) were left out because "
                     "their offset in the reference's flat view could not be "
                     "verified"),
            severity=Severity.WARNING, details=dict(skipped)))
    if not_judged["chunks"]:
        out.append(Diagnostic(
            code=NOT_JUDGED_CODE,
            message=(f"{not_judged['chunks']} chunk(s) ({not_judged['bytes']} bytes) "
                     f"in {len(not_judged['signatures'])} signature(s) absent from "
                     "at least one other dump were never compared: neither kept "
                     "nor ruled out"),
            severity=Severity.INFO, details=dict(not_judged)))
    if not num_regions:
        out.append(Diagnostic(
            code=CANDIDATES_EMPTY_CODE,
            message="No candidate regions: "
                    + _empty_reason(funnel, total_chunks, skipped) + ".",
            severity=Severity.INFO, details={"funnel": funnel}))
    return [d.to_dict() for d in out]


def _stage_end_extra(summary: Dict[str, Any]) -> Dict[str, Any]:
    """The summary a live surface needs, without its unbounded detail.

    Stage events sit in a bounded replay ring and cross a process queue, while a
    real app's not-judged signature list runs to thousands of entries.
    """
    not_judged = summary["not_judged"]
    return {
        "source": summary["source"],
        "num_regions": summary["totals"]["regions"],
        "funnel": summary["funnel"],
        "totals": summary["totals"],
        "skipped": summary["skipped"],
        "consensus": summary["consensus"],
        "region_scope": summary["region_scope"],
        "reference_dump": summary["reference_dump"],
        "num_dumps": summary["N"],
        "not_judged": {"chunks": not_judged["chunks"], "bytes": not_judged["bytes"]},
        "diagnostics": [
            {k: v for k, v in diagnostic.items() if k != "details"}
            for diagnostic in summary["diagnostics"]
        ],
    }


# --------------------------------------------------------------------------
# The producer
# --------------------------------------------------------------------------


def search_reduce_android(
    *,
    dump_paths: Sequence[str],
    reference_path: str,
    output_dir: str,
    key_sizes: Sequence[int] = (32,),
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    allocator: str = "auto",
    mixed_ok: bool = False,
    on_source: Optional[Callable[[Any], None]] = None,
    on_progress: Optional[Callable[..., None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
    force_memory: Optional[bool] = None,
) -> Dict[str, Any]:
    """Reduce N Android Scudo dumps to ``brute-force`` candidates of one reference.

    Backs the ``search-reduce`` command's Scudo mode and a web pipeline Scudo run.

    Builds the chunk-signature consensus over ``dump_paths`` (content alignment
    on), classifies every Scudo primary chunk of ``reference_path`` and writes
    the chunks that can hold a per-run random value to
    ``<output_dir>/candidates.json`` as ``{"regions": [{"offset", "length", ...}]}``
    in the reference's unfiltered flat ``"vas"`` view -- the file
    ``brute-force --candidates ... --dump <reference_path>`` reads unchanged.
    No ``region_filter`` is recorded, so brute-force opens the reference
    unfiltered, which is the view the offsets are in.

    ``key_sizes`` only sizes the reported window estimate (how many windows
    brute-force will test at stride 1); it never filters a region.
    ``key_file`` / ``passphrase`` / ``kem_key_file`` decrypt encrypted dumps,
    the same three parameters ``search_reduce`` takes. ``allocator`` picks the
    heap: ``"scudo"`` forces this path, ``"auto"`` requires allocator detection
    on the reference to find Scudo, and anything else is refused
    (``scudo.wrong_allocator``) -- see :func:`_require_scudo`. ``mixed_ok``
    lifts the ``cohort.mixed`` refusal. ``on_source`` is invoked on the opened
    reference (the CLI reports AEAD tag status through it).

    ``on_progress`` / ``is_cancelled`` are the same optional surface hooks the
    other pipeline producers take: the ``search_reduce`` stage stream, with
    sub-stages ``chunk_consensus`` / ``classify`` / ``regions``, and cooperative
    cancellation. Unset, the artifact and the return value do not change.

    ``force_memory`` gates the build on the memory budget: ``None`` (the CLI)
    applies no gate, ``False`` refuses an over-budget build with
    ``memory_budget_exceeded``, ``True`` proceeds with a warning.

    Returns the run summary (no region list -- that is the artifact):
    ``candidates_path``, ``num_regions``, ``totals``, ``funnel``,
    ``not_judged``, ``skipped``, ``diagnostics``, ``consensus``,
    ``region_scope``, ``reference_dump``, ``reference_index``, ``cohort``.

    :raises CapabilityError: on every refusal named in the module docstring;
        :class:`~memdiver.core.service_errors.EncryptedDumpLockedError` for a
        locked dump.
    """
    from memdiver.core.dump_source import open_dump
    from memdiver.core.memory_budget import check_budget
    from memdiver.engine.scudo_candidates import (
        SCUDO_CANDIDATES_VERSION,
        VERDICT_MISSING,
        classify_chunks,
        verdict_funnel,
    )
    from memdiver.engine.scudo_chunk_consensus import (
        ALIGNMENT_SCUDO_CHUNK,
        CHUNK_CONSENSUS_VERSION,
        SCOPE_ALL_RW,
        build_chunk_consensus,
        chunk_consensus_estimate,
    )

    paths = [str(p) for p in dump_paths]
    sizes, ref_index, cohort = _validate_scudo_dumps(
        paths, reference_path, key_sizes, mixed_ok)
    km = key_material_kwargs(key_file, passphrase, kem_key_file)
    key_material = km if has_key_material(km) else None

    def _check_cancelled() -> None:
        _experiment_check_cancelled(is_cancelled, on_progress)

    def _progress(sub_stage: str, pct: float, msg: str) -> None:
        _emit(on_progress, "progress", stage=f"search_reduce:{sub_stage}",
              pct=pct, msg=msg)

    def _on_dump_scanned(done: int, total: int, chunks: Sequence[Any]) -> None:
        _check_cancelled()
        # After one dump: real chunk counts exist, and most of the peak does not.
        if done == 1 and force_memory is not None:
            check_budget(chunk_consensus_estimate(chunks, total), force=force_memory,
                         suggestions=_BUDGET_SUGGESTIONS)
        # The scan is the slow part, so it gets most of the stage's bar.
        _progress("chunk_consensus", 0.8 * done / total,
                  f"scanned Scudo chunks of dump {done}/{total}")

    _emit(on_progress, "stage_start", stage="search_reduce", pct=0.0,
          msg=f"Scudo chunk consensus over {len(paths)} dumps")
    _check_cancelled()
    _require_scudo(reference_path, allocator, km)

    scc = build_chunk_consensus(
        paths, key_material=key_material, content_alignment=True,
        on_dump_scanned=_on_dump_scanned)
    _check_cancelled()
    _progress("classify", 0.85, "classifying the reference's chunks")
    verdicts = classify_chunks(scc, ref_index)
    funnel = verdict_funnel(verdicts)
    kept = sorted((v for v in verdicts if v.kept), key=lambda v: v.va)

    _check_cancelled()
    _progress("regions", 0.9, f"verifying {len(kept)} kept chunk(s)")
    with open_dump(Path(reference_path), **km) as source:
        if on_source is not None:
            on_source(source)
        _refuse_truncated(source, reference_path)
        regions, skipped = _translate(source, kept)
        dump_len = source.size_for("vas")

    missing = [v for v in verdicts if v.verdict == VERDICT_MISSING]
    not_judged = {
        "chunks": len(missing),
        "bytes": sum(v.length for v in missing),
        "signatures": sorted({v.chunk.sig for v in missing}),
    }
    scopes = [scope.to_dict() for scope in scc.per_dump_scopes]
    fallback = [path for path, scope in zip(paths, scopes, strict=True)
                if scope["kind"] == SCOPE_ALL_RW]
    totals = {
        "regions": len(regions),
        "bytes": sum(r["length"] for r in regions),
        "key_sizes": list(sizes),
        "stride": _ESTIMATE_STRIDE,
        "windows": _windows(regions, sizes, dump_len),
    }
    diagnostics = _diagnostics(
        funnel=funnel, total_chunks=len(verdicts), num_regions=len(regions),
        skipped=skipped, not_judged=not_judged, fallback_dumps=fallback)
    consensus = {
        "method": ALIGNMENT_SCUDO_CHUNK,
        "version": CHUNK_CONSENSUS_VERSION,
        "aligned_rows": len(scc.signatures),
        "ambiguous_signatures": len(scc.ambiguous),
        "missing_signatures": len(scc.missing),
        "empty_signatures": len(scc.empty),
    }
    summary = {
        "source": SCUDO_SOURCE,
        "version": SCUDO_CANDIDATES_VERSION,
        "consensus": consensus,
        "N": len(paths),
        "dumps": list(scc.dump_paths),
        "reference_dump": paths[ref_index],
        "reference_index": ref_index,
        "cohort": cohort,
        "region_scope": scopes[ref_index],
        "funnel": funnel,
        "not_judged": not_judged,
        "skipped": {reason: skipped.get(reason, 0) for reason in _SKIP_REASONS},
        "totals": totals,
        "diagnostics": diagnostics,
    }

    out = _ensure_dir(Path(output_dir))
    candidates_path = out / CANDIDATES_FILENAME
    _dump_json({**summary, "regions": regions}, candidates_path)
    logger.info("search-reduce[scudo]: %d region(s), %d bytes, %d window(s) -> %s",
                totals["regions"], totals["bytes"], totals["windows"], candidates_path)
    _emit(on_progress, "stage_end", stage="search_reduce", pct=1.0,
          msg=f"{len(regions)} regions", extra=_stage_end_extra(summary))
    return {
        **summary,
        "candidates_path": str(candidates_path),
        "num_regions": len(regions),
    }
