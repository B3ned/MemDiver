"""Key-finder producers: list the finders, scan a dump with them.

The ``keyfinders.*`` capabilities. A key finder recognises key material by its
structure (an expanded AES schedule, an RSA private key, ...) with no ground
truth; every finder is an ordinary registry algorithm whose module lives in
:mod:`memdiver.algorithms.keyfinders`, so new finders appear here with no edit.

Semantic-workbench rules this module is built around:

* **P2, every address carries its coordinate system.** A hit's ``addr`` is in
  the scanned ``view`` (``va`` = virtual address, ``vas`` = packed ``.msl`` stream
  offset, ``raw`` = file offset) and each row names its ``space`` plus a full
  :class:`~memdiver.core.location.Location` dict.
* **P3, coverage is part of the answer; absent bytes are never zeros.** Only
  CAPTURED runs are read, one VA-contiguous run at a time, so a structure that
  would straddle a capture gap is not found rather than found in invented zeros.
  ``coverage`` reports bytes scanned, runs scanned and gaps skipped; a ``limit``
  that cuts the result sets ``truncated`` and stops the scan (``complete: false``).
* **Interpretations live in the case, never in the ``.msl``.** With ``case_dir``
  the hits become the ``key_hits`` table (one ``case query`` can join it to
  ``heap_chunks`` / ``msl_regions``) and ``key_hit`` analysis-record entries.

``heap_policy``: ``off`` | ``annotate`` (attach the holding allocator chunk) |
``mask`` (keep only hits whose first AND last byte sit in one chunk's
``user_data``). ``mask`` is decided per hit from the chunk annotation rather than
through :class:`~memdiver.engine.consensus_heap.HeapRoleRuns`, which is a
consensus-slab-coordinate structure; a single dump's hit already has an exact
VA, so the per-hit check is exact and needs no projection.
"""

from __future__ import annotations

import ast
import inspect
import math
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, cast

from memdiver.app import scan_plan
from memdiver.app.scan_plan import Plan, Regions, Segment
from memdiver.core.location import Location
from memdiver.core.service_result import ServiceResult

FINDERS_PACKAGE = "memdiver.algorithms.keyfinders"
DEFAULT_FINDERS: Tuple[str, ...] = ("aes_schedule",)
HEAP_POLICIES: Tuple[str, ...] = ("off", "annotate", "mask")
#: Rows a scan returns before it stops and reports ``truncated``.
DEFAULT_LIMIT = 10_000
#: Author of the ``key_hit`` analysis-record entries.
ANNOTATION_AUTHOR = "tool:keyfinders"

ProgressFn = Callable[[float, str], None]

# The dump scan planner (windows, plan, coverage) lives in :mod:`memdiver.app.scan_plan`;
# shrink the windows in tests through ``scan_plan.WINDOW_BYTES`` / ``WINDOW_OVERLAP``.


# -- finder discovery ----------------------------------------------------------


def _finders() -> Dict[str, Any]:
    """Registry algorithms living in the key-finder package, by name."""
    from memdiver.algorithms.registry import get_registry

    return {a.name: a for a in get_registry().list_all()
            if type(a).__module__.startswith(FINDERS_PACKAGE)}


def _jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _default_of(node: ast.expr, module: Any) -> Any:
    try:
        return _jsonable(ast.literal_eval(node))
    except (ValueError, SyntaxError):
        pass
    if isinstance(node, ast.Name) and hasattr(module, node.id):
        return _jsonable(getattr(module, node.id))
    return None


def _is_extra_get(call: ast.Call) -> bool:
    func = call.func
    holder = func.value if isinstance(func, ast.Attribute) and func.attr == "get" else None
    named = isinstance(holder, ast.Name) and holder.id == "extra"
    attr = isinstance(holder, ast.Attribute) and holder.attr == "extra"
    return (named or attr) and bool(call.args) and isinstance(call.args[0], ast.Constant)


def _introspected_parameters(finder: Any) -> List[Dict[str, Any]]:
    """``extra.get("name", default)`` reads of the finder's ``run``, in source order."""
    module = sys.modules.get(type(finder).__module__)
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(type(finder).run)))
    except (OSError, TypeError, SyntaxError):
        return []
    found: Dict[str, Any] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_extra_get(node):
            default = _default_of(node.args[1], module) if len(node.args) > 1 else None
            found.setdefault(str(cast(ast.Constant, node.args[0]).value), default)
    return [{"name": n, "default": d, "source": "introspected"} for n, d in found.items()]


def _parameters(finder: Any) -> List[Dict[str, Any]]:
    """Declared ``parameters`` (a dict or list on the finder) win over introspection."""
    declared = getattr(finder, "parameters", None)
    if isinstance(declared, dict):
        return [{"name": n, **(_jsonable(d) if isinstance(d, dict) else {"default": _jsonable(d)}),
                 "source": "declared"} for n, d in declared.items()]
    if declared:
        return [{**_jsonable(d), "source": "declared"} for d in declared]
    return _introspected_parameters(finder)


def keyfinders_list_result() -> "ServiceResult":
    """Every key finder with its description, mode and ``params`` it understands."""
    rows = [{"name": f.name, "description": f.description, "mode": f.mode,
             "module": type(f).__module__, "parameters": _parameters(f)}
            for f in sorted(_finders().values(), key=lambda f: f.name)]
    return ServiceResult.ok({"finders": rows, "count": len(rows),
                             "default_finders": [n for n in DEFAULT_FINDERS
                                                 if n in {r["name"] for r in rows}],
                             "heap_policies": list(HEAP_POLICIES)})


# -- scan plan: the stride alignment the finders need (the plan is in scan_plan) --


#: ``params`` keys that set a finder's stride, with the default (``None``: stride 1).
_STRIDE_PARAMS = {"stride": None, "step": None, "rsa_le_stride": 8, "rsa_be_stride": 1}
_MAX_ALIGN = 1 << 20


def _stride_alignment(names: Sequence[str], params: Dict[str, Any]) -> int:
    """Common alignment of the strides the selected finders will use (1 when none)."""
    strides = [1]
    for key, default in _STRIDE_PARAMS.items():
        if key.startswith("rsa") and "rsa_factor" not in names:
            continue
        value = params.get(key, default)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            strides.append(value)
    align = math.lcm(*strides)
    return align if align <= _MAX_ALIGN else 1


# -- hits ---------------------------------------------------------------------


@dataclass
class _Hit:
    row: Dict[str, Any]
    candidate: Dict[str, Any] = field(default_factory=dict)


def _translated(metadata: Dict[str, Any], delta: int) -> Dict[str, Any]:
    """``*_offset`` metadata is window-relative; move it into the view's coordinates."""
    out = _jsonable(metadata)
    for key, value in metadata.items():
        if key.endswith("_offset") and isinstance(value, int) and not isinstance(value, bool):
            out[key] = value + delta
    return out


def _candidate(finder: str, match: Any, row: Dict[str, Any], seg: Segment,
               window: int) -> Dict[str, Any]:
    """A ``candidates.json`` region (offset into the flat reference stream)."""
    key_offset = match.metadata.get("key_offset")
    key_hex = match.metadata.get("key_hex")
    if isinstance(key_offset, int) and key_hex:
        offset, length = seg.vas + window + key_offset, len(key_hex) // 2
    else:
        offset, length = row["vas_offset"], row["length"]
    return {"offset": int(offset), "length": int(length), "finder": finder,
            "label": row["label"], "confidence": row["confidence"],
            "addr": row["addr"], "space": row["space"]}


def _hit_of(plan: Plan, finder: str, match: Any, seg: Segment, window: int) -> _Hit:
    rel = window + match.offset
    addr = seg.addr + rel
    location = plan.location(addr)
    row = {"finder": finder, "label": match.label, "addr": addr,
           "space": location.space.value, "location": location.to_dict(),
           "length": int(match.length), "confidence": float(match.confidence),
           "metadata": _translated(match.metadata, seg.addr + window),
           "va": None if seg.va is None else seg.va + rel,
           "vas_offset": seg.vas + rel, "heap": None, "region": None}
    return _Hit(row, _candidate(finder, match, row, seg, window))


# -- heap enrichment ------------------------------------------------------------


def _heap_offset(plan: Plan, row: Dict[str, Any], last_byte: bool) -> int:
    shift = row["length"] - 1 if last_byte else 0
    if plan.heap_view == "va":
        return row["va"] + shift - plan.span_start
    return row["vas_offset"] + shift


def _annotate_heap(plan: Plan, hits: List[_Hit]) -> None:
    from memdiver.engine.heap_hits import heap_hit_annotations

    rows = [h.row for h in hits if h.row["va"] is not None or plan.heap_view != "va"]
    offsets = [_heap_offset(plan, r, False) for r in rows]
    offsets += [_heap_offset(plan, r, True) for r in rows]
    found = heap_hit_annotations(plan.source, offsets, plan.heap_view, "auto")
    for row, first, last in zip(rows, found[:len(rows)], found[len(rows):]):
        if first is not None:
            row["heap"] = {**first, "spans_chunks": last is None
                           or last["chunk_va"] != first["chunk_va"]}


def _in_user_data(row: Dict[str, Any]) -> bool:
    heap = row["heap"]
    return heap is not None and heap["role"] == "user_data" and not heap["spans_chunks"]


def _enrich(plan: Plan, hits: List[_Hit], regions: Regions,
            policy: str) -> Tuple[List[_Hit], int]:
    """Attach region (+ heap) context; ``mask`` drops hits outside chunk user data."""
    for hit in hits:
        hit.row["region"] = regions.at(hit.row["va"])
    if policy == "off" or not hits:
        return hits, 0
    _annotate_heap(plan, hits)
    if policy != "mask":
        return hits, 0
    kept = [h for h in hits if _in_user_data(h.row)]
    return kept, len(hits) - len(kept)


def _heap_status(plan: Plan, policy: str) -> str:
    from memdiver.heap.analyze import analyze_heap
    from memdiver.heap.model import AllocatorKind

    if policy == "off":
        return "off"
    try:
        layout = analyze_heap(plan.source, "auto")
    except Exception:  # noqa: BLE001 - annotation is soft, like heap_hit_annotations
        return "no_heap_detected"
    detected = layout.allocator != AllocatorKind.UNKNOWN and bool(layout.chunks)
    return "ok" if detected else "no_heap_detected"


# -- the scan -----------------------------------------------------------------


@dataclass
class _Scan:
    hits: List[_Hit] = field(default_factory=list)
    bytes_scanned: int = 0
    runs_scanned: int = 0
    short_reads: int = 0
    masked_out: int = 0
    stopped_early: bool = False


def _run_finders(plan: Plan, finders: Dict[str, Any], names: Sequence[str],
                 params: Dict[str, Any], seg: Segment, window: int,
                 data: bytes, last: bool) -> List[_Hit]:
    from memdiver.algorithms.base import AnalysisContext

    context = AnalysisContext(library="", protocol_version="", phase="",
                              extra=dict(params))
    hits: List[_Hit] = []
    for name in names:
        for match in finders[name].run(data, context).matches:
            if (scan_plan.owns(match.offset, window, last)
                    and seg.addr + window + match.offset >= seg.floor):
                hits.append(_hit_of(plan, name, match, seg, window))
    return sorted(hits, key=lambda h: (h.row["addr"], h.row["finder"], h.row["label"]))


def _scan_segment(plan: Plan, finders: Dict[str, Any], names: Sequence[str],
                  params: Dict[str, Any], seg: Segment, regions: Regions,
                  policy: str, limit: int, scan: _Scan,
                  progress: Optional[ProgressFn], total: int) -> None:
    scan.runs_scanned += 1
    scan.bytes_scanned -= seg.lead      # read to align the stride grid, not scanned
    for win in scan_plan.read_windows(plan, seg):
        scan.short_reads += int(win.short)   # never pad: scan only what came back
        found = _run_finders(plan, finders, names, params, seg, win.offset, win.data, win.last)
        kept, dropped = _enrich(plan, found, regions, policy)
        scan.hits.extend(kept)
        scan.masked_out += dropped
        scan.bytes_scanned += scan_plan.owned_bytes(len(win.data), win.last)
        if progress is not None:
            progress(min(scan.bytes_scanned / max(total, 1), 0.99), "scanning")
        if len(scan.hits) >= limit:
            scan.stopped_early = not (win.last and seg is plan.segments[-1])
            return


def _harvest_moduli(plan: Plan, params: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    """RSA moduli of EVERY captured run in scope, so a prime in one run meets its modulus
    held in another. Provenance keeps the source kind; the offset is dropped (it is only
    meaningful inside the window it was read from)."""
    from memdiver.algorithms.keyfinders import rsa_factor as rf

    if not params.get("rsa_scan_public_keys", True):
        return {}
    min_bits = params.get("rsa_min_bits", rf.DEFAULT_MIN_BITS)
    max_bits = params.get("rsa_max_bits", rf.DEFAULT_MAX_BITS)
    cap = params.get("rsa_max_moduli", rf.DEFAULT_MAX_MODULI)
    found: Dict[int, Dict[str, Any]] = {}
    windows = (win for seg in plan.segments for win in scan_plan.read_windows(plan, seg))
    for win in windows:
        for n, info in rf.collect_moduli(win.data, (), True, min_bits, max_bits, cap).items():
            found.setdefault(n, {**info, "offset": None})
        if _moduli_full(found, cap):
            break       # first-seen order: later windows could only append past the cap
    return dict(list(found.items())[:cap])


def _moduli_full(found: Dict[int, Any], cap: Any) -> bool:
    """Has the harvest reached a (non-negative int) ``rsa_max_moduli`` cap?"""
    return isinstance(cap, int) and 0 <= cap <= len(found)


def _with_harvested_moduli(plan: Plan, names: Sequence[str],
                           params: Dict[str, Any]) -> Dict[str, Any]:
    """``params`` plus ``rsa_moduli_info`` when ``rsa_factor`` runs over several windows."""
    windows = sum(len(scan_plan.windows(s)) for s in plan.segments)
    if "rsa_factor" not in names or windows < 2:
        return params
    return {**params, "rsa_moduli_info": _harvest_moduli(plan, params)}


def _scan_plan(plan: Plan, finders: Dict[str, Any], names: Sequence[str],
               params: Dict[str, Any], policy: str, limit: int,
               progress: Optional[ProgressFn]) -> _Scan:
    scan, regions = _Scan(), scan_plan.regions_of(plan)
    params = _with_harvested_moduli(plan, names, params)
    total = sum(s.length for s in plan.segments)
    for seg in plan.segments:
        _scan_segment(plan, finders, names, params, seg, regions, policy, limit,
                      scan, progress, total)
        if len(scan.hits) >= limit:
            break
    return scan


# -- case integration ----------------------------------------------------------


def _table_row(row: Dict[str, Any]) -> Dict[str, Any]:
    import json

    heap, region = row["heap"] or {}, row["region"] or {}
    return {"addr": row["addr"], "length": row["length"], "va": row["va"],
            "vas_offset": row["vas_offset"], "confidence": row["confidence"],
            "finder": row["finder"], "label": row["label"],
            "key_hex": row["metadata"].get("key_hex"),
            "heap_chunk_va": heap.get("chunk_va"), "heap_chunk_size": heap.get("chunk_size"),
            "heap_role": heap.get("role"), "heap_state": heap.get("state"),
            "region_start": region.get("start"), "region_end": region.get("end"),
            "region_perms": region.get("perms"), "region_path": region.get("path"),
            "metadata_json": json.dumps(row["metadata"], sort_keys=True)}


def _entry_of(plan: Plan, row: Dict[str, Any], run_id: str):
    from memdiver.analysis.record import KEY_HIT, AnalysisEntry, Support

    payload = {"finder": row["finder"], "label": row["label"],
               "confidence": row["confidence"], "metadata": row["metadata"],
               "heap": row["heap"], "region": row["region"], "table_run_id": run_id}
    return AnalysisEntry(
        capture_id=plan.capture_id, kind=KEY_HIT, author=ANNOTATION_AUTHOR,
        locations=(Location.from_dict(row["location"]),), length=row["length"],
        label=f"{row['finder']}:{row['label']}", payload=payload,
        support=(Support("keyfinder", row["finder"]),))


def _file_case(plan: Plan, rows: List[Dict[str, Any]], case_dir: str,
               truncated: bool, annotate: bool) -> Dict[str, Any]:
    from memdiver.analysis.exporters import export_key_hits
    from memdiver.analysis.record_store import AnalysisRecord
    from memdiver.app.tools_case import _open

    case = _open(case_dir)
    ref = export_key_hits(
        case, [_table_row(r) for r in rows], capture_id=plan.capture_id,
        space=plan.location(0).space.value, pid=plan.pid,
        image_sha256=plan.image_sha256, truncated=truncated)
    entries = 0
    if annotate:
        record = AnalysisRecord(case.dir)
        entries = len(record.append_many([_entry_of(plan, row, ref.run_id) for row in rows]))
    return {"case_dir": str(case.dir), "table": ref.name, "run_id": ref.run_id,
            "rows": ref.row_count, "path": ref.path, "annotations": entries,
            "annotation_kind": "key_hit"}


def _write_candidates(candidates: List[Dict[str, Any]], out: str) -> str:
    from memdiver.app.tools_pipeline import _dump_json

    path = Path(out).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    _dump_json({"regions": candidates}, path)
    return str(path)


# -- the producer -----------------------------------------------------------------


def _validated(finders: Sequence[str], heap_policy: str, limit: int,
               offset: Optional[int], length: Optional[int]) -> Dict[str, Any]:
    known = _finders()
    unknown = [f for f in finders if f not in known]
    if not finders or unknown:
        raise scan_plan.invalid(f"unknown key finder(s): {unknown or 'none given'}; "
                       f"choose from: {', '.join(sorted(known))}", "keyfinders.unknown_finder")
    if heap_policy not in HEAP_POLICIES:
        raise scan_plan.invalid(f"heap_policy must be one of {', '.join(HEAP_POLICIES)}",
                       "keyfinders.bad_heap_policy")
    if limit < 1:
        raise scan_plan.invalid("limit must be >= 1", "invalid_limit")
    if (offset is not None and offset < 0) or (length is not None and length < 1):
        raise scan_plan.invalid("offset must be >= 0 and length >= 1", "keyfinders.bad_range")
    return known


def keyfinders_scan_result(
    dump_path: str, finders: Sequence[str] = DEFAULT_FINDERS,
    view: Optional[str] = None, offset: Optional[int] = None,
    length: Optional[int] = None, heap_policy: str = "annotate",
    params: Optional[Dict[str, Any]] = None, case_dir: Optional[str] = None,
    limit: int = DEFAULT_LIMIT, candidates_out: Optional[str] = None,
    annotate: bool = True, progress: Optional[ProgressFn] = None,
) -> "ServiceResult":
    """Scan the CAPTURED bytes of a dump with key finders.

    ``view`` / ``offset`` / ``length`` select the window in the chosen view's
    coordinates (default: ``va`` for an ``.msl`` or ``.mdview``, ``raw`` for a flat
    file; ``vas`` is also offered for an ``.msl``). Each row carries ``addr`` +
    ``space`` + ``location``, ``length``, ``confidence``, finder ``metadata``,
    ``heap`` and ``region`` context, plus ``va`` and ``vas_offset``. ``coverage``,
    ``truncated`` and ``candidates`` (the ``regions`` of a ``candidates.json``,
    offsets into the flat reference stream) are always present. With ``case_dir`` the
    rows become the ``key_hits`` table (and, with ``annotate``, ``key_hit`` entries).
    """
    from memdiver.core.dump_source import open_dump

    names = tuple(finders)
    known = _validated(names, heap_policy, limit, offset, length)
    path = scan_plan.dump_file(dump_path)
    with open_dump(path) as source:
        plan = scan_plan.build_plan(source, path, view, offset, length,
                           _stride_alignment(names, params or {}))
        scan = _scan_plan(plan, known, names, dict(params or {}), heap_policy,
                          limit, progress)
        status = _heap_status(plan, heap_policy)
    hits = scan.hits[:limit]
    truncated = scan.stopped_early or len(scan.hits) > limit
    payload: Dict[str, Any] = {
        "dump_path": str(path), "format": source.format_name, "view": plan.view,
        "space": plan.location(0).space.value, "capture_id": plan.capture_id,
        "finders": list(names), "params": _jsonable(params or {}),
        "heap_policy": heap_policy,
        "heap": {"policy": heap_policy, "status": status, "masked_out": scan.masked_out},
        "rows": [h.row for h in hits], "row_count": len(hits), "limit": limit,
        "truncated": truncated,
        "complete": not (truncated or scan.short_reads),
        "incomplete_reason": scan_plan.incomplete_reason(truncated, scan.short_reads),
        "coverage": scan_plan.coverage(plan, scan, offset, length),
        "candidates": [h.candidate for h in hits],
    }
    if candidates_out:
        payload["candidates_path"] = _write_candidates(payload["candidates"], candidates_out)
    if case_dir:
        payload["case"] = _file_case(plan, payload["rows"], case_dir, truncated, annotate)
    return ServiceResult.ok(payload)


__all__ = ["DEFAULT_FINDERS", "DEFAULT_LIMIT", "HEAP_POLICIES",
           "keyfinders_list_result", "keyfinders_scan_result"]
