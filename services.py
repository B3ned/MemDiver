"""MemDiver structured services — the surface-agnostic producer layer.

Every user-facing MemDiver capability is backed by ONE producer function in the
``memdiver.app`` layer. The CLI, the FastAPI web app and the MCP server are all
thin *presenters* that route to these same functions, so the compute cannot
fork between surfaces. This module is the Python **library** surface: it
re-exports every ``app`` producer under a stable public name so a library user
reaches the whole feature set without importing deep internal modules.

Contract
--------
* The ``*_result`` producers (and :func:`get_cross_references_result` etc.)
  return a :class:`~memdiver.core.service_result.ServiceResult` — a payload plus
  a :class:`~memdiver.core.service_result.StatusBlock` that carries key/decrypt
  state. Read ``result.payload`` for the data and ``result.status`` for whether
  an encrypted dump was locked (missing/wrong key) rather than genuinely empty.
* The pipeline producers (:func:`consensus`, :func:`n_sweep`, …) and the
  dataset/analysis producers (:func:`scan_dataset`, …) return their native
  payloads (JSON-able dicts / artefact paths).
* Hard errors are RAISED as :class:`~memdiver.core.service_errors.CapabilityError`
  subclasses (e.g. ``FileNotFoundServiceError``, ``OffsetOutOfRangeError``,
  ``EncryptedDumpLockedError``) — never returned as ``{"error": ...}`` dicts.

Session
-------
The inspect / xref / dataset producers take a :class:`ToolSession` as their
first argument (it caches dataset scans across calls); construct one with
``memdiver.services.ToolSession()``. The pipeline / verify / experiment
producers are stateless and keyword-only.

Example::

    import memdiver

    session = memdiver.services.ToolSession()
    result = memdiver.services.session_info_result(session, "capture.msl")
    if result.status.key.decrypted:
        print(result.payload["region_count"])
    else:
        print(result.status.key.hint)  # neutral, surface-agnostic lock hint
"""

from __future__ import annotations

# Shared stateful context passed to the inspect/xref/dataset producers.
from memdiver.app.session import ToolSession

# --- inspect: hex / entropy / strings / byte-search / structured MSL --------
from memdiver.app.tools_inspect import (
    analyze_region_result,
    blocks_result,
    connections_result,
    detect_format_result,
    entropy_result,
    handles_result,
    modules_result,
    module_index_result,
    import_provenance_result,
    page_states_result,
    processes_result,
    read_hex_raw_result,
    read_hex_result,
    resolve_va_result,
    search_bytes_result,
    session_info_result,
    strings_result,
    vas_regions_result,
)

# --- xref / structure -------------------------------------------------------
from memdiver.app.tools_semantic import (
    artifact_model_build_result,
    artifact_model_export_result,
    artifact_model_validate_result,
    propose_layout_result,
)
from memdiver.app.tools_xref import (
    xref_pointers_result,
    apply_structure_result,
    get_cross_references_result,
    identify_structure_result,
)

# --- pipeline stages + verify / experiment ----------------------------------
from memdiver.app.experiment_orchestration import capture_result, experiment_result
from memdiver.app.tools_pipeline import (
    analyze_candidates,
    auto_floor,
    brute_force,
    consensus,
    emit_plugin,
    export_key_pattern,
    export_pattern,
    inspect_pcap,
    keylog_result,
    locate_field_across_pairs,
    locate_key,
    manual_export_pattern,
    n_sweep,
    scan_yara_rule,
    score_detector_matches,
    search_reduce,
    verify_key_result,
    verify_vol3_plugin,
)
from memdiver.app.tools_pipeline_android import search_reduce_android

# --- dataset / analysis -----------------------------------------------------
from memdiver.app.tools import (
    analyze_library,
    import_dump,
    list_phases,
    list_protocols,
    preview_import,
    scan_dataset,
)

# --- import-time region selection (value types for import_dump/preview) ----
from memdiver.msl.region_select import (
    RegionCategory,
    RegionSelection,
    parse_selection,
)

# --- consensus: the aligned window (the N-dump differential viewer) --------
from memdiver.app.tools_consensus import (
    aligned_window_from_vector,
    aligned_window_result,
    class_regions_from_vector,
    class_regions_result,
    anchor_consensus_result,
)

# --- frontend-serving producers (field inference / algorithm availability) --
from memdiver.app.tools_algorithms import algorithm_availability
from memdiver.app.tools_fields import infer_fields_result

# --- heap: allocator detection, chunk layout, free lists --------------------
from memdiver.app.tools_heap import (
    heap_chunk_at_result,
    heap_chunks_result,
    heap_detect_result,
    heap_free_lists_result,
    heap_roles_result,
    heap_summary_result,
)

# --- analysis record: versioned annotations per capture ---------------------
from memdiver.app.tools_annotations import (
    annotations_add_result,
    annotations_list_result,
    annotations_retract_result,
    annotations_supersede_result,
)

# --- case data lake + semantic context ---------------------------------------
from memdiver.app.tools_case import (
    case_export_result,
    case_init_result,
    case_manifest_result,
    case_query_result,
    case_schema_result,
    case_status_result,
    context_at_result,
)

# --- memory-image views (probe / profile / open / processes / extract) --------
from memdiver.app.tools_image import (
    image_extract_process_result,
    image_open_view_result,
    image_probe_result,
    image_processes_result,
    image_profile_result,
)

# --- key finders (structure-based key recognition over captured bytes) --------
from memdiver.app.tools_keyfinders import (
    keyfinders_list_result,
    keyfinders_scan_result,
)

# --- ISF workbench (pakunoda probes, ISF drafts, try-loop) and disassembly ---------
from memdiver.app.tools_disasm import disasm_result
from memdiver.app.tools_code_evidence import code_evidence_result
from memdiver.app.tools_isf import (
    isf_probe_result,
    isf_draft_create_result,
    isf_draft_list_result,
    isf_draft_get_result,
    isf_draft_set_result,
    isf_draft_import_result,
    isf_draft_retract_result,
    isf_draft_versions_result,
    isf_draft_diff_result,
    isf_draft_validate_result,
    isf_draft_export_result,
    isf_try_result,
)

# --- YARA editor (compile-check + captured-bytes scan of one dump) ---------------
from memdiver.app.tools_yara import yara_check_result, yara_scan_dump_result
from memdiver.app.tools_yara_rules import (
    yara_rule_delete_result,
    yara_rule_get_result,
    yara_rule_list_result,
    yara_rule_put_result,
)

# --- detector fixtures (positive controls / decoys for YARA rules and key finders)
from memdiver.app.tools_detector_fixtures import (
    detector_fixtures_add_result,
    detector_fixtures_list_result,
    detector_fixtures_remove_result,
    detector_fixtures_run_result,
)

# --- strings as a table (+ IOC badges; ``strings_iocs`` saved query) ---------
from memdiver.app.tools_strings import strings_table_result

# --- Volatility 3 plugins over a .mdview (run / query / annotate / dev tools) --
from memdiver.app.tools_vol3 import (
    vol3_annotate_result,
    vol3_describe_result,
    vol3_plugins_result,
    vol3_query_result,
    vol3_run_result,
)
from memdiver.app.tools_vol3_dev import (
    vol3_check_result,
    vol3_import_parquet_result,
    vol3_scaffold_result,
    vol3_write_config_result,
)
from memdiver.app.tools_vol3_fixtures import (
    vol3_fixture_list_result,
    vol3_fixture_put_result,
    vol3_fixture_run_result,
)
from memdiver.app.tools_vol3_sources import (
    vol3_source_get_result,
    vol3_source_list_result,
    vol3_source_put_result,
)

__all__ = [
    # session
    "ToolSession",
    # inspect
    "read_hex_result",
    "read_hex_raw_result",
    "resolve_va_result",
    "analyze_region_result",
    "search_bytes_result",
    "entropy_result",
    "strings_result",
    "detect_format_result",
    "session_info_result",
    "vas_regions_result",
    "page_states_result",
    "processes_result",
    "modules_result",
    "handles_result",
    "connections_result",
    "module_index_result",
    "import_provenance_result",
    "blocks_result",
    # xref / structure
    "get_cross_references_result",
    "identify_structure_result",
    "apply_structure_result",
    # pipeline
    "consensus",
    "analyze_candidates",
    "search_reduce",
    "search_reduce_android",
    "brute_force",
    "n_sweep",
    "auto_floor",
    "emit_plugin",
    "export_pattern",
    "manual_export_pattern",
    "locate_key",
    "export_key_pattern",
    # C3 — the paired field search (N (dump, capture) pairs, one needle each).
    "locate_field_across_pairs",
    # D1 — RUN an emitted YARA rule over N dumps. The other side of
    # ``export_pattern`` / ``export_key_pattern``, which only ever wrote one.
    "scan_yara_rule",
    # D2 — SCORE what D1 found. ``scan_yara_rule`` says the rule fired; this
    # says whether it was right, which is a different fact.
    "score_detector_matches",
    # D3 — RUN the Volatility3 plugin we emit, in BOTH of the ways a user runs
    # one: in-process against the framework MemDiver imports, and out-of-process
    # through the operator's own ``vol`` launcher. Every row names the runtime
    # and the RESOLVED framework version that produced it, because three
    # Volatility3 trees commonly coexist on one machine and they disagree.
    "verify_vol3_plugin",
    "keylog_result",
    "inspect_pcap",
    # consensus — one window, read in every dump at the address the consensus
    # aligned. ``aligned_window_from_vector`` is the same compute over a vector
    # the caller already has (no rebuild); ``aligned_window_result`` builds one.
    "aligned_window_result",
    "aligned_window_from_vector",
    # consensus — EVERY occurrence of a class, paginated and jumpable. The
    # complement of the window: the window answers "what is at this offset in
    # all N dumps", this answers "where are all the offsets worth looking at",
    # and each row carries the navigable offset to go there.
    "class_regions_result",
    "anchor_consensus_result",
    "xref_pointers_result",
    "propose_layout_result",
    "artifact_model_build_result",
    "artifact_model_export_result",
    "artifact_model_validate_result",
    "class_regions_from_vector",
    # verify / experiment / capture
    "verify_key_result",
    "experiment_result",
    "capture_result",
    # dataset / analysis
    "scan_dataset",
    "list_protocols",
    "list_phases",
    "analyze_library",
    "import_dump",
    "preview_import",
    # import-time region selection value types
    "RegionSelection",
    "RegionCategory",
    "parse_selection",
    # frontend-serving producers
    "infer_fields_result",
    "algorithm_availability",
    # heap — which allocator, its chunks and free lists, and the role of any
    # heap byte; every one runs the single heap.analyze_heap facade.
    "heap_detect_result",
    "heap_summary_result",
    "heap_chunks_result",
    "heap_chunk_at_result",
    "heap_free_lists_result",
    "heap_roles_result",
    # analysis record — versioned, append-only annotations per capture.
    "annotations_list_result",
    "annotations_add_result",
    "annotations_supersede_result",
    "annotations_retract_result",
    # case data lake — Parquet tables + read-only SQL, and locate_context.
    "case_init_result",
    "case_status_result",
    "case_manifest_result",
    "case_schema_result",
    "case_query_result",
    "case_export_result",
    "context_at_result",
    # memory-image views — a .mdview descriptor per image view, pslist, extraction.
    "image_probe_result",
    "image_profile_result",
    "image_open_view_result",
    "image_processes_result",
    "image_extract_process_result",
    # Volatility 3 — plugins over a .mdview into a case, saved queries, dev tools.
    "keyfinders_list_result",
    "keyfinders_scan_result",
    "yara_check_result",
    "yara_scan_dump_result",
    "yara_rule_list_result",
    "yara_rule_get_result",
    "yara_rule_put_result",
    "yara_rule_delete_result",
    # ISF workbench + disassembly
    "isf_probe_result",
    "isf_draft_create_result",
    "isf_draft_list_result",
    "isf_draft_get_result",
    "isf_draft_set_result",
    "isf_draft_import_result",
    "isf_draft_retract_result",
    "isf_draft_versions_result",
    "isf_draft_diff_result",
    "isf_draft_validate_result",
    "isf_draft_export_result",
    "isf_try_result",
    "disasm_result",
    "code_evidence_result",
    "detector_fixtures_run_result",
    "detector_fixtures_add_result",
    "detector_fixtures_list_result",
    "detector_fixtures_remove_result",
    "strings_table_result",
    "vol3_plugins_result",
    "vol3_describe_result",
    "vol3_run_result",
    "vol3_query_result",
    "vol3_annotate_result",
    "vol3_scaffold_result",
    "vol3_check_result",
    "vol3_import_parquet_result",
    "vol3_write_config_result",
    "vol3_source_list_result",
    "vol3_source_get_result",
    "vol3_source_put_result",
    "vol3_fixture_put_result",
    "vol3_fixture_list_result",
    "vol3_fixture_run_result",
]
