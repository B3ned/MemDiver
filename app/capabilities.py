"""Declarative registry of MemDiver capabilities and the surfaces that expose them.

Every user-facing capability is backed by ONE surface-agnostic producer in the
``memdiver.app`` layer. Each surface (the Python library, the CLI, the FastAPI
web app, the MCP server, and — eventually — the marimo UI) is meant to be a thin
presenter that routes to that same producer, so the compute cannot fork.

This module makes that mapping explicit and machine-checkable. It pairs each
capability with its producer's dotted path and the set of surfaces *currently*
routed to that producer. ``tests/test_architecture_invariants.py`` consumes it
as a RATCHET: it asserts every capability is wired on every in-scope surface
except a documented, non-stale set of gaps (:data:`KNOWN_PARITY_GAPS`), and that
every producer path imports and is callable.

That ratchet iterates :data:`CAPABILITIES` and nothing else, so it is blind BY
CONSTRUCTION to a producer that was never registered here — exactly the hole
``pcap.inspect`` sat in (see its comment below). The complementary guard is
``tests/test_capability_completeness.py``: it discovers every public producer in
the app-layer producer modules and every route in ``api/routers/*.py`` by AST
and requires each to be either reachable from :data:`CAPABILITIES` or on an
annotated, shrink-only exemption list. Add a producer without registering it and
that test fails.

Scope note: the registry currently enumerates the presentation-separation
producer families — inspect, xref/structure, the Phase-25 pipeline stages, and
the Phase-5 ``verify`` / ``experiment`` capabilities — plus the dataset/analysis
producers in ``app.tools``. Surfaces are recorded from the ACTUAL wiring
(``cli.py`` subcommands, ``mcp_server/server.py`` tools, ``api/routers/*``, and
re-export of the ``app`` producer through the public ``memdiver.services``
facade for the library). ``marimo`` is a known-incomplete surface
and is deliberately OUT of :data:`IN_SCOPE_SURFACES` for now, so the parity
ratchet does not hold capabilities to it.

The ``memdiver notebook <case>`` command (``ui/notebooks/case_explorer.py``)
opens a marimo case explorer for analysts. It is an analyst companion, not a
parity surface: no capability is registered for it and it does not change
:data:`IN_SCOPE_SURFACES`.
The in-UI agent chat (``app/agent_chat``, ``api/routers/agent_chat.py``) is likewise
not a capability: it is a CLIENT of the MCP server (it drives a sandboxed
``memdiver mcp`` child), so everything an agent does is already registered here
through the MCP tools. Its router is an annotated exemption in
``tests/test_capability_completeness.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Tuple

#: Every surface MemDiver can expose a capability on.
ALL_SURFACES: FrozenSet[str] = frozenset(
    {"library", "cli", "web", "mcp", "marimo"}
)

#: Surfaces the cross-surface parity ratchet holds every capability to. ``marimo``
#: is intentionally excluded until its surface is built out.
IN_SCOPE_SURFACES: FrozenSet[str] = frozenset({"library", "cli", "web", "mcp"})


@dataclass(frozen=True)
class Capability:
    """One MemDiver capability, its backing ``app`` producer, and its wiring.

    :param name: Stable dotted capability id (e.g. ``"inspect.processes"``).
    :param producer: Dotted path to the ``app`` producer that owns the compute
        (e.g. ``"memdiver.app.tools_inspect.processes_result"``).
    :param surfaces: The surfaces currently routed to ``producer``.
    """

    name: str
    producer: str
    surfaces: FrozenSet[str]


def _cap(name: str, producer: str, surfaces: Tuple[str, ...]) -> Capability:
    return Capability(name=name, producer=producer, surfaces=frozenset(surfaces))


# The "library" surface means REACHABLE VIA THE SUPPORTED PUBLIC API — i.e.
# re-exported through ``memdiver.services`` (and lifted onto the ``memdiver``
# top level), NOT merely importable from a deep ``memdiver.app.*`` module. As of
# the Phase-6 library-parity work every producer below is re-exported by
# ``memdiver/services.py``, so every capability is genuinely wired on "library".
# The per-capability tuples additionally record cli / web / mcp presence exactly
# as wired today.
CAPABILITIES: Tuple[Capability, ...] = (
    # -- inspect: hex / entropy / strings / byte-search / structured MSL -----
    _cap("inspect.hex", "memdiver.app.tools_inspect.read_hex_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.hex_raw", "memdiver.app.tools_inspect.read_hex_raw_result",
         ("library", "web", "mcp")),
    _cap("inspect.resolve_va", "memdiver.app.tools_inspect.resolve_va_result",
         ("library", "web", "mcp")),
    _cap("inspect.byte_search", "memdiver.app.tools_inspect.search_bytes_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.entropy", "memdiver.app.tools_inspect.entropy_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.strings", "memdiver.app.tools_inspect.strings_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.detect_format", "memdiver.app.tools_inspect.detect_format_result",
         ("library", "web", "mcp")),
    _cap("inspect.session_info", "memdiver.app.tools_inspect.session_info_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.vas", "memdiver.app.tools_inspect.vas_regions_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.page_states", "memdiver.app.tools_inspect.page_states_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.processes", "memdiver.app.tools_inspect.processes_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.modules", "memdiver.app.tools_inspect.modules_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.handles", "memdiver.app.tools_inspect.handles_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.connections", "memdiver.app.tools_inspect.connections_result",
         ("library", "web", "mcp")),
    _cap("inspect.module_index", "memdiver.app.tools_inspect.module_index_result",
         ("library", "web", "mcp")),
    _cap("inspect.blocks", "memdiver.app.tools_inspect.blocks_result",
         ("library", "web", "mcp")),
    # IMPORT_PROVENANCE (0x0030) with its note parsed: which region categories
    # an import kept, what it excluded, and whether the file is a materialized
    # copy (plus the original EoC hash). Wired on all four surfaces at once.
    _cap("inspect.import_provenance",
         "memdiver.app.tools_inspect.import_provenance_result",
         ("library", "cli", "web", "mcp")),
    # "What is at this offset?" — the per-offset investigation view (byte
    # value, local entropy band, printable strings in the neighbourhood). It
    # was a complete, tested producer reachable from NOWHERE, parked in the
    # completeness suite's EXEMPT_PRODUCERS; P2.4 wired the missing web route
    # (GET /api/inspect/region), MCP tool (``analyze_region``), CLI subcommand
    # (``inspect region``) and library re-export in one atomic change, so it is
    # registered truthfully on all four surfaces and needs no KNOWN_PARITY_GAPS
    # entry. The marimo investigation panel still calls
    # core.region_analysis.analyze_region directly, because it holds in-memory
    # variance/hits this path-based producer cannot accept — and marimo is out
    # of IN_SCOPE_SURFACES anyway.
    _cap("inspect.analyze_region", "memdiver.app.tools_inspect.analyze_region_result",
         ("library", "cli", "web", "mcp")),
    # -- xref / structure ----------------------------------------------------
    _cap("xref.cross_references",
         "memdiver.app.tools_xref.get_cross_references_result",
         ("library", "cli", "web", "mcp")),
    _cap("structure.identify",
         "memdiver.app.tools_xref.identify_structure_result",
         ("library", "cli", "web", "mcp")),
    _cap("structure.apply", "memdiver.app.tools_xref.apply_structure_result",
         ("library", "web")),
    # -- pipeline stages (Phase 25) -----------------------------------------
    # The web pipeline (app.pipeline.pipeline_runner, streamed via the task manager)
    # now delegates each stage's compute to these app producers, so web is wired
    # for all of them. ``pipeline.consensus`` on CLI is still a gap — the CLI
    # `consensus` command is a separate region-report implementation, not the
    # origination producer.
    _cap("pipeline.consensus", "memdiver.app.tools_pipeline.consensus",
         ("library", "web", "mcp")),
    _cap("pipeline.search_reduce", "memdiver.app.tools_pipeline.search_reduce",
         ("library", "cli", "web", "mcp")),
    # Android Scudo heaps across cold boots: the chunk-signature reduction behind
    # `search-reduce` on a Scudo session and behind a web pipeline run with `scudo`
    # params. Not on MCP yet (KNOWN_PARITY_GAPS).
    _cap("pipeline.search_reduce_android",
         "memdiver.app.tools_pipeline_android.search_reduce_android",
         ("library", "cli", "web")),
    _cap("pipeline.brute_force", "memdiver.app.tools_pipeline.brute_force",
         ("library", "cli", "web", "mcp")),
    _cap("pipeline.n_sweep", "memdiver.app.tools_pipeline.n_sweep",
         ("library", "cli", "web", "mcp")),
    _cap("pipeline.auto_floor", "memdiver.app.tools_pipeline.auto_floor",
         ("library", "cli", "web", "mcp")),
    _cap("pipeline.emit_plugin", "memdiver.app.tools_pipeline.emit_plugin",
         ("library", "cli", "web", "mcp")),
    _cap("pipeline.export_pattern", "memdiver.app.tools_pipeline.export_pattern",
         ("library", "cli", "web", "mcp")),
    # The exact COMPLEMENT of ``export.key_pattern``: "I know the offset, I do
    # not have the key bytes" -- the path out of ``analyze_candidates`` or a
    # reverse-engineering session. It was CLI-only for a long time (and so sat
    # outside the parity ratchet entirely, parked in the completeness suite's
    # EXEMPT_PRODUCERS); P2.3 wired the missing web route
    # (POST /api/analysis/manual-export), MCP tool (``manual_export_pattern``)
    # and library re-export in one atomic change, so it is registered truthfully
    # on all four surfaces and needs no KNOWN_PARITY_GAPS entry.
    _cap("pipeline.manual_export_pattern",
         "memdiver.app.tools_pipeline.manual_export_pattern",
         ("library", "cli", "web", "mcp")),
    # -- consensus: the aligned window (the N-dump differential viewer) -----
    # The ONE place N dumps are read in correspondence. Registered on all four
    # surfaces in the change that introduced it, precisely so it never joins
    # KNOWN_PARITY_GAPS: a capability that ships web-only is how the CLI and
    # MCP surfaces end up re-deriving slab->VA arithmetic of their own, which
    # is the class of bug this producer exists to delete.
    _cap("consensus.aligned_window",
         "memdiver.app.tools_consensus.aligned_window_result",
         ("library", "cli", "web", "mcp")),
    # The COMPLEMENT of the window: the window answers "what is at this offset
    # in all N dumps", this answers "where are all the offsets worth looking
    # at" -- every occurrence of a class, paginated, each row carrying the
    # navigable offset to jump to. Registered on all four surfaces in the
    # change that introduced it, for the identical reason: the per-row
    # slab -> VA -> offset translation is exactly the arithmetic a surface
    # without this capability re-derives, differently and wrongly.
    _cap("consensus.class_regions",
         "memdiver.app.tools_consensus.class_regions_result",
         ("library", "cli", "web", "mcp")),
    # Anchor-relative consensus: statistics keyed by delta from each dump's OWN
    # anchor (e.g. the located key), the correct frame around heap objects.
    _cap("consensus.anchor",
         "memdiver.app.tools_consensus.anchor_consensus_result",
         ("library", "cli", "web", "mcp")),
    # Who points here: captured words holding a pointer into a target VA
    # interval, with explicit uncaptured-gap coverage.
    _cap("xref.pointers_to",
         "memdiver.app.tools_xref.xref_pointers_result",
         ("library", "cli", "web", "mcp")),
    # Semantic producers: field-boundary proposal around a verified anchor, and
    # the validated artifact model built from it (written to a new .json file).
    _cap("semantic.propose_layout",
         "memdiver.app.tools_semantic.propose_layout_result",
         ("library", "cli", "web", "mcp")),
    _cap("artifact_model.build",
         "memdiver.app.tools_semantic.artifact_model_build_result",
         ("library", "cli", "web", "mcp")),
    _cap("artifact_model.export",
         "memdiver.app.tools_semantic.artifact_model_export_result",
         ("library", "cli", "web", "mcp")),
    _cap("artifact_model.validate",
         "memdiver.app.tools_semantic.artifact_model_validate_result",
         ("library", "cli", "web", "mcp")),
    # -- pcap arm/validate (the pcap verification oracle's first step) -------
    # Wired on all four surfaces since Phase 1 (services.py, CLI `inspect-pcap`,
    # POST /api/pcaps/validate, MCP `inspect_pcap`) but never registered here, so
    # the parity ratchet had a blind spot over it. Registering it is a pure
    # tightening: no KNOWN_PARITY_GAPS entry is needed.
    _cap("pcap.inspect", "memdiver.app.tools_pipeline.inspect_pcap",
         ("library", "cli", "web", "mcp")),
    # -- export: Wireshark NSS key log (the mission's headline artifact) -----
    _cap("export.keylog", "memdiver.app.tools_pipeline.keylog_result",
         ("library", "cli", "web", "mcp")),
    # -- verify + experiment (Phase 5, G4) ----------------------------------
    _cap("verify", "memdiver.app.tools_pipeline.verify_key_result",
         ("library", "cli", "web", "mcp")),
    _cap("experiment", "memdiver.app.experiment_orchestration.experiment_result",
         ("library", "cli", "web", "mcp")),
    # One dump of an existing process (pid or name; local / USB / remote device).
    _cap("capture", "memdiver.app.experiment_orchestration.capture_result",
         ("library", "cli", "web", "mcp")),
    # -- dataset / analysis (app.tools) -------------------------------------
    # CLI scan/analyze are separate (non-producer) implementations
    # (core.discovery.DatasetScanner / engine.batch), so cli is a gap here.
    _cap("dataset.scan", "memdiver.app.tools.scan_dataset",
         ("library", "web", "mcp")),
    _cap("dataset.list_protocols", "memdiver.app.tools.list_protocols",
         ("library", "web", "mcp")),
    _cap("dataset.list_phases", "memdiver.app.tools.list_phases",
         ("library", "web", "mcp")),
    _cap("analysis.analyze_library", "memdiver.app.tools.analyze_library",
         ("library", "web", "mcp")),
    # -- the exploratory differential path (A4) -----------------------------
    # N dumps in, ranked candidates out, with NO oracle and no capture. Wired
    # on all four surfaces from the start: the whole point of the capability is
    # that the analyst who cannot yet confirm a key still reaches a candidate
    # list, and a headless/agent-driven analyst is exactly that analyst.
    _cap("analysis.candidates", "memdiver.app.tools_pipeline.analyze_candidates",
         ("library", "cli", "web", "mcp")),
    # -- the key-location spine (B1/B3) -------------------------------------
    # "I already hold the secret — which of my dumps still contain it, and
    # where?" and "turn that location into a scanning signature". Both claim all
    # four surfaces from the start for the same reason ``analysis.candidates``
    # does: the headless/agent-driven analyst is the one who most needs the
    # honest three-valued verdict, and the exported rule is a file an agent must
    # be able to ask for.
    _cap("analysis.locate_key", "memdiver.app.tools_pipeline.locate_key",
         ("library", "cli", "web", "mcp")),
    _cap("export.key_pattern", "memdiver.app.tools_pipeline.export_key_pattern",
         ("library", "cli", "web", "mcp")),
    # -- the paired field search (C3) ---------------------------------------
    # ``analysis.locate_key`` above is N dumps and ONE needle. This is N
    # (dump, capture) PAIRS, each dump taking its needle from the capture of
    # the run it belongs to -- the question a corpus of independent handshakes
    # can actually answer, and one no key log is read for. Wired on all four
    # surfaces in the change that introduced it (services.py re-export, CLI
    # ``locate-field-pairs``, POST /api/pcaps/locate-field, MCP
    # ``locate_field_across_pairs``), so it needs no KNOWN_PARITY_GAPS entry --
    # and could not have one, since that baseline is shrink-only.
    _cap("analysis.locate_field_pairs",
         "memdiver.app.tools_pipeline.locate_field_across_pairs",
         ("library", "cli", "web", "mcp")),
    # -- running the rules we EMIT (D1) -------------------------------------
    # ``export.key_pattern`` / ``export_pattern`` above write a signature;
    # until this capability landed nothing could RUN one, so every emitted
    # detector was unevaluated BY CONSTRUCTION. ``engine/yara_scan.py`` was
    # fully built and tested and reachable from no surface at all -- the same
    # hole ``pcap.inspect`` sat in, and the reason
    # ``tests/test_capability_completeness.py`` exists. Named
    # ``analysis.yara_scan`` and NOT ``scan.yara``: ``dataset.scan`` above is a
    # dataset WALK, and a ``scan.*`` family beside it would read as a sibling of
    # that rather than of the analysis producers it actually belongs with.
    # Wired on all four surfaces in the change that introduced it (services.py
    # re-export, CLI ``scan-yara``, POST /api/scan/yara, MCP ``scan_yara_rule``),
    # so it needs no KNOWN_PARITY_GAPS entry -- and could not have one, since
    # that baseline is shrink-only.
    _cap("analysis.yara_scan",
         "memdiver.app.tools_pipeline.scan_yara_rule",
         ("library", "cli", "web", "mcp")),
    # -- and scoring what those rules found (D2) ---------------------------
    # The second half of ``analysis.yara_scan``, and the half that makes it
    # mean anything: a scan says the rule FIRED, and a census of firings with
    # no ground truth beside it measures nothing (a rule matching every page
    # scores a perfect dumps_matched). ``engine/detector_metrics.py`` was the
    # same shape of hole as ``engine/yara_scan.py`` before it -- 472 lines,
    # fully tested, reachable from NO surface. Named ``analysis.score_detector``
    # rather than ``analysis.detector_metrics``: the capability is the act of
    # scoring, and the module name is an implementation detail. Wired on all
    # four surfaces in the change that introduced it (services.py re-export,
    # CLI ``score-detector``, POST /api/scan/score, MCP
    # ``score_detector_matches``), so it needs no KNOWN_PARITY_GAPS entry --
    # and could not have one, since that baseline is shrink-only.
    _cap("analysis.score_detector",
         "memdiver.app.tools_pipeline.score_detector_matches",
         ("library", "cli", "web", "mcp")),
    # -- and RUNNING the Volatility3 plugin we emit (D3) --------------------
    # The vol3 half of ``analysis.yara_scan``. Emitting a plugin was never
    # evidence that it works: for most of this repo's life an emitted plugin
    # was checked only by ``ast.parse`` and substring assertions over its
    # generated text, so one that could not even be IMPORTED passed the whole
    # suite -- and Phase B's four real bugs were all found by RUNNING things,
    # one of them a vol3 export that disagreed with the YARA rule it embedded.
    # ``engine/vol3_verify.py`` (in-process) and ``engine/vol3_subproc.py`` (a
    # real ``vol`` launcher) were written to close that loop and were reachable
    # from NO surface at all -- the same hole ``engine/yara_scan.py`` sat in.
    #
    # Named ``analysis.verify_plugin`` and not ``analysis.vol3_verify``: the
    # capability is the act of verifying an emitted detector, and which of the
    # two engine modules answers is a MODE of the request rather than a
    # different capability. Wired on all four surfaces in the change that
    # introduced it (services.py re-export, CLI ``verify-plugin``,
    # POST /api/scan/verify-plugin, MCP ``verify_vol3_plugin``), so it needs no
    # KNOWN_PARITY_GAPS entry -- and could not have one, since that baseline is
    # shrink-only.
    _cap("analysis.verify_plugin",
         "memdiver.app.tools_pipeline.verify_vol3_plugin",
         ("library", "cli", "web", "mcp")),
    # -- frontend-serving producers (Phase 9) -------------------------------
    # Field inference + algorithm-availability gating were duplicated in the
    # React frontend; they now originate here. Both are wired on the library
    # (re-exported via ``memdiver.services``) and web (FastAPI) surfaces. They
    # carry no CLI subcommand or MCP tool — they exist to feed the web UI — so
    # cli / mcp are documented gaps below.
    _cap("analysis.infer_fields", "memdiver.app.tools_fields.infer_fields_result",
         ("library", "web")),
    _cap("analysis.algorithm_availability",
         "memdiver.app.tools_algorithms.algorithm_availability",
         ("library", "web")),
    # -- heap: allocator detection, chunk layout, free lists (0.10.0) ---------
    _cap("heap.detect", "memdiver.app.tools_heap.heap_detect_result",
         ("library", "cli", "web", "mcp")),
    _cap("heap.summary", "memdiver.app.tools_heap.heap_summary_result",
         ("library", "cli", "web", "mcp")),
    _cap("heap.chunks", "memdiver.app.tools_heap.heap_chunks_result",
         ("library", "cli", "web", "mcp")),
    _cap("heap.chunk_at", "memdiver.app.tools_heap.heap_chunk_at_result",
         ("library", "cli", "web", "mcp")),
    _cap("heap.free_lists", "memdiver.app.tools_heap.heap_free_lists_result",
         ("library", "cli", "web", "mcp")),
    _cap("heap.roles", "memdiver.app.tools_heap.heap_roles_result",
         ("library", "cli", "web", "mcp")),
    # -- analysis record: versioned annotations per capture (plan T1.5) ------
    _cap("annotations.list", "memdiver.app.tools_annotations.annotations_list_result",
         ("library", "cli", "web", "mcp")),
    _cap("annotations.add", "memdiver.app.tools_annotations.annotations_add_result",
         ("library", "cli", "web", "mcp")),
    _cap("annotations.supersede",
         "memdiver.app.tools_annotations.annotations_supersede_result",
         ("library", "cli", "web", "mcp")),
    _cap("annotations.retract",
         "memdiver.app.tools_annotations.annotations_retract_result",
         ("library", "cli", "web", "mcp")),
    # -- case data lake + semantic context (plan T1.8 / T1.9) ------------------
    _cap("case.init", "memdiver.app.tools_case.case_init_result",
         ("library", "cli", "web", "mcp")),
    _cap("case.status", "memdiver.app.tools_case.case_status_result",
         ("library", "cli", "web", "mcp")),
    _cap("case.manifest", "memdiver.app.tools_case.case_manifest_result",
         ("library", "cli", "web", "mcp")),
    _cap("case.schema", "memdiver.app.tools_case.case_schema_result",
         ("library", "cli", "web", "mcp")),
    _cap("case.query", "memdiver.app.tools_case.case_query_result",
         ("library", "cli", "web", "mcp")),
    _cap("case.context_at", "memdiver.app.tools_case.context_at_result",
         ("library", "cli", "web", "mcp")),
    _cap("case.export", "memdiver.app.tools_case.case_export_result",
         ("library", "cli", "web", "mcp")),
    # -- memory-image views: probe / profile / open / processes / extract (T1.7) --
    _cap("image.probe", "memdiver.app.tools_image.image_probe_result",
         ("library", "cli", "web", "mcp")),
    _cap("image.profile", "memdiver.app.tools_image.image_profile_result",
         ("library", "cli", "web", "mcp")),
    _cap("image.open_view", "memdiver.app.tools_image.image_open_view_result",
         ("library", "cli", "web", "mcp")),
    _cap("image.processes", "memdiver.app.tools_image.image_processes_result",
         ("library", "cli", "web", "mcp")),
    _cap("image.extract_process", "memdiver.app.tools_image.image_extract_process_result",
         ("library", "cli", "web", "mcp")),
    # -- Volatility 3 plugins over a .mdview (T2.2). User plugin source runs
    # UNSANDBOXED in-process (D7; 127.0.0.1-bound, sha256 logged). vol3.run is
    # inline on CLI/MCP and a job above 30 s / 10000 rows on REST.
    _cap("vol3.plugins", "memdiver.app.tools_vol3.vol3_plugins_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.describe", "memdiver.app.tools_vol3.vol3_describe_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.run", "memdiver.app.tools_vol3.vol3_run_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.query", "memdiver.app.tools_vol3.vol3_query_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.annotate", "memdiver.app.tools_vol3.vol3_annotate_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.scaffold", "memdiver.app.tools_vol3_dev.vol3_scaffold_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.check", "memdiver.app.tools_vol3_dev.vol3_check_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.write_config", "memdiver.app.tools_vol3_dev.vol3_write_config_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.import", "memdiver.app.tools_vol3_dev.vol3_import_parquet_result",
         ("library", "cli", "web", "mcp")),
    # -- Stored user plugin sources (T2.5) and plugin fixtures (T2.8, D13).
    _cap("vol3.source_list", "memdiver.app.tools_vol3_sources.vol3_source_list_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.source_get", "memdiver.app.tools_vol3_sources.vol3_source_get_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.source_put", "memdiver.app.tools_vol3_sources.vol3_source_put_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.fixture_put", "memdiver.app.tools_vol3_fixtures.vol3_fixture_put_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.fixture_list", "memdiver.app.tools_vol3_fixtures.vol3_fixture_list_result",
         ("library", "cli", "web", "mcp")),
    _cap("vol3.fixture_run", "memdiver.app.tools_vol3_fixtures.vol3_fixture_run_result",
         ("library", "cli", "web", "mcp")),
    # -- key finders: structure-based key recognition over captured bytes (T3.3).
    # keyfinders.scan registers the ``key_hits`` case table; REST runs a large
    # scan as a job (app.pipeline.keyfinders_task_runner).
    _cap("keyfinders.list", "memdiver.app.tools_keyfinders.keyfinders_list_result",
         ("library", "cli", "web", "mcp")),
    _cap("keyfinders.scan", "memdiver.app.tools_keyfinders.keyfinders_scan_result",
         ("library", "cli", "web", "mcp")),
    # -- YARA editor: compile-check (errors with lines) and a captured-bytes scan of
    # ONE dump (windowed, VA coordinates, coverage); the N-dump census is analysis.yara_scan.
    # REST runs a large / async scan as a job (app.pipeline.yara_task_runner).
    _cap("yara.check", "memdiver.app.tools_yara.yara_check_result",
         ("library", "cli", "web", "mcp")),
    _cap("yara.scan_dump", "memdiver.app.tools_yara.yara_scan_dump_result",
         ("library", "cli", "web", "mcp")),
    # -- stored YARA rules: a per-user library and per-case directories; check/scan take
    # ``rule_name`` in place of the source.
    _cap("yara.rule_list", "memdiver.app.tools_yara_rules.yara_rule_list_result",
         ("library", "cli", "web", "mcp")),
    _cap("yara.rule_get", "memdiver.app.tools_yara_rules.yara_rule_get_result",
         ("library", "cli", "web", "mcp")),
    _cap("yara.rule_put", "memdiver.app.tools_yara_rules.yara_rule_put_result",
         ("library", "cli", "web", "mcp")),
    _cap("yara.rule_delete", "memdiver.app.tools_yara_rules.yara_rule_delete_result",
         ("library", "cli", "web", "mcp")),
    # -- ISF workbench (P4): pakunoda probes, versioned ISF drafts in a case, and the
    # try-loop. REST runs isf.probe / isf.try as image jobs (app.pipeline.image_task_runner).
    _cap("isf.probe", "memdiver.app.tools_isf.isf_probe_result",
         ("library", "cli", "web", "mcp")),
    _cap("isf.draft.create", "memdiver.app.tools_isf.isf_draft_create_result",
         ("library", "cli", "web", "mcp")),
    _cap("isf.draft.list", "memdiver.app.tools_isf.isf_draft_list_result",
         ("library", "cli", "web", "mcp")),
    _cap("isf.draft.get", "memdiver.app.tools_isf.isf_draft_get_result",
         ("library", "cli", "web", "mcp")),
    _cap("isf.draft.set", "memdiver.app.tools_isf.isf_draft_set_result",
         ("library", "cli", "web", "mcp")),
    _cap("isf.draft.import", "memdiver.app.tools_isf.isf_draft_import_result",
         ("library", "cli", "web", "mcp")),
    _cap("isf.draft.retract", "memdiver.app.tools_isf.isf_draft_retract_result",
         ("library", "cli", "web", "mcp")),
    _cap("isf.draft.versions", "memdiver.app.tools_isf.isf_draft_versions_result",
         ("library", "cli", "web", "mcp")),
    _cap("isf.draft.diff", "memdiver.app.tools_isf.isf_draft_diff_result",
         ("library", "cli", "web", "mcp")),
    _cap("isf.draft.validate", "memdiver.app.tools_isf.isf_draft_validate_result",
         ("library", "cli", "web", "mcp")),
    _cap("isf.draft.export", "memdiver.app.tools_isf.isf_draft_export_result",
         ("library", "cli", "web", "mcp")),
    _cap("isf.try", "memdiver.app.tools_isf.isf_try_result",
         ("library", "cli", "web", "mcp")),
    _cap("code_evidence.field_accesses",
         "memdiver.app.tools_code_evidence.code_evidence_result",
         ("library", "cli", "web", "mcp")),
    _cap("disasm", "memdiver.app.tools_disasm.disasm_result",
         ("library", "cli", "web", "mcp")),
    # -- detector fixtures (T3.7, D13): positive controls / decoys with a verdict
    # for YARA rules and key finders; stored in the case, shared store primitives
    # with the vol3 fixtures.
    _cap("detector_fixtures.run",
         "memdiver.app.tools_detector_fixtures.detector_fixtures_run_result",
         ("library", "cli", "web", "mcp")),
    _cap("detector_fixtures.add",
         "memdiver.app.tools_detector_fixtures.detector_fixtures_add_result",
         ("library", "cli", "web", "mcp")),
    _cap("detector_fixtures.list",
         "memdiver.app.tools_detector_fixtures.detector_fixtures_list_result",
         ("library", "cli", "web", "mcp")),
    _cap("detector_fixtures.remove",
         "memdiver.app.tools_detector_fixtures.detector_fixtures_remove_result",
         ("library", "cli", "web", "mcp")),
    # -- strings as a table (T3.6): registers the ``strings`` case table; the
    # ``strings_iocs`` saved query adds IOC columns. REST runs a large scan as a job.
    _cap("strings.table", "memdiver.app.tools_strings.strings_table_result",
         ("library", "cli", "web", "mcp")),
)


#: (capability, surface) pairs that are IN scope but NOT YET wired — the current,
#: known per-surface parity gaps. This baseline may only SHRINK: the ratchet
#: flags a NEW gap (undocumented) and a STALE gap (documented but now wired).
#:
#: The gaps cluster into a few genuine divergences still to unify:
#:   * inspect read_hex_raw / resolve_va / detect_format / connections /
#:     module_index / blocks and structure.apply lack CLI subcommands.
#:   * structure.apply is web-only (no MCP tool).
#:   * the web pipeline now routes every stage through the app producers
#:     (app.pipeline.pipeline_runner delegates consensus / search_reduce / brute_force /
#:     n_sweep / auto_floor / emit_plugin to ``app.tools_pipeline``), so those are
#:     wired on web. ``pipeline.consensus`` still differs on CLI: the CLI
#:     `consensus` command is a separate region-report implementation, not the
#:     origination producer. (The synchronous ``POST /consensus`` analysis route
#:     is a distinct stateful region/range feature over
#:     ``consensus_session`` — not the origination producer — so it is unaffected.)
#:     ``export_pattern`` is likewise wired everywhere: its CLI `export` command
#:     and the `/auto-export` route both route through the producer.
#:   * dataset scan / list_* / analyze have CLI implementations that do not
#:     route through the app producer.
#:   * pipeline.search_reduce_android has no MCP tool yet that routes to the
#:     producer.
KNOWN_PARITY_GAPS: FrozenSet[Tuple[str, str]] = frozenset({
    ("inspect.hex_raw", "cli"),
    ("inspect.resolve_va", "cli"),
    ("inspect.detect_format", "cli"),
    ("inspect.connections", "cli"),
    ("inspect.module_index", "cli"),
    ("inspect.blocks", "cli"),
    ("structure.apply", "cli"),
    ("structure.apply", "mcp"),
    ("pipeline.consensus", "cli"),
    ("dataset.scan", "cli"),
    ("dataset.list_protocols", "cli"),
    ("dataset.list_phases", "cli"),
    ("analysis.analyze_library", "cli"),
    # Phase-9 frontend-serving producers: web + library only. No CLI subcommand
    # or MCP tool — they feed the React UI (hex neighborhood overlay / wizard
    # availability), not the terminal/agent surfaces.
    ("analysis.infer_fields", "cli"),
    ("analysis.infer_fields", "mcp"),
    ("analysis.algorithm_availability", "cli"),
    ("analysis.algorithm_availability", "mcp"),
    ("pipeline.search_reduce_android", "mcp"),
})


def missing_wirings() -> FrozenSet[Tuple[str, str]]:
    """Return every (capability, surface) that is in scope but not yet wired.

    A pair is missing when ``surface`` is in :data:`IN_SCOPE_SURFACES` but not in
    the capability's recorded ``surfaces``. This is the raw gap set the parity
    ratchet compares against :data:`KNOWN_PARITY_GAPS`.
    """
    gaps = set()
    for cap in CAPABILITIES:
        for surface in IN_SCOPE_SURFACES - cap.surfaces:
            gaps.add((cap.name, surface))
    return frozenset(gaps)
