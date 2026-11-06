"""CLI entry point for MemDiver — headless analysis and interactive UI."""

import argparse
import logging
import sys
from pathlib import Path

# The one app-layer import in this module: parser defaults that must be the
# SAME numbers/names the producers apply, or the CLI would advertise a cap or a
# field the library does not use. numpy is already resolved by
# ``cli.consensus`` above, so this costs no additional startup time.
# ``DEFAULT_PAIR_FIELD_ID`` is locate-field-pairs' --field-id: the producer
# picks ``client_random`` because it is the one field every TLS version carries
# and is unique per handshake, so the flag advertises that choice rather than
# re-spelling it.
# ``DEFAULT_INCLUDE_MATCHES`` is scan-yara's payload verbosity: --count-only is
# spelled as the NEGATION of that constant rather than a bare False, so the flag
# and the producer cannot disagree about which shape is the default one.
# ``DEFAULT_INCLUDE_HITS`` / ``VOL3_*`` are verify-plugin's equivalents: the
# --count-only flag is again the NEGATION of the constant, and --mode /
# --timeout / --max-hits must advertise the SAME vocabulary and budgets the
# producer applies.
# The region-page defaults live with the producer, so `--limit`'s help text
# and its cap cannot drift from the page the producer actually serves.
from memdiver.core.needle import NEEDLE_FORMATS
from memdiver.app.tools_consensus import (
    DEFAULT_REGIONS_PER_PAGE,
    MAX_REGIONS_PER_PAGE,
    REGION_SORTS,
)
from memdiver.app.tools_pipeline import (
    DEFAULT_INCLUDE_HITS,
    DEFAULT_INCLUDE_MATCHES,
    DEFAULT_MAX_RETURNED_REGIONS,
    DEFAULT_PAIR_FIELD_ID,
    DEFAULT_RESOURCE_TYPE,
    VOL3_MAX_HITS,
    VOL3_MODE_AUTO,
    VOL3_MODES,
    VOL3_SUBPROC_TIMEOUT_S,
)
from memdiver.core.service_errors import CapabilityError
# Same reasoning for --neighborhood-pad: the flag must advertise the SAME pad
# the engine applies, so it imports the canonical constant instead of repeating
# the literal (this file used to be one of four places holding a bare 64).
from memdiver.engine.brute_force import DEFAULT_NEIGHBORHOOD_PAD
# Same reasoning again for --context / --max-offsets on the two key-location
# subcommands: the flags must advertise the SAME numbers the engine applies.
from memdiver.engine.key_location import (
    DEFAULT_KEY_CONTEXT,
    DEFAULT_MAX_KEY_OFFSETS,
)
# Same reasoning again for score-detector's --tolerance-bytes: the flag must
# advertise the SAME alignment slack the scorer applies.
from memdiver.engine.detector_metrics import DEFAULT_TOLERANCE_BYTES
# Same reasoning again for scan-yara's --max-matches / --timeout: the flags
# must advertise the SAME cap and libyara budget the engine applies, so they
# import the canonical constants instead of repeating the literals.
from memdiver.engine.yara_scan import (
    DEFAULT_MAX_MATCHES,
    DEFAULT_TIMEOUT_S,
)
# And verify-plugin's two launcher env vars, named in --vol-bin/--vol-python's
# help so an operator can see which variable each flag beats.
from memdiver.engine.vol3_subproc import VOL3_BIN_ENV, VOL3_PYTHON_ENV

from ._shared import (
    _decrypt_parent_parser,
    _region_selection_parent_parser,
    _setup_logging,
    add_allocator_argument,
    add_force_memory_argument,
    add_heap_policy_argument,
    add_keylog_anchor_arguments,
    add_mixed_ok_argument,
    to_cli_exit,
)
from .import_keys import decrypt_output_parent_parser
from .dataset import (
    _cmd_analyze,
    _cmd_batch,
    _cmd_import,
    _cmd_mcp,
    _cmd_notebook,
    _cmd_scan,
    _cmd_ui,
    _cmd_web,
)
from .consensus import (
    _cmd_consensus,
    _cmd_consensus_add,
    _cmd_consensus_anchor,
    _cmd_consensus_begin,
    _cmd_consensus_finalize,
    _cmd_consensus_regions,
    _cmd_consensus_window,
    add_region_filter_arguments,
)
from .capture import _cmd_capture, add_capture_parser
from .heap import _cmd_heap, add_heap_parser
from .annotations import _cmd_annotations, add_annotations_parser
from .case import _cmd_case, add_case_parser
from .image import _cmd_image, add_image_parser
from .fixtures import _cmd_fixtures, add_fixtures_parser
from .keys import _cmd_keys, add_keys_parser
from .yara import _cmd_yara, add_yara_parser
from .isf import _cmd_isf, add_isf_parser
from .disasm import _cmd_disasm, add_disasm_parser
from .strings import _cmd_strings, add_strings_parser
from .vol3 import _cmd_vol3, add_vol3_parser
from .experiment import _cmd_experiment
from .pipeline import (
    DEFAULT_AUTO_EXPORT_CONTEXT,
    _cmd_analyze_candidates,
    _cmd_auto_floor,
    _cmd_brute_force,
    _cmd_emit_plugin,
    _cmd_export,
    _cmd_export_key_pattern,
    _cmd_export_keylog,
    _cmd_gen_kem_key,
    _cmd_import_dir,
    _cmd_inspect_pcap,
    _cmd_locate_field_pairs,
    _cmd_locate_key,
    _cmd_n_sweep,
    _cmd_scan_yara,
    _cmd_score_detector,
    _cmd_verify_plugin,
    _cmd_search_reduce,
    _cmd_verify,
)

from .inspect import (
    _cmd_inspect,
    _cmd_xref_pointers,
)
from .semantic import (
    _cmd_model_build,
    _cmd_model_export,
    _cmd_model_validate,
    _cmd_propose_layout,
)

logger = logging.getLogger("memdiver.cli")

#: Shared help text for ``--neighborhood-pad`` (brute-force + auto-floor).
_NEIGHBORHOOD_PAD_HELP = (
    "Bytes of context sliced on EACH side of a hit for the emitted "
    "neighborhood window (window = pad + key_size + pad, so 160 bytes for a "
    "32-byte key at the default). This value is baked into every Volatility3 "
    "plugin and YARA rule MemDiver emits, so changing it rewrites the emitted "
    f"signature (default: {DEFAULT_NEIGHBORHOOD_PAD})"
)


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(prog="memdiver", description="MemDiver — Memory dump analysis platform")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("ui", help='Launch interactive Marimo UI (needs: pip install "memdiver[marimo]")').add_argument("extra_args", nargs="*", default=[])
    nb = sub.add_parser("notebook", help="Open the case-explorer notebook on a case (needs the marimo extra)")
    nb.add_argument("case", help="Case directory or bare case name")
    nb.add_argument("--edit", action="store_true", help="Open for editing instead of as an app")
    nb.add_argument("--port", type=int, default=None, help="Port for the marimo server")
    nb.add_argument("--headless", action="store_true", help="Do not open a browser")
    az = sub.add_parser("analyze", help="Analyze library directories")
    az.add_argument("library_dirs", nargs="+", help="Library directory paths")
    az.add_argument("--phase", required=True, help="Lifecycle phase")
    az.add_argument("--protocol-version", required=True, help="Protocol version")
    az.add_argument("--keylog-filename", default="keylog.csv")
    az.add_argument("--template", default="Auto-detect")
    az.add_argument("--max-runs", type=int, default=10)
    az.add_argument("--normalize", action="store_true")
    az.add_argument("--no-expand", action="store_true", help="Skip key expansion")
    az.add_argument("-o", "--output", help="Output JSON file")
    add_force_memory_argument(az)
    az.add_argument("-v", "--verbose", action="store_true")
    # scan
    sc = sub.add_parser("scan", help="Scan dataset root")
    sc.add_argument("--root", required=True, help="Dataset root path")
    sc.add_argument("--keylog-filename", default="keylog.csv")
    sc.add_argument("--protocols", nargs="*", help="Protocol names to scan")
    sc.add_argument("-o", "--output", help="Output JSON file")
    sc.add_argument("-v", "--verbose", action="store_true")
    # mcp
    mc = sub.add_parser("mcp", help="Start MCP server for AI integration (included in the base install)")
    mc.add_argument("--sse", action="store_true", help="Use SSE transport instead of stdio")
    mc.add_argument("--port", type=int, default=8080, help="SSE port (default: 8080)")
    mc.add_argument("-v", "--verbose", action="store_true")
    # batch
    bt = sub.add_parser("batch", help="Run batch analysis from config")
    bt.add_argument("--config", required=True, help="Batch config JSON file")
    bt.add_argument("-w", "--workers", type=int, default=1,
                    help="Number of parallel workers (default: 1)")
    bt.add_argument("-o", "--output", help="Output file")
    bt.add_argument("--output-format", choices=["json", "jsonl"], default=None,
                    help="Output format (overrides config); default: from config or 'json'")
    bt.add_argument("-v", "--verbose", action="store_true")
    add_force_memory_argument(bt)
    # web (FastAPI + React — also the default when no command given)
    wp = sub.add_parser("web", help="Launch FastAPI + React web application (included in the base install)")
    # default=None, not 8080: an explicit 8080 here would always beat
    # MEMDIVER_PORT / .env, so the env var could never take effect.
    wp.add_argument("--port", type=int, default=None,
                    help="Server port (default: $MEMDIVER_PORT or 8080)")
    # consensus
    cs = sub.add_parser("consensus", help="Build consensus matrix from dumps",
                        parents=[_decrypt_parent_parser()])
    cs.add_argument("dumps", nargs="+", help="Dump file paths or directories")
    cs.add_argument("--normalize", action="store_true", help="ASLR-aware normalization")
    cs.add_argument("--min-length", type=int, default=16,
                    help="Minimum region length (default: 16)")
    cs.add_argument("--align", action="store_true",
                    help="Apply alignment filtering to KEY_CANDIDATE regions")
    cs.add_argument("--block-size", type=int, default=32,
                    help="Alignment block size (default: 32)")
    cs.add_argument("--alignment-bytes", type=int, default=16,
                    help="Memory alignment (default: 16)")
    cs.add_argument("--density", type=float, default=0.75,
                    help="Alignment density threshold (default: 0.75)")
    cs.add_argument("--convergence", action="store_true",
                    help="Run convergence sweep")
    cs.add_argument("--max-fp", type=int, default=0,
                    help="FP target for convergence (default: 0)")
    cs.add_argument("-o", "--output", help="Output JSON file")
    cs.add_argument("-v", "--verbose", action="store_true")
    add_region_filter_arguments(cs)
    add_force_memory_argument(cs)
    add_allocator_argument(cs)
    add_mixed_ok_argument(cs)
    # incremental consensus (Welford-backed, persisted state)
    cb = sub.add_parser(
        "consensus-begin",
        help="Create a new consensus session on disk (generic Welford, or "
             "Android Scudo collect)",
    )
    cb.add_argument("--state", required=True, help="Path to session state JSON")
    cb.add_argument("--size", type=int, default=None,
                    help="Consensus width in bytes (generic/Welford pipeline). "
                         "Omit and pass --allocator scudo/auto for the Android "
                         "Scudo pipeline; mutually exclusive with "
                         "--allocator scudo.")
    cb.add_argument("dumps", nargs="*",
                    help="Optional dumps the session will be fed: their "
                         "experiment cohort is recorded and enforced by "
                         "consensus-add")
    add_allocator_argument(
        cb, default=None,
        help_text="Select the Android Scudo pipeline instead of --size: "
                  "'scudo' forces it; 'auto' defers to memdiver's allocator "
                  "detection on the reference dump at search-reduce time and "
                  "requires Scudo. Mutually exclusive with --size.")
    add_mixed_ok_argument(cb)
    cb.add_argument("-v", "--verbose", action="store_true")
    ca = sub.add_parser(
        "consensus-add",
        help="Fold one dump into an existing incremental consensus session",
        parents=[_decrypt_parent_parser()],
    )
    ca.add_argument("--state", required=True, help="Path to session state JSON")
    ca.add_argument("dump", help="Path to a .dump or .msl file")
    add_mixed_ok_argument(ca)
    ca.add_argument("-v", "--verbose", action="store_true")
    cf = sub.add_parser(
        "consensus-finalize",
        help="Materialize variance + classifications from a session",
    )
    cf.add_argument("--state", required=True, help="Path to session state JSON")
    cf.add_argument("-o", "--output", help="Output JSON file")
    cf.add_argument("-v", "--verbose", action="store_true")
    # consensus-window — ONE window, read in every dump at the aligned address
    cw = sub.add_parser(
        "consensus-window",
        help="Read one window in every dump at the address the consensus aligned",
        parents=[_decrypt_parent_parser()],
    )
    cw.add_argument("dumps", nargs="+", help="Dump file paths or directories")
    cw.add_argument("--anchor-dump",
                    help="Dump whose view --offset is a coordinate in "
                         "(omit to anchor on the aligned slab)")
    cw.add_argument("--view", choices=["va", "vas", "raw"], default="va",
                    help="Anchor's navigable view (default: va)")
    cw.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                    help="Window start in the anchor's view (hex or decimal)")
    cw.add_argument("--slab-offset", type=lambda x: int(x, 0), default=None,
                    help="Slab-coordinate anchor (mutually exclusive with "
                         "--anchor-dump)")
    cw.add_argument("--length", type=int, default=1024,
                    help="Window length in bytes (default: 1024)")
    cw.add_argument("--normalize", action="store_true",
                    help="ASLR-aware normalization for the build")
    cw.add_argument("--no-classify", dest="classify", action="store_false",
                    help="Skip the consensus build; serve the LABELLED "
                         "unclassified window (every class -1)")
    cw.add_argument("--no-bytes", action="store_true",
                    help="Return coordinates and classes without the bytes")
    cw.add_argument("-o", "--output", help="Output JSON file")
    cw.add_argument("-v", "--verbose", action="store_true")
    add_region_filter_arguments(cw)
    add_force_memory_argument(cw)
    add_allocator_argument(cw)
    add_mixed_ok_argument(cw)
    # consensus-regions — EVERY occurrence of a class, paginated and jumpable
    cr = sub.add_parser(
        "consensus-regions",
        help="List every occurrence of a consensus class, with jump offsets",
        parents=[_decrypt_parent_parser()],
    )
    cr.add_argument("dumps", nargs="+", help="Dump file paths or directories")
    cr.add_argument("--classes", nargs="+", default=None,
                    help="Byte classes to list: invariant, structural, "
                         "pointer, key_candidate, or non_invariant (default: "
                         "the non_invariant union — real key material is "
                         "class-MIXED, so a per-class query shatters it)")
    cr.add_argument("--min-length", type=int, default=8,
                    help="Shortest region to report (default: 8)")
    cr.add_argument("--max-length", type=int, default=0,
                    help="Longest region to report; 0 = unbounded")
    cr.add_argument("--sort", choices=list(REGION_SORTS), default="offset",
                    help="Row order: offset (address order) or by region "
                         "length (default: offset)")
    cr.add_argument("--after", type=lambda x: int(x, 0), default=-1,
                    help="Exclusive cursor — the previous page's next_after. "
                         "An aligned-space offset when --sort=offset, a rank "
                         "index for the length sorts (default: -1)")
    cr.add_argument("--limit", type=int, default=DEFAULT_REGIONS_PER_PAGE,
                    help=f"Rows per page (default: {DEFAULT_REGIONS_PER_PAGE}, "
                         f"max {MAX_REGIONS_PER_PAGE})")
    cr.add_argument("--anchor-dump",
                    help="Dump whose coordinate the jump offsets are in "
                         "(omit for slab coordinates only)")
    cr.add_argument("--view", choices=["va", "vas", "raw"], default="va",
                    help="Anchor's navigable view (default: va)")
    cr.add_argument("--no-anchor-offsets", action="store_true",
                    help="Skip opening the anchor entirely — no jump offsets")
    cr.add_argument("--normalize", action="store_true",
                    help="ASLR-aware normalization for the build")
    cr.add_argument("-o", "--output", help="Output JSON file")
    cr.add_argument("-v", "--verbose", action="store_true")
    add_region_filter_arguments(cr)
    add_force_memory_argument(cr)
    add_allocator_argument(cr)
    add_mixed_ok_argument(cr)
    # consensus-anchor — statistics keyed by delta from each dump's own anchor
    ca = sub.add_parser(
        "consensus-anchor",
        help="Consensus relative to each dump's own anchor (e.g. the key)",
    )
    ca.add_argument("dumps", nargs="+", help="Dump file paths or directories")
    ca.add_argument("--needle", help="Hex needle searched in EVERY dump")
    ca.add_argument("--needle-file",
                    help="JSON {dump_path: hex} (one needle per dump)")
    ca.add_argument("--anchor", action="append", metavar="PATH=VA",
                    help="Explicit anchor (absolute VA); repeatable")
    ca.add_argument("--occurrence", type=int, default=0,
                    help="Which needle occurrence per dump (default: 0)")
    ca.add_argument("--delta-start", type=int, default=-256,
                    help="Window start relative to the anchor (default: -256)")
    ca.add_argument("--length", type=int, default=768,
                    help="Window length in bytes (default: 768)")
    ca.add_argument("--min-instances", type=int, default=None,
                    help="Instances that must capture a delta (default: all)")
    ca.add_argument("--include-bytes", action="store_true",
                    help="Also emit per-delta classes and reference_hex")
    ca.add_argument("-o", "--output", help="Output JSON file")
    ca.add_argument("-v", "--verbose", action="store_true")
    add_mixed_ok_argument(ca)
    add_keylog_anchor_arguments(ca)
    # propose-layout / model-build — semantic producers (app.tools_semantic)
    for cmd, help_text in (
            ("propose-layout", "Propose field boundaries around a verified anchor (N dumps)"),
            ("model-build", "Build an artifact model from the proposal; writes a NEW .json")):
        sp = sub.add_parser(cmd, help=help_text)
        sp.add_argument("dumps", nargs="+", help="Dump file paths or directories")
        sp.add_argument("--needle", help="Hex needle searched in EVERY dump")
        sp.add_argument("--needles-file", help="JSON {dump_path: hex} (one needle per dump)")
        sp.add_argument("--anchor", action="append", metavar="PATH=VA",
                        help="Explicit anchor (absolute VA); repeatable")
        sp.add_argument("--related-file", help="JSON {name: {dump_path: hex}}")
        sp.add_argument("--occurrence", type=int, default=0)
        sp.add_argument("--delta-start", type=int, default=-2048)
        sp.add_argument("--length", type=int, default=6144)
        sp.add_argument("--anchor-length", type=int, default=None,
                        help="Anchor bytes (default: needle length; required with --anchor)")
        sp.add_argument("--pointer-quorum", type=int, default=None)
        sp.add_argument("--no-heap", action="store_true",
                        help="Skip allocator-chunk object bounds")
        sp.add_argument("--case-dir", help="File one structure_proposal entry per capture")
        sp.add_argument("--detail", choices=("summary", "full"), default="summary",
                        help="summary (default) omits bulky keys; full is the complete payload")
        sp.add_argument("-o", "--output", help="Output JSON file")
        sp.add_argument("-v", "--verbose", action="store_true")
        add_mixed_ok_argument(sp)
        add_keylog_anchor_arguments(sp)
        if cmd == "model-build":
            sp.add_argument("--name", required=True, help="Model name")
            sp.add_argument("--spec-file",
                            help="JSON {meanings, relationships, applicability}")
            sp.add_argument("--prefilter-length", type=int, default=64)
            sp.add_argument("--out-path", required=True,
                            help="NEW .json file the model is written to")
    # model-export / model-validate — plugin from a model; held-out scoring
    me = sub.add_parser("model-export",
                        help="Export an artifact model as a Volatility3 plugin (NEW .py)")
    me.add_argument("model", help="Artifact model JSON")
    me.add_argument("--out-path", required=True, help="NEW .py file the plugin is written to")
    me.add_argument("--plugin-name", help="Plugin class name")
    me.add_argument("-o", "--output", help="Output JSON file")
    me.add_argument("-v", "--verbose", action="store_true")
    mv = sub.add_parser("model-validate",
                        help="Score a model's plugin on held-out captures (needs volatility3)")
    mv.add_argument("model", help="Artifact model JSON")
    mv.add_argument("--held-out-file",
                    help="JSON [{dump_path, keylog_path | expected:[{label,owner_hex,value_hex}]}]")
    mv.add_argument("--keylog-run-dir", nargs="+", metavar="DIR",
                    help="Run dirs pairing DIR/dumps/msl/*.msl with DIR/keylog.csv")
    mv.add_argument("--held-out-dumps", nargs="+", metavar="DUMP",
                    help="Held-out dumps scored against the shared --keylog")
    mv.add_argument("--labels", nargs="+", help="Labels to score (default: the model's)")
    mv.add_argument("--plugin", help="Use this exported plugin instead of exporting in memory")
    mv.add_argument("--out-path", help="NEW .json: the model with its validation recorded")
    mv.add_argument("--min-run", type=int, default=64)
    add_keylog_anchor_arguments(mv, shared_only=True)
    mv.add_argument("-o", "--output", help="Output JSON file")
    mv.add_argument("-v", "--verbose", action="store_true")
    # xref-pointers — which captured words point into a target VA span
    xp = sub.add_parser(
        "xref-pointers",
        help="Who points here: captured words holding a pointer into a target VA",
    )
    xp.add_argument("dump_path", metavar="DUMP", help=".msl / core dump (needs VAs)")
    xp.add_argument("--target", type=lambda x: int(x, 0), required=True,
                    help="Target VA (hex or decimal)")
    xp.add_argument("--before", type=lambda x: int(x, 0), default=0,
                    help="Bytes below the target included in the interval")
    xp.add_argument("--after", type=lambda x: int(x, 0), default=1,
                    help="Bytes from the target up (exclusive end; default: 1)")
    xp.add_argument("--word-size", type=int, choices=(4, 8), default=8)
    xp.add_argument("--alignment", type=int, default=8)
    xp.add_argument("--max-refs", type=int, default=1000)
    xp.add_argument("--exclude-target", action="store_true",
                    help="Skip holders lying inside the target interval itself")
    xp.add_argument("-o", "--output", help="Output JSON file")
    xp.add_argument("-v", "--verbose", action="store_true")
    # search-reduce
    sr = sub.add_parser(
        "search-reduce",
        help="Reduce candidate set: variance → alignment → entropy "
             "(generic/Welford), or an Android Scudo heap session",
        parents=[_decrypt_parent_parser()],
    )
    sr.add_argument("--state", required=True,
                    help="Path to a consensus state JSON: a generic (Welford) "
                         "session, or an Android Scudo collect session "
                         "(consensus-begin --allocator scudo/auto). The state's "
                         "kind selects the pipeline.")
    sr.add_argument("--reference-dump", required=True,
                    help="One dump file used for per-region entropy sampling "
                         "(generic), or the dump brute-force will read and whose "
                         "flat 'vas' offsets the regions are in (Scudo; must be "
                         "one of the collected dumps)")
    sr.add_argument("--alignment", type=int, default=8)
    sr.add_argument("--block-size", type=int, default=32)
    sr.add_argument("--density-threshold", type=float, default=0.5)
    sr.add_argument("--min-variance", type=float, default=3000.0,
                    help="Variance floor for candidate regions (default 3000). "
                         "The output's 'recommended_floor' is a data-driven "
                         "suggestion to consider here (0.0 = too few dumps / no "
                         "crypto component: keep everything).")
    sr.add_argument("--entropy-window", type=int, default=32)
    sr.add_argument("--entropy-threshold", type=float, default=4.5)
    sr.add_argument("--min-region", type=int, default=16)
    sr.add_argument("--max-region", type=int, default=0,
                    help="Drop regions LONGER than this many bytes (0 = unbounded)")
    sr.add_argument("--classes",
                    help="Comma-separated ByteClass bands to keep: invariant, "
                         "structural, pointer, key_candidate. Applied IN "
                         "ADDITION to --min-variance, whose 3000 default "
                         "already excludes everything below key_candidate — "
                         "pass --min-variance 0 with a multi-class query.")
    sr.add_argument("--order", choices=("offset", "rank"), default="offset",
                    help="Order of the emitted regions (default offset). Every "
                         "region carries 'rank' and 'score' either way.")
    sr.add_argument("--key-sizes", default="32",
                    help="Scudo session only: comma-separated key sizes for the "
                         "reported window estimate (never filters; default 32, "
                         "brute-force's default; 48 for TLS_AES_256_GCM_SHA384). "
                         "Ignored by the generic/Welford path.")
    sr.add_argument("-o", "--output", required=True, help="Output candidates.json")
    sr.add_argument("-v", "--verbose", action="store_true")
    # The Welford --state session carries no heap roles, so 'annotate' is a
    # no-op there and 'mask' is refused (use analyze-candidates for heap work).
    add_heap_policy_argument(sr)
    # Scudo session only: lift the cohort.mixed refusal when the collected dumps
    # span experiment cohorts on purpose. Ignored by the generic/Welford path.
    add_mixed_ok_argument(sr)
    # analyze-candidates (the exploratory path: no oracle, no capture)
    ac = sub.add_parser(
        "analyze-candidates",
        help="Rank candidate regions across N dumps (no oracle needed)",
        parents=[_decrypt_parent_parser()],
    )
    ac.add_argument("dumps", nargs="+", help="Dump file paths or directories (N >= 2)")
    ac.add_argument("--classes",
                    help="Comma-separated ByteClass bands to keep: invariant, "
                         "structural, pointer, key_candidate. Real key material "
                         "is class-MIXED, so prefer all three non-invariant "
                         "bands over key_candidate alone.")
    ac.add_argument("--min-variance", type=float, default=None,
                    help="Variance floor. Left unset it resolves against "
                         "--classes: 3000 with no class named, 0 with one, so a "
                         "class query is not silently re-narrowed by this floor.")
    ac.add_argument("--min-region", type=int, default=16)
    ac.add_argument("--max-region", type=int, default=0,
                    help="Drop regions LONGER than this many bytes (0 = unbounded)")
    ac.add_argument("--alignment", type=int, default=8)
    ac.add_argument("--block-size", type=int, default=32)
    ac.add_argument("--density-threshold", type=float, default=0.5)
    ac.add_argument("--entropy-window", type=int, default=32)
    ac.add_argument("--entropy-threshold", type=float, default=4.5)
    ac.add_argument("--order", choices=("offset", "rank"), default="rank",
                    help="Order of the emitted regions (default rank, best "
                         "first). Every region carries 'rank' and 'score' "
                         "either way.")
    ac.add_argument("--max-returned", type=int,
                    default=DEFAULT_MAX_RETURNED_REGIONS,
                    help=f"Cap the returned regions to this many best-ranked "
                         f"rows (default {DEFAULT_MAX_RETURNED_REGIONS}, "
                         f"0 = uncapped)")
    ac.add_argument("--normalize", action="store_true",
                    help="ASLR-aware normalization for native .msl inputs")
    ac.add_argument("--project-id", default="",
                    help="Project to file the stored comparison under")
    ac.add_argument("-o", "--output", help="Output JSON file")
    ac.add_argument("-v", "--verbose", action="store_true")
    add_force_memory_argument(ac)
    add_heap_policy_argument(ac)
    add_allocator_argument(ac)
    # brute-force
    bf = sub.add_parser(
        "brute-force",
        help="Iterate candidates through a user oracle script",
        parents=[_decrypt_parent_parser()],
    )
    bf.add_argument("--candidates", required=True, help="candidates.json from search-reduce")
    bf.add_argument("--dump", required=True, help="Reference dump file")
    bf.add_argument("--oracle", help="Path to user Python oracle script "
                    "(mutually exclusive with --pcap)")
    bf.add_argument("--oracle-config", help="Optional TOML config passed to build_oracle")
    bf.add_argument("--pcap", help="pcap/pcapng of the same TLS session; confirm a "
                    "recovered key decrypts real captured records via the "
                    "first-party trusted oracle (mutually exclusive with --oracle)")
    bf.add_argument("--tls-client-random", help="Hex TLS client_random restricting "
                    "the pcap oracle to one session")
    bf.add_argument("--pcap-max-records", type=int, default=None,
                    help="Cap the encrypted application-data records each direction "
                    "of a captured session contributes to the pcap oracle "
                    "(default: 16). Lower it for speed, raise it for coverage; "
                    "'inspect-pcap' reports whether a capture is being clipped")
    bf.add_argument("--pcap-max-challenges", type=int, default=None,
                    help="Cap the total challenges the pcap oracle keeps across "
                    "all sessions (default: uncapped). A cap silently discards "
                    "verification work, so it is set explicitly, never by default")
    bf.add_argument("--resource-type", default=DEFAULT_RESOURCE_TYPE,
                    help="Registered verification resource the capture is read "
                    "through (default: tls-pcap, the first-party TLS-over-TCP "
                    "one). Only change it when the capture holds a protocol "
                    "another installed resource handles: "
                    "'inspect-pcap --protocols' lists what a capture holds and "
                    "which resource_type can decrypt each")
    bf.add_argument("--persist-ground-truth", action="store_true",
                    help="Record confirmed hits in the project ground-truth ledger "
                    "(opt-in; no-op if the DuckDB backend is unavailable)")
    bf.add_argument("--key-sizes", default="32", help="Comma-separated key sizes in bytes")
    bf.add_argument("--stride", type=int, default=1,
                    help="Candidate offset step in bytes. Only offsets that are multiples of the stride are tested, so a secret that is not stride-aligned is never reached; the default 1 walks every offset (full coverage). Raise it to trade coverage for speed (default: 1)")
    bf.add_argument("--jobs", type=int, default=0,
                    help="Brute-force worker processes. 0 (default) auto-selects: serial for a small or --first-hit sweep, otherwise a small pool. Any explicit value is used verbatim; 1 forces serial (default: 0)")
    bf.add_argument("--first-hit", action="store_true",
                    help="Stop at the first verified candidate (default: exhaustive)")
    bf.add_argument("--state", help="Consensus state path (attaches neighborhood variance)")
    bf.add_argument("--neighborhood-pad", type=int, default=DEFAULT_NEIGHBORHOOD_PAD,
                    help=_NEIGHBORHOOD_PAD_HELP)
    bf.add_argument("--top-k", type=int, default=10)
    bf.add_argument("-o", "--output", required=True, help="Output hits.json")
    bf.add_argument("-v", "--verbose", action="store_true")
    # n-sweep
    ns = sub.add_parser(
        "n-sweep",
        help="Sweep N=1..N_max; emit survivor-count curve + oracle hits",
        parents=[_decrypt_parent_parser()],
    )
    ns.add_argument("--runs-dir", required=True, help="Directory containing run_* subdirs")
    ns.add_argument("--dump-glob", default="*.msl", help="Glob under each run")
    ns.add_argument("--n-values", default="1,3,5,10,20,30,50,75,100")
    ns.add_argument("--alignment", type=int, default=8)
    ns.add_argument("--block-size", type=int, default=32)
    ns.add_argument("--density-threshold", type=float, default=0.5)
    ns.add_argument("--min-variance", type=float, default=3000.0)
    ns.add_argument("--entropy-window", type=int, default=32)
    ns.add_argument("--entropy-threshold", type=float, default=4.5)
    ns.add_argument("--min-region", type=int, default=16)
    ns.add_argument("--oracle", help="Path to user oracle script "
                    "(mutually exclusive with --pcap)")
    ns.add_argument("--oracle-config", help="Optional TOML config")
    ns.add_argument("--pcap", help="pcap/pcapng of the same TLS session; the sweep "
                    "re-verifies against real captured records through the "
                    "first-party trusted oracle at every N (mutually exclusive "
                    "with --oracle)")
    ns.add_argument("--tls-client-random", help="Hex TLS client_random restricting "
                    "the pcap oracle to one session")
    ns.add_argument("--pcap-max-records", type=int, default=None,
                    help="Cap the encrypted application-data records each direction "
                    "of a captured session contributes to the pcap oracle "
                    "(default: 16); same knob 'brute-force' takes")
    ns.add_argument("--pcap-max-challenges", type=int, default=None,
                    help="Cap the total challenges the pcap oracle keeps across "
                    "all sessions (default: uncapped)")
    ns.add_argument("--resource-type", default=DEFAULT_RESOURCE_TYPE,
                    help="Registered verification resource the capture is read "
                    "through (default: tls-pcap, the first-party TLS-over-TCP "
                    "one). Only change it when the capture holds a protocol "
                    "another installed resource handles: "
                    "'inspect-pcap --protocols' lists what a capture holds and "
                    "which resource_type can decrypt each")
    ns.add_argument("--key-sizes", default="32")
    ns.add_argument("--stride", type=int, default=1,
                    help="Candidate offset step in bytes. Only offsets that are multiples of the stride are tested, so a secret that is not stride-aligned is never reached; the default 1 walks every offset (full coverage). Raise it to trade coverage for speed (default: 1)")
    ns.add_argument("--first-hit", action="store_true")
    ns.add_argument("--escalate", action="store_true",
                    help="If no checkpoint finds a hit, run a floor-free "
                         "descending-variance sweep once at the terminal N "
                         "(reuses the in-memory variance; no re-fold)")
    ns.add_argument("--escalate-oracle-budget", type=int, default=None,
                    help="Optional cap on oracle calls during escalation "
                         "(default: exhaustive)")
    ns.add_argument("--output-dir", required=True, help="Directory for report.{json,md,html}")
    add_mixed_ok_argument(ns)
    ns.add_argument("-v", "--verbose", action="store_true")
    # auto-floor
    af = sub.add_parser(
        "auto-floor",
        help="Automated ground-truth-free variance-floor selection (single verdict)",
        parents=[_decrypt_parent_parser()],
    )
    af.add_argument("--state", required=True, help="Path to consensus state JSON")
    af.add_argument("--reference-dump", required=True,
                    help="One dump the oracle verifies candidates against")
    af.add_argument("--oracle", required=True, help="Path to user Python oracle script")
    af.add_argument("--oracle-config", help="Optional TOML config passed to build_oracle")
    af.add_argument("--key-sizes", default="32", help="Comma-separated key sizes in bytes")
    af.add_argument("--stride", type=int, default=1,
                    help="Candidate offset step in bytes. The default 1 walks every offset (full coverage); raise it to trade coverage for speed (default: 1)")
    af.add_argument("--alignment", type=int, default=8)
    af.add_argument("--block-size", type=int, default=32)
    af.add_argument("--density-threshold", type=float, default=0.5)
    af.add_argument("--entropy-window", type=int, default=32)
    af.add_argument("--entropy-threshold", type=float, default=4.5)
    af.add_argument("--min-region", type=int, default=16)
    af.add_argument("--phi0-method", default="pmin", choices=["pmin", "otsu"],
                    help="Recommended-floor method: 'pmin' (phi=p_min*sigma_k^2, "
                         "default) or 'otsu' (legacy data-driven valley fit)")
    af.add_argument("--p-min", type=float, default=0.35,
                    help="Retention policy for --phi0-method pmin: retain keys "
                         "whose per-run correspondence >= p_min (default 0.35)")
    af.add_argument("--coverage", type=float, default=None,
                    help="Precomputed cross-run coverage-intersection C∩ in [0,1] "
                         "(gates/qualifies the ABSENT verdict)")
    af.add_argument("--correspondence", type=float, default=None,
                    help="Precomputed correspondence score in [0,1] (reported)")
    af.add_argument("--filter-recall", type=float, default=None,
                    help="Precomputed entropy/alignment filter recall in [0,1]")
    af.add_argument("--min-coverage", type=float, default=0.80)
    af.add_argument("--self-test-trials", type=int, default=8,
                    help="Oracle self-test random-negative probes (lower for "
                         "one-shot/rate-limited oracles; each costs one call)")
    af.add_argument("--oracle-budget", type=int, default=None,
                    help="Max total oracle calls; if the maximal set is not "
                         "exhausted within budget, the verdict is INCONCLUSIVE(cost), "
                         "never a false ABSENT")
    af.add_argument("--alignment-quality", type=float, default=None,
                    help="Precomputed per-region alignment quality in [0,1]; below "
                         "--min-alignment a no-hit is INCONCLUSIVE(alignment)")
    af.add_argument("--min-alignment", type=float, default=0.5)
    af.add_argument("--managed-region", action="store_true",
                    help="Target is a managed runtime / moving-GC heap: a no-hit is "
                         "INCONCLUSIVE(regime) (off-grid object headers may hide the key)")
    af.add_argument("--neighborhood-pad", type=int, default=DEFAULT_NEIGHBORHOOD_PAD,
                    help=_NEIGHBORHOOD_PAD_HELP)
    af.add_argument("--positive-control",
                    help="Hex of a known-good key for the oracle self-test (optional)")
    af.add_argument("--output-dir", required=True, help="Directory for verdict.json/report.md")
    af.add_argument("-v", "--verbose", action="store_true")
    # emit-plugin
    ep_emit = sub.add_parser(
        "emit-plugin",
        help="Emit a Volatility3 plugin from a brute-force hit neighborhood",
        parents=[_decrypt_parent_parser()],
    )
    ep_emit.add_argument("--hit", required=True, help="hits.json from brute-force")
    ep_emit.add_argument("--reference", required=True, help="Reference dump file")
    ep_emit.add_argument("--name", required=True, help="Plugin class / rule name")
    ep_emit.add_argument("--hit-index", type=int, default=0)
    ep_emit.add_argument("--description")
    ep_emit.add_argument(
        "--variance-threshold", type=float, default=None,
        help="Max variance for static bytes (default: 2000). Lower values "
        "produce more wildcards → more cross-session robust patterns.",
    )
    ep_emit.add_argument("-o", "--output", required=True, help="Output .py file path")
    ep_emit.add_argument("-v", "--verbose", action="store_true")
    # export
    ex = sub.add_parser("export", help="Export pattern as YARA/JSON/Volatility3",
                        parents=[_decrypt_parent_parser()])
    ex.add_argument("dumps", nargs="+", help="Dump file paths or directories")
    ex.add_argument("--offset", type=lambda x: int(x, 0), default=None,
                    help="Region offset (hex or decimal)")
    ex.add_argument("--length", type=int, default=None, help="Region length in bytes")
    ex.add_argument("--auto", action="store_true",
                    help="Auto-detect largest KEY_CANDIDATE region")
    # default=None, NOT 32: the manual (--offset/--length) path cannot honour
    # --context at all, so it must be able to tell "omitted" from an explicit
    # value and refuse only the latter. The 32 is resolved in _cmd_export.
    ex.add_argument("--context", type=int, default=None,
                    help=f"--auto only: static-anchor bytes kept on each side "
                         f"of the AUTO-DETECTED region (default: "
                         f"{DEFAULT_AUTO_EXPORT_CONTEXT}). Not applicable with "
                         f"--offset/--length -- use `export-key-pattern "
                         f"--context N` to pad a known key instead")
    ex.add_argument("--name", default="memdiver_pattern", help="Pattern name")
    ex.add_argument("--format", default="volatility3",
                    choices=["yara", "json", "volatility3", "vol3"])
    ex.add_argument("--min-static-ratio", type=float, default=0.3,
                    help="Minimum static byte ratio (default: 0.3)")
    ex.add_argument("--align", action="store_true",
                    help="Use alignment-filtered candidates for auto-detection")
    ex.add_argument("-o", "--output", help="Output file path")
    ex.add_argument("-v", "--verbose", action="store_true")
    add_force_memory_argument(ex)
    # locate-key (where ONE known secret sits across N dumps)
    # The epilog is the scripting contract (cli.pipeline._LOCATE_KEY_EXIT plus
    # the CapabilityError backstop below); Raw* keeps its table aligned.
    lk = sub.add_parser(
        "locate-key",
        help="Locate a KNOWN secret across N dumps (exit 0 found / 3 absent / "
             "2 not searched or invalid input)",
        description="Search every given dump for ONE known secret and report "
                    "where it sits. The verdict is three-valued, so a dump "
                    "that could not be read is never reported as an absence.",
        epilog="exit codes:\n"
               "  0  found — the secret is in at least one searched dump\n"
               "  3  absent — every dump was searched, the secret is in none\n"
               # One line per row: sphinx-argparse renders this epilog as
               # reStructuredText, where a deeper-indented continuation line
               # is an "Unexpected indentation" error.
               "  2  not searched — no dump could be searched (unreadable / "
               "too small)\n"
               "  2  invalid input — bad hex, missing dump path, bad "
               "--pcap-field, locked encrypted dump\n"
               "\n"
               "The JSON payload (-o) is written for 0, 3 and 2-not-searched;\n"
               "invalid input writes none.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[_decrypt_parent_parser()],
    )
    lk.add_argument("dumps", nargs="+",
                    help="Dump file paths or directories (N >= 1: locating a "
                         "key in ONE dump is a complete answer)")
    lk_form = lk.add_mutually_exclusive_group(required=True)
    lk_form.add_argument("--key-hex",
                         help="The secret as hex bytes ('aa bb cc' and "
                              "'0xaabbcc' both accepted)")
    lk_form.add_argument("--keylog-line",
                         help="One NSS key-log row: "
                              "'<LABEL> <client_random_hex> <secret_hex>'")
    # The SYMBOLIC form (C2): name a handshake field instead of pasting its
    # bytes. In the same mutually-exclusive group as the two hex forms, so the
    # parser refuses a mixture before the producer is ever reached.
    lk_form.add_argument("--pcap-field", metavar="FIELD_ID",
                         help="Read the needle off the wire instead of pasting "
                              "it: a field id from --pcap, e.g. 'client_random' "
                              "or 'sni'. List them with "
                              "'inspect-pcap --fields'. Only searchable fields "
                              "are accepted (a short field matches everywhere)")
    lk.add_argument("--pcap",
                    help="Capture --pcap-field is read from (required with it). "
                         "Same spelling as brute-force's --pcap")
    lk.add_argument("--pcap-session", metavar="CLIENT_RANDOM",
                    help="Which session's --pcap-field to take, by client_random "
                         "hex. Needed only when the capture holds several: "
                         "there is no default, because the wrong session's field "
                         "is a valid-looking needle from another handshake")
    lk.add_argument("--view", default=None,
                    help="Byte view to search (default: the format's own — "
                         "'raw' for raw dumps, 'vas' for .msl)")
    lk.add_argument("--max-offsets", type=int, default=DEFAULT_MAX_KEY_OFFSETS,
                    help=f"Offsets RETURNED per dump (default "
                         f"{DEFAULT_MAX_KEY_OFFSETS}); hit_count stays the "
                         f"true total either way")
    lk.add_argument("-o", "--output", help="Output JSON file")
    lk.add_argument("-v", "--verbose", action="store_true")
    add_allocator_argument(lk)
    # locate-field-pairs (N (dump, capture) pairs, each with its OWN needle)
    lfp = sub.add_parser(
        "locate-field-pairs",
        help="Locate a handshake FIELD across N dumps, each dump taking the "
             "field from its own capture (exit 0 found / 3 absent / 2 nothing "
             "searched)",
        parents=[_decrypt_parent_parser()],
    )
    lfp.add_argument("dumps", nargs="*",
                     help="Dump file paths or directories. Each finds the "
                          "capture of the run it lives in (run_data/traffic."
                          "pcap*, meta.json's 'capture', or a capture beside "
                          "the dumps). Mutually exclusive with --pairs")
    lfp.add_argument("--pairs", metavar="JSON",
                     help="Explicit pairings instead of discovery: a JSON file "
                          "(or inline JSON) holding a list of "
                          "{'dump_path', 'pcap_path', 'client_random'?} dicts. "
                          "There is no precedence between this and the "
                          "positional dumps -- supply exactly one")
    lfp.add_argument("--field-id", default=DEFAULT_PAIR_FIELD_ID,
                     help=f"Handshake field to search for (default "
                          f"{DEFAULT_PAIR_FIELD_ID}). List a capture's ids with "
                          f"'inspect-pcap --fields'; only searchable ones are "
                          f"accepted")
    lfp.add_argument("--view", default=None,
                     help="Byte view to search (default: the format's own — "
                          "'raw' for raw dumps, 'vas' for .msl)")
    lfp.add_argument("--max-offsets", type=int, default=DEFAULT_MAX_KEY_OFFSETS,
                     help=f"Offsets RETURNED per dump (default "
                          f"{DEFAULT_MAX_KEY_OFFSETS}); hit_count stays the "
                          f"true total either way")
    lfp.add_argument("--pcap-max-records", type=int, default=None,
                     help="Cap the encrypted application-data records each "
                          "direction contributes when the capture is parsed")
    lfp.add_argument("--pcap-max-challenges", type=int, default=None,
                     help="Cap the total decryption challenges kept ACROSS all "
                          "sessions when the capture is parsed")
    lfp.add_argument("-o", "--output", help="Output JSON file")
    lfp.add_argument("-v", "--verbose", action="store_true")
    # scan-yara (RUN an emitted rule over N dumps -- the other half of export)
    sy = sub.add_parser(
        "scan-yara",
        help="Scan N dumps with a YARA rule set (exit 0 matched / 3 proven "
             "clean / 2 inconclusive or nothing scanned)",
        parents=[_decrypt_parent_parser()],
    )
    sy.add_argument("dumps", nargs="+",
                    help="Dump file paths or directories to scan. Each is "
                         "scanned in ITS OWN default view unless --view says "
                         "otherwise ('raw' for raw dumps, 'vas' for .msl)")
    # Deliberately NOT a mutually exclusive group: the producer owns the
    # exactly-one-of refusal (and names both forms in it), so all four surfaces
    # report the mistake in the same words instead of argparse inventing its
    # own for this one. Same posture as locate-field-pairs' --pairs.
    sy.add_argument("--rule-source", metavar="TEXT",
                    help="YARA rule TEXT, inline. Mutually exclusive with "
                         "--rule-file, with no precedence -- supply exactly "
                         "one. A precompiled .yarc is never accepted: it is "
                         "executable libyara bytecode, so loading one would be "
                         "a code-loading surface")
    sy.add_argument("--rule-file", action="append", metavar="PATH",
                    help="Path to a .yar rule file; repeat for several. Each "
                         "file is compiled into its own YARA namespace, so two "
                         "files may define the same rule name")
    sy.add_argument("--view", default=None,
                    help="Byte view to scan (default: the format's own — "
                         "'raw' for raw dumps, 'vas' for .msl)")
    sy.add_argument("--max-matches", type=int, default=DEFAULT_MAX_MATCHES,
                    help=f"Matches KEPT per dump (default "
                         f"{DEFAULT_MAX_MATCHES}); the row's scan.truncated "
                         f"says when the cap bit. Must be positive — pass "
                         f"--no-max-matches for an uncapped census")
    sy.add_argument("--no-max-matches", dest="max_matches",
                    action="store_const", const=None,
                    help="Scan without a match cap. Spelled as its own flag "
                         "because 0 is REFUSED rather than read as "
                         "'unlimited': a cap computed to 0 means stop")
    sy.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S,
                    help=f"libyara budget in seconds, per chunk on the chunked "
                         f"strategy and per file on the filepath one (default "
                         f"{DEFAULT_TIMEOUT_S}). Exhausting it leaves bytes "
                         f"UNSCANNED and makes a zero-match result "
                         f"inconclusive, never clean")
    sy.add_argument("--overlap-bytes", type=int, default=0,
                    help="Bytes stitched between chunks so a match straddling "
                         "a boundary is still seen whole. 0 (the default) sizes "
                         "it from the rules' pattern_length meta, which every "
                         "MemDiver-emitted rule carries")
    # --count-only, and not --no-matches. Three reasons, in order of weight:
    # this parser ALREADY carries --no-max-matches, and two flags differing by
    # one word ("--no-matches" / "--no-max-matches") is a mistyping hazard that
    # argparse's prefix matching would resolve silently; "no matches" is also
    # already what the `clean` verdict MEANS on this command, so the flag would
    # read as an assertion about the result rather than a request about the
    # output; and --count-only says positively what you get back rather than
    # only what is missing.
    sy.add_argument("--count-only", dest="count_only", action="store_true",
                    default=not DEFAULT_INCLUDE_MATCHES,
                    help="Return COUNTS without the per-match lists. Every "
                         "count and flag is kept (match_count per dump, "
                         "matches_total, truncated, timed_out, errors, "
                         "scanned_bytes, chunks, strategy, the verdict); only "
                         "each row's matches list is omitted. Bounds the "
                         "OUTPUT, not the scan: libyara still finds every "
                         "match, so this is no faster — but an unselective "
                         "rule over a corpus writes gigabytes of matched_hex "
                         "otherwise. Independent of --max-matches, so combine "
                         "it with --no-max-matches for an honest census (under "
                         "a cap the counts are a floor, and the payload's "
                         "count_only diagnostic says so)")
    sy.add_argument("-o", "--output", help="Output JSON file")
    sy.add_argument("-v", "--verbose", action="store_true")
    # verify-plugin (RUN the emitted vol3 plugin -- the other half of emit,
    # and the vol3 twin of scan-yara)
    vp = sub.add_parser(
        "verify-plugin",
        help="RUN a MemDiver-emitted Volatility3 plugin over N dumps, "
             "in-process and/or through your own vol (exit 0 fired / 3 "
             "measured absence / 2 inconclusive or nothing run)",
        parents=[_decrypt_parent_parser()],
    )
    vp.add_argument("dumps", nargs="+",
                    help="Dump file paths or directories to run the plugin "
                         "over. Each is read in ITS OWN default view unless "
                         "--view says otherwise ('raw' for raw dumps, 'vas' "
                         "for .msl)")
    # Deliberately NOT a mutually exclusive group, exactly as scan-yara's two
    # rule forms are not: the producer owns the exactly-one-of refusal (and
    # names both forms in it), so all four surfaces report the mistake in the
    # same words instead of argparse inventing its own for this one.
    vp.add_argument("--plugin", metavar="PATH",
                    help="Path to an emitted Volatility3 plugin (.py). "
                         "Mutually exclusive with --plugin-source, with no "
                         "precedence -- supply exactly one")
    vp.add_argument("--plugin-source", metavar="TEXT",
                    help="The plugin's Python TEXT, inline -- e.g. the "
                         "'content' field export-key-pattern --format vol3 "
                         "just produced. Mutually exclusive with --plugin")
    vp.add_argument("--mode", default=VOL3_MODE_AUTO, choices=list(VOL3_MODES),
                    help=f"Which runtime runs the plugin (default "
                         f"'{VOL3_MODE_AUTO}'). 'in_process' execs the plugin "
                         f"against the volatility3 MemDiver imports and can "
                         f"scan a PROJECTED view, so it is the only mode that "
                         f"can address an .msl. 'subprocess' runs `vol -p <dir> "
                         f"-f <dump> <module>.<Class>` against your own "
                         f"launcher -- the way a plugin is actually used, and "
                         f"often a different framework version. '{VOL3_MODE_AUTO}' "
                         f"prefers in-process and falls back to the launcher")
    vp.add_argument("--vol-bin", metavar="PATH", default=None,
                    help=f"The vol/vol.py launcher to use, beating "
                         f"${VOL3_BIN_ENV}. This is the 'point me at the "
                         f"actual tool' flag: by default the PyPI volatility3 "
                         f"in MemDiver's own environment is used")
    vp.add_argument("--vol-python", metavar="PATH", default=None,
                    help=f"The interpreter that owns the launcher's "
                         f"volatility3, beating ${VOL3_PYTHON_ENV}. A "
                         f"checkout's vol.py belongs to that checkout's venv, "
                         f"and running it under MemDiver's interpreter "
                         f"silently changes which framework is under test")
    vp.add_argument("--view", default=None,
                    help="Byte view to project for the in-process runtime "
                         "(default: the format's own -- 'raw' for raw dumps, "
                         "'vas' for .msl). Ignored by --mode subprocess, where "
                         "`vol` maps the file itself -- which is exactly why a "
                         "container is REFUSED there rather than reported in "
                         "the wrong coordinate space")
    vp.add_argument("--expected-offset", type=int, default=None,
                    help="A byte position the key is known to occupy. "
                         "Membership is EXACT, with no tolerance: the failure "
                         "worth catching is a hit 64 bytes from the real key, "
                         "and a tolerance would score that as a near miss")
    vp.add_argument("--key-hex", default=None,
                    help="The secret's bytes, to assert the plugin handed the "
                         "KEY back rather than merely fired near it. Accepts "
                         "'aa bb cc' and '0xaabbcc'. Note that an emitted "
                         "pattern WILDCARDS the key, so a window can match a "
                         "dump the key was wiped from -- key_recovered is what "
                         "tells those apart")
    vp.add_argument("--pid", type=int, default=None,
                    help="Passed through to the plugin's --pid. EXPLICITLY "
                         "UNPROVEN: narrowing needs a kernel image plus a "
                         "matching ISF so the OS PsList can return a process "
                         "layer, and a flat process dump has neither -- the "
                         "emitted plugin then warns and scans the whole layer "
                         "anyway. A diagnostic says so on every run")
    vp.add_argument("--timeout", type=int, default=VOL3_SUBPROC_TIMEOUT_S,
                    help=f"Wall-clock ceiling for ONE subprocess plugin run, "
                         f"in seconds (default {VOL3_SUBPROC_TIMEOUT_S})")
    vp.add_argument("--max-hits", type=int, default=VOL3_MAX_HITS,
                    help=f"Hits RETAINED per dump (default {VOL3_MAX_HITS}). "
                         f"match_count stays the honest total and hits_capped "
                         f"says when the cap bit -- which also means "
                         f"key_recovered may then be a false negative")
    vp.add_argument("--count-only", dest="count_only", action="store_true",
                    default=not DEFAULT_INCLUDE_HITS,
                    help="Return COUNTS without the per-hit lists. Every count "
                         "and flag is kept; only each row's hits list is "
                         "omitted. Bounds the OUTPUT, not the run")
    vp.add_argument("-o", "--output", help="Output JSON file")
    vp.add_argument("-v", "--verbose", action="store_true")
    # score-detector (was the rule RIGHT? -- the other half of scan-yara)
    sd = sub.add_parser(
        "score-detector",
        help="Score detector firings against known-true key intervals "
             "(exit 0 scored / 3 measured total miss / 2 nothing scorable)",
    )
    # Deliberately NOT a mutually exclusive group, and deliberately no
    # `required=`: the producer owns the exactly-one-of refusal over the two
    # intakes (and names both in it), so all four surfaces report the mistake
    # in the same words. Same posture as scan-yara's two rule forms.
    sd.add_argument("--matches", metavar="JSON|PATH",
                    help="The detector's firings, as a JSON list (a file path "
                         "or inline JSON) of {'offset','length'} objects, "
                         "optionally with 'key_offset'/'key_length'. This is "
                         "exactly a scan-yara row's scan.matches. Pair with "
                         "--truths; mutually exclusive with --rows, with no "
                         "precedence")
    sd.add_argument("--truths", metavar="JSON|PATH",
                    help="The known-true key intervals, as a JSON list of "
                         "{'start'(or 'offset'),'length'} objects, ideally "
                         "with 'source' ('keylog'/'ledger') so sparse ledger "
                         "corroboration is not mistaken for complete key-log "
                         "truth")
    sd.add_argument("--rows", metavar="JSON|PATH",
                    help="N pre-grouped rows instead: a JSON list of "
                         "{'matches','truths','detector','dump'} objects. Each "
                         "row is scored INDEPENDENTLY and only the counts are "
                         "summed, so a firing from one dump can never pair "
                         "with a truth from another whose offsets line up")
    sd.add_argument("--detector", default=None,
                    help="Rule/detector name for the --matches/--truths form "
                         "(default 'unknown'). In the --rows form each row "
                         "carries its own")
    sd.add_argument("--dump", default=None,
                    help="Dump label for the --matches/--truths form, carried "
                         "through for provenance. A LABEL only -- nothing is "
                         "opened, and no bytes are read")
    sd.add_argument("--truth-source", action="append", metavar="NAME",
                    help="Override the truth provenance instead of deriving "
                         "it from the intervals' own 'source'; repeat for "
                         "several")
    sd.add_argument("--tolerance-bytes", type=int,
                    default=DEFAULT_TOLERANCE_BYTES,
                    help=f"Slack for the key_offset criterion (default "
                         f"{DEFAULT_TOLERANCE_BYTES}, the alignment=16 "
                         f"grouping candidates are blocked on, so a region "
                         f"starting up to 15 bytes below the true key still "
                         f"counts as the same finding). The 'exact' criterion "
                         f"always runs at 0 and is reported alongside")
    sd.add_argument("-o", "--output", help="Output JSON file")
    sd.add_argument("-v", "--verbose", action="store_true")
    # export-key-pattern (a signature anchored on an already-known secret)
    ekp = sub.add_parser(
        "export-key-pattern",
        help="Export a scanning signature anchored on a KNOWN secret "
             "(wildcards the key, keeps its neighbourhood)",
        parents=[_decrypt_parent_parser()],
    )
    ekp.add_argument("dumps", nargs="+",
                     help="Dump file paths or directories (N >= 2: a static "
                          "mask is a comparison). INCLUDE dumps in which the "
                          "key is absent — they are what wildcard the key.")
    ekp_form = ekp.add_mutually_exclusive_group(required=True)
    ekp_form.add_argument("--key-hex", help="The secret as hex bytes")
    ekp_form.add_argument("--keylog-line", help="One NSS key-log row")
    ekp.add_argument("--context", type=int, default=DEFAULT_KEY_CONTEXT,
                     help=f"Static-anchor bytes per side of the key (default "
                          f"{DEFAULT_KEY_CONTEXT})")
    # yara, NOT the producer's volatility3 — a documented per-surface default
    # divergence of the same kind as --order (rank here, offset in the producer).
    ekp.add_argument("--format", default="yara",
                     choices=("yara", "json", "volatility3", "vol3"),
                     help="Output format (default yara)")
    ekp.add_argument("--name", default="memdiver_key_pattern",
                     help="Pattern / rule name")
    ekp.add_argument("--min-static-ratio", type=float, default=0.3,
                     help="Minimum static-byte ratio for a pattern to be "
                          "emitted (default 0.3). A LOWER bound only — see the "
                          "key_fully_static diagnostic for the upper end.")
    ekp.add_argument("--view", default=None,
                     help="Byte view to read (default: the format's own)")
    ekp.add_argument("--output-dir",
                     help="Also write the rendered pattern into this directory")
    ekp.add_argument("--include-window-hex", action="store_true",
                     help="Include each dump's raw window bytes as hex")
    ekp.add_argument("--max-offsets", type=int, default=DEFAULT_MAX_KEY_OFFSETS,
                     help=f"Offsets returned per dump (default "
                          f"{DEFAULT_MAX_KEY_OFFSETS})")
    ekp.add_argument("-o", "--output", help="Output JSON file")
    ekp.add_argument("-v", "--verbose", action="store_true")
    # export-keylog
    ekl = sub.add_parser(
        "export-keylog",
        help="Emit a Wireshark-loadable NSS key log from recovered TLS secrets",
    )
    ekl.add_argument(
        "--secrets", required=True,
        help="JSON file: list of {secret_type, client_random, secret} dicts "
             "(client_random/secret are hex strings)",
    )
    ekl.add_argument("-o", "--output",
                     help="Output key-log file path (default: stdout)")
    ekl.add_argument("-v", "--verbose", action="store_true")
    # inspect-pcap
    ipc = sub.add_parser(
        "inspect-pcap",
        help="Summarise the TLS sessions in a capture (the pcap arm/validate step)",
    )
    ipc.add_argument("pcap", help="Path to a .pcap/.pcapng capture")
    ipc.add_argument("--pcap-max-records", type=int, default=None,
                     help="Cap the encrypted application-data records each "
                          "direction contributes (default: 16). Pass the same "
                          "value the brute-force run will use so the reported "
                          "caps are the caps actually in force")
    ipc.add_argument("--pcap-max-challenges", type=int, default=None,
                     help="Cap the total decryption challenges kept ACROSS all "
                          "sessions (default: uncapped). TLS 1.3 yields several "
                          "challenges per record, so this is not a record count")
    ipc.add_argument("--fields", action="store_true",
                     help="Also report each session's byte-addressable protocol "
                          "fields (randoms, session ids, SNI, key shares, "
                          "certificates) with their wire provenance, plus a "
                          "top-level field_index. These field ids are what "
                          "'locate-key --pcap-field' takes. Costs a second read "
                          "of the capture, so it is off by default")
    ipc.add_argument("--protocols", action="store_true",
                     help="Also report what protocols the capture holds "
                          "(TLS/QUIC/DTLS/SSH/HTTP), which resource_type would "
                          "read each, and whether anything installed can "
                          "decrypt it. Read this when session_count is 0: the "
                          "capture is not empty, it is something else. Never "
                          "errors -- an unrecognisable capture reports none")
    ipc.add_argument("-o", "--output",
                     help="Output JSON file (default: stdout)")
    ipc.add_argument("-v", "--verbose", action="store_true")
    # gen-kem-key
    gk = sub.add_parser(
        "gen-kem-key",
        help="Generate a KEM keypair for encrypted-MSL recipients (spec §10.4)",
    )
    gk.add_argument("--mechanism", required=True,
                    choices=["X25519", "ML-KEM-768", "ML-KEM-1024",
                             "X25519+ML-KEM-768"],
                    help="Key encapsulation mechanism")
    gk.add_argument("--public-out", required=True,
                    help="Output path for the recipient public key")
    gk.add_argument("--private-out", required=True,
                    help="Output path for the recipient private key "
                         "(use later via --kem-key-file)")
    gk.add_argument("-v", "--verbose", action="store_true")
    # import
    im = sub.add_parser(
        "import", help="Import a dump (raw .dump, ELF core, or minidump) to .msl",
        parents=[_region_selection_parent_parser(), _decrypt_parent_parser(),
                 decrypt_output_parent_parser()])
    im.add_argument("dump_file", help="Dump file path (.dump/.core/.dmp)")
    im.add_argument("-o", "--output", help="Output .msl file path")
    im.add_argument("--pid", type=int, default=0, help="Process ID")
    im.add_argument("--keylog", help="Keylog file for key hints")
    im.add_argument("--maps", metavar="PATH",
                    help="/proc/<pid>/maps-style memory map of a raw dump "
                         "(splits it into real regions; default: auto-detect "
                         "a .maps sidecar with the same name)")
    im.add_argument("-v", "--verbose", action="store_true")
    # import-dir
    imd = sub.add_parser(
        "import-dir",
        help="Import all dumps (.dump/.dmp/.core, .bin with a .maps "
             "sidecar) in a directory to .msl",
        description="Import all dumps in a directory. Region flags apply to "
                    "every dump; an interactive run prompts ONCE, using the "
                    "first dump's regions, and applies that choice to all.",
        parents=[_region_selection_parent_parser(), _decrypt_parent_parser(),
                 decrypt_output_parent_parser()])
    imd.add_argument("run_dir", help="Run directory path")
    imd.add_argument("-o", "--output-dir", required=True, help="Output directory")
    imd.add_argument("--keylog-filename", default="keylog.csv")
    imd.add_argument("-v", "--verbose", action="store_true")
    # verify
    vr = sub.add_parser("verify", help="Verify candidate key via decryption",
                        parents=[_decrypt_parent_parser()])
    vr.add_argument("dump", help="Dump file path")
    vr.add_argument("--offset", type=lambda x: int(x, 0), required=True,
                    help="Candidate key offset (hex or decimal)")
    vr.add_argument("--length", type=int, default=32, help="Key length (default: 32)")
    vr.add_argument("--ciphertext-hex", required=True, help="Known ciphertext (hex)")
    vr.add_argument("--iv-hex", help="IV (hex, default: 0x00010203...0f)")
    vr.add_argument("--nonce-hex", help="AEAD nonce (hex, for GCM/ChaCha20-Poly1305)")
    vr.add_argument("--aad-hex", help="AEAD associated data (hex, optional)")
    vr.add_argument("--tag-hex", help="AEAD authentication tag (hex, for GCM/ChaCha20-Poly1305)")
    vr.add_argument("--cipher", default="AES-256-CBC", help="Cipher name")
    vr.add_argument("--view", choices=["raw", "vas", "va"], default=None,
                    help="Byte view --offset addresses (default: the format's "
                         "own — 'vas' for .msl, the file for flat dumps)")
    vr.add_argument("-o", "--output", help="Output JSON file")
    vr.add_argument("-v", "--verbose", action="store_true")
    # experiment
    ep_exp = sub.add_parser("experiment",
                            help="Run full dump-and-analyze experiment",
                            parents=[_decrypt_parent_parser()])
    ep_exp.add_argument("--target", required=True,
                        help="Target script path (e.g., aes_sample_process.py)")
    ep_exp.add_argument("--num-runs", type=int, default=30,
                        help="Number of dump iterations per tool (default: 30)")
    ep_exp.add_argument("--tools", help="Comma-separated dump tools (default: auto-detect)")
    ep_exp.add_argument("--output-dir", type=Path, default=Path("./experiment_output"),
                        help="Output directory (default: ./experiment_output)")
    ep_exp.add_argument("--convergence", action="store_true",
                        help="Run convergence sweep after dumping")
    ep_exp.add_argument("--max-fp", type=int, default=0,
                        help="FP target for convergence (default: 0)")
    ep_exp.add_argument("--export-format", default="volatility3",
                        choices=["yara", "json", "volatility3"],
                        help="Auto-export format (default: volatility3)")
    ep_exp.add_argument("-o", "--output", help="Output JSON results file")
    ep_exp.add_argument("-v", "--verbose", action="store_true")
    add_force_memory_argument(ep_exp)
    # capture — one dump of an existing process (pid/name, local/USB/remote)
    add_capture_parser(sub)
    # heap — allocator detection, summary, chunk table, chunk lookup, free
    # lists, byte roles over the app.tools_heap producers (same as /api/heap
    # and MCP).
    add_heap_parser(sub)
    # annotations — the versioned analysis record over app.tools_annotations
    # (same producers as /api/annotations and the MCP annotations_* tools).
    add_annotations_parser(sub)
    # case — the case data lake and locate_context over app.tools_case (same
    # producers as /api/case and the MCP case_* / context_at tools).
    add_case_parser(sub)

    # image — memory-image views over app.tools_image (same producers as
    # /api/image and the MCP image_* tools).
    add_image_parser(sub)

    # vol3 — Volatility 3 plugins over app.tools_vol3 / app.tools_vol3_dev (same
    # producers as /api/vol3 and the MCP vol3_* tools).
    add_vol3_parser(sub)

    # keys — key finders over app.tools_keyfinders (same producers as
    # /api/keyfinders and the MCP keyfinders_* tools).
    add_keys_parser(sub)
    # yara — the YARA editor backend over app.tools_yara (same producers as
    # /api/yara and the MCP yara_* tools).
    add_yara_parser(sub)
    # isf / disasm — the ISF workbench and disassembly over app.tools_isf / app.tools_disasm
    # (same producers as /api/isf, /api/disasm and the MCP isf_* / disasm tools).
    add_isf_parser(sub)
    add_disasm_parser(sub)
    # fixtures — detector fixtures over app.tools_detector_fixtures.
    add_fixtures_parser(sub)
    # strings — the strings table over app.tools_strings (same producer as
    # /api/strings and the MCP strings_table tool).
    add_strings_parser(sub)
    # inspect — low-level dump / structured-MSL inspection views. Nested
    # `inspect <action>` group reusing the pure tools_inspect / tools_xref
    # functions behind the HTTP `/api/inspect` endpoints and the MCP server.
    dp = _decrypt_parent_parser()
    insp = sub.add_parser(
        "inspect",
        help="Low-level dump / structured-MSL inspection views (hex, entropy, "
             "region, strings, byte-search, page-states, session-info, vas, "
             "processes, modules, handles, xref, structure)",
    )
    insp_sub = insp.add_subparsers(dest="inspect_action")
    # inspect hex
    ih = insp_sub.add_parser("hex", parents=[dp],
                             help="Hex + ASCII dump of a byte range")
    ih.add_argument("dump_path", help="Dump (.dump/.core) or .msl file path")
    ih.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                    help="Start offset (hex or decimal, default: 0)")
    ih.add_argument("--length", type=int, default=256,
                    help="Bytes to read (default: 256)")
    ih.add_argument("--view", choices=["raw", "vas", "va"], default="raw",
                    help="MSL byte source: raw container, flattened VAS, or the sparse full VA span (captured bytes only)")
    ih.add_argument("-o", "--output", help="Output JSON file")
    ih.add_argument("-v", "--verbose", action="store_true")
    # inspect entropy
    ie = insp_sub.add_parser("entropy", parents=[dp],
                             help="Shannon entropy profile of a region")
    ie.add_argument("dump_path", help="Dump or .msl file path")
    ie.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                    help="Start offset (hex or decimal, default: 0)")
    ie.add_argument("--length", type=int, default=0,
                    help="Region length (0 = whole file)")
    ie.add_argument("--window", type=int, default=32,
                    help="Sliding window size (default: 32)")
    ie.add_argument("--step", type=int, default=16,
                    help="Window step (default: 16)")
    ie.add_argument("--threshold", type=float, default=None,
                    help="High-entropy region threshold in bits/byte (default: "
                         "window-aware, 4.5 at --window 32; the maximum a "
                         "window can reach is log2(min(window, 256)))")
    ie.add_argument("--resolution", choices=("auto", "sampled", "full"),
                    default="auto",
                    help="full = every window (step 1, exact regions + min/max "
                         "envelope); sampled = bounded --step; auto (default) = "
                         "full up to 8 MiB, sampled above")
    ie.add_argument("--buckets", type=int, default=None,
                    help="Envelope buckets (default 1500, max 4096)")
    ie.add_argument("-o", "--output", help="Output JSON file")
    ie.add_argument("-v", "--verbose", action="store_true")
    # inspect region — the per-offset investigation view. Sibling of `entropy`
    # (which profiles a whole range); this answers "what is at THIS offset?".
    ireg = insp_sub.add_parser("region", parents=[dp],
                               help="Investigate one offset: byte value, "
                                    "entropy band, neighbourhood strings")
    ireg.add_argument("dump_path", help="Dump or .msl file path")
    ireg.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                      help="Offset to investigate (hex or decimal, default: 0)")
    ireg.add_argument("--window", type=int, default=64,
                      help="Neighbourhood window size (default: 64)")
    ireg.add_argument("--view", choices=["raw", "vas", "va"], default="raw",
                      help="MSL byte source: raw container, flattened VAS, or the sparse full VA span (captured bytes only)")
    ireg.add_argument("-o", "--output", help="Output JSON file")
    ireg.add_argument("-v", "--verbose", action="store_true")
    # inspect strings
    istr = insp_sub.add_parser("strings", parents=[dp],
                               help="Extract printable strings")
    istr.add_argument("dump_path", help="Dump or .msl file path")
    istr.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                      help="Start offset (hex or decimal, default: 0)")
    istr.add_argument("--length", type=int, default=0,
                      help="Scan window length (0 = to end of file)")
    istr.add_argument("--min-length", type=int, default=4,
                      help="Minimum string length (default: 4)")
    istr.add_argument("--encoding", default="ascii",
                      help="String encoding (default: ascii)")
    istr.add_argument("--max-results", type=int, default=500,
                      help="Maximum strings to return (default: 500)")
    istr.add_argument("-o", "--output", help="Output JSON file")
    istr.add_argument("-v", "--verbose", action="store_true")
    # inspect byte-search
    ibs = insp_sub.add_parser("byte-search", parents=[dp],
                              help="Find all occurrences of a byte pattern "
                                   "(hex, text, utf16le, base64 or integer)")
    ibs.add_argument("dump_path", help="Dump or .msl file path")
    ibs.add_argument("--pattern", required=True,
                     help="The pattern text; --format says how to read it")
    ibs.add_argument("--format", choices=list(NEEDLE_FORMATS), default="hex",
                     help="How to read --pattern: hex (default, optional "
                          "leading 0x), text (UTF-8), utf16le for wide "
                          "strings, base64, or u32le/u32be/u64le/u64be for a "
                          "value or pointer. auto picks hex for unambiguous "
                          "whole-byte hex and text otherwise")
    ibs.add_argument("--view", choices=["raw", "vas", "va"], default="raw",
                     help="MSL byte source: raw container, flattened VAS, or the sparse full VA span (captured bytes only)")
    ibs.add_argument("--max-results", type=int, default=500,
                     help="Maximum matches to return (default: 500)")
    ibs.add_argument("-o", "--output", help="Output JSON file")
    ibs.add_argument("-v", "--verbose", action="store_true")
    # inspect page-states
    ips = insp_sub.add_parser("page-states", parents=[dp],
                              help="MSL three-state page model (MSL only)")
    ips.add_argument("msl_path", help=".msl file path (or .mdview image view)")
    ips.add_argument("--view", choices=["va", "vas"], default="va",
                     help="'vas' = only the VA -> packed-offset map (kernel image views)")
    ips.add_argument("-o", "--output", help="Output JSON file")
    ips.add_argument("-v", "--verbose", action="store_true")
    # inspect session-info
    isi = insp_sub.add_parser("session-info", parents=[dp],
                              help="MSL session metadata (MSL only)")
    isi.add_argument("msl_path", help=".msl file path")
    isi.add_argument("-o", "--output", help="Output JSON file")
    isi.add_argument("-v", "--verbose", action="store_true")
    # inspect vas
    iva = insp_sub.add_parser("vas", parents=[dp],
                              help="Per-dump VAS region layout (MSL only)")
    iva.add_argument("msl_path", help=".msl file path")
    iva.add_argument("-o", "--output", help="Output JSON file")
    iva.add_argument("-v", "--verbose", action="store_true")
    # inspect processes
    ipr = insp_sub.add_parser("processes", parents=[dp],
                              help="List PROCESS_TABLE entries (MSL only)")
    ipr.add_argument("msl_path", help=".msl file path")
    ipr.add_argument("-o", "--output", help="Output JSON file")
    ipr.add_argument("-v", "--verbose", action="store_true")
    # inspect modules
    imo = insp_sub.add_parser("modules", parents=[dp],
                              help="List loaded modules from MSL metadata (MSL only)")
    imo.add_argument("msl_path", help=".msl file path")
    imo.add_argument("-o", "--output", help="Output JSON file")
    imo.add_argument("-v", "--verbose", action="store_true")
    # inspect handles
    ihn = insp_sub.add_parser("handles", parents=[dp],
                              help="List HANDLE_TABLE entries (MSL only)")
    ihn.add_argument("msl_path", help=".msl file path")
    ihn.add_argument("-o", "--output", help="Output JSON file")
    ihn.add_argument("-v", "--verbose", action="store_true")
    # inspect provenance
    ipv = insp_sub.add_parser("provenance", parents=[dp],
                              help="Import provenance: source, kept/excluded "
                                   "regions, materialized copy (empty for "
                                   "non-.msl)")
    ipv.add_argument("msl_path", help=".msl file path")
    ipv.add_argument("--text", action="store_true",
                     help="Print a human-readable summary instead of JSON")
    ipv.add_argument("-o", "--output", help="Output JSON file")
    ipv.add_argument("-v", "--verbose", action="store_true")
    # inspect xref
    ixr = insp_sub.add_parser("xref", parents=[dp],
                              help="Resolve cross-references (MSL only)")
    ixr.add_argument("msl_path", help=".msl file path")
    ixr.add_argument("-o", "--output", help="Output JSON file")
    ixr.add_argument("-v", "--verbose", action="store_true")
    # inspect structure
    ist = insp_sub.add_parser("structure", parents=[dp],
                              help="Identify a data structure at an offset")
    ist.add_argument("dump_path", help="Dump or .msl file path")
    ist.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                     help="Offset to overlay structures at (hex or decimal)")
    ist.add_argument("--protocol", default="",
                     help="Restrict candidates to a protocol (default: all)")
    ist.add_argument("-o", "--output", help="Output JSON file")
    ist.add_argument("-v", "--verbose", action="store_true")
    return parser


def build_parser() -> argparse.ArgumentParser:
    """Public alias for sphinx-argparse and external tooling."""
    return _build_parser()


def main():
    """MemDiver CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()
    if args.command is None or args.command == "web":
        sys.exit(_cmd_web(args))
    if args.command == "ui":
        sys.exit(_cmd_ui(args))
    if args.command == "notebook":
        sys.exit(_cmd_notebook(args))
    _setup_logging(getattr(args, "verbose", False))
    handlers = {
        "analyze": _cmd_analyze, "scan": _cmd_scan, "batch": _cmd_batch,
        "mcp": _cmd_mcp, "import": _cmd_import, "import-dir": _cmd_import_dir,
        "consensus": _cmd_consensus, "export": _cmd_export,
        "verify": _cmd_verify, "experiment": _cmd_experiment,
        "capture": _cmd_capture,
        "consensus-begin": _cmd_consensus_begin,
        "consensus-add": _cmd_consensus_add,
        "consensus-finalize": _cmd_consensus_finalize,
        "consensus-window": _cmd_consensus_window,
        "consensus-regions": _cmd_consensus_regions,
        "consensus-anchor": _cmd_consensus_anchor,
        "xref-pointers": _cmd_xref_pointers,
        "propose-layout": _cmd_propose_layout,
        "model-build": _cmd_model_build,
        "model-export": _cmd_model_export,
        "model-validate": _cmd_model_validate,
        "search-reduce": _cmd_search_reduce,
        "analyze-candidates": _cmd_analyze_candidates,
        "brute-force": _cmd_brute_force,
        "n-sweep": _cmd_n_sweep,
        "auto-floor": _cmd_auto_floor,
        "emit-plugin": _cmd_emit_plugin,
        "export-keylog": _cmd_export_keylog,
        "locate-key": _cmd_locate_key,
        "locate-field-pairs": _cmd_locate_field_pairs,
        "export-key-pattern": _cmd_export_key_pattern,
        "inspect-pcap": _cmd_inspect_pcap,
        "scan-yara": _cmd_scan_yara,
        "score-detector": _cmd_score_detector,
        "verify-plugin": _cmd_verify_plugin,
        "gen-kem-key": _cmd_gen_kem_key,
        "inspect": _cmd_inspect,
        "heap": _cmd_heap,
        "annotations": _cmd_annotations,
        "case": _cmd_case,
        "image": _cmd_image,
        "vol3": _cmd_vol3,
        "keys": _cmd_keys,
        "yara": _cmd_yara,
        "isf": _cmd_isf,
        "disasm": _cmd_disasm,
        "fixtures": _cmd_fixtures,
        "strings": _cmd_strings,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    # BACKSTOP: a CapabilityError propagating out of ANY handler is translated
    # here into a single stderr line + category exit code, so it never escapes
    # as a traceback. Handlers that already present their own errors and return
    # an exit code (e.g. the inspect handlers, which catch CapabilityError in
    # _present_inspect_cli_call) never reach this except clause.
    try:
        sys.exit(handler(args))
    except CapabilityError as e:
        sys.exit(to_cli_exit(e))


if __name__ == "__main__":
    main()
