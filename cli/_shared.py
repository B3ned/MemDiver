"""Shared CLI helpers — error mapping, key material, argument parsing, output.

Leaf utilities used by the command handlers (``cli.dataset`` / ``cli.pipeline``
/ ``cli.consensus`` / ``cli.experiment`` / ``cli.inspect``) and by the parser
construction in ``cli.main``. Extracted from the monolithic ``cli`` module
(P3.1); depends only on ``memdiver.core`` and stdlib, never on the command
modules, so it sits at the bottom of the CLI package's import graph.
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path

from memdiver.core.install_hints import (missing_package_message,
                                        native_runtime_message)
from memdiver.core.service_errors import CapabilityError, ErrorCategory

logger = logging.getLogger("memdiver.cli")


# Per-category process exit codes for the CLI backstop: NOT_FOUND is its own
# code (3) so scripts can distinguish "missing input" from a bad argument (2);
# caller-correctable input/precondition/unsupported errors share 2; anything
# INTERNAL is 1 (and additionally logs a traceback for the operator).
_CLI_EXIT = {
    ErrorCategory.NOT_FOUND: 3,
    ErrorCategory.INVALID_INPUT: 2,
    ErrorCategory.PRECONDITION: 2,
    ErrorCategory.UNSUPPORTED: 2,
    ErrorCategory.INTERNAL: 1,
}


#: ``CapabilityError.code`` the memory-budget guard (``core.memory_budget``)
#: raises when an operation's estimated working set exceeds the budget.
MEMORY_BUDGET_EXCEEDED_CODE = "memory_budget_exceeded"

#: Follow-up line printed under a memory-budget refusal.
FORCE_MEMORY_HINT = "Re-run with --force-memory to proceed anyway."

_FORCE_MEMORY_HELP = (
    "Override the memory-budget refusal: run even when the estimated working "
    "set exceeds the budget (MEMDIVER_MEMORY_BUDGET_MB). The run may exhaust "
    "RAM or swap heavily"
)


def add_force_memory_argument(parser: argparse.ArgumentParser) -> None:
    """Register the shared ``--force-memory`` flag (dest ``force_memory``)."""
    parser.add_argument("--force-memory", dest="force_memory",
                        action="store_true", help=_FORCE_MEMORY_HELP)


#: Allocators the heap parser understands (``auto`` lets the detector pick).
#: Mirrors ``memdiver.heap.analyze.parse_allocator_hint``; spelled out here
#: because this module depends only on ``core`` (parity is test-guarded).
ALLOCATOR_CHOICES = ("auto", "ptmalloc2", "dlmalloc", "scudo",
                     "mallocng", "jemalloc", "generic")

#: ``--allocator`` choices on the consensus-backed commands: ``off`` skips the
#: heap analysis entirely.
PIPELINE_ALLOCATOR_CHOICES = ALLOCATOR_CHOICES + ("off",)

#: ``--allocator`` choices on the incremental session (``consensus-begin``)
#: whose heap projections feed ``search-reduce``. The concrete names must equal
#: ``memdiver.heap.registry.reduce_ready_kinds()`` (parity is test-guarded;
#: this module depends only on ``core`` so it cannot import ``heap``).
SEARCH_REDUCE_ALLOCATOR_CHOICES = ("auto", "ptmalloc2", "off")

#: ``--heap-policy`` choices (``engine.candidate_pipeline.HEAP_POLICIES``).
HEAP_POLICY_CHOICES = ("off", "annotate", "mask")


_ALLOCATOR_HELP = ("Heap allocator for the non-destructive heap-role annotation "
                   "(default: auto-detect; 'off' disables heap analysis)")


def add_allocator_argument(parser: argparse.ArgumentParser,
                           choices: "tuple[str, ...]" = PIPELINE_ALLOCATOR_CHOICES,
                           help_text: str = _ALLOCATOR_HELP) -> None:
    """Register ``--allocator`` (heap-role annotation of the consensus)."""
    parser.add_argument("--allocator", choices=choices, default="auto",
                        help=help_text)


def add_mixed_ok_argument(parser: argparse.ArgumentParser) -> None:
    """Register ``--mixed-ok`` (allow dumps from several experiment cohorts)."""
    parser.add_argument(
        "--mixed-ok", action="store_true",
        help="Allow dumps whose meta.json declare different experiment "
             "cohorts in one build (refused with code cohort.mixed otherwise)")


def add_keylog_anchor_arguments(parser: argparse.ArgumentParser, *,
                                shared_only: bool = False) -> None:
    """Register the key-log anchor flags (``--keylog`` and friends).

    ``shared_only`` (model-validate) omits the per-dump and anchor-selection
    flags: held-out scoring only needs one shared key log.
    """
    parser.add_argument(
        "--keylog", metavar="PATH",
        help="NSS key log (SSLKEYLOGFILE) shared by all dumps; each dump is "
             "matched to the session whose secret it contains")
    if shared_only:
        return
    parser.add_argument(
        "--keylog-per-dump", metavar="JSON",
        help="One key log per dump: inline JSON or a JSON file "
             "{dump_path: keylog_path}")
    parser.add_argument(
        "--anchor-label", metavar="LABEL",
        help="NSS label whose secret anchors each dump (default: "
             "CLIENT_TRAFFIC_SECRET_0, else CLIENT_RANDOM's master secret)")
    parser.add_argument(
        "--related-labels", nargs="+", metavar="LABEL",
        help="Other labels of the session to locate (default: all of them)")


def keylog_spec_from_args(args: argparse.Namespace):
    """The ``keylog`` producer input from ``--keylog`` / ``--keylog-per-dump``."""
    shared = getattr(args, "keylog", None)
    per_dump = getattr(args, "keylog_per_dump", None)
    if shared and per_dump:
        raise ValueError("pass --keylog or --keylog-per-dump, not both")
    if shared:
        return {"path": shared}
    if per_dump:
        raw = per_dump if per_dump.lstrip().startswith("{") else Path(per_dump).read_text()
        return {"per_dump": json.loads(raw)}
    return None


def add_heap_policy_argument(parser: argparse.ArgumentParser) -> None:
    """Register ``--heap-policy`` (how candidates treat allocator metadata)."""
    parser.add_argument(
        "--heap-policy", choices=HEAP_POLICY_CHOICES, default="annotate",
        help="annotate (default, non-destructive): tag each candidate with its "
             "heap chunk; mask: remove allocator metadata from the candidates "
             "(counted in stages.heap_masked); off: no heap analysis")


def force_memory_requested(args: argparse.Namespace) -> bool:
    """True when the operator passed ``--force-memory`` on this subcommand."""
    return bool(getattr(args, "force_memory", False))


def print_cli_error(err: CapabilityError, *, stream=None) -> None:
    """Print ``memdiver: ERROR — <message>`` (plus the override hint for a
    memory-budget refusal) to ``stream`` (``sys.stderr`` at call time)."""
    if stream is None:
        stream = sys.stderr
    print(f"memdiver: ERROR — {err.message}", file=stream)
    if err.code == MEMORY_BUDGET_EXCEEDED_CODE:
        print(FORCE_MEMORY_HINT, file=stream)


def to_cli_exit(err: CapabilityError, *, stream=None) -> int:
    """Translate a propagating ``CapabilityError`` into a CLI message + exit code.

    Prints a single ``memdiver: ERROR — <message>`` line to ``stream`` and maps
    the error's category to a process exit code via ``_CLI_EXIT``. Internal
    errors additionally log a full traceback under ``memdiver.cli`` so an
    operator can diagnose an unexpected failure.

    ``stream`` defaults to ``sys.stderr`` resolved AT CALL TIME (not bound once
    at definition), so it honours any active redirection of ``sys.stderr``.
    """
    print_cli_error(err, stream=stream)
    if err.category is ErrorCategory.INTERNAL:
        logging.getLogger("memdiver.cli").exception("internal error")
    return _CLI_EXIT[err.category]


def _decrypt_parent_parser() -> argparse.ArgumentParser:
    """Shared parent parser for encrypted-MSL decryption flags (spec §10).

    Attach via ``parents=[_decrypt_parent_parser()]`` to any subcommand that
    opens a dump, so it accepts a key for AES/XChaCha-encrypted .msl files.
    """
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("encrypted MSL (spec §10)")
    g.add_argument("--key-file", help="32-byte raw content-encryption key file "
                                      "(KeyEncap=None, KDF=None)")
    g.add_argument("--passphrase", help="Passphrase for Argon2id-derived key "
                                        "(KeyEncap=None, KDF=Argon2id)")
    g.add_argument("--kem-key-file", help="Recipient private key file for "
                                          "X25519/ML-KEM/hybrid key encapsulation")
    return p


def output_parent_parser() -> argparse.ArgumentParser:
    """Shared parent parser for the JSON-payload commands' ``-o/-v`` flags.

    Attach via ``parents=[output_parent_parser()]``; pairs with :func:`emit`.
    """
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("-o", "--output", help="Write the JSON payload to this file")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _auto_int(text: str) -> int:
    """Parse a hex (``0x…``) or decimal integer argument.

    Keeps the ``_auto_int`` name: argparse quotes the type function's
    ``__name__`` in its "invalid _auto_int value" usage error.
    """
    return int(text, 0)


def _key_material_from_args(args: argparse.Namespace) -> dict:
    """Build the open_dump() key-material kwargs from decryption CLI flags.

    Returns a dict with key/passphrase/kem_private_key (all None when no
    decryption flags were supplied), suitable for ``open_dump(path, **kw)``.

    Thin surface adapter over the shared ``key_material_from_files`` re-export
    from :mod:`memdiver.app.composition` (itself ``core.key_material.from_files``);
    the ``getattr`` guards let subcommands whose Namespace lacks the decryption
    attributes still resolve to the all-None dict.
    """
    from memdiver.app.composition import key_material_from_files
    return key_material_from_files(
        getattr(args, "key_file", None),
        getattr(args, "passphrase", None),
        getattr(args, "kem_key_file", None),
    )


# CLI-surface remedy for a locked encrypted dump. The neutral core hint
# (``KeyStatus.hint``) never names a transport-specific remedy; the CLI owns
# the guidance that points its operator at the decryption FLAGS, so this string
# lives here in the CLI surface — never in core.
_KEY_FLAGS_HINT = "supply --key-file / --passphrase / --kem-key-file"


def _warn_tag_status(source) -> None:
    """Print a user-facing line about an encrypted dump's AEAD verification.

    Green = verified, red = failed/missing key. Plaintext dumps say nothing.
    """
    from memdiver.msl.enums import TagStatus
    status = getattr(source, "tag_status", TagStatus.NOT_ENCRYPTED)
    if status == TagStatus.VALID:
        print("memdiver: AEAD verified — encrypted dump decrypted successfully",
              file=sys.stderr)
    elif status == TagStatus.CORRUPTED:
        print("memdiver: ERROR — AEAD verification FAILED (wrong key or tampered file)",
              file=sys.stderr)
    elif status == TagStatus.MISSING_KEY:
        print(f"memdiver: ERROR — dump is encrypted; {_KEY_FLAGS_HINT}",
              file=sys.stderr)


#: Glob patterns a DIRECTORY argument is expanded with (see ``_scan_dump_inputs``).
_DUMP_GLOBS = ("*.dump", "*.msl", "*.gcore.core", "*.core",
               "*gdb_raw.bin", "*lldb_raw.bin")

#: Suffixes of the sidecar files a run directory routinely holds next to its
#: dumps (metadata, key logs, captures, rules, arrays, notes). A file matching
#: no dump glob is reported as "skipped" only when it is NOT one of these, so the
#: note names plausible dumps the operator may have expected to be searched
#: rather than every meta.json in the tree.
_NON_DUMP_SUFFIXES = frozenset({".json", ".txt", ".log", ".pcap", ".pcapng",
                                ".yar", ".yara", ".npy", ".md"})

#: How many skipped file names the per-directory note quotes as examples.
_SKIPPED_EXAMPLES = 3


@dataclass(frozen=True)
class DumpInputs:
    """What the dump-path arguments resolved to, before anything is reported.

    ``paths`` is the searchable list (files passed through, directories
    expanded); ``missing`` holds the raw arguments that named nothing on disk;
    ``unrecognised`` maps each directory argument to the regular files directly
    inside it that matched no dump glob and are not known sidecars.
    """

    paths: list = field(default_factory=list)
    missing: list = field(default_factory=list)
    unrecognised: dict = field(default_factory=dict)


def _expand_dump_dir(path: Path) -> list:
    """Glob one directory for every supported dump flavour, de-duplicated + sorted."""
    collected: list[Path] = []
    for pattern in _DUMP_GLOBS:
        collected.extend(path.glob(pattern))
    # De-duplicate (``*.gcore.core`` overlaps ``*.core``) and sort.
    return sorted({c.resolve(): c for c in collected}.values())


def _unrecognised_in_dir(path: Path, matched: list) -> list:
    """Regular files in ``path`` that no glob matched, minus dotfiles + sidecars."""
    taken = {m.resolve() for m in matched}
    return sorted(
        child for child in path.iterdir()
        if child.is_file()
        and not child.name.startswith(".")
        and child.suffix.lower() not in _NON_DUMP_SUFFIXES
        and child.resolve() not in taken
    )


def _scan_dump_inputs(raw_paths: list) -> DumpInputs:
    """Resolve dump-path arguments WITHOUT printing anything (pure, testable).

    Recognised extensions inside a run directory:
      * ``.dump`` and ``.msl`` (legacy + Memory Slice)
      * ``.gcore.core`` and bare ``.core`` (Linux gcore/ELF core)
      * ``gdb_raw.bin`` / ``lldb_raw.bin`` (regioned raw dumps)
    """
    inputs = DumpInputs()
    for p in raw_paths:
        path = Path(p)
        if path.is_dir():
            expanded = _expand_dump_dir(path)
            inputs.paths.extend(expanded)
            skipped = _unrecognised_in_dir(path, expanded)
            if skipped:
                inputs.unrecognised[path] = skipped
        elif path.is_file():
            inputs.paths.append(path)
        else:
            inputs.missing.append(str(p))
    return inputs


def _report_missing_inputs(inputs: DumpInputs) -> None:
    """Warn on stderr about each dump-path argument that named nothing on disk."""
    for raw in inputs.missing:
        print(f"memdiver: WARNING — skipping non-existent path: {raw}",
              file=sys.stderr)


def _report_unrecognised_inputs(inputs: DumpInputs) -> None:
    """Note on stderr, per directory, the files skipped for their extension."""
    for directory, skipped in inputs.unrecognised.items():
        examples = ", ".join(f.name for f in skipped[:_SKIPPED_EXAMPLES])
        print(f"memdiver: note — skipped {len(skipped)} file(s) in {directory} "
              f"with unrecognised extensions (e.g. {examples}); pass a file "
              f"explicitly to include it", file=sys.stderr)


def _report_skipped_inputs(inputs: DumpInputs) -> None:
    """Print every missing path and every skipped-file note to stderr."""
    _report_missing_inputs(inputs)
    _report_unrecognised_inputs(inputs)


def _resolve_dump_paths(raw_paths: list) -> list:
    """Expand directories to all supported dump flavours; pass through files.

    ``_scan_dump_inputs`` (see there for the recognised extensions) followed by
    ``_report_skipped_inputs``: a non-existent path is dropped with a
    ``memdiver: WARNING`` line on stderr, and a directory's files that match no
    dump glob (dotfiles and known sidecars aside) get one ``memdiver: note``
    line, so neither omission is silent. Returns only the searchable paths.
    """
    inputs = _scan_dump_inputs(raw_paths)
    _report_skipped_inputs(inputs)
    return inputs.paths


def _setup_logging(verbose: bool) -> None:
    """Configure logging for CLI mode."""
    from memdiver.core.log import setup_logging
    setup_logging(level="DEBUG" if verbose else "WARNING")


def _write_output(
    data: dict,
    output_path: str | None,
    fmt: str = "json",
) -> None:
    """Write data to file or stdout as json or jsonl."""
    if fmt == "jsonl":
        text = _format_jsonl(data)
    else:
        text = json.dumps(data, indent=2)
    if output_path:
        try:
            Path(output_path).write_text(text)
        except OSError as exc:
            print(f"memdiver: cannot write output to {output_path}: {exc}",
                  file=sys.stderr)
            raise SystemExit(1)
        logger.info("Output written to %s", output_path)
    else:
        print(text)


def emit(args: argparse.Namespace, payload: dict) -> int:
    """Write *payload* as JSON to ``args.output`` (or stdout); exit code 0."""
    _write_output(payload, args.output)
    return 0


def _format_jsonl(data: dict) -> str:
    """Serialize a BatchResult-shaped dict as newline-delimited JSON.

    One record per completed job + a trailing summary line tagged
    ``"_type": "summary"``. Non-batch shapes (no ``jobs`` list) fall
    back to a single-line JSON dump.
    """
    jobs = data.get("jobs")
    if not isinstance(jobs, list):
        return json.dumps(data)
    lines = [json.dumps(j) for j in jobs]
    summary = {k: v for k, v in data.items() if k != "jobs"}
    summary["_type"] = "summary"
    lines.append(json.dumps(summary))
    return "\n".join(lines) + "\n"


def _print_missing_package(package: str, extra: str | None = None) -> None:
    """Print a uniform 'package missing' install hint to stderr.

    ``extra`` names an optional-dependencies group (e.g. ``"marimo"``) and is
    kept for backward compatibility with every existing call site. Groups that
    became empty back-compat aliases when their contents moved into the base
    install are resolved to the reinstall wording by
    :func:`~memdiver.core.install_hints.missing_package_message`, so a caller
    never has to know which side of the contract its package sits on.
    """
    print(missing_package_message(package, extra), file=sys.stderr)


def _print_missing_native_runtime(component: str, detail: str = "") -> None:
    """Print the OS-level action for a missing NATIVE runtime piece to stderr.

    The companion to :func:`_print_missing_package` for the case where the
    Python wheel is present but the C library / OS debugger / attachable target
    behind it is not, and a pip hint would therefore be wrong.
    """
    print(native_runtime_message(component, detail), file=sys.stderr)


def _region_selection_parent_parser() -> argparse.ArgumentParser:
    """Shared parent parser for import-time region selection flags.

    Attached to ``import`` and ``import-dir``. Without any of these flags a
    non-interactive run imports EVERY region (unchanged behaviour); only an
    interactive terminal is prompted.
    """
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group(
        "region selection",
        "Default without --regions/--exclude-regions: a non-interactive run "
        "(pipe, script, CI, or --yes) imports EVERY region, exactly as "
        "before; an interactive terminal shows the region categories and "
        "prompts, with heap+stack+unclassified preselected. Categories: "
        "heap, stack, image_code, image_data, mapped_file, shared, "
        "unclassified, runtime (alias: image = image_code,image_data). "
        "'runtime' is never preselected: it holds maps classified by name "
        "(Android zygote/boot-image/ART metadata, JIT caches, kernel/device "
        "maps such as [vdso]/[vvar]); add it with --regions ...,runtime "
        "or --regions all.")
    g.add_argument("--regions", metavar="LIST|all",
                   help="Comma-separated region categories to import, or "
                        "'all' (e.g. --regions heap,stack). Never prompts")
    g.add_argument("--exclude-regions", metavar="LIST",
                   help="Categories to drop (alone: everything except LIST; "
                        "with --regions: LIST is removed from it). Never "
                        "prompts")
    g.add_argument("--list-regions", action="store_true",
                   help="Dry run: print region counts/bytes per category "
                        "(and every region with -v) for the input, honouring "
                        "--regions/--exclude-regions, then exit without "
                        "importing")
    g.add_argument("--json", action="store_true",
                   help="With --list-regions: print the preview as JSON "
                        "instead of a table")
    g.add_argument("--materialize", action="store_true",
                   help="For .msl input only: write a FILTERED copy holding "
                        "just the selected regions. Without it a .msl is "
                        "copied verbatim and the selection is applied at "
                        "analysis time. Ignored for other formats")
    g.add_argument("-y", "--yes", action="store_true",
                   help="Never prompt: behave like a non-interactive run, "
                        "i.e. import every region unless --regions/"
                        "--exclude-regions is given (it does NOT accept the "
                        "interactive heap+stack+unclassified preselection)")
    return p
