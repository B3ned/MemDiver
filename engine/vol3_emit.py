"""Vol3 plugin emission from brute-force hits.

Takes a hit + its neighborhood variance (the window around a successful
candidate that ``brute-force`` already sliced from the Welford state) and
produces a Python Volatility3 plugin via the existing
architect.Volatility3Exporter.

The window is ``pad + key_length + pad`` where ``pad`` is
``engine.brute_force.DEFAULT_NEIGHBORHOOD_PAD`` (64) unless the caller passed
``--neighborhood-pad`` / ``neighborhood_pad=``: 160 bytes for a 32-byte key at
the default, not 128. (128 is the *total* padding, never a window size.)

The static anchor comes from bytes *around* the hit, not the hit
itself — the key region is ~100% volatile by construction and cannot
yield an anchor. The surrounding struct fields (pointers, flags,
length prefixes) are what make the plugin searchable on an unrelated
dump.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional

from memdiver.architect.pattern_generator import PatternGenerator
from memdiver.architect.volatility3_exporter import Volatility3Exporter
from memdiver.architect.yara_exporter import YaraExporter
from memdiver.core.variance import POINTER_MAX
# Imported (not re-typed) so the "widen the pad" advice below can never quote a
# default the engine no longer uses.
from memdiver.engine.brute_force import DEFAULT_NEIGHBORHOOD_PAD
from memdiver.engine.progress import (
    ProgressEvent,
    ProgressFn,
    noop_progress,
    safe_emit,
)

logger = logging.getLogger("memdiver.engine.vol3_emit")

# Default variance threshold for plugin static-mask generation.
#
# The consensus system classifies bytes as STRUCTURAL (≤200),
# POINTER (200–3000), or KEY_CANDIDATE (>3000).  POINTER-class bytes
# (heap pointers, GC state, counters) vary between sessions by
# definition — they should NOT be pattern anchors.
#
# A threshold of 2000 keeps the lower-variance POINTER bytes (type
# metadata, function pointers — consistent within the same binary
# build) while excluding session-variable heap state (var 2000–3000).
# This was empirically validated: threshold 3000 → 0 cross-session
# matches; threshold 2000 → correct matches.  Users can override
# via ``--variance-threshold`` on ``emit-plugin``.
PLUGIN_STATIC_THRESHOLD = 2000.0


def resolve_variance_threshold(variance_threshold: Optional[float]) -> float:
    """Return ``variance_threshold`` if given, else the plugin default."""
    return variance_threshold if variance_threshold is not None else PLUGIN_STATIC_THRESHOLD


def _static_mask_from_variance(
    variance: List[float],
    threshold: float = PLUGIN_STATIC_THRESHOLD,
) -> List[bool]:
    """True where variance is low enough that the byte isn't a KEY_CANDIDATE."""
    return [float(v) <= threshold for v in variance]


def _build_vtypes(
    name: str, fields: List[dict], total_size: int,
) -> dict:
    """Generate Volatility3-compatible vtypes from inferred fields."""
    vtype_fields: dict = {}
    for f in fields:
        vtype_fields[f["label"]] = [
            f["offset"],
            ["Array", {"count": f["length"], "target": "unsigned char"}],
        ]
    return {name: [total_size, vtype_fields]}


def _log_structure_summary(fields: List[dict], name: str) -> None:
    """Print human-readable structure analysis to stderr."""
    static = [f for f in fields if f["type"] == "static"]
    dynamic = [f for f in fields if f["type"] == "dynamic"]
    key = next((f for f in fields if f["type"] == "key_material"), None)
    total_static = sum(f["length"] for f in static)
    total = sum(f["length"] for f in fields)
    if static:
        logger.info(
            "Structure '%s': %d static anchor(s) (%d/%d bytes, %.0f%%)",
            name, len(static), total_static, total,
            100 * total_static / total if total else 0,
        )
        for f in static:
            logger.info(
                "  +%d..+%d  %s  (%d bytes, var=%.1f)",
                f["offset"], f["offset"] + f["length"],
                f["label"], f["length"], f["mean_variance"],
            )
    else:
        logger.warning(
            "Structure '%s': NO stable structural fields in neighborhood. "
            "YARA pattern relies on byte-level matching only. Re-run "
            "brute-force with a larger --neighborhood-pad (auto-floor and the "
            "brute_force/auto_floor producers take neighborhood_pad=), or fold "
            "more dumps into the consensus so more bytes settle as invariant.",
            name,
        )
    if key:
        logger.info(
            "  +%d..+%d  key_material (%d bytes, var=%.1f)",
            key["offset"], key["offset"] + key["length"],
            key["length"], key["mean_variance"],
        )


def emit_plugin_for_hit(
    hit: dict,
    reference_data: bytes,
    name: str,
    output_path: Path,
    *,
    description: Optional[str] = None,
    min_static_ratio: float = 0.3,
    variance_threshold: Optional[float] = None,
    progress_callback: ProgressFn = noop_progress,
) -> Path:
    """Emit a vol3 plugin anchored on the neighborhood around a brute-force hit.

    Writes TWO files and returns the first: ``output_path`` (the Volatility 3
    plugin) and a sibling ``<stem>.yar`` holding the same YARA rule the plugin
    embeds, so the rule is loadable by ``yara.compile`` /
    :func:`engine.yara_scan.compile_rules` and not only readable inside the
    generated Python. The return value is unchanged (the plugin path) because
    the plugin is still the primary artifact.
    """
    safe_emit(
        progress_callback,
        ProgressEvent(stage="emit_plugin:load", pct=0.0, msg=f"plugin={name}"),
    )
    nb_start = int(hit["neighborhood_start"])
    nb_variance: List[float] = hit.get("neighborhood_variance") or []
    if not nb_variance:
        raise ValueError(
            f"hit at offset 0x{int(hit['offset']):x} has no neighborhood "
            f"variance; re-run brute-force with the --state of a generic "
            f"(Welford) session so the slice is attached. A hit from the "
            f"Android Scudo method has none: plugin generation is not "
            f"supported yet with that method"
        )
    nb_end = nb_start + len(nb_variance)
    if nb_end > len(reference_data):
        raise ValueError(
            f"neighborhood [{nb_start}:{nb_end}] exceeds reference dump "
            f"length {len(reference_data)}"
        )
    window = reference_data[nb_start:nb_end]
    thresh = resolve_variance_threshold(variance_threshold)
    static_mask = _static_mask_from_variance(nb_variance, threshold=thresh)

    # Compute key position within the neighborhood window.
    key_offset_in_window = int(hit["offset"]) - nb_start
    key_length = int(hit["length"])

    # Infer field structure from the variance profile.
    fields = PatternGenerator.infer_fields(
        nb_variance, key_offset_in_window, key_length, threshold=thresh,
    )
    vtypes = _build_vtypes(name, fields, len(window))
    _log_structure_summary(fields, name)

    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="emit_plugin:render",
            pct=0.5,
            msg=f"window={len(window)} static={sum(static_mask)}",
        ),
    )
    pattern = PatternGenerator.generate(
        window, static_mask, name=name, min_static_ratio=min_static_ratio,
    )
    if pattern is None:
        static_ratio = sum(static_mask) / len(static_mask) if static_mask else 0.0
        raise RuntimeError(
            f"insufficient static bytes in neighborhood for {name}: "
            f"{static_ratio:.1%} static (need >= {min_static_ratio:.1%}). "
            f"Re-run brute-force with a larger --neighborhood-pad (the "
            f"brute_force / auto_floor producers and the MCP tools take "
            f"neighborhood_pad=; it defaults to {DEFAULT_NEIGHBORHOOD_PAD} "
            f"bytes per side), or fold "
            f"more dumps into the consensus so more bytes settle as invariant."
        )

    # Attach key position + structure metadata for the template.
    pattern["key_offset"] = key_offset_in_window
    pattern["key_length"] = key_length
    pattern["vtypes"] = vtypes
    pattern["fields"] = fields

    # The key locator is known exactly here (the hit is what defined the
    # window), so the YARA rule carries it too -- not just the vol3 template.
    yara_rule = YaraExporter.export(
        pattern, key_offset=key_offset_in_window, key_length=key_length,
    )
    source = Volatility3Exporter.export(
        pattern,
        plugin_name=name,
        description=description,
        yara_rule=yara_rule,
    )
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(source)
    logger.info("wrote vol3 plugin %s (%d bytes)", output_path, len(source))

    # The same rule text, ALSO as a standalone ``.yar`` beside the plugin.
    #
    # Until now this rule existed only *inside* the generated Python -- the
    # exporter drops it into the template's ``YARA_RULE`` string -- so nothing
    # could load it: ``yara.compile`` and ``engine.yara_scan.compile_rules``
    # take rule text or rule FILES, and a ``.py`` is neither. The rule emitted
    # here carries the exact ``key_offset``/``key_length`` (the hit is what
    # defined the window, so these are the highest-confidence locator metas
    # MemDiver produces anywhere), which made it the one rule most worth
    # scanning with and the one rule that could not be. The plugin's bytes are
    # untouched; this is purely an additional file, and the two can never
    # disagree because both render the same ``yara_rule`` string.
    # ``with_suffix`` would collapse onto the plugin itself if a caller ever
    # named the output ``*.yar``; the plugin is the primary artifact and must
    # never be overwritten by its own sidecar, so append instead of replace.
    rule_path = output_path.with_suffix(".yar")
    if rule_path == output_path:
        rule_path = output_path.with_name(output_path.name + ".yar")
    # One trailing newline, so the file is a well-formed POSIX text file a
    # user can ``cat`` into a larger rule set. Nothing else is added: the
    # plugin's embedded copy differs only in the surrounding whitespace the
    # Python template puts around the ``$yara_rule`` slot.
    rule_text = yara_rule.rstrip("\n") + "\n"
    rule_path.write_text(rule_text)
    logger.info("wrote YARA rule %s (%d bytes)", rule_path, len(rule_text))

    safe_emit(
        progress_callback,
        ProgressEvent(
            stage="emit_plugin:write",
            pct=1.0,
            msg=f"wrote {output_path.name}",
            extra={
                "path": str(output_path),
                "size": len(source),
                "yara_rule_path": str(rule_path),
                "yara_rule_size": len(rule_text),
            },
        ),
    )
    return output_path


def extract_inferred_fields(
    hit: dict,
    variance_threshold: Optional[float] = None,
) -> List[dict]:
    """Derive inferred field structure from a hit's neighborhood variance.

    Lightweight wrapper around ``PatternGenerator.infer_fields()`` that
    resolves key offset and threshold from the hit dict.  Used by the
    pipeline runner to attach field metadata without importing internals.
    """
    nb_variance = hit.get("neighborhood_variance", [])
    if not nb_variance:
        return []
    nb_start = int(hit.get("neighborhood_start", hit["offset"]))
    key_off = int(hit["offset"]) - nb_start
    key_len = int(hit["length"])
    thresh = resolve_variance_threshold(variance_threshold)
    return PatternGenerator.infer_fields(
        nb_variance, key_off, key_len, threshold=thresh,
    )


def emit_plugin_from_hits_file(
    hits_path: Path,
    reference_data: bytes,
    name: str,
    output_path: Path,
    *,
    hit_index: int = 0,
    description: Optional[str] = None,
    variance_threshold: Optional[float] = None,
) -> Path:
    """Load hits.json, pick one hit, emit its vol3 plugin."""
    payload = json.loads(Path(hits_path).read_text())
    hits = payload.get("hits", [])
    if not hits:
        raise ValueError(f"{hits_path}: no hits to emit plugin from")
    if hit_index < 0 or hit_index >= len(hits):
        raise ValueError(
            f"{hits_path}: requested hit {hit_index} but only "
            f"{len(hits)} present"
        )
    return emit_plugin_for_hit(
        hits[hit_index], reference_data, name, output_path,
        description=description,
        variance_threshold=variance_threshold,
    )
