"""The stderr funnel for ``search-reduce``'s Scudo mode.

A thin presenter over the summary
:func:`memdiver.app.tools_pipeline_android._search_reduce_android` returns: the
reference's scan scope, every verdict (kept / dropped / not judged), the window
total and the diagnostics. The artifact itself goes to ``--output``; this is the
short human-readable account that goes to stderr, mirroring what the generic
``search-reduce`` path reports through ``_warn_tag_status``.
"""

import sys
from pathlib import Path
from typing import Any, Dict

#: How each verdict reads in the funnel.
_KEPT, _DROPPED, _NOT_JUDGED = "kept", "dropped", "not judged"


def _kib(nbytes: int) -> str:
    return f"{nbytes / 1024:.1f} KiB"


def print_scudo_funnel(result: Dict[str, Any], output: str) -> None:
    """The funnel on stderr: scope, every verdict, the total, the diagnostics."""
    from memdiver.engine.scudo_candidates import KEEP_VERDICTS, NOT_JUDGED_VERDICTS

    err = sys.stderr
    cons = result["consensus"]
    print(f"memdiver: search-reduce[scudo] {result['version']} over {result['N']} "
          f"dump(s), {cons['method']} {cons['version']}: {cons['aligned_rows']} "
          f"aligned row(s), {cons['ambiguous_signatures']} ambiguous / "
          f"{cons['missing_signatures']} missing signature(s)", file=err)
    scope = result["region_scope"]
    funnel = result["funnel"]
    chunks = sum(b["chunks"] for b in funnel.values())
    nbytes = sum(b["bytes"] for b in funnel.values())
    print(f"memdiver: reference {Path(result['reference_dump']).name} "
          f"[{scope['kind']}: {scope['rw_regions_scanned']}/{scope['rw_regions']} "
          f"RW region(s), {_kib(scope['bytes_scanned'])} scanned]: {chunks} "
          f"chunk(s), {_kib(nbytes)}", file=err)
    for verdict, bucket in funnel.items():
        if verdict in KEEP_VERDICTS:
            label = _KEPT
        elif verdict in NOT_JUDGED_VERDICTS:
            label = _NOT_JUDGED
        else:
            label = _DROPPED
        print(f"memdiver:   {label:<10} {verdict:<27} {bucket['chunks']:>8} "
              f"chunk(s) {_kib(bucket['bytes']):>12}", file=err)
    totals = result["totals"]
    sizes = ",".join(str(k) for k in totals["key_sizes"])
    print(f"memdiver: -> {totals['regions']} region(s), {_kib(totals['bytes'])}, "
          f"{totals['windows']} window(s) (key sizes {sizes}, stride "
          f"{totals['stride']}) -> {output}", file=err)
    for diag in result["diagnostics"]:
        tag = "WARNING —" if diag["severity"] == "warning" else "note —"
        print(f"memdiver: {tag} {diag['message']}", file=err)
