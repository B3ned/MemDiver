"""Search-space reduction over an Android Scudo heap: one verdict per chunk.

The problem this module exists to remove
----------------------------------------
``search-reduce`` reduces a POSITIONAL consensus: a Welford variance indexed
by slab position, the same region-relative offset in every dump (region keys
take ASLR out, nothing takes out what an allocator does inside a region).
After an Android cold boot Scudo has placed every heap allocation at a
different region, slot and virtual address (see
:mod:`memdiver.engine.scudo_chunk_consensus`), so position ``p`` of one dump
and position ``p`` of the next hold unrelated bytes. The variance is then high
almost everywhere and the reduction stops reducing.

:func:`~memdiver.engine.scudo_chunk_consensus.build_chunk_consensus` already
puts the dumps' Scudo primary chunks in correspondence by allocator signature
and pointer-masked content instead of by address. This module turns that
consensus into what ``brute-force`` needs: the chunks of ONE reference dump
that can still hold a value that is freshly random in every run -- a key, a
TLS traffic secret -- and the honest bookkeeping of everything that was ruled
out or could not be judged.

The rule: every chunk of the reference gets exactly one verdict
---------------------------------------------------------------
:func:`classify_chunks` partitions the reference's extracted chunks; the
verdicts below are checked in this order and the first that applies wins:

===================================  =========================================  ===============
verdict                              condition                                  kept
===================================  =========================================  ===============
:data:`VERDICT_EMPTY`                no user bytes (``malloc(0)``)              no
:data:`VERDICT_SIGNATURE_UNIQUE`     a signature-unique row, mean variance > 0  **yes**
:data:`VERDICT_SIGNATURE_INVARIANT`  a signature-unique row, variance 0         no
:data:`VERDICT_DYNAMIC_RESIDUE`      a ``<sig>#dynamic`` row                    **yes**
:data:`VERDICT_CONTENT_INVARIANT`    a ``<sig>#content:<hex>`` row              no
:data:`VERDICT_DYNAMIC_CANDIDATE`    masked content occurs in no other dump     **yes**
:data:`VERDICT_MISSING`              signature absent from some dump            no (not judged)
:data:`VERDICT_CONTENT_SHARED`       masked content recurs in another dump      no
===================================  =========================================  ===============

Why exactly these are kept: a value generated afresh every run differs in
every run. A chunk whose bytes agree in every dump (signature-unique with zero
variance), whose pointer-masked bytes agree in every dump (content-invariant),
or whose masked content recurs in another dump (content-shared: a repeated or
partial content group) cannot hold one. What is left is a signature-unique
chunk whose bytes vary at all, the dynamic residue (the one per-run-unique
chunk content alignment could pair) and every dynamic candidate (the per-run-
unique chunks it could not pair). That is the selection rule the lab's
``cwa_to_candidates.py`` applied to a ``consensus-window-android
--list-signatures`` JSON, carried over one to one, with two deliberate
differences:

* a chunk is listed ONCE. A dynamic-residue chunk is also one of its
  signature's ``dynamic_candidates``; reading both lists emitted it twice, so
  ``brute-force`` tested it twice and would report a secret in it as two hits;
* "variance > 0" is the exact float, not the two-decimal value the JSON
  carries, so a chunk in which a single byte differs is never rounded away.

LIMITATIONS (honest, and reported rather than hidden):

* a chunk whose signature is MISSING from some dump was never compared; it is
  neither kept nor ruled out but counted as not judged. One failed run (say,
  one without the TLS connection) therefore removes its signature from the
  candidates of EVERY reference -- the funnel says how many bytes that is;
* only Scudo PRIMARY chunks are seen; secondary (large) allocations, the ART
  heap and stacks are outside the scan (see ``ScudoScanScope``);
* a random 8-byte word that happens to look like a pointer is masked before
  content grouping. For uniform random data that is ~1e-9 per word, and a
  secret needs every word masked to lose its uniqueness;
* the reference dump is part of its own consensus. A held-out reference (not
  in the consensus) is a different experiment.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from memdiver.engine.scudo_chunk_consensus import (
    CONTENT_DYNAMIC_RESIDUE,
    CONTENT_INVARIANT,
    CONTENT_SIGNATURE_UNIQUE,
    ScudoChunk,
    ScudoChunkConsensus,
)

logger = logging.getLogger("memdiver.engine.scudo_candidates")

__all__ = [
    "SEARCH_REDUCE_ANDROID_VERSION",
    "VERDICT_SIGNATURE_UNIQUE",
    "VERDICT_SIGNATURE_INVARIANT",
    "VERDICT_DYNAMIC_RESIDUE",
    "VERDICT_CONTENT_INVARIANT",
    "VERDICT_DYNAMIC_CANDIDATE",
    "VERDICT_MISSING",
    "VERDICT_EMPTY",
    "VERDICT_CONTENT_SHARED",
    "VERDICTS",
    "KEEP_VERDICTS",
    "NOT_JUDGED_VERDICTS",
    "ChunkVerdict",
    "classify_chunks",
    "verdict_funnel",
]

#: Version of the ``search-reduce-android`` subcommand, stamped into every
#: ``candidates.json`` it writes beside the chunk-consensus version it read.
SEARCH_REDUCE_ANDROID_VERSION = "0.1.0"

# --------------------------------------------------------------------------
# Verdicts. Stable strings: they are written into candidates.json and keyed
# on by tests and downstream tooling, so the wording of prose may improve but
# these may not change.
# --------------------------------------------------------------------------

VERDICT_SIGNATURE_UNIQUE = "signature_unique"
VERDICT_SIGNATURE_INVARIANT = "signature_unique_invariant"
VERDICT_DYNAMIC_RESIDUE = "dynamic_residue"
VERDICT_CONTENT_INVARIANT = "content_invariant"
VERDICT_DYNAMIC_CANDIDATE = "dynamic_candidate"
VERDICT_MISSING = "missing"
VERDICT_EMPTY = "empty"
VERDICT_CONTENT_SHARED = "content_shared"

#: Every verdict, kept ones first -- the order a funnel is reported in.
VERDICTS = (
    VERDICT_SIGNATURE_UNIQUE,
    VERDICT_DYNAMIC_RESIDUE,
    VERDICT_DYNAMIC_CANDIDATE,
    VERDICT_SIGNATURE_INVARIANT,
    VERDICT_CONTENT_INVARIANT,
    VERDICT_CONTENT_SHARED,
    VERDICT_MISSING,
    VERDICT_EMPTY,
)

#: The verdicts whose chunks become ``brute-force`` candidate regions.
KEEP_VERDICTS = frozenset({
    VERDICT_SIGNATURE_UNIQUE,
    VERDICT_DYNAMIC_RESIDUE,
    VERDICT_DYNAMIC_CANDIDATE,
})

#: Dropped because nothing could be compared -- not because it was ruled out.
NOT_JUDGED_VERDICTS = frozenset({VERDICT_MISSING})

#: Paired-row ``content_class`` -> verdict. A signature-unique row splits on
#: its variance (see :func:`_row_verdict`), the other two map directly.
_ROW_VERDICT = {
    CONTENT_DYNAMIC_RESIDUE: VERDICT_DYNAMIC_RESIDUE,
    CONTENT_INVARIANT: VERDICT_CONTENT_INVARIANT,
}


@dataclass(frozen=True)
class ChunkVerdict:
    """One reference chunk and the verdict :func:`classify_chunks` gave it.

    ``row_key`` names the aligned row the chunk was paired in -- the bare
    signature of a signature-unique row, or a ``<sig>#content:<hex>`` /
    ``<sig>#dynamic`` key -- and is ``None`` for an unpaired chunk.
    ``mean_variance`` is that row's mean per-byte variance across the dumps
    (exact, unrounded); an unpaired chunk has no cross-dump variance, so it is
    ``None`` there rather than a misleading 0.
    """

    chunk: ScudoChunk
    verdict: str
    row_key: Optional[str] = None
    mean_variance: Optional[float] = None

    @property
    def kept(self) -> bool:
        return self.verdict in KEEP_VERDICTS

    @property
    def va(self) -> int:
        return self.chunk.user_va

    @property
    def length(self) -> int:
        return len(self.chunk.data)


def _row_verdict(content_class: str, mean_variance: float) -> str:
    if content_class == CONTENT_SIGNATURE_UNIQUE:
        return (VERDICT_SIGNATURE_UNIQUE if mean_variance > 0
                else VERDICT_SIGNATURE_INVARIANT)
    try:
        return _ROW_VERDICT[content_class]
    except KeyError:
        raise ValueError(f"unknown aligned-row content_class {content_class!r}") from None


def _dynamic_vas(scc: ScudoChunkConsensus, dump_index: int) -> set:
    """User VAs of ``dump_index``'s dynamic candidates, over every signature.

    Read from the same ``content_alignment.per_signature[*].dynamic_candidates``
    provenance ``--list-signatures`` writes, so the two surfaces cannot
    disagree about which chunks are dynamic. No content block (nothing was
    ambiguous) means no dynamic candidates.
    """
    out = set()
    if scc.content is None:
        return out
    for entry in scc.content.per_signature.values():
        for cand in entry["dynamic_candidates"][dump_index]:
            out.add(int(cand["va"], 16))
    return out


def classify_chunks(
    scc: ScudoChunkConsensus, dump_index: int,
) -> List[ChunkVerdict]:
    """Give every chunk of dump ``dump_index`` exactly one verdict.

    Returns one :class:`ChunkVerdict` per chunk in
    ``scc.per_dump_chunks[dump_index]``, in that order -- a partition, so the
    verdict counts always add up to the chunks the reference holds. See the
    module docstring for the rule and its order.

    :raises ValueError: when ``scc`` was built without content alignment
        (``content_alignment=False``) and has ambiguous signatures: those were
        then never compared by content, so no chunk of them could honestly be
        called dynamic, invariant or shared. (A content-aligned build with
        nothing ambiguous carries no content block either; it is accepted.)
        Also for a ``dump_index`` outside the build.
    :raises RuntimeError: when a chunk fits no verdict at all -- an
        inconsistent consensus, never a property of the data.
    """
    if scc.content is None and scc.ambiguous:
        raise ValueError(
            "classify_chunks needs a content-aligned chunk consensus "
            "(build_chunk_consensus(..., content_alignment=True)); without it "
            "ambiguous signatures were never compared, so their chunks cannot "
            "be judged")
    if not 0 <= dump_index < len(scc.per_dump_chunks):
        raise ValueError(
            f"dump_index {dump_index} outside the build's "
            f"{len(scc.per_dump_chunks)} dump(s)")

    rows = {row.user_vas[dump_index]: row for row in scc.signatures}
    dynamic = _dynamic_vas(scc, dump_index)
    missing = set(scc.missing)
    ambiguous = set(scc.ambiguous)

    verdicts: List[ChunkVerdict] = []
    for chunk in scc.per_dump_chunks[dump_index]:
        row = rows.get(chunk.user_va)
        if not chunk.data:
            verdicts.append(ChunkVerdict(chunk, VERDICT_EMPTY))
        elif row is not None:
            verdicts.append(ChunkVerdict(
                chunk, _row_verdict(row.content_class, row.mean_variance),
                row_key=row.sig, mean_variance=float(row.mean_variance)))
        elif chunk.user_va in dynamic:
            verdicts.append(ChunkVerdict(chunk, VERDICT_DYNAMIC_CANDIDATE))
        elif chunk.sig in missing:
            verdicts.append(ChunkVerdict(chunk, VERDICT_MISSING))
        elif chunk.sig in ambiguous:
            # Unpaired, not dynamic: its masked content occurs in at least one
            # other dump (a repeated or partial group) -- not a per-run value.
            verdicts.append(ChunkVerdict(chunk, VERDICT_CONTENT_SHARED))
        else:
            raise RuntimeError(
                f"chunk {chunk.sig} at {chunk.user_va:#x} in dump {dump_index} "
                "is neither paired, dynamic, missing nor ambiguous -- the chunk "
                "consensus is inconsistent")
    logger.info("search-reduce[scudo]: dump %d: %s", dump_index,
                dict(Counter(v.verdict for v in verdicts)))
    return verdicts


def verdict_funnel(verdicts: Sequence[ChunkVerdict]) -> Dict[str, Dict[str, int]]:
    """``{verdict: {"chunks": n, "bytes": b}}`` for every verdict, zeros included.

    Keyed in :data:`VERDICTS` order, so a reader sees the kept buckets first
    and an empty bucket as an explicit zero rather than an absent key.
    """
    out = {v: {"chunks": 0, "bytes": 0} for v in VERDICTS}
    for cv in verdicts:
        out[cv.verdict]["chunks"] += 1
        out[cv.verdict]["bytes"] += cv.length
    return out
