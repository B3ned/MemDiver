"""Chunk-anchored consensus for Android Scudo primary heaps.

The problem this engine exists to remove
----------------------------------------
:mod:`engine.consensus_msl` aligns ``.msl`` dumps by ``anon:<type>:<size>:
<ordinal>`` and then intersects pages by position. On Android's Scudo that
pairs the WRONG regions and the WRONG bytes, because the allocator randomises
its layout on three levels that a positional overlay cannot see through:

* the size-class -> region map is a per-init permutation (region shuffle);
* every region begins behind a random 1..16-page offset;
* each refill window of fresh blocks is shuffled before it enters the freelist.

So two dumps of the same program put the same allocation at a different region,
a different slot, and a different virtual address every run. ``consensus-window``
(VA / module-offset alignment) therefore cannot recover a value that moved: a
randomly generated heap secret is lost.

What this engine does instead
-----------------------------
It aligns by the allocator's OWN bookkeeping rather than by address. Every
allocated primary chunk is keyed by the signature in its 8-byte header
(class, origin, requested size), and the user bytes behind the header are what
gets compared across dumps. Address plays no role, so Scudo's randomisation
drops out: the same allocation carries the same signature in every run even
though it sits at a different slot and VA each time.

The result is expressed as an ordinary
:class:`~memdiver.engine.consensus.ConsensusVector`. The chunk correspondence
is encoded into the vector's ``msl_layout`` exactly the way the aligned MSL/VA
builders encode their page correspondence: one layout row per aligned chunk,
``(slab_offset, user_len, [user_va_per_dump])``, with ``variance`` /
``classifications`` indexed by the synthetic slab. That is deliberate — the
alignment differs only in HOW correspondence is established; once it exists it
is the same slab, so the whole windowing machinery
(:func:`memdiver.app.tools_consensus.aligned_window_from_vector`) serves a
chunk-aligned window with no second, differently-wrong copy of the slab -> VA
arithmetic. ``search-reduce`` consumes it through
:mod:`memdiver.engine.scudo_candidates`.

Why this does not build on :mod:`memdiver.heap.allocators.scudo`
-----------------------------------------------------------------
Both read the same ``UnpackedHeader``, for different jobs. ``parse_scudo`` maps
a heap without knowing the Android release: it infers each class's stride from
where headers repeat, so a class needs at least two headers, and a
low-confidence slot falls back to ``user_len = stride - header``. A signature
here needs the exact requested size of every allocated chunk, even in a class
with a single live chunk, across whole regions. So the headers are tested in one
vectorised pass against Scudo's own size-class table, without the parser's
``max_chunks`` budget (200,000 by default).

Scudo facts are taken from AOSP ``platform/external/scudo`` @
``android-17.0.0_r1``:

* ``config/custom_scudo_config.h`` -- ``AndroidNormalSizeClassConfig`` (64-bit);
* ``standalone/chunk.h`` -- ``UnpackedHeader`` bit layout, ``getHeaderSize``;
* ``standalone/size_class_map.h`` -- ``TableSizeClassMap::getClassIdBySize``.

LIMITATIONS (honest, and the point of the measurement):

* clean pairing is only possible for a signature present EXACTLY ONCE in every
  dump; thousands of same-class/same-size chunks in a real app collapse to one
  ambiguous signature and are skipped (reported in :attr:`ambiguous`);
* a signature missing from some dump is skipped (:attr:`missing`);
* a pairable signature with no user bytes (``malloc(0)``) has nothing to
  compare and is skipped (:attr:`empty`);
* a chunk any of whose bytes lie in an uncaptured page is not extracted --
  the dump does not hold it, so it is not compared;
* the header scan is restricted to the regions the dump's VAS map names
  ``[anon:scudo:primary]`` (:class:`ScudoScanScope`); a dump with no VAS map, or
  one that names no primary region, falls back to every RW region and
  can then mistake a header-shaped word in ``dalvik-*`` / ``boot*.art`` / a
  thread stack for a chunk; secondary (large) allocations are never covered;
* the header checksum is a per-process nonce a dump reader never has, so headers
  are judged on structure, not on their checksum;
* the size-class table is pinned to ``android-17.0.0_r1`` (64-bit). On a release
  with a different ``AndroidNormalSizeClassConfig``, valid chunks fail the
  size-fits-class test and are not extracted.
"""

from __future__ import annotations

import hashlib
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

import numpy as np

from memdiver.core.memory_budget import MemoryEstimate
from memdiver.core.region_align import (
    AlignedSlice,
    AlignmentCoverage,
    build_dump_region_map,
)
from memdiver.msl.region_names import MappingNameIndex
from memdiver.core.service_errors import EncryptedDumpLockedError
from memdiver.core.service_result import KeyStatus
from memdiver.core.variance import VarianceThresholds, classify_variance
from memdiver.engine.consensus import (
    SIGNIFICANT_DISCARD_FRACTION,
    AlignmentReport,
    ConsensusVector,
)

logger = logging.getLogger("memdiver.engine.scudo_chunk_consensus")

__all__ = [
    "ALIGNMENT_SCUDO_CHUNK",
    "PRIMARY_MAPPING_NAME",
    "SCOPE_VAS_PRIMARY",
    "SCOPE_ALL_RW",
    "CHUNK_CONSENSUS_VERSION",
    "CONTENT_SIGNATURE_UNIQUE",
    "CONTENT_INVARIANT",
    "CONTENT_DYNAMIC_RESIDUE",
    "MASK_SOURCE_VAS",
    "MASK_SOURCE_REGIONS",
    "ScudoRegion",
    "ScudoChunk",
    "ScudoScanScope",
    "ContentAlignment",
    "SignatureRow",
    "ScudoChunkConsensus",
    "extract_chunks",
    "align_chunks",
    "build_chunk_consensus",
    "chunk_consensus_estimate",
]

PathLike = Union[str, Path]

#: ``alignment.method`` value for a chunk-signature build. Deliberately NOT a
#: member of :data:`memdiver.core.region_align.ALIGNMENT_METHODS`: that tuple is
#: the closed vocabulary of POSITIONAL alignments the project DB keys on, and a
#: chunk-signature variance is produced by a different correspondence entirely.
#: It only ever reaches a surface's JSON ``alignment.method`` (never
#: ``project_db.add_consensus_run``), so it names itself without widening that
#: closed set.
ALIGNMENT_SCUDO_CHUNK = "scudo_chunk_signature"


# --------------------------------------------------------------------------
# Scudo geometry, Android 17, 64-bit (AOSP android-17.0.0_r1)
# --------------------------------------------------------------------------

#: ``AndroidNormalSizeClassConfig`` block sizes (incl. the 16-byte header area),
#: class 1..32; class 0 is the internal BatchClass and never holds user data.
CLASSES = [
    0x00020, 0x00030, 0x00040, 0x00050, 0x00060, 0x00070, 0x00090, 0x000b0,
    0x000c0, 0x000e0, 0x00120, 0x00160, 0x001c0, 0x00250, 0x00320, 0x00450,
    0x00670, 0x00830, 0x00a10, 0x00c30, 0x01010, 0x01210, 0x01bd0, 0x02210,
    0x02d90, 0x03790, 0x04010, 0x04810, 0x05a10, 0x07310, 0x08210, 0x10010,
]
NUM_BITS, MIN_SIZE_LOG, MID_SIZE_LOG, MAX_SIZE_LOG, SIZE_DELTA = 7, 4, 6, 16, 16
#: ``roundUp(sizeof(u64), 1 << SCUDO_MIN_ALIGNMENT_LOG)`` -- the user pointer
#: sits this many bytes past the block start, so a real header is in byte 0..7
#: of a 16-byte-aligned slot.
HEADER_SIZE = 16
STATE_ALLOCATED = 1
PROT_RW = 3

#: ``mapped_path`` of a Scudo primary region in a memslicer VAS map. memslicer
#: copies the kernel's ``/proc/<pid>/maps`` label verbatim (the agent reads
#: ``/proc/self/maps`` and ``acquirer/frida_bridge.py`` enriches each range with
#: it), so the bracketed form is exactly what the device reports. The match is
#: EXACT, never a prefix: ``[anon:scudo:primary]`` is itself a prefix of
#: ``[anon:scudo:primary_reserve]`` (the PROT_NONE reserve) and of nothing the
#: primary heap allocates from. A kernel that gave the label without brackets
#: has not been observed so far; such a dump takes the fallback.
PRIMARY_MAPPING_NAME = "[anon:scudo:primary]"

#: ``region_scope.kind`` recorded per dump: the VAS-named primary scan, or the
#: fallback over every RW region when the map cannot name the heap.
SCOPE_VAS_PRIMARY = "vas:scudo_primary"
SCOPE_ALL_RW = "all_rw_fallback"

#: Format version of the chunk-consensus provenance, stamped into the
#: ``scudo_alignment`` block and into ``candidates.json``. It counts changes to
#: this method's output and is independent of the MemDiver package version.
CHUNK_CONSENSUS_VERSION = "0.2.0"

# --------------------------------------------------------------------------
# Content alignment: pointer masking + invariant-content pairing
# --------------------------------------------------------------------------

#: ``content_class`` of an aligned row. A signature-unique row is paired by
#: header signature alone (one chunk per dump). A content-invariant
#: row is a group within an otherwise-ambiguous signature whose POINTER-MASKED
#: bytes occur exactly once in every dump. A dynamic-residue row is the one
#: chunk per dump whose masked content occurs in no other dump, paired only when
#: every dump leaves exactly one such chunk for the signature.
CONTENT_SIGNATURE_UNIQUE = "signature_unique"
CONTENT_INVARIANT = "content_invariant"
CONTENT_DYNAMIC_RESIDUE = "dynamic_residue"

#: ``mask_source``: the address ranges a dump's pointer mask was built from --
#: its VAS map (every entry, readable or not: the widest, right answer) or, with
#: no VAS map, its stored memory regions (narrower: a PROT_NONE reserve has no
#: region block, so a pointer into it is not recognised).
MASK_SOURCE_VAS = "vas"
MASK_SOURCE_REGIONS = "regions"

#: A value below this is treated as a small integer, never a pointer: the lowest
#: user mapping on Android/Linux sits far above it, so masking it would blank out
#: ordinary counters and lengths. Pointers into the fixed ART heap
#: (0x02000000..) are ABOVE it and so are masked -- a documented over-mask.
MASK_MIN_POINTER = 0x10000

#: Width, in bytes, of the blake2b digest that labels a content-invariant row
#: (``<sig>#content:<hex>``). 8 bytes = 16 hex chars; the full masked bytes are
#: the grouping key, so this only has to stay collision-free as a label.
_CONTENT_LABEL_BYTES = 8


def _compute_class_id(size: int) -> int:
    for i, c in enumerate(CLASSES):
        if size <= c:
            return i + 1
    return 255


def _scaled_log2(size: int, zero_log: int, log_bits: int) -> int:
    lg = size.bit_length() - 1
    return ((size >> (lg - log_bits)) - (1 << log_bits)) + ((lg - zero_log) << log_bits)


def _build_size_table() -> List[int]:
    s = NUM_BITS - 1
    pos, inc = 1 << MID_SIZE_LOG, 1 << (MID_SIZE_LOG - s)
    tab: List[int] = []
    for _ in range((MAX_SIZE_LOG - MID_SIZE_LOG) << s):
        pos += inc
        if pos & (pos - 1) == 0:
            inc *= 2
        tab.append(_compute_class_id(pos + SIZE_DELTA))
    return tab


_SIZE_TABLE = _build_size_table()


def class_id_by_size(needed: int) -> int:
    """``TableSizeClassMap::getClassIdBySize`` for the Android config."""
    if needed <= CLASSES[0]:
        return 1
    size = needed - SIZE_DELTA
    if size <= (1 << MID_SIZE_LOG):
        return ((size - 1) >> MIN_SIZE_LOG) + 1
    return _SIZE_TABLE[_scaled_log2(size - 1, MID_SIZE_LOG, NUM_BITS - 1)]


def needed_size(size: int) -> int:
    """Block size Scudo reserves for a ``size``-byte request (header included)."""
    return ((size + 15) & ~15) + HEADER_SIZE


#: Expected ClassId for every requested size a primary chunk can carry, so the
#: size-fits-class test below is a table lookup instead of a per-header call.
_MAX_USER = CLASSES[-1] - HEADER_SIZE
_EXPECTED_CLASS = np.zeros(1 << 20, dtype=np.uint8)
for _sz in range(0, _MAX_USER + 1):
    _EXPECTED_CLASS[_sz] = class_id_by_size(needed_size(_sz))
_BLOCK_SIZE = np.array([0] + CLASSES, dtype=np.int64)


# --------------------------------------------------------------------------
# Per-dump chunk extraction
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ScudoRegion:
    """One detected Scudo primary region and how confidently it was read."""

    key: str
    base: int
    class_id: int
    block_size: int
    chunks: int
    off_grid_plausible: int
    other_class_votes: int
    #: The region's VAS-map name (``PRIMARY_MAPPING_NAME`` under the VAS scope,
    #: whatever the map says under the fallback, ``""`` when the map does not
    #: cover its base). Additive; names WHY a region was in scope.
    name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key, "base": self.base, "class": self.class_id,
            "block_size": self.block_size, "chunks": self.chunks,
            "off_grid_plausible": self.off_grid_plausible,
            "other_class_votes": self.other_class_votes,
            "name": self.name,
        }


@dataclass(frozen=True)
class ScudoScanScope:
    """Which RW regions one dump's header scan looked at, and why.

    The scan covers the regions a memslicer VAS map names
    :data:`PRIMARY_MAPPING_NAME`. The VAS map (block
    ``0x1001``) is written on every capture, encrypted or not, and covers even
    unreadable and skipped ranges, so the scope is available from the ``.msl``
    alone -- the device's ``.maps`` file is never needed. When the dump carries
    no VAS map, or one that names no primary region, the scan falls back to
    every RW region: a header-shaped word in ``dalvik-*``, ``boot*.art`` or a
    thread stack can then still be mistaken for a chunk, which is exactly the
    false-positive the VAS scope removes.
    """

    kind: str
    reason: str
    rw_regions: int
    rw_regions_scanned: int
    bytes_scanned: int
    bytes_skipped: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "reason": self.reason,
            "rw_regions": self.rw_regions,
            "rw_regions_scanned": self.rw_regions_scanned,
            "bytes_scanned": self.bytes_scanned,
            "bytes_skipped": self.bytes_skipped,
        }


@dataclass(frozen=True)
class ScudoChunk:
    """One allocated primary chunk's identity and its user bytes."""

    sig: str
    user_va: int
    slot: int
    data: bytes


def _region_slots(region: Any) -> Tuple[np.ndarray, np.ndarray]:
    """``(rel_offsets, header_words)`` for every 16-byte slot of the region.

    A real header is the first u64 of a 16-byte-aligned slot (the user pointer
    is 16 bytes in), so the region's captured pages are scanned as a grid of
    16-byte slots and only the low 8 bytes of each are taken as a candidate.
    Uncaptured pages leave gaps in ``captured_pages`` and are simply absent.
    """
    rels: List[np.ndarray] = []
    hdrs: List[np.ndarray] = []
    for page_off, data in sorted(region.captured_pages.items()):
        words = np.frombuffer(data[: len(data) // 16 * 16], dtype="<u8")[::2]
        rels.append(page_off + 16 * np.arange(len(words), dtype=np.int64))
        hdrs.append(words)
    if not rels:
        return np.empty(0, np.int64), np.empty(0, np.uint64)
    return np.concatenate(rels), np.concatenate(hdrs)


def _plausible(hdr: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Vectorised ``UnpackedHeader`` test over a whole word array.

    A word is a plausible allocated primary header when its ClassId is in
    range, its state is Allocated, its Offset is 0 (no realignment in the
    primary) and its recorded size maps -- through Scudo's own size-class
    table -- back to that ClassId. Returns ``(ok_mask, class_ids, sizes)``.
    """
    cls = (hdr & 0xFF).astype(np.int64)             # ClassId, bits 0..7
    state = (hdr >> 8) & 3                           # State, bits 8..9
    size = ((hdr >> 12) & 0xFFFFF).astype(np.int64)  # requested size, bits 12..31
    offset = (hdr >> 32) & 0xFFFF                     # Offset, bits 32..47
    ok = (cls >= 1) & (cls <= len(CLASSES)) & (state == STATE_ALLOCATED) & (offset == 0)
    ok &= size <= _MAX_USER
    ok &= _EXPECTED_CLASS[np.minimum(size, _MAX_USER)] == cls
    return ok, cls, size


def _captured_user_bytes(
    pages: Mapping[int, bytes], page_size: int, user_rel: int, size: int,
) -> Optional[bytes]:
    """The ``size`` bytes at region offset ``user_rel``, or None if not all captured.

    EVERY page the span touches must be captured: joining only the captured
    ones would splice the next captured page into an uncaptured hole and hand
    back the right length from the wrong address.
    """
    if size == 0:
        return b""
    first = user_rel - user_rel % page_size
    last = user_rel + size - 1
    span = range(first, last - last % page_size + page_size, page_size)
    if any(p not in pages for p in span):
        return None
    buf = b"".join(pages[p] for p in span)
    start = user_rel - first
    user = buf[start:start + size]
    return user if len(user) == size else None


def _scope_from_vas(
    entries: Sequence[Any], index: MappingNameIndex,
) -> Tuple[Any, str, str]:
    """``(in_scope(base), kind, reason)`` for one dump's RW header scan.

    When the dump's effective VAS map names at least one
    :data:`PRIMARY_MAPPING_NAME` region, ``in_scope`` is CONTAINMENT in such a
    region: :class:`~memdiver.msl.region_names.MappingNameIndex` resolves a base
    that sits inside an entry, not only one equal to its start, so a region
    whose recorded base falls within a larger primary mapping still matches.
    Otherwise every RW region is in scope and a warning
    is logged -- never "0 chunks because the names were missing".
    """
    n_primary = sum(e.mapped_path == PRIMARY_MAPPING_NAME for e in entries)
    if n_primary:
        reason = f"VAS map names {n_primary} {PRIMARY_MAPPING_NAME} region(s)"
        return (lambda base: index.name_for(base) == PRIMARY_MAPPING_NAME,
                SCOPE_VAS_PRIMARY, reason)
    reason = ("dump carries no VAS map" if not entries
              else f"VAS map names no {PRIMARY_MAPPING_NAME} region")
    logger.warning("scudo chunk scan: %s; scanning every RW region -- "
                   "header-shaped words outside the Scudo primary heap may be "
                   "mistaken for chunks", reason)
    return (lambda _base: True, SCOPE_ALL_RW, reason)


def extract_chunks(
    reader: Any,
) -> Tuple[List[ScudoRegion], List[ScudoChunk], ScudoScanScope]:
    """Detect Scudo primary regions by header grid and return their chunks.

    *reader* is an open MSL reader (``DumpSource.get_reader()``). Only
    read/write regions are considered, and the scan is narrowed to the regions
    the dump's VAS map names :data:`PRIMARY_MAPPING_NAME` (:func:`_scope_from_vas`),
    falling back to every RW region when the map is absent or names no primary
    region. Within each scanned region a class is accepted when its plausible
    headers land on the stride of that class's block size, and the dominant
    on-grid class names the region. The returned :class:`ScudoScanScope` records
    which scope ran and how many RW regions / captured bytes it read vs skipped.
    """
    prot = {r.base_addr: r.protection for r in reader.collect_regions()}
    rmap = build_dump_region_map(0, reader)

    vas = reader.effective_vas_map()
    entries = list(vas.entries) if vas else []
    index = MappingNameIndex.from_vas_entries(entries)
    in_scope, scope_kind, scope_reason = _scope_from_vas(entries, index)

    regions: List[ScudoRegion] = []
    chunks: List[ScudoChunk] = []
    rw_regions = rw_scanned = bytes_scanned = bytes_skipped = 0
    for key, region in rmap.regions.items():
        if prot.get(region.source_base_addr) != PROT_RW:
            continue
        rw_regions += 1
        # Captured bytes, counted without materialising a page: a skipped
        # region is never read at all, which is where the scope earns its time.
        region_bytes = len(region.captured_pages) * region.page_size
        if not in_scope(region.source_base_addr):
            bytes_skipped += region_bytes
            continue
        rw_scanned += 1
        bytes_scanned += region_bytes

        rel, hdr = _region_slots(region)
        if not len(hdr):
            continue
        ok, cls, size = _plausible(hdr)
        # The sharpest test: a real chunk begins exactly on its class's block
        # grid, i.e. its region-relative offset is a multiple of the block
        # size. 1 is a placeholder divisor for the words already rejected.
        on_grid = ok & (rel % _BLOCK_SIZE[np.where(ok, cls, 1)] == 0)
        if not on_grid.any():
            continue
        votes = Counter(cls[on_grid].tolist())
        region_cls, n = votes.most_common(1)[0]
        regions.append(ScudoRegion(
            key=key, base=region.source_base_addr, class_id=region_cls,
            block_size=CLASSES[region_cls - 1], chunks=n,
            off_grid_plausible=int(ok.sum() - on_grid.sum()),
            other_class_votes=sum(votes.values()) - n,
            name=index.name_for(region.source_base_addr) or ""))

        pages = region.captured_pages
        ps = region.page_size
        for i in np.nonzero(on_grid & (cls == region_cls))[0]:
            r, h = int(rel[i]), int(hdr[i])
            sz = int(size[i])
            user_rel = r + HEADER_SIZE
            user = _captured_user_bytes(pages, ps, user_rel, sz)
            if user is None:  # some byte of it lies in an uncaptured page
                continue
            chunks.append(ScudoChunk(
                sig=f"scudo:c{region_cls}:o{(h >> 10) & 3}:s{sz}",
                user_va=region.source_base_addr + user_rel,
                slot=r // CLASSES[region_cls - 1], data=user))

    scope = ScudoScanScope(
        kind=scope_kind, reason=scope_reason, rw_regions=rw_regions,
        rw_regions_scanned=rw_scanned, bytes_scanned=bytes_scanned,
        bytes_skipped=bytes_skipped)
    return regions, chunks, scope


# --------------------------------------------------------------------------
# Cross-dump alignment by signature
# --------------------------------------------------------------------------


def align_chunks(
    per_dump: Sequence[Sequence[ScudoChunk]],
) -> Tuple[List[AlignedSlice], List[str], List[str]]:
    """Pair chunks by signature; keep signatures present ONCE in every dump.

    Returns ``(slices, ambiguous, missing)``. ``slices`` are the uniquely
    pairable signatures as :class:`~memdiver.core.region_align.AlignedSlice`
    (``data[d]`` is dump ``d``'s user bytes, ``source_vaddrs[d]`` its user VA).
    ``ambiguous`` appear in every dump but more than once somewhere (copies a
    dump reader cannot tell apart); ``missing`` are absent from some dump. Both
    are skipped -- honestly, and reported.
    """
    counts = [Counter(c.sig for c in chunks) for chunks in per_dump]
    all_sigs = set().union(*counts) if counts else set()
    unique = sorted(s for s in all_sigs if all(cnt[s] == 1 for cnt in counts))
    ambiguous = sorted(s for s in all_sigs
                       if all(cnt[s] >= 1 for cnt in counts) and s not in unique)
    missing = sorted(s for s in all_sigs if any(cnt[s] == 0 for cnt in counts))
    by_sig = [{c.sig: c for c in chunks} for chunks in per_dump]
    slices = [
        AlignedSlice(key=s, page_offset=0, page_size=len(by_sig[0][s].data),
                     source_vaddrs=[d[s].user_va for d in by_sig],
                     data=[d[s].data for d in by_sig])
        for s in unique if by_sig[0][s].data
    ]
    return slices, ambiguous, missing


# --------------------------------------------------------------------------
# Content alignment: pointer masking + invariant-content pairing
# --------------------------------------------------------------------------


def _pointer_ranges(reader: Any) -> Tuple[np.ndarray, np.ndarray, str]:
    """``(starts, ends, source)``: the mapped address ranges of one dump.

    From the VAS map when present (every entry, readable or not -- a pointer can
    point into a PROT_NONE reserve), else from the stored memory regions. Ranges
    are sorted ascending and non-overlapping (both sources describe distinct
    mappings), so :func:`_mask_pointer_words` can resolve a value with one
    ``searchsorted``. ``ends`` are exclusive bounds here; the mask treats the
    last mapped byte and the one-past-end address as in range.
    """
    vas = reader.effective_vas_map()
    entries = list(vas.entries) if vas else []
    if entries:
        pairs = sorted((e.base_addr, e.base_addr + e.region_size) for e in entries)
        source = MASK_SOURCE_VAS
    else:
        pairs = sorted((r.base_addr, r.base_addr + r.region_size)
                       for r in reader.collect_regions())
        source = MASK_SOURCE_REGIONS
    starts = np.array([p[0] for p in pairs], dtype="<u8")
    ends = np.array([p[1] for p in pairs], dtype="<u8")
    return starts, ends, source


def _mask_pointer_words(
    data: bytes, starts: np.ndarray, ends: np.ndarray,
) -> Tuple[bytes, Tuple[int, ...]]:
    """Zero every aligned 8-byte word of *data* that points into a mapping.

    Returns ``(masked_bytes, masked_word_offsets)``. A word at offset 0, 8,
    16 ... (the user pointer is 16-byte aligned, so a stored pointer is 8-byte
    aligned) is a pointer when its little-endian ``u64`` is
    >= :data:`MASK_MIN_POINTER` and lies in ``[start, end]`` -- END INCLUSIVE, so
    a one-past-end pointer still counts -- for one of the dump's ranges. Trailing
    bytes that do not fill a word are copied through unchanged.

    LIMITATIONS (measured on the x86_64 lab corpus, documented not fixed):

    * 32-bit ART references, unaligned pointers, and encoded or relative
      pointers are not recognised and so are not masked;
    * an integer that merely falls inside a mapped range is masked too -- most
      consequentially the fixed ART heap ``0x02000000..0x32000000``, so a plain
      number in that window is blanked as if it were a pointer;
    * on ARM64 a tagged pointer (top-byte-ignore, e.g. ``0xb4..``) would need its
      top byte stripped before this range test; the corpus tested so far is x86_64, so
      that is only noted here, not handled.
    """
    n = len(data) // 8
    if n == 0 or not len(starts):
        return data, ()
    words = np.frombuffer(data[: n * 8], dtype="<u8").copy()
    idx = np.searchsorted(starts, words, side="right") - 1
    safe = np.where(idx >= 0, idx, 0)
    is_ptr = (idx >= 0) & (words >= MASK_MIN_POINTER) & (words <= ends[safe])
    if not is_ptr.any():
        return data, ()
    offsets = tuple(int(o) for o in (np.nonzero(is_ptr)[0] * 8))
    words[is_ptr] = 0
    return words.tobytes() + data[n * 8:], offsets


def _content_label(masked: bytes) -> str:
    """Short, deterministic hex label for a content-invariant group."""
    return hashlib.blake2b(masked, digest_size=_CONTENT_LABEL_BYTES).hexdigest()


@dataclass(frozen=True)
class _MaskedChunk:
    """A chunk reduced to what content pairing needs (RAW bytes kept for output)."""

    content: bytes                   # pointer-masked bytes: the grouping key
    masked_offsets: Tuple[int, ...]  # word offsets zeroed to get ``content``
    chunk: ScudoChunk                # the original chunk (raw ``data``, VA)


@dataclass
class ContentAlignment:
    """Result of pointer-masked content pairing over the ambiguous signatures.

    The signature-unique pairings are untouched; this only subdivides each
    AMBIGUOUS signature by the pointer-masked content of its chunks. ``slices``
    are the new aligned rows (keyed ``<sig>#content:<hex>`` or ``<sig>#dynamic``);
    ``row_class`` / ``row_masked_offsets`` annotate them; ``per_signature`` and
    ``totals`` are the provenance; the three lists say how far each ambiguous
    signature was resolved.
    """

    enabled: bool
    mask_source: List[str] = field(default_factory=list)
    slices: List[AlignedSlice] = field(default_factory=list)
    row_class: Dict[str, str] = field(default_factory=dict)
    row_masked_offsets: Dict[str, Tuple[int, ...]] = field(default_factory=dict)
    per_signature: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    fully_resolved: List[str] = field(default_factory=list)
    partially_resolved: List[str] = field(default_factory=list)
    still_ambiguous: List[str] = field(default_factory=list)

    def totals(self) -> Dict[str, Any]:
        content_rows = sum(1 for c in self.row_class.values() if c == CONTENT_INVARIANT)
        dynamic_rows = sum(1 for c in self.row_class.values()
                           if c == CONTENT_DYNAMIC_RESIDUE)
        paired = sum(s.get("paired_chunks", 0) for s in self.per_signature.values())
        unpaired = sum(s.get("unpaired_chunks", 0) for s in self.per_signature.values())
        return {
            "signatures_fully_resolved": len(self.fully_resolved),
            "signatures_partially_resolved": len(self.partially_resolved),
            # Still reported in ``ambiguous_skipped`` (partially resolved ones
            # included): a signature with any unpaired chunk left.
            "signatures_still_ambiguous": len(self.still_ambiguous),
            "content_rows": content_rows,
            "dynamic_rows": dynamic_rows,
            "paired_chunks": paired,
            "unpaired_chunks": unpaired,
        }

    def provenance(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mask_source": list(self.mask_source),
            "fully_resolved": list(self.fully_resolved),
            "partially_resolved": list(self.partially_resolved),
            "per_signature": self.per_signature,
            "totals": self.totals(),
        }


def _mask_ambiguous(
    per_dump: Sequence[Sequence[ScudoChunk]],
    ambiguous: Sequence[str],
    ranges: Sequence[Tuple[np.ndarray, np.ndarray, str]],
) -> List[Dict[str, List[_MaskedChunk]]]:
    """``masked[d][sig]`` -> that dump's masked chunks for each ambiguous sig."""
    amb = set(ambiguous)
    masked: List[Dict[str, List[_MaskedChunk]]] = []
    for d, chunks in enumerate(per_dump):
        starts, ends, _src = ranges[d]
        bucket: Dict[str, List[_MaskedChunk]] = {}
        for c in chunks:
            if c.sig in amb:
                content, offs = _mask_pointer_words(c.data, starts, ends)
                bucket.setdefault(c.sig, []).append(_MaskedChunk(content, offs, c))
        masked.append(bucket)
    return masked


def _content_align(
    per_dump: Sequence[Sequence[ScudoChunk]],
    ambiguous: Sequence[str],
    ranges: Sequence[Tuple[np.ndarray, np.ndarray, str]],
) -> ContentAlignment:
    """Subdivide each ambiguous signature by pointer-masked chunk content.

    For a signature present more than once in some dump, group its chunks by
    masked content and classify each group:

    * present in EVERY dump exactly once  -> pair (``content_invariant`` row);
    * present in every dump, some more than once -> count only (G3);
    * present in 2..N-1 dumps -> count only;
    * present in exactly ONE dump -> ``dynamic`` candidate. When every dump has
      exactly one dynamic chunk for the signature, pair them (``dynamic_residue``
      row); otherwise report the per-dump candidate count and pair nothing.

    Raw bytes are never altered: masking decides CORRESPONDENCE, the row still
    carries each dump's raw user bytes, so a pointer word shows up as variance.
    """
    n = len(per_dump)
    masked = _mask_ambiguous(per_dump, ambiguous, ranges)

    result = ContentAlignment(enabled=True,
                              mask_source=[r[2] for r in ranges])
    for sig in sorted(set(ambiguous)):
        groups = [_group_by_content(masked[d].get(sig, [])) for d in range(n)]
        keys = set().union(*[set(g) for g in groups]) if groups else set()
        dumps_with = {k: sum(1 for g in groups if k in g) for k in keys}
        total = sum(len(masked[d].get(sig, [])) for d in range(n))

        paired = 0
        invariant = repeated = partial = 0
        for k in sorted(keys):
            counts = [len(groups[d].get(k, ())) for d in range(n)]
            if dumps_with[k] == n and all(c == 1 for c in counts):
                members = [groups[d][k][0] for d in range(n)]
                key = f"{sig}#content:{_content_label(k)}"
                result.slices.append(_slice_from_members(key, members))
                result.row_class[key] = CONTENT_INVARIANT
                result.row_masked_offsets[key] = _union_offsets(members)
                paired += n
                invariant += 1
            elif dumps_with[k] == n:
                repeated += 1
            elif dumps_with[k] >= 2:
                partial += 1

        dynamic = [[m for k, lst in groups[d].items() if dumps_with[k] == 1
                    for m in lst] for d in range(n)]
        dyn_per_dump = [len(dyn) for dyn in dynamic]
        # The fully-dynamic candidates themselves, per dump: each chunk whose
        # masked content occurs in no other dump. Address-level, so the user can
        # validate the set against ground truth -- the one list the consensus
        # output otherwise only COUNTS. ``size`` is the chunk's user length (the
        # signature's ``s``), carried per candidate for convenience.
        dynamic_candidates = [
            [{"va": hex(m.chunk.user_va), "size": len(m.chunk.data)}
             for m in sorted(dyn, key=lambda m: m.chunk.user_va)]
            for dyn in dynamic
        ]
        dynamic_paired = n >= 2 and all(cnt == 1 for cnt in dyn_per_dump)
        if dynamic_paired:
            members = [dynamic[d][0] for d in range(n)]
            key = f"{sig}#dynamic"
            result.slices.append(_slice_from_members(key, members))
            result.row_class[key] = CONTENT_DYNAMIC_RESIDUE
            result.row_masked_offsets[key] = _union_offsets(members)
            paired += n

        unpaired = total - paired
        result.per_signature[sig] = {
            "chunks_per_dump": [len(masked[d].get(sig, ())) for d in range(n)],
            "content_invariant_paired": invariant,
            "content_invariant_repeated": repeated,
            "partial": partial,
            "dynamic_per_dump": dyn_per_dump,
            "dynamic_candidates": dynamic_candidates,
            "dynamic_paired": dynamic_paired,
            "paired_chunks": paired,
            "unpaired_chunks": unpaired,
        }
        if unpaired == 0:
            result.fully_resolved.append(sig)
        elif paired > 0:
            result.partially_resolved.append(sig)
            result.still_ambiguous.append(sig)
        else:
            result.still_ambiguous.append(sig)
    return result


def _group_by_content(
    items: Sequence[_MaskedChunk],
) -> Dict[bytes, List[_MaskedChunk]]:
    groups: Dict[bytes, List[_MaskedChunk]] = {}
    for m in items:
        groups.setdefault(m.content, []).append(m)
    return groups


def _slice_from_members(key: str, members: Sequence[_MaskedChunk]) -> AlignedSlice:
    """One aligned row from one masked chunk per dump, carrying RAW bytes."""
    return AlignedSlice(
        key=key, page_offset=0, page_size=len(members[0].chunk.data),
        source_vaddrs=[m.chunk.user_va for m in members],
        data=[m.chunk.data for m in members])


def _union_offsets(members: Sequence[_MaskedChunk]) -> Tuple[int, ...]:
    """Word offsets masked in ANY paired chunk -- the pointer-contaminated ones."""
    out: set = set()
    for m in members:
        out.update(m.masked_offsets)
    return tuple(sorted(out))


# --------------------------------------------------------------------------
# The synthetic consensus vector
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SignatureRow:
    """One aligned signature's place in the synthetic slab.

    ``sig`` is a bare header signature for a signature-unique row, or a
    content-suffixed key (``<sig>#content:<hex>`` / ``<sig>#dynamic>``) for a row
    paired by content. ``content_class`` says which, and ``masked_word_offsets``
    are the chunk-relative offsets of the 8-byte words a pointer mask zeroed when
    deciding the pairing -- so a consumer can tell pointer variance (those words)
    from real disagreement.
    """

    sig: str
    slab_offset: int
    length: int
    class_id: int
    origin: int
    size: int
    mean_variance: float
    user_vas: Tuple[int, ...]
    content_class: str = CONTENT_SIGNATURE_UNIQUE
    masked_word_offsets: Tuple[int, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature": self.sig, "slab_offset": self.slab_offset,
            "length": self.length, "class": self.class_id,
            "origin": self.origin, "size": self.size,
            "mean_variance": round(self.mean_variance, 2),
            "user_vas": [hex(v) for v in self.user_vas],
            "content_class": self.content_class,
            "masked_word_offsets": list(self.masked_word_offsets),
        }


@dataclass
class ScudoChunkConsensus:
    """A chunk-signature consensus: the vector plus its alignment provenance."""

    vector: ConsensusVector
    signatures: List[SignatureRow] = field(default_factory=list)
    ambiguous: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    #: Present exactly once in every dump but with no user bytes to compare
    #: (``malloc(0)``): pairable, yet nothing to put in the slab.
    empty: List[str] = field(default_factory=list)
    per_dump_regions: List[List[ScudoRegion]] = field(default_factory=list)
    #: One :class:`ScudoScanScope` per dump, in ``dump_paths`` order: which
    #: region scope the header scan ran under and how much it read vs skipped.
    per_dump_scopes: List[ScudoScanScope] = field(default_factory=list)
    #: Every extracted chunk per dump, in ``dump_paths`` order. Kept so the
    #: producer can name the signature at an anchor VA that fell in no aligned
    #: row (e.g. a dynamic chunk content alignment could not uniquely pair).
    per_dump_chunks: List[List[ScudoChunk]] = field(default_factory=list)
    #: Pointer-masked content pairing over the ambiguous signatures, or ``None``
    #: when content alignment was turned off. Its rows are already folded into
    #: ``signatures`` / the vector; this holds the provenance and the per-signature
    #: candidate counts.
    content: Optional[ContentAlignment] = None
    dump_paths: List[str] = field(default_factory=list)

    def row_for_signature(self, signature: str) -> Optional[SignatureRow]:
        for row in self.signatures:
            if row.sig == signature:
                return row
        return None

    def chunk_at_va(self, dump_index: int, va: int) -> Optional[ScudoChunk]:
        """The extracted chunk whose user bytes contain *va* in ``dump_index``."""
        if not 0 <= dump_index < len(self.per_dump_chunks):
            return None
        for chunk in self.per_dump_chunks[dump_index]:
            if chunk.user_va <= va < chunk.user_va + len(chunk.data):
                return chunk
        return None

    def alignment_provenance(self) -> Dict[str, Any]:
        """The ``scudo_alignment`` block attached to a window payload.

        ``region_scope`` has one entry per dump, in ``dump_paths`` order.
        ``aligned_signatures`` also carries content-paired rows, each tagged
        ``content_class``, and ``ambiguous_skipped`` means "at least partially
        unpaired".
        """
        block = {
            "method": ALIGNMENT_SCUDO_CHUNK,
            "version": CHUNK_CONSENSUS_VERSION,
            "aligned_signatures": [r.to_dict() for r in self.signatures],
            "ambiguous_skipped": list(self.ambiguous),
            "missing_skipped": list(self.missing),
            "empty_skipped": list(self.empty),
            "region_scope": [
                {"dump": path, **scope.to_dict()}
                for path, scope in zip(self.dump_paths, self.per_dump_scopes,
                                       strict=False)
            ],
            "content_alignment": (self.content.provenance() if self.content
                                  else {"enabled": False}),
        }
        return block


def _parse_signature(sig: str) -> Tuple[int, int, int]:
    """``scudo:c<class>:o<origin>:s<size>`` -> ``(class, origin, size)``.

    A content-aligned key carries a ``#content:<hex>`` / ``#dynamic`` suffix on
    the base signature; it is dropped before parsing, so ``s<size>#...`` does not
    make ``int()`` choke. The size field already pins the slab length, so the
    suffix adds nothing to ``(class, origin, size)``.
    """
    base = sig.split("#", 1)[0]
    cls = origin = size = 0
    for part in base.split(":")[1:]:
        if part.startswith("c"):
            cls = int(part[1:])
        elif part.startswith("o"):
            origin = int(part[1:])
        elif part.startswith("s"):
            size = int(part[1:])
    return cls, origin, size


def _skipped_bytes(per_dump: Sequence[Sequence[ScudoChunk]], sigs: Sequence[str]) -> int:
    """User bytes, summed over every dump, of the chunks carrying ``sigs``."""
    wanted = set(sigs)
    return sum(len(c.data) for chunks in per_dump for c in chunks if c.sig in wanted)


def _coverage_warnings(
    coverage: AlignmentCoverage,
    per_dump: Sequence[Sequence[ScudoChunk]],
    ambiguous: Sequence[str],
    missing: Sequence[str],
    content_ran: bool = False,
) -> Tuple[str, ...]:
    """The chunk path's own warnings, naming WHY bytes were not compared.

    The positional wording ("present in some dumps but not all", "no bytes
    common to all N dumps") is untrue here: an AMBIGUOUS chunk is present in
    every dump and is skipped because its copies cannot be told apart, which
    has a different remedy than a chunk some dump lacks. Same trigger as the
    positional report -- nothing compared, or a significant discard.

    The ambiguous byte figure is ``discarded - missing`` rather than the sum of
    all ambiguous chunks: with content alignment on, some chunks of an ambiguous
    signature are now PAIRED, so only the rest is still discarded. With content
    off the two are equal.
    """
    if not coverage.n_sources or not sum(coverage.bytes_available):
        return ()
    if coverage.bytes_compared and coverage.discarded_fraction <= SIGNIFICANT_DISCARD_FRACTION:
        return ()
    if coverage.bytes_compared:
        head = (f"{ALIGNMENT_SCUDO_CHUNK} alignment compared {coverage.bytes_compared} "
                f"bytes per dump; {coverage.bytes_discarded} chunk bytes "
                f"({coverage.discarded_fraction:.1%} of the input) were not compared")
    else:
        head = (f"{ALIGNMENT_SCUDO_CHUNK} alignment found no chunk signature exactly "
                f"once in each of the {coverage.n_sources} dumps; nothing was compared")
    missing_bytes = _skipped_bytes(per_dump, missing)
    ambiguous_bytes = max(coverage.bytes_discarded - missing_bytes, 0)
    ambiguous_why = ("not uniquely pairable by signature or pointer-masked content"
                     if content_ran else "in every dump, but more than once in some")
    reasons = []
    for nbytes, count, label, why in (
        (ambiguous_bytes, len(ambiguous), "ambiguous", ambiguous_why),
        (missing_bytes, len(missing), "missing", "absent from at least one dump"),
    ):
        if nbytes:
            reasons.append(f"{nbytes} bytes in {count} {label} signature(s) ({why})")
    return (head + (": " + "; ".join(reasons) if reasons else "") + ".",)


def _coverage_report(
    total: int,
    per_dump: Sequence[Sequence[ScudoChunk]],
    ambiguous: Sequence[str],
    missing: Sequence[str],
    content_ran: bool = False,
) -> AlignmentReport:
    """The vector's alignment report, in CHUNK bytes and chunk wording."""
    coverage = AlignmentCoverage(
        bytes_compared=total,
        bytes_available=tuple(sum(len(c.data) for c in chunks) for chunks in per_dump))
    warnings = _coverage_warnings(coverage, per_dump, ambiguous, missing, content_ran)
    for message in warnings:
        logger.warning("%s", message)
    return AlignmentReport(
        method=ALIGNMENT_SCUDO_CHUNK,
        bytes_compared=coverage.bytes_compared,
        bytes_discarded=coverage.bytes_discarded,
        sizes_differed=coverage.sizes_differed,
        n_sources=coverage.n_sources,
        warnings=warnings,
    )


def _assemble_vector(
    slices: List[AlignedSlice],
    dump_paths: Sequence[str],
    per_dump: Sequence[Sequence[ScudoChunk]],
    thresholds: Optional[VarianceThresholds],
    ambiguous: Sequence[str] = (),
    missing: Sequence[str] = (),
    row_class: Optional[Mapping[str, str]] = None,
    row_masked_offsets: Optional[Mapping[str, Tuple[int, ...]]] = None,
    content_ran: bool = False,
) -> Tuple[ConsensusVector, List[SignatureRow]]:
    """Lay the aligned chunks end to end into one synthetic slab + vector.

    Each aligned chunk becomes one ``msl_layout`` row
    ``(slab_offset, user_len, [user_va_per_dump])`` and occupies a contiguous
    slab range whose ``variance`` is the per-byte variance across the dumps and
    whose ``reference_bytes`` is the first dump's bytes -- exactly the shape
    :meth:`ConsensusVector._adopt_aligned` produces for a positional build.

    ``row_class`` / ``row_masked_offsets`` annotate the content-paired rows by
    their slice key; a slice absent from them is a signature-unique row
    (:data:`CONTENT_SIGNATURE_UNIQUE`, no masked words). Signature-unique slices
    come first and in sorted order, so their slab offsets -- and therefore
    their windows -- are byte-identical whether or not content alignment ran.
    """
    row_class = row_class or {}
    row_masked_offsets = row_masked_offsets or {}
    total = sum(s.page_size for s in slices)
    variance = np.zeros(total, dtype=np.float32)
    reference = bytearray(total)
    layout: List[Tuple[int, int, List[int]]] = []
    rows: List[SignatureRow] = []
    off = 0
    for s in slices:
        mat = np.stack([np.frombuffer(d, dtype=np.uint8) for d in s.data]).astype(np.float32)
        seg_var = np.var(mat, axis=0)
        variance[off:off + s.page_size] = seg_var
        reference[off:off + s.page_size] = s.data[0]
        layout.append((off, s.page_size, [int(v) for v in s.source_vaddrs]))
        cls, origin, size = _parse_signature(s.key)
        rows.append(SignatureRow(
            sig=s.key, slab_offset=off, length=s.page_size, class_id=cls,
            origin=origin, size=size, mean_variance=float(seg_var.mean()) if s.page_size else 0.0,
            user_vas=tuple(int(v) for v in s.source_vaddrs),
            content_class=row_class.get(s.key, CONTENT_SIGNATURE_UNIQUE),
            masked_word_offsets=row_masked_offsets.get(s.key, ())))
        off += s.page_size

    cm = ConsensusVector(thresholds=thresholds)
    cm.num_dumps = len(dump_paths)
    cm.size = total
    cm.variance = variance
    cm.reference_bytes = bytes(reference)
    cm.classifications = classify_variance(variance, thresholds)
    cm.msl_layout = layout
    cm.dump_paths = [str(p) for p in dump_paths]
    cm.region_filter = None
    cm.heap = None
    cm.alignment_report = _coverage_report(total, per_dump, ambiguous, missing, content_ran)
    return cm, rows


#: What one kept ``ScudoChunk`` costs beyond its user bytes: 273 measured on
#: CPython 3.14, with room for the larger instance dicts of older interpreters.
_CHUNK_OBJECT_BYTES = 320
#: The same for its ``_MaskedChunk``, which lives through content alignment.
_MASKED_OBJECT_BYTES = 250
#: A paired user byte costs a float32 variance, the reference bytes twice
#: (bytearray, then bytes) and a classification byte.
_SLAB_BYTES_PER_USER_BYTE = 7


def chunk_consensus_estimate(
    first_dump_chunks: Sequence[ScudoChunk], num_dumps: int,
) -> MemoryEstimate:
    """Peak memory of a build, extrapolated from its first scanned dump.

    The cost of a Scudo heap follows its chunk count, not its size: a heap of
    32-byte blocks costs several times its own bytes in Python objects, and only
    a scan can tell how many chunks there are. Runs of one app allocate alike,
    so one real dump is a sound basis, but this stays an extrapolation.
    """
    user_bytes = sum(len(chunk.data) for chunk in first_dump_chunks)
    chunks = len(first_dump_chunks)
    breakdown = {
        "chunks": num_dumps * (user_bytes + chunks * _CHUNK_OBJECT_BYTES),
        "content_masks": num_dumps * (user_bytes + chunks * _MASKED_OBJECT_BYTES),
        "slab": user_bytes * _SLAB_BYTES_PER_USER_BYTE,
    }
    return MemoryEstimate(
        sum(breakdown.values()), f"Scudo chunk consensus ({num_dumps} dumps)", breakdown)


def build_chunk_consensus(
    dump_paths: Sequence[PathLike],
    *,
    key_material: Optional[Mapping[str, Any]] = None,
    thresholds: Optional[VarianceThresholds] = None,
    content_alignment: bool = True,
    on_dump_scanned: Optional[Callable[[int, int, Sequence[ScudoChunk]], None]] = None,
) -> ScudoChunkConsensus:
    """Open the dumps, extract + align Scudo chunks, build the consensus.

    Mirrors :func:`memdiver.engine.consensus_service.build_consensus`: the
    sources are opened together, every chunk's user bytes are materialised
    while they are live, then the sources are closed -- the returned vector
    holds its own copies of ``variance`` / ``reference_bytes`` and the per-dump
    user VAs, so the window producer re-opens the dumps independently for the
    byte read-back, exactly as it does after a positional build.

    A LOCKED source (encrypted, no usable key) is refused with
    :class:`~memdiver.core.service_errors.EncryptedDumpLockedError` before any
    chunk is read: it reads back empty, so every signature of the other dumps
    would otherwise be reported "missing" from it -- a confident claim about
    bytes nobody decrypted.

    :param dump_paths: Native Scudo ``.msl`` dumps, in order (>= 2).
    :param key_material: Optional ``open_dump`` keyword arguments for encrypted
        containers.
    :param thresholds: Optional variance band boundaries for classification.
    :param content_alignment: When True (the default), subdivide each AMBIGUOUS
        signature by pointer-masked content, pairing the groups that line up one
        per dump (:func:`_content_align`). Signature-unique pairings are
        untouched either way; ``False`` pairs by header signature alone.
    :param on_dump_scanned: Optional ``(done, total, chunks)`` hook called after
        each dump's chunks are extracted, the one slow, per-dump step here. It
        is how a caller reports progress, cancels and gates memory on real
        chunk counts: an exception it raises propagates, and the sources are
        closed on the way out.
    """
    from memdiver.engine.consensus_service import open_consensus_sources

    paths = [str(p) for p in dump_paths]
    with open_consensus_sources(paths, key_material=key_material) as sources:
        for path, src in zip(paths, sources, strict=True):
            key = KeyStatus.from_source(src)
            if not key.decrypted:
                raise EncryptedDumpLockedError(
                    key.hint or f"dump is encrypted and locked: {path}")
        per_regions: List[List[ScudoRegion]] = []
        per_dump: List[List[ScudoChunk]] = []
        per_scopes: List[ScudoScanScope] = []
        per_ranges: List[Tuple[np.ndarray, np.ndarray, str]] = []
        for done, src in enumerate(sources, start=1):
            reader = src.get_reader()
            regions, chunks, scope = extract_chunks(reader)
            per_regions.append(regions)
            per_dump.append(chunks)
            per_scopes.append(scope)
            if content_alignment:
                per_ranges.append(_pointer_ranges(reader))
            if on_dump_scanned is not None:
                on_dump_scanned(done, len(sources), chunks)

    unique_slices, ambiguous, missing = align_chunks(per_dump)
    seen = {c.sig for chunks in per_dump for c in chunks}
    empty = sorted(seen - {s.key for s in unique_slices} - set(ambiguous) - set(missing))

    content: Optional[ContentAlignment] = None
    slices = list(unique_slices)
    reported_ambiguous = list(ambiguous)
    if content_alignment and ambiguous:
        content = _content_align(per_dump, ambiguous, per_ranges)
        slices = unique_slices + content.slices
        # ``ambiguous_skipped`` keeps "at least partially unpaired": a signature
        # every chunk of which got content-paired drops out; the rest stay.
        reported_ambiguous = sorted(content.still_ambiguous)

    cm, rows = _assemble_vector(
        slices, paths, per_dump, thresholds, reported_ambiguous, missing,
        row_class=(content.row_class if content else None),
        row_masked_offsets=(content.row_masked_offsets if content else None),
        content_ran=bool(content))
    logger.info(
        "Scudo chunk consensus: %d aligned row(s) (%d signature-unique, %d by "
        "content), %d ambiguous, %d missing, %d empty across %d dumps",
        len(rows), len(unique_slices), len(rows) - len(unique_slices),
        len(reported_ambiguous), len(missing), len(empty), len(paths))
    return ScudoChunkConsensus(
        vector=cm, signatures=rows, ambiguous=reported_ambiguous, missing=missing,
        empty=empty, per_dump_regions=per_regions, per_dump_scopes=per_scopes,
        per_dump_chunks=[list(chunks) for chunks in per_dump], content=content,
        dump_paths=paths)
