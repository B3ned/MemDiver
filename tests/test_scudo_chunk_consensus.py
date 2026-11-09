"""engine.scudo_chunk_consensus: Scudo geometry, chunk extraction, pairing.

The Scudo reduction is only as good as the correspondence this engine hands its
consumers, so the engine's three claims are pinned here
on their own, below any surface:

**C1 -- a chunk is what the allocator says it is.** A header is judged by the
AOSP ``android-17.0.0_r1`` bit layout and size-class map, and a chunk's bytes
are exactly the user bytes the dump CAPTURED behind that header -- never the
header, never the padding, never bytes from some other page.

**C2 -- pairing is by signature, exactly once in every dump.** A signature
that occurs once per dump is aligned; one that occurs in every dump but more
than once somewhere is ambiguous; one absent from some dump is missing. Every
signature the extraction saw is reported -- the skips are the method's honest
limits, so a silent drop is a lie by omission.

**C3 -- the synthetic vector is an ordinary aligned vector.** One
``msl_layout`` row per aligned chunk, variance measured over the paired chunk
bytes exactly as the positional builders measure it, and a coverage report
whose prose is true.
"""

from __future__ import annotations

import logging
import os
import sys
import tracemalloc
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.dump_source import open_dump  # noqa: E402
from memdiver.core.variance import ByteClass, classify_variance  # noqa: E402
from memdiver.engine.scudo_chunk_consensus import (  # noqa: E402
    ALIGNMENT_SCUDO_CHUNK,
    CLASSES,
    CONTENT_DYNAMIC_RESIDUE,
    CONTENT_INVARIANT,
    MASK_MIN_POINTER,
    PRIMARY_MAPPING_NAME,
    SCOPE_ALL_RW,
    SCOPE_VAS_PRIMARY,
    ScudoChunk,
    _mask_pointer_words,
    _parse_signature,
    _plausible,
    align_chunks,
    build_chunk_consensus,
    chunk_consensus_estimate,
    class_id_by_size,
    extract_chunks,
)
from memdiver.msl.enums import PageState  # noqa: E402
from tests.fixtures.generate_msl_fixtures import PAGE_SIZE  # noqa: E402
from tests.fixtures.generate_scudo_msl_fixtures import (  # noqa: E402
    BLOCK_C3,
    CONST_FILL,
    CONST_SIG,
    CONST_SIZE,
    DALVIK_NAME,
    FILLER_SIG,
    FILLER_SIZE,
    HEADER_SIZE,
    NEW_FILL,
    NEW_SIG,
    PRIMARY_NAME,
    PRIMARY_RESERVE_NAME,
    SECONDARY_NAME,
    SECRET_SIG,
    SECRET_SIZE,
    content_dynamic_user,
    content_dynamic_user_va,
    neighbour_secret_user_va,
    place_chunk_at,
    scudo_header,
    secret_value,
    vas_entry,
    write_content_runs,
    write_neighbour_run,
    write_neighbour_runs,
    write_scudo_msl,
    write_scudo_msl_fixtures,
)

#: The header word in front of the ``malloc(32)`` secret in the lab's
#: ``random_secret_in_heap-1.msl`` (API 37 emulator, Android 17), read straight
#: off the dump 16 bytes before the secret. Ground truth from a real device,
#: not from this repo's own packer.
DEVICE_HEADER = bytes.fromhex("020102000000277f")

BASE = 0x7F0000000000
#: Class 7 is a 0x90-byte block, which does not divide a 4 KiB page: slot 28
#: starts at 4032, so its user bytes [4048, 4176) straddle the page boundary.
CLASS_7, BLOCK_C7, SIZE_C7, STRADDLING_SLOT = 7, 0x90, 128, 28


def _write(tmp_path, name, page, *, vas_entries=None, **region_kwargs):
    return str(write_scudo_msl(tmp_path / name, [(BASE, page, region_kwargs)],
                               vas_entries=vas_entries))


def _extract(path):
    """``(regions, chunks)`` for one dump; the scan scope is dropped here.

    Scope is pinned separately in :func:`_scope` and the VAS-scope tests; the
    many extraction tests below read only regions and chunks.
    """
    regions, chunks, _scope = _extract_full(path)
    return regions, chunks


def _extract_full(path):
    with open_dump(Path(path)) as source:
        return extract_chunks(source.get_reader())


def _scope(path):
    return _extract_full(path)[2]


def _decode(word: bytes):
    ok, cls, size = _plausible(np.frombuffer(word, dtype="<u8"))
    return bool(ok[0]), int(cls[0]), int(size[0])


# ---------------------------------------------------------------------------
# Scudo geometry (AOSP android-17.0.0_r1)
# ---------------------------------------------------------------------------


def test_size_class_map_passes_scudos_own_map_validation():
    """The port of ``TableSizeClassMap::getClassIdBySize`` is exact.

    These are the properties scudo's own size-class-map test validates for
    every map it ships: each class's block size maps to that class, one byte
    less still does, one byte more is the next class -- and, exhaustively for
    every request up to the largest block, the chosen class is the SMALLEST
    one that fits. An off-by-one in ``_scaled_log2`` or in the table walk
    would make real headers fail the size-fits-class test and be dropped
    without a trace, so the whole range is swept rather than sampled.
    """
    n = len(CLASSES)
    boundary = []
    for class_id in range(1, n + 1):
        block = CLASSES[class_id - 1]
        if class_id_by_size(block) != class_id or class_id_by_size(block - 1) != class_id:
            boundary.append(class_id)
        if class_id < n and class_id_by_size(block + 1) != class_id + 1:
            boundary.append(class_id)
    assert boundary == []

    not_smallest = [
        size for size in range(1, CLASSES[-1] + 1)
        if CLASSES[class_id_by_size(size) - 1] < size
        or (class_id_by_size(size) > 1 and CLASSES[class_id_by_size(size) - 2] >= size)
    ]
    assert not_smallest == []


def test_a_header_observed_on_the_device_decodes_and_round_trips():
    """A REAL header word is the ground truth the bit layout is checked by.

    The fixture packer and the decoder were written together, so they could
    agree on a wrong layout and every synthetic test would still pass. The
    device's own word cannot be wrong that way: it must decode to class 2,
    allocated, 32 bytes, and the fixture packer must reproduce it bit for bit.
    """
    assert _decode(DEVICE_HEADER) == (True, 2, 32)
    assert scudo_header(2, 32, checksum=0x7F27) == DEVICE_HEADER


@pytest.mark.parametrize("class_id, size, origin", [
    (1, 0, 0),         # malloc(0) is a real, live chunk
    (1, 16, 0),
    (2, 17, 0),        # first size past class 1
    (3, 40, 0),
    (3, 48, 2),        # new[]
    (20, 2760, 0),     # the large chunk that aligns in the lab corpus
    (32, 65536, 0),    # the largest request the primary serves
])
def test_header_decode_accepts_allocated_primary_chunks(class_id, size, origin):
    # The checksum is a per-process nonce a dump reader never has, so any
    # value must pass: headers are judged on structure.
    word = scudo_header(class_id, size, origin=origin, checksum=0xFFFF)
    assert _decode(word) == (True, class_id, size)


@pytest.mark.parametrize("word", [
    # Freed chunks: their bytes may already be reused, and no live peer pairs.
    pytest.param(scudo_header(3, 40, state=0), id="state-available"),
    pytest.param(scudo_header(3, 40, state=2), id="state-quarantined"),
    # Class 0 is the internal BatchClass; >32 does not exist in this config.
    pytest.param(scudo_header(0, 8), id="batch-class"),
    pytest.param(scudo_header(33, 40), id="class-out-of-range"),
    # The size-fits-class test, both directions: a decoder that skipped it
    # would accept almost any word whose low byte is 1..32.
    pytest.param(scudo_header(3, 8), id="size-too-small-for-class"),
    pytest.param(scudo_header(1, 17), id="size-too-large-for-class"),
    # A realigned (memalign) chunk carries an Offset: outside this contract.
    pytest.param(scudo_header(3, 40, offset=1), id="realigned-offset"),
    pytest.param(scudo_header(32, 65537), id="size-beyond-the-primary"),
])
def test_header_decode_rejects_what_is_not_an_allocated_primary_chunk(word):
    assert _decode(word)[0] is False


# ---------------------------------------------------------------------------
# C1 -- extraction
# ---------------------------------------------------------------------------


def test_extracted_chunk_is_exactly_the_user_bytes_behind_its_header(tmp_path):
    """User bytes start 16 bytes past the block and run for the HEADER's size.

    The header's unused half and the block's tail padding are 0xEE here, so a
    reader that is off by the 8-byte header word, or that takes the block
    size minus the header instead of the recorded size, returns 0xEE bytes.
    """
    page = bytearray(b"\xEE" * PAGE_SIZE)
    place_chunk_at(page, 5 * BLOCK_C3, 3, SECRET_SIZE, secret_value(0))
    regions, chunks = _extract(_write(tmp_path, "one.msl", bytes(page)))

    assert len(chunks) == 1
    chunk = chunks[0]
    assert chunk.sig == SECRET_SIG
    assert chunk.data == secret_value(0)
    assert chunk.user_va == BASE + 5 * BLOCK_C3 + HEADER_SIZE
    assert chunk.slot == 5
    assert [(r.class_id, r.block_size, r.chunks) for r in regions] == [(3, BLOCK_C3, 1)]


def test_a_plausible_word_off_the_block_grid_is_counted_not_extracted(tmp_path):
    """The grid test is what separates a header from data that looks like one.

    The planted word inside the chunk's user bytes is a perfectly plausible
    header (non-vacuous: the decoder accepts it), but it sits 16 bytes into a
    64-byte block, so it is reported as ``off_grid_plausible`` and is NOT a
    second chunk.
    """
    planted = scudo_header(3, 44)
    assert _decode(planted)[0] is True
    page = bytearray(PAGE_SIZE)
    place_chunk_at(page, 2 * BLOCK_C3, 3, SECRET_SIZE, planted + bytes(SECRET_SIZE - 8))
    regions, chunks = _extract(_write(tmp_path, "planted.msl", bytes(page)))

    assert [c.slot for c in chunks] == [2]
    assert regions[0].off_grid_plausible == 1


@pytest.mark.parametrize("protection, expected", [
    (0x1, 0),   # r--
    (0x5, 0),   # r-x: header-shaped words in code or rodata
    (0x7, 0),   # rwx: not what Scudo maps
    (0x3, 1),   # rw-: the heap -- the control
])
def test_only_read_write_regions_are_scanned(tmp_path, protection, expected):
    page = bytearray(PAGE_SIZE)
    place_chunk_at(page, 3 * BLOCK_C3, 3, SECRET_SIZE, secret_value(0))
    regions, chunks = _extract(_write(
        tmp_path, f"prot{protection}.msl", bytes(page), protection=protection))
    assert len(chunks) == expected
    assert len(regions) == expected


def test_the_dominant_on_grid_class_names_the_region(tmp_path):
    """A Scudo region holds ONE class; a minority class on its grid is noise.

    Two class-1 words sit on the 32-byte grid but off the 64-byte one, so they
    vote for class 1. They are counted in ``other_class_votes`` and NOT
    extracted -- the region is class 3 because five class-3 headers say so.
    """
    page = bytearray(PAGE_SIZE)
    for k in range(5):
        size = SECRET_SIZE + k
        place_chunk_at(page, 2 * k * BLOCK_C3, 3, size, bytes([k + 1]) * size)
    for offset in (1056, 1440):   # multiples of 32, not of 64
        place_chunk_at(page, offset, 1, 8, b"\x77" * 8)
    regions, chunks = _extract(_write(tmp_path, "dominant.msl", bytes(page)))

    assert [(r.class_id, r.chunks, r.other_class_votes) for r in regions] == [(3, 5, 2)]
    assert sorted(c.sig for c in chunks) == [f"scudo:c3:o0:s{SECRET_SIZE + k}" for k in range(5)]


def _straddling_page() -> bytearray:
    """Page 0 with a control chunk (slot 0) and one straddling into page 1."""
    page = bytearray(PAGE_SIZE)
    place_chunk_at(page, 0, CLASS_7, SIZE_C7, b"\x5C" * SIZE_C7)
    head = PAGE_SIZE - (STRADDLING_SLOT * BLOCK_C7 + HEADER_SIZE)
    place_chunk_at(page, STRADDLING_SLOT * BLOCK_C7, CLASS_7, SIZE_C7, b"\xAB" * head)
    return page


def test_a_chunk_running_off_the_captured_pages_is_skipped(tmp_path):
    page0 = _straddling_page()
    path = _write(tmp_path, "tail.msl", bytes(page0),
                  page_states=[PageState.CAPTURED, PageState.FAILED])
    _regions, chunks = _extract(path)
    assert [c.slot for c in chunks] == [0]


def test_a_chunk_spanning_an_uncaptured_page_is_never_spliced(tmp_path):
    """C1 across a hole: bytes the dump did not capture are not chunk bytes.

    Pages are [CAPTURED, FAILED, CAPTURED]. The straddling chunk's last 80
    bytes live in the FAILED page, so the dump simply does not have them. A
    reader that joins the CAPTURED pages it finds and slices the result shifts
    page 2 (0xEE) into the hole: the chunk comes back the right LENGTH with
    bytes from the wrong ADDRESS, and its variance is then measured over
    fiction. The only honest outcome is the one the run-off-the-end case
    already gets: the chunk is skipped. The control chunk must survive.
    """
    page0 = _straddling_page()
    page2 = b"\xEE" * PAGE_SIZE
    path = _write(tmp_path, "hole.msl", bytes(page0) + page2,
                  page_states=[PageState.CAPTURED, PageState.FAILED, PageState.CAPTURED])
    _regions, chunks = _extract(path)

    assert [c.slot for c in chunks] == [0], [
        (c.slot, c.data.count(0xEE)) for c in chunks]
    assert all(0xEE not in c.data for c in chunks)


# ---------------------------------------------------------------------------
# C2 -- pairing
# ---------------------------------------------------------------------------


def _chunk(sig: str, va: int) -> ScudoChunk:
    size = int(sig.rsplit(":s", 1)[1])
    return ScudoChunk(sig=sig, user_va=va, slot=0, data=bytes([va & 0xFF]) * size)


def test_exactly_once_in_every_dump_is_the_pairing_rule():
    """One input per rule, so each bucket has exactly one way to be right.

    ``A`` is once everywhere (aligned). ``B`` is once in two dumps and twice
    in the third -- the copies there cannot be told apart, so it is ambiguous,
    NOT aligned on the dumps where it happens to be unique. ``C`` is twice in
    dump 0 and absent from dump 1 -- missing wins over ambiguous. ``D`` exists
    in one dump only.
    """
    a, b, c, d = (f"scudo:c3:o0:s{s}" for s in (33, 34, 35, 36))
    per_dump = [
        [_chunk(a, 0x100), _chunk(b, 0x200), _chunk(c, 0x300), _chunk(c, 0x340)],
        [_chunk(a, 0x110), _chunk(b, 0x210), _chunk(d, 0x410)],
        [_chunk(a, 0x120), _chunk(b, 0x220), _chunk(b, 0x260), _chunk(c, 0x320)],
    ]
    slices, ambiguous, missing = align_chunks(per_dump)

    assert [s.key for s in slices] == [a]
    assert slices[0].source_vaddrs == [0x100, 0x110, 0x120]
    assert ambiguous == [b]
    assert missing == [c, d]


def test_every_signature_seen_is_accounted_for(tmp_path):
    """C2's second half: a skip is reported, never silent.

    ``malloc(0)`` is a live chunk with a plausible header (class 1, size 0),
    unique in both dumps here -- but it has no bytes to compare. Whatever the
    engine decides to do with it, the provenance must still name it somewhere;
    dropping it from aligned, ambiguous AND missing at once makes the report
    claim a signature the extraction saw never existed. Also pins that the
    reported buckets are disjoint.
    """
    paths = []
    for run in range(2):
        page = bytearray(PAGE_SIZE)
        place_chunk_at(page, 5 * 32, 1, 0, b"")
        place_chunk_at(page, 9 * 32, 1, 8, bytes([run + 1]) * 8)
        paths.append(_write(tmp_path, f"zero{run}.msl", bytes(page)))
    seen = {c.sig for path in paths for c in _extract(path)[1]}
    assert "scudo:c1:o0:s0" in seen          # non-vacuous: it WAS extracted

    provenance = build_chunk_consensus(paths).alignment_provenance()
    aligned = {row["signature"] for row in provenance["aligned_signatures"]}
    ambiguous = set(provenance["ambiguous_skipped"])
    missing = set(provenance["missing_skipped"])
    assert not (aligned & ambiguous or aligned & missing or ambiguous & missing)

    reported = set(aligned)
    for key, value in provenance.items():
        if key != "aligned_signatures" and isinstance(value, list):
            reported |= {v for v in value if isinstance(v, str)}
    assert seen - reported == set()


def test_origin_tells_same_size_allocations_apart(tmp_path):
    """``malloc(36)`` and ``new char[36]`` share class and size, not origin.

    Collapsing them into one ``c3:s36`` signature would make both ambiguous
    and lose two pairable chunks.
    """
    scc = build_chunk_consensus(write_neighbour_runs(tmp_path, 3))
    rows = {r.sig: r for r in scc.signatures}
    assert {CONST_SIG, NEW_SIG} <= set(rows)
    assert (rows[CONST_SIG].class_id, rows[CONST_SIG].size) == \
        (rows[NEW_SIG].class_id, rows[NEW_SIG].size)
    assert (rows[CONST_SIG].origin, rows[NEW_SIG].origin) == (0, 1)
    assert scc.ambiguous == []


def test_alignment_is_independent_of_dump_order(tmp_path):
    paths = [str(p) for p in write_neighbour_runs(tmp_path, 3)]
    forward = build_chunk_consensus(paths)
    rotated = build_chunk_consensus([paths[2], paths[0], paths[1]])

    assert [r.sig for r in forward.signatures] == [r.sig for r in rotated.signatures]
    for f_row, r_row in zip(forward.signatures, rotated.signatures, strict=True):
        f_vas = f_row.user_vas
        assert r_row.user_vas == (f_vas[2], f_vas[0], f_vas[1])
        assert r_row.mean_variance == pytest.approx(f_row.mean_variance)


# ---------------------------------------------------------------------------
# C3 -- the synthetic vector
# ---------------------------------------------------------------------------


@pytest.fixture
def neighbours(tmp_path):
    paths = [str(p) for p in write_neighbour_runs(tmp_path, 3)]
    return build_chunk_consensus(paths), paths


def test_the_vector_is_a_well_formed_aligned_vector(neighbours):
    """One layout row per aligned chunk, laid end to end, mapping back to VA.

    ``slab_to_va`` is the inverse every window segment is built from, so it is
    checked at both ends of every row and one byte past the slab, where it
    must answer -1 rather than a plausible address.
    """
    scc, paths = neighbours
    cm = scc.vector

    assert [(r.sig, r.slab_offset, r.length) for r in scc.signatures] == [
        (CONST_SIG, 0, CONST_SIZE),
        (SECRET_SIG, CONST_SIZE, SECRET_SIZE),
        (NEW_SIG, CONST_SIZE + SECRET_SIZE, CONST_SIZE),
    ]
    total = 2 * CONST_SIZE + SECRET_SIZE
    assert cm.size == total == len(cm.variance) == len(cm.classifications)
    assert len(cm.reference_bytes) == total
    assert cm.num_dumps == 3
    assert cm.dump_paths == paths
    assert cm.alignment_report.method == ALIGNMENT_SCUDO_CHUNK
    assert cm.msl_layout == [
        (r.slab_offset, r.length, list(r.user_vas)) for r in scc.signatures]

    secret = scc.row_for_signature(SECRET_SIG)
    assert list(secret.user_vas) == [neighbour_secret_user_va(run) for run in range(3)]
    for row in scc.signatures:
        for dump in range(3):
            assert cm.slab_to_va(dump, row.slab_offset) == row.user_vas[dump]
            last = row.slab_offset + row.length - 1
            assert cm.slab_to_va(dump, last) == row.user_vas[dump] + row.length - 1
    assert cm.slab_to_va(0, total) == -1

    assert cm.reference_bytes == (
        bytes([CONST_FILL] * CONST_SIZE) + secret_value(0) + bytes([NEW_FILL] * CONST_SIZE))


def test_variance_is_measured_over_the_paired_chunks(neighbours):
    """Recomputed independently from the runs' KNOWN secret bytes.

    The window re-reads bytes by VA, so a vector built from the wrong bytes
    (a mispaired chunk, or one read 16 bytes early) would still show the
    right ``bytes`` and silently wrong ``classes``. Same estimator as the
    positional builders (float32 population variance), same classifier.
    """
    scc, _paths = neighbours
    cm = scc.vector
    stacked = np.stack([np.frombuffer(secret_value(run), dtype=np.uint8) for run in range(3)])
    expected = np.var(stacked.astype(np.float32), axis=0)

    row = scc.row_for_signature(SECRET_SIG)
    span = slice(row.slab_offset, row.slab_offset + row.length)
    np.testing.assert_array_equal(cm.variance[span], expected)
    assert cm.classifications[span].tolist() == classify_variance(expected).tolist()
    assert ByteClass.INVARIANT not in set(cm.classifications[span].tolist())
    assert row.mean_variance == pytest.approx(float(expected.mean()))

    for sig in (CONST_SIG, NEW_SIG):
        const = scc.row_for_signature(sig)
        span = slice(const.slab_offset, const.slab_offset + const.length)
        assert not cm.variance[span].any()
        assert set(cm.classifications[span].tolist()) == {ByteClass.INVARIANT}


def test_coverage_reconciles_and_counts_chunk_bytes(tmp_path):
    """``sum(available) == compared * n + discarded``, in CHUNK bytes.

    Runs 1-2 offer the secret, two fillers and the class-1 chunk; run 3 lacks
    the class-1 chunk. Only the secret is compared.
    """
    report = build_chunk_consensus(write_scudo_msl_fixtures(tmp_path, 3)).vector.alignment_report
    full = SECRET_SIZE + 2 * FILLER_SIZE + 8
    available = [full, full, full - 8]

    assert report.bytes_compared == SECRET_SIZE
    assert report.n_sources == 3
    assert report.sizes_differed is True
    assert report.bytes_discarded == sum(available) - SECRET_SIZE * 3
    assert sum(available) == report.bytes_compared * report.n_sources + report.bytes_discarded


@pytest.mark.parametrize("with_aligned_secret", [True, False],
                         ids=["secret-aligned", "nothing-aligned"])
def test_coverage_warning_never_calls_an_ambiguous_chunk_absent(tmp_path, with_aligned_secret):
    """The reused positional warnings describe positional losses.

    Positionally, a discarded byte is one some dump did not capture, hence
    "present in some dumps but not all" / "no bytes common to all N dumps".
    Here every discarded byte belongs to the AMBIGUOUS filler signature, which
    is present in EVERY dump -- it is skipped because its two copies cannot be
    told apart, which is a different finding with a different remedy. Nothing
    is missing (non-vacuous: and bytes WERE discarded), so a warning that
    says otherwise misdirects the operator.
    """
    paths = []
    for run in range(3):
        page = bytearray(PAGE_SIZE)
        slot = (run * 7 + 3) % 40
        if with_aligned_secret:
            place_chunk_at(page, slot * BLOCK_C3, 3, SECRET_SIZE, secret_value(run))
        # Two fillers with IDENTICAL content, so content alignment keeps the
        # signature ambiguous (repeated, G3) and the discard this test is about
        # still happens -- the point is the WORDING, not whether it pairs.
        for k in (11, 22):
            place_chunk_at(page, ((slot + k) % 40) * BLOCK_C3, 3, FILLER_SIZE,
                           bytes([0xAB]) * FILLER_SIZE)
        paths.append(_write(tmp_path, f"amb{run}.msl", bytes(page)))
    scc = build_chunk_consensus(paths)

    assert scc.missing == []
    assert scc.ambiguous == [FILLER_SIG]
    report = scc.vector.alignment_report
    assert report.bytes_discarded > 0
    for warning in report.warnings:
        assert "some dumps but not all" not in warning, warning
        assert "no bytes common to all" not in warning, warning


# ---------------------------------------------------------------------------
# VAS region scope: scan only [anon:scudo:primary], fall back honestly
# ---------------------------------------------------------------------------
#
# memslicer writes a VAS map (block 0x1001) on every capture, naming every
# enumerated range -- captured or not -- with the kernel's /proc/<pid>/maps
# label. The scan uses it to cover only the Scudo primary heap, so a
# header-shaped word in an ART region is not mistaken for a chunk. When the map
# is absent or names no primary region the scan falls back to every RW region,
# never to "0 chunks because the names were missing".

#: A second RW region, far from BASE, standing in for the ART managed heap.
DECOY_BASE = BASE + 0x200000
#: Class 3, 44 user bytes -> a DIFFERENT signature than the secret's c3:s40, so
#: a decoy chunk found under the fallback is unmistakable in the chunk list.
DECOY_SIZE = 44
DECOY_SIG = "scudo:c3:o0:s44"


def _primary_and_decoy(tmp_path, name, *, with_vas):
    """A primary heap page (the secret) plus a decoy RW page (ART-like).

    The decoy carries an on-grid, perfectly plausible class-3 header, so the
    all-RW fallback extracts it as a chunk; the VAS scope never looks at it.
    With ``with_vas`` the two regions are named ``[anon:scudo:primary]`` and
    ``[anon:dalvik-main space]``.
    """
    primary = bytearray(PAGE_SIZE)
    place_chunk_at(primary, 2 * BLOCK_C3, 3, SECRET_SIZE, secret_value(0))
    decoy = bytearray(PAGE_SIZE)
    place_chunk_at(decoy, 0, 3, DECOY_SIZE, bytes([0x9]) * DECOY_SIZE)
    regions = [(BASE, bytes(primary), {}), (DECOY_BASE, bytes(decoy), {})]
    vas = None
    if with_vas:
        vas = [vas_entry(BASE, PAGE_SIZE, PRIMARY_NAME),
               vas_entry(DECOY_BASE, PAGE_SIZE, DALVIK_NAME)]
    return str(write_scudo_msl(tmp_path / name, regions, vas_entries=vas))


def test_vas_scope_scans_only_the_named_primary_region(tmp_path):
    """The decoy's chunk is absent, the primary's chunks are whole, scope=vas.

    The decoy region holds a real-looking class-3 header; that it does NOT
    appear proves the scope excluded the region before the header grid ran,
    not that the header failed to decode.
    """
    regions, chunks, scope = _extract_full(_primary_and_decoy(
        tmp_path, "vas.msl", with_vas=True))

    assert scope.kind == SCOPE_VAS_PRIMARY
    assert [c.sig for c in chunks] == [SECRET_SIG]
    assert DECOY_SIG not in {c.sig for c in chunks}
    assert [r.name for r in regions] == [PRIMARY_NAME]
    assert (scope.rw_regions, scope.rw_regions_scanned) == (2, 1)
    assert PRIMARY_MAPPING_NAME in scope.reason


def test_without_a_vas_map_the_scan_falls_back_to_every_rw_region(tmp_path, caplog):
    """No map -> every RW region: the decoy IS extracted, and a warning says so.

    Non-vacuous against the test above: the only change is the missing VAS map,
    and it flips the decoy from absent to present.
    """
    with caplog.at_level(logging.WARNING, logger="memdiver.engine.scudo_chunk_consensus"):
        regions, chunks, scope = _extract_full(_primary_and_decoy(
            tmp_path, "nov.msl", with_vas=False))

    assert scope.kind == SCOPE_ALL_RW
    assert {c.sig for c in chunks} == {SECRET_SIG, DECOY_SIG}
    assert {r.name for r in regions} == {""}      # no names to attach
    assert (scope.rw_regions, scope.rw_regions_scanned) == (2, 2)
    assert "no VAS map" in caplog.text


def test_a_vas_map_without_a_primary_name_falls_back_not_to_zero(tmp_path, caplog):
    """A map that never says ``primary`` must not silence the scan.

    The heap region is really a Scudo primary, but the map mislabels it; the
    only safe move is the fallback, so the secret is still found -- never
    "0 chunks because no name matched".
    """
    primary = bytearray(PAGE_SIZE)
    place_chunk_at(primary, 2 * BLOCK_C3, 3, SECRET_SIZE, secret_value(0))
    path = str(write_scudo_msl(
        tmp_path / "noname.msl", [(BASE, bytes(primary), {})],
        vas_entries=[vas_entry(BASE, PAGE_SIZE, DALVIK_NAME)]))

    with caplog.at_level(logging.WARNING, logger="memdiver.engine.scudo_chunk_consensus"):
        _regions, chunks, scope = _extract_full(path)

    assert scope.kind == SCOPE_ALL_RW
    assert [c.sig for c in chunks] == [SECRET_SIG]
    assert f"no {PRIMARY_MAPPING_NAME}" in caplog.text


def test_primary_reserve_and_secondary_are_not_the_primary_scope(tmp_path):
    """The prefix trap: ``primary`` is a prefix of ``primary_reserve``.

    Three RW regions carry a chunk each; only the one named EXACTLY
    ``[anon:scudo:primary]`` is scanned. A ``startswith`` match would wrongly
    pull in ``primary_reserve``; a name-agnostic scan would pull in both it and
    ``secondary``. All three are RW with real chunks, so only the name can tell
    them apart.
    """
    regions = []
    vas = []
    specs = [(BASE, PRIMARY_NAME, SECRET_SIZE),
             (BASE + 0x200000, PRIMARY_RESERVE_NAME, SECRET_SIZE + 1),
             (BASE + 0x400000, SECONDARY_NAME, SECRET_SIZE + 2)]
    for base, name, size in specs:
        page = bytearray(PAGE_SIZE)
        place_chunk_at(page, 0, 3, size, bytes([size & 0xFF]) * size)
        regions.append((base, bytes(page), {}))
        vas.append(vas_entry(base, PAGE_SIZE, name))
    _regions, chunks, scope = _extract_full(str(write_scudo_msl(
        tmp_path / "prefix.msl", regions, vas_entries=vas)))

    assert scope.kind == SCOPE_VAS_PRIMARY
    assert scope.rw_regions_scanned == 1
    assert [c.sig for c in chunks] == [f"scudo:c3:o0:s{SECRET_SIZE}"]


def test_a_region_base_inside_a_primary_entry_is_in_scope(tmp_path):
    """Containment, not base equality: the region sits INSIDE a primary entry.

    The VAS entry spans a range that begins 0x4000 before the region's base, so
    a scope that compared region base == entry base would miss it. memslicer
    page-aligns both, but a primary mapping can be larger than one region
    block, so the index must answer by containment.
    """
    primary = bytearray(PAGE_SIZE)
    place_chunk_at(primary, 0, 3, SECRET_SIZE, secret_value(0))
    span_base = BASE - 0x4000
    path = str(write_scudo_msl(
        tmp_path / "inside.msl", [(BASE, bytes(primary), {})],
        vas_entries=[vas_entry(span_base, 0x8000, PRIMARY_NAME)]))

    regions, chunks, scope = _extract_full(path)
    assert scope.kind == SCOPE_VAS_PRIMARY
    assert [c.sig for c in chunks] == [SECRET_SIG]
    assert regions[0].base != span_base      # matched though not at the start
    assert regions[0].name == PRIMARY_NAME


def test_scope_counts_reconcile_scanned_plus_skipped(tmp_path):
    """Provenance stands in for the stopwatch: bytes/regions scanned vs skipped.

    The win the scope buys is "did not read 2 GiB"; a byte count in the
    provenance proves it without a flaky timing assertion.
    """
    _regions, _chunks, scope = _extract_full(_primary_and_decoy(
        tmp_path, "counts.msl", with_vas=True))
    assert scope.bytes_scanned == PAGE_SIZE       # the one primary page
    assert scope.bytes_skipped == PAGE_SIZE       # the one decoy page
    assert scope.rw_regions == scope.rw_regions_scanned + 1


def test_mixed_dumps_record_their_own_scope_and_still_align(tmp_path):
    """One dump with a VAS map, one without: each keeps its own scope.

    Alignment is by signature and does not care how each dump was scoped, so
    the secret and its two neighbours still pair across the two dumps; the
    provenance carries one scope per dump, in path order.
    """
    p_vas = str(write_neighbour_run(tmp_path / "a.msl", 0, vas=True))
    p_nov = str(write_neighbour_run(tmp_path / "b.msl", 1, vas=False))
    scc = build_chunk_consensus([p_vas, p_nov])

    assert [s.kind for s in scc.per_dump_scopes] == [SCOPE_VAS_PRIMARY, SCOPE_ALL_RW]
    assert {r.sig for r in scc.signatures} >= {SECRET_SIG, CONST_SIG, NEW_SIG}
    prov = scc.alignment_provenance()
    assert prov["version"] == "0.2.0"
    assert [e["dump"] for e in prov["region_scope"]] == [p_vas, p_nov]
    assert [e["kind"] for e in prov["region_scope"]] == [SCOPE_VAS_PRIMARY, SCOPE_ALL_RW]


def test_vas_scope_is_order_independent_and_deterministic(tmp_path):
    """Same signatures and scope stats however the dumps are ordered or re-run."""
    paths = [str(p) for p in write_neighbour_runs(tmp_path, 3, vas=True)]
    first = build_chunk_consensus(paths)
    again = build_chunk_consensus(paths)
    rotated = build_chunk_consensus([paths[2], paths[0], paths[1]])

    sigs = [r.sig for r in first.signatures]
    assert [r.sig for r in again.signatures] == sigs
    assert [r.sig for r in rotated.signatures] == sigs
    assert all(s.kind == SCOPE_VAS_PRIMARY for s in first.per_dump_scopes)
    assert [s.to_dict() for s in again.per_dump_scopes] == \
        [s.to_dict() for s in first.per_dump_scopes]


@pytest.fixture
def aes_key():
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    return os.urandom(32)


def test_vas_scope_survives_an_encrypted_container(tmp_path, aes_key):
    """The VAS map is encrypted with the rest; the key reads it, scope=vas.

    An unkeyed open reads the container back empty, so this also pins that the
    scope is decided AFTER decryption, not from a plaintext side channel.
    """
    paths = [str(p) for p in write_neighbour_runs(tmp_path, 3, key=aes_key, vas=True)]
    scc = build_chunk_consensus(paths, key_material={"key": aes_key})

    assert [s.kind for s in scc.per_dump_scopes] == [SCOPE_VAS_PRIMARY] * 3
    assert SECRET_SIG in {r.sig for r in scc.signatures}


@pytest.mark.parametrize("seed", range(12))
def test_scope_matches_exactly_the_primary_named_regions(tmp_path, seed):
    """Over random name layouts, the scanned set == the primary-named set.

    A small property sweep instead of a single hand-built layout: each RW
    region gets a random Scudo/ART name, and the regions actually scanned must
    be exactly those named ``[anon:scudo:primary]`` -- or, when none is, every
    region (the fallback). Bases are far apart so the page spans never overlap.
    """
    rng = np.random.default_rng(seed)
    names = [PRIMARY_NAME, PRIMARY_RESERVE_NAME, SECONDARY_NAME, DALVIK_NAME]
    n = int(rng.integers(2, 6))
    regions, vas, primary_bases = [], [], []
    for i in range(n):
        base = BASE + i * 0x100000
        name = names[int(rng.integers(len(names)))]
        page = bytearray(PAGE_SIZE)
        place_chunk_at(page, 0, 3, SECRET_SIZE, bytes([i + 1]) * SECRET_SIZE)
        regions.append((base, bytes(page), {}))
        vas.append(vas_entry(base, PAGE_SIZE, name))
        if name == PRIMARY_NAME:
            primary_bases.append(base)
    scanned_regions, _chunks, scope = _extract_full(str(write_scudo_msl(
        tmp_path / f"rand{seed}.msl", regions, vas_entries=vas)))

    if primary_bases:
        assert scope.kind == SCOPE_VAS_PRIMARY
        assert sorted(r.base for r in scanned_regions) == sorted(primary_bases)
    else:
        assert scope.kind == SCOPE_ALL_RW
        assert scope.rw_regions_scanned == n


# ---------------------------------------------------------------------------
# Content alignment: pointer masking + invariant-content pairing
# ---------------------------------------------------------------------------
#
# A signature present more than once in a dump is ambiguous by header alone.
# Content alignment groups its chunks by their POINTER-MASKED content and pairs
# the groups that line up one per dump: a static allocation whose only per-run
# difference is an ASLR
# pointer (``content_invariant``), or -- when every dump leaves exactly one --
# the lone chunk whose content is unique to a dump (``dynamic_residue``, the
# moved secret). Raw bytes are never altered; masking only decides pairing.

#: Non-overlapping ranges for the masking unit tests, both ABOVE
#: ``MASK_MIN_POINTER`` (0x10000) so values inside them are eligible to be
#: pointers: [0x100000,0x200000) and [0x500000,0x600000). ``ends`` are exclusive
#: bounds; the mask treats the last byte and the one-past-end address as in range.
_MASK_STARTS = np.array([0x100000, 0x500000], dtype="<u8")
_MASK_ENDS = np.array([0x200000, 0x600000], dtype="<u8")


def _mask(words):
    """Mask a little-endian u64 list against the unit-test ranges."""
    import struct
    data = b"".join(struct.pack("<Q", w) for w in words)
    masked, offs = _mask_pointer_words(data, _MASK_STARTS, _MASK_ENDS)
    return list(np.frombuffer(masked, dtype="<u8")), offs


def test_mask_zeroes_only_words_that_point_into_a_range():
    """A word inside a range is zeroed; one outside, and a small one, are kept."""
    out, offs = _mask([0x150000,       # inside range 0 -> masked
                        0x0042,        # < MASK_MIN_POINTER -> kept
                        0x999999,      # above both ranges -> kept
                        0x500000])     # range-1 start -> masked
    assert out == [0, 0x0042, 0x999999, 0]
    assert offs == (0, 24)


def test_mask_is_end_inclusive_for_one_past_end_pointers():
    """A pointer one past the end of a mapping is still into the mapping.

    0x200000 is the exclusive end of range 0 (and below range 1's start), so a
    naive half-open test would miss it; the mask must zero it.
    """
    out, offs = _mask([0x200000, 0x1FFFFF, 0x200001])
    assert out == [0, 0, 0x200001]      # end and last-byte masked; the gap kept
    assert offs == (0, 8)


def test_mask_below_min_pointer_is_never_masked():
    """Even inside a range by value, anything < MASK_MIN_POINTER stays.

    The lowest user mapping is far above this floor, so a small value in a
    chunk is an integer, not an address.
    """
    low = np.array([0], dtype="<u8")
    high = np.array([MASK_MIN_POINTER], dtype="<u8")
    import struct
    data = struct.pack("<Q", MASK_MIN_POINTER - 1)
    masked, offs = _mask_pointer_words(data, low, high)
    assert masked == data and offs == ()


def test_mask_leaves_a_trailing_partial_word_and_preserves_length():
    """Bytes that do not fill an 8-byte word are copied through; length holds."""
    import struct
    data = struct.pack("<Q", 0x150000) + b"\xAB\xCD\xEF"     # 8 + 3 bytes
    masked, offs = _mask_pointer_words(data, _MASK_STARTS, _MASK_ENDS)
    assert len(masked) == len(data)
    assert masked == bytes(8) + b"\xAB\xCD\xEF"
    assert offs == (0,)


def test_mask_is_idempotent():
    """Masking already-masked bytes changes nothing more (a zeroed word stays)."""
    import struct
    data = struct.pack("<Q", 0x1500) + struct.pack("<Q", 0x12)
    once, _o = _mask_pointer_words(data, _MASK_STARTS, _MASK_ENDS)
    twice, _o2 = _mask_pointer_words(once, _MASK_STARTS, _MASK_ENDS)
    assert once == twice


def test_mask_counts_an_unreadable_range_the_same_as_a_readable_one():
    """A VAS range is a range whether or not its bytes were captured.

    Masking takes the ranges as given; a pointer into a PROT_NONE reserve (no
    captured bytes, but a real mapping) is masked exactly like one into the
    heap. Non-vacuous: the value is in the (unreadable) range and is zeroed.
    """
    import struct
    reserve_start, reserve_end = np.array([0x80000], "<u8"), np.array([0x90000], "<u8")
    data = struct.pack("<Q", 0x85000)
    masked, offs = _mask_pointer_words(data, reserve_start, reserve_end)
    assert masked == bytes(8) and offs == (0,)


@pytest.mark.parametrize("seed", range(16))
def test_random_bytes_are_almost_never_masked(seed):
    """High-entropy bytes rarely land in the tiny mapped fraction of 2**64.

    A 40-byte random chunk is five words; with ranges covering a sliver of the
    address space, masking should touch nothing almost always. This guards the
    dynamic path: a fresh secret must stay a dynamic candidate, not be blanked.
    """
    rng = np.random.default_rng(seed)
    data = rng.integers(0, 256, size=SECRET_SIZE, dtype=np.uint8).tobytes()
    masked, offs = _mask_pointer_words(data, _MASK_STARTS, _MASK_ENDS)
    assert masked == data and offs == ()


def _content(paths, **kw):
    return build_chunk_consensus([str(p) for p in paths], **kw)


def test_static_chunk_with_an_aslr_pointer_pairs_as_content_invariant(tmp_path):
    """Same allocation every run, only its heap pointer shifts -> one row.

    The chunk is ambiguous by signature (two per run) but its MASKED bytes are
    identical across runs, so it pairs; the variance is confined to the pointer
    word, and ``masked_word_offsets`` names that word.
    """
    scc = _content(write_content_runs(tmp_path, 3, statics=1, dynamics=1))
    inv = [r for r in scc.signatures if r.content_class == CONTENT_INVARIANT]
    assert len(inv) == 1
    row = inv[0]
    assert row.sig.startswith(SECRET_SIG + "#content:")
    assert row.masked_word_offsets == (0,)
    # Variance lives only inside the pointer word; the constant tail is flat.
    span = scc.vector.variance[row.slab_offset:row.slab_offset + row.length]
    assert span[8:].sum() == 0
    assert span[:8].sum() > 0


def test_one_dynamic_chunk_per_dump_pairs_as_dynamic_residue(tmp_path):
    """Exactly one per-run-unique chunk per dump -> paired, each its own value.

    This is the recoverable case: the signature is ambiguous, but after the
    static chunk is set aside the only chunk left per dump is the dynamic one,
    so the rows carry each run's own bytes.
    """
    paths = write_content_runs(tmp_path, 3, statics=1, dynamics=1)
    scc = _content(paths)
    dyn = [r for r in scc.signatures if r.content_class == CONTENT_DYNAMIC_RESIDUE]
    assert len(dyn) == 1
    row = dyn[0]
    assert row.sig == SECRET_SIG + "#dynamic"
    assert list(row.user_vas) == [content_dynamic_user_va(run) for run in range(3)]
    assert scc.ambiguous == []           # static + dynamic -> fully resolved
    assert scc.content.per_signature[SECRET_SIG]["dynamic_paired"] is True


def test_two_dynamic_chunks_per_dump_do_not_pair_but_are_counted(tmp_path):
    """Two dynamic chunks per dump: no unique residue, so nothing pairs there.

    The static chunk still pairs; the signature stays ambiguous with its dynamic
    chunks counted per dump, which is the honest "narrowed, not solved" result.
    """
    scc = _content(write_content_runs(tmp_path, 3, statics=1, dynamics=2))
    info = scc.content.per_signature[SECRET_SIG]
    assert info["dynamic_per_dump"] == [2, 2, 2]
    assert info["dynamic_paired"] is False
    assert info["unpaired_chunks"] == 6          # 2 dynamic * 3 dumps
    assert SECRET_SIG in scc.ambiguous
    assert SECRET_SIG in scc.content.partially_resolved
    assert not any(r.content_class == CONTENT_DYNAMIC_RESIDUE for r in scc.signatures)


def test_a_constant_secret_in_an_overfull_signature_pairs_as_invariant(tmp_path):
    """A STATIC secret (same bytes every run) in an ambiguous signature pairs.

    With one static-with-pointer chunk and one constant 'secret' per dump, both
    are content-invariant (the secret has no pointer, so masked == raw and is
    identical across runs). Nothing is discarded.
    """
    # statics=1 (ASLR pointer) + repeated=1 (one constant 'secret', count 1 per
    # dump): both are present once in every dump, so both pair as invariant.
    paths = write_content_runs(tmp_path, 3, statics=1, dynamics=0, repeated=1)
    scc = _content(paths)
    inv = [r for r in scc.signatures if r.content_class == CONTENT_INVARIANT]
    assert len(inv) == 2                 # the pointer chunk and the constant one
    assert scc.ambiguous == []
    assert scc.content.per_signature[SECRET_SIG]["unpaired_chunks"] == 0


def test_repeated_invariant_content_is_counted_not_paired(tmp_path):
    """Content present in EVERY dump more than once (m>1) is counted (G3).

    Two identical constant chunks per dump cannot be told apart, so pairing them
    would invent a correspondence; the group is counted, the signature stays
    ambiguous.
    """
    scc = _content(write_content_runs(tmp_path, 3, statics=0, dynamics=0, repeated=2))
    info = scc.content.per_signature[SECRET_SIG]
    assert info["content_invariant_repeated"] == 1
    assert info["content_invariant_paired"] == 0
    assert info["unpaired_chunks"] == 6
    assert SECRET_SIG in scc.ambiguous
    assert not scc.signatures                 # nothing aligned at all here


def test_partial_content_present_in_some_but_not_all_dumps_is_counted(tmp_path):
    """A masked content in 2 of 3 dumps is neither invariant nor dynamic.

    It is reported under ``partial`` and left unpaired -- correspondence across
    all dumps is exactly what it lacks.
    """
    dumps = []
    for run in range(3):
        page = bytearray(PAGE_SIZE)
        # A constant chunk present only in runs 0 and 1 (absent from run 2).
        if run < 2:
            place_chunk_at(page, 0, 3, SECRET_SIZE, bytes([0x33]) * SECRET_SIZE)
        # A per-run dynamic chunk so the signature is ambiguous in every dump.
        place_chunk_at(page, BLOCK_C3, 3, SECRET_SIZE, content_dynamic_user(run))
        place_chunk_at(page, 2 * BLOCK_C3, 3, SECRET_SIZE, content_dynamic_user(run, 1))
        dumps.append(_write(tmp_path, f"part{run}.msl", bytes(page),
                            vas_entries=[vas_entry(BASE, PAGE_SIZE, PRIMARY_NAME)]))
    scc = build_chunk_consensus(dumps)
    info = scc.content.per_signature[SECRET_SIG]
    assert info["partial"] == 1
    assert SECRET_SIG in scc.ambiguous


def test_content_alignment_off_pairs_by_signature_alone(tmp_path):
    """``content_alignment=False`` pairs by signature alone: the signature is skipped.

    No content rows, the signature stays ambiguous, and the provenance marks
    content alignment disabled. This is the regression guard for the flag.
    """
    paths = [str(p) for p in write_content_runs(tmp_path, 3, statics=1, dynamics=1)]
    off = build_chunk_consensus(paths, content_alignment=False)
    assert off.signatures == []
    assert off.ambiguous == [SECRET_SIG]
    assert off.content is None
    assert off.alignment_provenance()["content_alignment"] == {"enabled": False}


def test_content_alignment_is_order_independent_and_deterministic(tmp_path):
    paths = [str(p) for p in write_content_runs(tmp_path, 3, statics=1, dynamics=1)]
    first = build_chunk_consensus(paths)
    again = build_chunk_consensus(paths)
    rotated = build_chunk_consensus([paths[2], paths[0], paths[1]])

    keys = sorted(r.sig for r in first.signatures)
    assert sorted(r.sig for r in again.signatures) == keys
    assert sorted(r.sig for r in rotated.signatures) == keys
    assert first.content.totals() == again.content.totals()


def test_content_alignment_survives_an_encrypted_container(tmp_path, aes_key):
    """The pointer mask reads the VAS map through the key, and pairing holds."""
    paths = [str(p) for p in write_content_runs(tmp_path, 3, statics=1, dynamics=1,
                                                key=aes_key)]
    scc = build_chunk_consensus(paths, key_material={"key": aes_key})
    assert set(scc.content.mask_source) == {"vas"}
    assert any(r.content_class == CONTENT_DYNAMIC_RESIDUE for r in scc.signatures)


def test_parse_signature_drops_a_content_suffix():
    """``_parse_signature`` must not choke on ``s40#content:...`` / ``#dynamic``."""
    assert _parse_signature("scudo:c3:o0:s40#content:deadbeef") == (3, 0, 40)
    assert _parse_signature("scudo:c2:o1:s32#dynamic") == (2, 1, 32)
    assert _parse_signature(SECRET_SIG) == (3, 0, 40)


def test_pointer_word_variance_classification_is_recorded(tmp_path):
    """Document how pointer bytes classify in a content-invariant row.

    The plan asks whether a pointer word -- which varies across runs -- shows up
    as a key candidate. It does carry nonzero variance, so this pins the
    observed classification rather than asserting a preferred one; the row's
    ``masked_word_offsets`` is how a consumer tells it from real variance.
    """
    scc = _content(write_content_runs(tmp_path, 3, statics=1, dynamics=1))
    row = next(r for r in scc.signatures if r.content_class == CONTENT_INVARIANT)
    classes = scc.vector.classifications[row.slab_offset:row.slab_offset + row.length]
    pointer_classes = set(int(c) for c in classes[:8])
    tail_classes = set(int(c) for c in classes[8:])
    # The constant tail is invariant; the pointer word is not (it varies by ASLR).
    assert tail_classes == {int(ByteClass.INVARIANT)}
    assert pointer_classes != {int(ByteClass.INVARIANT)}


def test_dynamic_candidate_vas_and_sizes_are_listed_per_dump(tmp_path):
    """The content provenance lists each dynamic candidate's VA + size per dump.

    With two per-run-unique chunks per dump neither pairs, but both are reported
    under ``dynamic_candidates`` with their address and user size (the signature's
    ``s``), so the set can be read out and validated against ground truth -- the
    list the consensus output otherwise only counts.
    """
    paths = [str(p) for p in write_content_runs(tmp_path, 3, statics=1, dynamics=2)]
    scc = build_chunk_consensus(paths)
    info = scc.content.per_signature[SECRET_SIG]
    cands = info["dynamic_candidates"]

    assert [len(c) for c in cands] == info["dynamic_per_dump"] == [2, 2, 2]
    for run, per_dump in enumerate(cands):
        expected = {hex(content_dynamic_user_va(run, statics=1, k=k)) for k in (0, 1)}
        assert {r["va"] for r in per_dump} == expected
        assert {r["size"] for r in per_dump} == {SECRET_SIZE}
    # The field round-trips through JSON (it reaches the provenance block).
    import json as _json
    assert _json.loads(_json.dumps(cands)) == cands


# ---------------------------------------------------------------------------
# The per-dump hook and the memory estimate
# ---------------------------------------------------------------------------


def test_the_hook_reports_every_dump_in_order(tmp_path):
    paths = [str(p) for p in write_neighbour_runs(tmp_path, 3)]
    seen = []

    build_chunk_consensus(paths, on_dump_scanned=lambda done, total, _chunks: seen.append((done, total)))

    assert seen == [(1, 3), (2, 3), (3, 3)]


def test_the_hook_does_not_change_the_consensus(tmp_path):
    paths = [str(p) for p in write_neighbour_runs(tmp_path, 3)]

    plain = build_chunk_consensus(paths)
    hooked = build_chunk_consensus(paths, on_dump_scanned=lambda _done, _total, _chunks: None)

    assert plain.signatures == hooked.signatures
    assert np.array_equal(plain.vector.variance, hooked.vector.variance)


def test_an_exception_from_the_hook_stops_the_build_and_closes_the_sources(
    tmp_path, monkeypatch,
):
    from memdiver.core.dump_source import MslDumpSource

    paths = [str(p) for p in write_neighbour_runs(tmp_path, 3)]
    real_close = MslDumpSource.close
    closed = []

    def _counting_close(self):
        closed.append(self)
        real_close(self)

    monkeypatch.setattr(MslDumpSource, "close", _counting_close)
    calls = []

    def _cancel(done, _total, _chunks):
        calls.append(done)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        build_chunk_consensus(paths, on_dump_scanned=_cancel)

    assert calls == [1]
    assert len({id(source) for source in closed}) == 3


def _small_chunks(count: int, size: int = 16) -> list:
    return [ScudoChunk(sig=f"scudo:c1:o0:s{size}#{i}", user_va=0x7000_0000_0000 + i * 32,
                       slot=i, data=os.urandom(size)) for i in range(count)]


def test_the_hook_hands_over_each_dumps_chunks(tmp_path):
    paths = [str(p) for p in write_neighbour_runs(tmp_path, 2)]
    seen = []

    consensus = build_chunk_consensus(
        paths, on_dump_scanned=lambda _done, _total, chunks: seen.append(list(chunks)))

    assert seen == consensus.per_dump_chunks


def test_the_estimate_extrapolates_one_dump_to_all_of_them():
    chunks = _small_chunks(100)

    two, four = chunk_consensus_estimate(chunks, 2), chunk_consensus_estimate(chunks, 4)

    assert four.breakdown["chunks"] == 2 * two.breakdown["chunks"]
    assert four.breakdown["content_masks"] == 2 * two.breakdown["content_masks"]
    assert four.breakdown["slab"] == two.breakdown["slab"]
    assert four.peak_bytes == sum(four.breakdown.values())


def test_the_estimate_covers_what_a_heap_of_small_chunks_really_holds():
    """Such a heap costs several times its own bytes in Python objects."""
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        chunks = _small_chunks(20_000)
        held = tracemalloc.get_traced_memory()[0] - before
    finally:
        tracemalloc.stop()

    assert chunk_consensus_estimate(chunks, 1).breakdown["chunks"] >= held
    assert held > 5 * sum(len(chunk.data) for chunk in chunks)
