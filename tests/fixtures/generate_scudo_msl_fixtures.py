"""Synthetic Scudo ``.msl`` fixtures for the chunk-signature consensus.

Each run is a tiny native ``.msl`` whose read/write anonymous region carries
REAL packed Scudo ``UnpackedHeader`` words on the size-class block grid, so
``engine.scudo_chunk_consensus.extract_chunks`` recognises them exactly as it
does a device dump. The runs model Scudo's randomisation deliberately:

* the heap region's base VA differs per run (ASLR / region placement);
* the secret chunk sits at a DIFFERENT slot each run (block shuffle);
* the secret's bytes differ each run (a freshly generated key).

so a positional (``consensus-window``) overlay cannot pair the secret, while a
chunk-signature overlay can. The region also holds two same-size filler chunks
(an AMBIGUOUS signature, skipped) and a second small region present in every
run but the last (a MISSING signature, skipped) -- the method's honest limits.

Geometry is 64-bit Android 17 (AOSP ``android-17.0.0_r1``): class 3 is a
64-byte block, class 1 a 32-byte block; see
:mod:`memdiver.engine.scudo_chunk_consensus`.

A second family of runs (:func:`write_neighbour_runs`) goes through
``msl.writer.MslWriter`` instead of the hand-built blocks, because it needs
what only the writer offers -- an ENCRYPTED container and FAILED pages inside
a Scudo region -- and it carries THREE uniquely aligned chunks, so a window can
cross from one aligned chunk into the next.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tests.fixtures.generate_msl_fixtures import (
    PAGE_SIZE,
    PAGE_SIZE_LOG2,
    _build_block,
    _build_end_of_capture,
    _build_file_header,
    _build_module_entry,
    _build_process_identity,
    _det_uuid,
    _pad8,
    chain_prev_hashes,
)

HEADER_SIZE = 16
PROT_RW = 0x03
PROT_NONE = 0x00
REGION_TYPE_HEAP = 0x01

#: VAS-map ``mapped_path`` labels the kernel gives Scudo's mappings. The primary
#: heap is what :data:`engine.scudo_chunk_consensus.PRIMARY_MAPPING_NAME` scopes
#: the scan to; the reserve is its PROT_NONE sibling (a prefix trap) and the
#: secondary holds the large allocations the primary scan never covers.
PRIMARY_NAME = "[anon:scudo:primary]"
PRIMARY_RESERVE_NAME = "[anon:scudo:primary_reserve]"
SECONDARY_NAME = "[anon:scudo:secondary]"
#: A read/write ART region whose object words can look like plausible headers --
#: the decoy the 0.1.0 all-RW scan mistook for Scudo chunks.
DALVIK_NAME = "[anon:dalvik-main space]"


def vas_entry(base: int, size: int, name: str, *, prot: int = PROT_RW,
              region_type: int = REGION_TYPE_HEAP, name_source: int = 1):
    """One :class:`~memdiver.msl.types.MslVasEntry` for a fixture VAS map.

    memslicer records ``name_source = LIVE`` (1) for names read off the running
    target; the default mirrors that. A VAS entry needs no matching memory
    region -- an unreadable or PROT_NONE range is described by name alone.
    """
    from memdiver.msl.types import MslVasEntry

    return MslVasEntry(base_addr=base, region_size=size, protection=prot,
                       region_type=region_type, mapped_path=name,
                       name_source=name_source)

#: class -> block size (incl. header), from AndroidNormalSizeClassConfig.
BLOCK_C1 = 0x20   # class 1, 32-byte block
BLOCK_C3 = 0x40   # class 3, 64-byte block

#: The secret: class 3, 40 user bytes -> signature ``scudo:c3:o0:s40`` (unique
#: because the fillers are 48 bytes). ``needed_size(40) = 64`` maps back to
#: class 3, so it passes the size-fits-class test.
SECRET_CLASS = 3
SECRET_SIZE = 40
SECRET_SIG = "scudo:c3:o0:s40"

FILLER_SIZE = 48           # class 3 too -> ``scudo:c3:o0:s48`` (twice: ambiguous)
FILLER_SIG = "scudo:c3:o0:s48"
MISSING_SIG = "scudo:c1:o0:s8"   # class 1, present in every run but the last

_HEAP_BASE_0 = 0x7F0000000000
_EXTRA_BASE_0 = 0x7E0000000000
_ASLR_STRIDE = 0x10000000
_MODULE_BASE = 0x00400000


def secret_slot(run: int) -> int:
    """The secret's slot (block shuffle): a different one every run."""
    return (run * 7 + 3) % 40


def heap_base(run: int) -> int:
    return _HEAP_BASE_0 + run * _ASLR_STRIDE


def secret_user_va(run: int) -> int:
    """Absolute VA of the secret's user bytes in ``run`` (0-based)."""
    return heap_base(run) + secret_slot(run) * BLOCK_C3 + HEADER_SIZE


def secret_value(run: int) -> bytes:
    """This run's secret bytes -- distinct per run, high-variance."""
    return bytes(((run * 37 + i * 5 + 17) & 0xFF) for i in range(SECRET_SIZE))


def scudo_header(class_id: int, size: int, *, origin: int = 0, state: int = 1,
                 offset: int = 0, checksum: int = 0xABCD) -> bytes:
    """One packed little-endian ``UnpackedHeader`` word (AOSP ``chunk.h``).

    ClassId bits 0..7, State 8..9, OriginOrWasZeroed 10..11,
    SizeOrUnusedBytes 12..31, Offset 32..47, Checksum 48..63.
    """
    word = ((class_id & 0xFF) | ((state & 3) << 8) | ((origin & 3) << 10)
            | ((size & 0xFFFFF) << 12) | ((offset & 0xFFFF) << 32)
            | ((checksum & 0xFFFF) << 48))
    return struct.pack("<Q", word)


def _place_chunk(page: bytearray, slot: int, block: int, class_id: int,
                 size: int, user: bytes) -> None:
    """Write ``[header][pad][user]`` for one chunk at ``slot*block``."""
    off = slot * block
    page[off:off + 8] = scudo_header(class_id, size)
    page[off + 8:off + 16] = b"\x00" * 8
    page[off + HEADER_SIZE:off + HEADER_SIZE + len(user)] = user


def _build_scudo_region(base_addr: int, page: bytes,
                        region_type: int = REGION_TYPE_HEAP) -> bytes:
    """A one-page, all-CAPTURED, read/write (prot 3) memory-region block."""
    assert len(page) == PAGE_SIZE
    bitmap = b"\x00" * _pad8(((1 * 2) + 7) // 8)   # 1 page, state 00 = CAPTURED
    payload = struct.pack("<QQBBB5xQ", base_addr, PAGE_SIZE,
                          PROT_RW, region_type, PAGE_SIZE_LOG2, 0)
    payload += bitmap + page
    block, _ = _build_block(0x0001, payload)
    return block


def _heap_page(run: int) -> bytes:
    """The class-3 region: the unique secret plus two ambiguous fillers.

    The two fillers carry the SAME constant bytes, so they stay one ambiguous
    signature under 0.2.0's content alignment too: identical masked content with
    count two in every dump is ``content_invariant_repeated`` (G3 -- counted, not
    paired), not a pairable one-per-dump group. That keeps ``scudo:c3:o0:s48``
    the fixture's "ambiguous, skipped" case regardless of content alignment.
    """
    page = bytearray(PAGE_SIZE)
    _place_chunk(page, secret_slot(run), BLOCK_C3, SECRET_CLASS, SECRET_SIZE,
                 secret_value(run))
    for extra in (11, 22):
        _place_chunk(page, (secret_slot(run) + extra) % 40, BLOCK_C3, 3,
                     FILLER_SIZE, bytes([0x11] * FILLER_SIZE))
    return bytes(page)


def _extra_page() -> bytes:
    """The class-1 region: one 8-byte chunk -> the soon-to-be-missing signature."""
    page = bytearray(PAGE_SIZE)
    _place_chunk(page, 0, BLOCK_C1, 1, 8, bytes([0x5A] * 8))
    return bytes(page)


def _build_run(run: int, *, with_extra: bool) -> bytes:
    """Assemble one complete Scudo ``.msl`` blob for run ``run`` (0-based)."""
    ts = 1_700_000_000_000_000_000 + run * 1_000_000
    blob = _build_file_header(_det_uuid(), ts, pid=4321 + run)
    proc_block, _ = _build_process_identity()
    blob += proc_block
    mod_block, _ = _build_module_entry(
        base_addr=_MODULE_BASE, module_size=0x100000,
        path="/system/lib64/libc.so", version="1")
    blob += mod_block
    blob += _build_scudo_region(heap_base(run), _heap_page(run))
    if with_extra:
        blob += _build_scudo_region(_EXTRA_BASE_0 + run * _ASLR_STRIDE,
                                    _extra_page())
    eoc_block, _ = _build_end_of_capture(ts + 1_000_000_000)
    blob += eoc_block
    return chain_prev_hashes(blob)


def generate_scudo_msl_runs(n_runs: int = 3) -> List[bytes]:
    """``n_runs`` Scudo ``.msl`` blobs; the class-1 chunk is absent from the last."""
    return [_build_run(run, with_extra=(run != n_runs - 1))
            for run in range(n_runs)]


def write_scudo_msl_fixtures(root, n_runs: int = 3) -> List[Path]:
    """Write ``root/scudo_run_<k>.msl`` for ``k`` in 1..n_runs; return the paths."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    paths = []
    for run, blob in enumerate(generate_scudo_msl_runs(n_runs)):
        path = root / f"scudo_run_{run + 1}.msl"
        path.write_bytes(blob)
        paths.append(path)
    return paths


# ---------------------------------------------------------------------------
# Writer-built runs: encryption, page states, three aligned chunks
# ---------------------------------------------------------------------------

#: Two class-3 chunks beside the secret, each present once per run, so all
#: three align. Same class and size, different ORIGIN: Scudo records malloc (0)
#: vs new (1) in the header, so they are two signatures, not one ambiguous one.
#: Sorted by signature the slab is ``[CONST 36 | SECRET 40 | NEW 36]``.
CONST_SIZE = 36
CONST_SIG = "scudo:c3:o0:s36"
CONST_FILL = 0xC0
NEW_SIG = "scudo:c3:o1:s36"
NEW_FILL = 0xC1
ORIGIN_NEW = 1

#: ``(base_addr, data, MslWriter.add_memory_region kwargs)``.
RegionSpec = Tuple[int, bytes, Dict[str, Any]]


def place_chunk_at(buf: bytearray, offset: int, class_id: int, size: int,
                   user: bytes, *, origin: int = 0) -> None:
    """Write one chunk whose header starts at ``offset``; user bytes at +16."""
    buf[offset:offset + 8] = scudo_header(class_id, size, origin=origin)
    buf[offset + HEADER_SIZE:offset + HEADER_SIZE + len(user)] = user


def write_scudo_msl(path, regions: Sequence[RegionSpec], *,
                    key: Optional[bytes] = None, pid: int = 4321,
                    vas_entries: Optional[Sequence[Any]] = None) -> Path:
    """One NATIVE (``imported=False``) ``.msl`` holding ``regions``.

    Native on purpose: an imported container takes the flat-offset fallback, so
    the positional comparison would not be an aligned one. ``key`` makes it an
    AES-256-GCM container that reads back EMPTY without that key.

    ``vas_entries`` (``MslVasEntry`` objects, e.g. from :func:`vas_entry`) writes
    a VAS map (block ``0x1001``) so 0.2.0's scan can scope by mapping name;
    ``None`` (the default) writes NO VAS map, so the dump takes the all-RW
    fallback -- the state every pre-0.2.0 fixture is in.
    """
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    encryption = MslEncryptionConfig(raw_key=key) if key is not None else None
    writer = MslWriter(str(path), pid=pid, imported=False, encryption=encryption)
    writer.add_process_identity(exe_path="/system/bin/scudo_toy")
    for base_addr, data, kwargs in regions:
        writer.add_memory_region(base_addr, data, **kwargs)
    if vas_entries is not None:
        writer.add_vas_map(list(vas_entries))
    writer.add_end_of_capture()
    writer.write()
    return Path(path)


def neighbour_base(run: int, *, moved: bool = True) -> int:
    return heap_base(run if moved else 0)


def neighbour_slot(run: int, *, moved: bool = True) -> int:
    return secret_slot(run if moved else 0)


def neighbour_secret_user_va(run: int, *, moved: bool = True) -> int:
    """Absolute VA of the secret's user bytes in neighbour run ``run``."""
    return (neighbour_base(run, moved=moved)
            + neighbour_slot(run, moved=moved) * BLOCK_C3 + HEADER_SIZE)


def neighbour_page(run: int, *, moved: bool = True) -> bytes:
    """The secret, the NEW chunk in the very next slot, the CONST chunk apart.

    The NEW chunk sits PHYSICALLY right behind the secret, so the bytes that
    follow the secret in memory are its 8 padding bytes and then a live header
    word -- not zeros. A window that read "whatever follows the chunk" instead
    of reporting a gap would therefore come back non-zero there.
    """
    page = bytearray(PAGE_SIZE)
    slot = neighbour_slot(run, moved=moved)
    place_chunk_at(page, slot * BLOCK_C3, SECRET_CLASS, SECRET_SIZE,
                   secret_value(run))
    place_chunk_at(page, (slot + 1) * BLOCK_C3, SECRET_CLASS, CONST_SIZE,
                   bytes([NEW_FILL] * CONST_SIZE), origin=ORIGIN_NEW)
    place_chunk_at(page, ((slot + 20) % 40) * BLOCK_C3, SECRET_CLASS, CONST_SIZE,
                   bytes([CONST_FILL] * CONST_SIZE))
    return bytes(page)


def write_neighbour_run(path, run: int, *, moved: bool = True,
                        key: Optional[bytes] = None, vas: bool = False) -> Path:
    """Write neighbour run ``run`` (0-based) to ``path``.

    ``vas=True`` names the heap region :data:`PRIMARY_NAME` in a VAS map, so the
    run takes 0.2.0's VAS scope instead of the all-RW fallback.
    """
    base = neighbour_base(run, moved=moved)
    page = neighbour_page(run, moved=moved)
    vas_entries = [vas_entry(base, len(page), PRIMARY_NAME)] if vas else None
    return write_scudo_msl(path, [(base, page, {})], key=key, pid=4321 + run,
                           vas_entries=vas_entries)


def write_neighbour_runs(root, n_runs: int = 3, *, moved: bool = True,
                         key: Optional[bytes] = None,
                         vas: bool = False) -> List[Path]:
    """Write ``root/neighbour_run_<k>.msl`` for ``k`` in 1..n_runs.

    ``moved=False`` freezes Scudo: every run puts every chunk in the same slot
    of the same base VA and only the secret's bytes differ -- the one case in
    which the positional overlay and the chunk overlay must give the same
    answer. ``vas=True`` adds a primary-naming VAS map to every run.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    return [
        write_neighbour_run(root / f"neighbour_run_{run + 1}.msl", run,
                            moved=moved, key=key, vas=vas)
        for run in range(n_runs)
    ]


# ---------------------------------------------------------------------------
# Content-alignment runs: one OVER-FULL signature, pointers that shift per run
# ---------------------------------------------------------------------------
#
# Every chunk here is class 3 / 40 user bytes -> the single signature
# :data:`SECRET_SIG`, present more than once per run, so it is AMBIGUOUS and
# 0.2.0's content alignment is what has to tell its chunks apart. The region is
# named ``[anon:scudo:primary]`` and the pointers point into it, so the VAS-map
# pointer mask recognises them. Three kinds of chunk:
#
# * STATIC-with-pointer: a heap pointer (its value shifts per run with the
#   region base, i.e. ASLR) followed by constant bytes. Raw bytes differ every
#   run, but the MASKED bytes are identical -> ``content_invariant``, paired,
#   with variance only on the pointer word.
# * DYNAMIC: bytes unique to one run, every word < MASK_MIN_POINTER so masking
#   never touches them -> a ``dynamic`` candidate (a stand-in for a fresh
#   secret). One per run pairs as ``dynamic_residue``; two per run cannot.
# * REPEATED / CONST: identical constant bytes, used to exercise the counted
#   (not paired) buckets.

_CONTENT_HEAP_0 = 0x7D0000000000
#: A heap-internal offset the static chunk's pointer word targets (well inside
#: the one-page region, so the VAS entry contains it).
_CONTENT_PTR_OFFSET = 0x240
_CONTENT_CONST_TAIL = 0xA5     # the static chunk's constant (non-pointer) tail
_CONTENT_REPEAT_FILL = 0xC7    # the repeated-invariant chunk's constant bytes


def content_heap_base(run: int) -> int:
    """Per-run heap base (ASLR): the static chunk's pointer tracks it."""
    return _CONTENT_HEAP_0 + run * _ASLR_STRIDE


def content_static_pointer(run: int) -> int:
    """The absolute pointer value the static chunk carries in ``run``."""
    return content_heap_base(run) + _CONTENT_PTR_OFFSET


def content_static_user(run: int) -> bytes:
    """Static chunk: ``[heap pointer (per-run)][constant tail]`` (40 bytes)."""
    return (struct.pack("<Q", content_static_pointer(run))
            + bytes([_CONTENT_CONST_TAIL]) * (SECRET_SIZE - 8))


def content_dynamic_user(run: int, k: int = 0) -> bytes:
    """A per-run-unique chunk whose every 8-byte word is a small integer.

    Small (< 0x10000) so the pointer mask never rewrites it: its masked form
    equals its raw form and is unique to this run, i.e. a clean dynamic chunk.
    """
    return b"".join(struct.pack("<Q", 0x101 + run * 977 + k * 131 + i)
                    for i in range(SECRET_SIZE // 8))


def content_const_user() -> bytes:
    """A constant chunk, identical in every run (repeated-invariant / const)."""
    return bytes([_CONTENT_REPEAT_FILL]) * SECRET_SIZE


def content_page(run: int, *, statics: int = 1, dynamics: int = 1,
                 repeated: int = 0) -> bytes:
    """One region page packing the requested over-full-signature chunks.

    ``statics`` distinct static-with-pointer chunks (each a different constant
    tail, so each is its own content-invariant group), ``dynamics`` per-run
    chunks, and ``repeated`` identical constant chunks -- all signature
    ``scudo:c3:o0:s40``.
    """
    page = bytearray(PAGE_SIZE)
    slot = 0
    for i in range(statics):
        user = struct.pack("<Q", content_static_pointer(run)) \
            + bytes([_CONTENT_CONST_TAIL + i]) * (SECRET_SIZE - 8)
        place_chunk_at(page, slot * BLOCK_C3, SECRET_CLASS, SECRET_SIZE, user)
        slot += 1
    for k in range(dynamics):
        place_chunk_at(page, slot * BLOCK_C3, SECRET_CLASS, SECRET_SIZE,
                       content_dynamic_user(run, k))
        slot += 1
    for _ in range(repeated):
        place_chunk_at(page, slot * BLOCK_C3, SECRET_CLASS, SECRET_SIZE,
                       content_const_user())
        slot += 1
    return bytes(page)


def content_dynamic_user_va(run: int, *, statics: int = 1, k: int = 0) -> int:
    """Absolute user VA of dynamic chunk ``k`` in ``run`` (statics come first)."""
    slot = statics + k
    return content_heap_base(run) + slot * BLOCK_C3 + HEADER_SIZE


def write_content_run(path, run: int, *, statics: int = 1, dynamics: int = 1,
                      repeated: int = 0, key: Optional[bytes] = None,
                      vas: bool = True) -> Path:
    """Write one content-alignment run to ``path``."""
    base = content_heap_base(run)
    page = content_page(run, statics=statics, dynamics=dynamics, repeated=repeated)
    vas_entries = [vas_entry(base, PAGE_SIZE, PRIMARY_NAME)] if vas else None
    return write_scudo_msl(path, [(base, page, {})], key=key, pid=5555 + run,
                           vas_entries=vas_entries)


def write_content_runs(root, n_runs: int = 3, *, statics: int = 1,
                       dynamics: int = 1, repeated: int = 0,
                       key: Optional[bytes] = None, vas: bool = True) -> List[Path]:
    """Write ``root/content_run_<k>.msl`` for ``k`` in 1..n_runs."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    return [
        write_content_run(root / f"content_run_{run + 1}.msl", run,
                          statics=statics, dynamics=dynamics, repeated=repeated,
                          key=key, vas=vas)
        for run in range(n_runs)
    ]


if __name__ == "__main__":
    out = write_scudo_msl_fixtures(Path(__file__).parent / "dataset" / "msl" / "scudo")
    print(f"Scudo MSL fixtures written to: {out[0].parent}")
