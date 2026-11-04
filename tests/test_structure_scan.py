"""Tests for algorithms.unknown_key.structure_scan module."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.algorithms.base import AnalysisContext
from memdiver.algorithms.unknown_key.structure_scan import StructureScanAlgorithm
from memdiver.core.constants import UNKNOWN_KEY


def _make_context(protocol_version="", library="test", phase="post_handshake"):
    return AnalysisContext(
        library=library,
        protocol_version=protocol_version,
        phase=phase,
    )


def test_uniform_fill_is_not_a_structure():
    """96 bytes of 0xFF satisfy ``not_zero`` but are no key: the removed
    first-KiB fallback loop reported them at confidence 1.0; the shape scan
    must not (zero entropy, no key-shaped region)."""
    data = bytearray(512)
    data[128:224] = b"\xff" * 96
    algo = StructureScanAlgorithm()
    result = algo.run(bytes(data), _make_context())
    assert result.matches == []


def test_no_match_zero_data():
    """All zeros — too uniform for high-entropy detection, and not_zero
    constraints correctly reject zero-filled BYTES fields.  Use a size
    smaller than any registered structure (minimum is aes_key_block at
    44 bytes) but >= scan window (32) so the algorithm runs but finds
    nothing."""
    data = b"\x00" * 40  # fits scan window but too short for any structure
    algo = StructureScanAlgorithm()
    result = algo.run(data, _make_context())
    assert len(result.matches) == 0
    assert result.confidence == 0.0


def test_small_dump():
    """Dump smaller than scan window returns empty with reason."""
    data = b"\xab" * 8
    algo = StructureScanAlgorithm()
    result = algo.run(data, _make_context())
    assert result.matches == []
    assert result.metadata.get("reason") == "dump too small"


def test_protocol_filter():
    """With protocol_version='13', matches should only be TLS (or generic)."""
    data = bytearray(512)
    data[0:64] = b"\xfe" * 64
    algo = StructureScanAlgorithm()
    result = algo.run(bytes(data), _make_context(protocol_version="13"))
    for m in result.matches:
        assert m.metadata["protocol"] in ("TLS", "")


def test_registry_discovery():
    """structure_scan should be discoverable via AlgorithmRegistry."""
    from memdiver.algorithms.registry import AlgorithmRegistry

    registry = AlgorithmRegistry()
    registry.discover()
    assert "structure_scan" in registry.names
    algo = registry.get("structure_scan")
    assert algo.mode == UNKNOWN_KEY


# ---------------------------------------------------------------------------
# shape-based scan (regions sized like a structure; bulk skipped; magic find)
# ---------------------------------------------------------------------------

import math  # noqa: E402
import mmap  # noqa: E402
import struct  # noqa: E402
import time  # noqa: E402
import tracemalloc  # noqa: E402

import numpy as np  # noqa: E402
import pytest  # noqa: E402

from memdiver.algorithms.unknown_key import structure_scan as ss  # noqa: E402
from memdiver.tests.test_entropy_overview import quiet_heap  # noqa: E402

MIB = 1 << 20


def _planted_heap(size, keys, seed=11):
    """quiet_heap bytes with random keys ``{offset: length}`` written in."""
    data = quiet_heap(size, seed=seed)
    rng = np.random.default_rng(seed)
    for offset, length in keys.items():
        data[offset:offset + length] = rng.integers(0, 256, length, dtype=np.uint8)
    return data.tobytes()


def _shape_matches(result):
    return {m.offset: m for m in result.matches if "size_class" in m.metadata}


def _elf_header():
    head = bytearray(64)
    head[0:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", head, 16, 3, 0x3E)
    return bytes(head)


@pytest.mark.parametrize("length", [32, 48])
def test_planted_key_found_with_its_size_class(length):
    keys = {64 * 1024 + 16 + 4096 * i: length for i in range(40)}
    result = StructureScanAlgorithm().run(_planted_heap(1 * MIB, keys), _make_context())
    found = _shape_matches(result)
    exact = [o for o, n in keys.items() if o in found and found[o].length == n]
    assert len(exact) >= 38, (len(exact), sorted(found))
    for offset in exact:
        m = found[offset]
        assert m.metadata["size_class"] == length
        assert any(n.startswith(("tls", "aes", "ssh")) for n in m.metadata["candidate_structures"])
        assert 0.5 <= m.confidence <= 1.0
    # nothing reported far from a key (the quiet heap itself is low-entropy)
    stray = [o for o in found if min(abs(o - k) for k in keys) > 64]
    assert stray == []


def test_planted_keys_with_protocol_filter_keep_tls_only():
    keys = {32 * 1024 + 16 * 4096 * i + 16: 48 for i in range(8)}
    result = StructureScanAlgorithm().run(_planted_heap(1 * MIB, keys),
                                          _make_context(protocol_version="12"))
    found = _shape_matches(result)
    assert sum(1 for o in keys if o in found) >= 7
    assert all(m.metadata["protocol"] == "TLS" for m in result.matches)


def test_elf_header_found_by_magic_anywhere():
    data = bytearray(_planted_heap(1 * MIB, {}))
    data[300_000:300_064] = _elf_header()
    result = StructureScanAlgorithm().run(bytes(data), _make_context())
    elf = [m for m in result.matches if m.metadata["structure_name"] == "elf64_header"]
    assert [m.offset for m in elf] == [300_000]
    assert elf[0].confidence == 1.0 and elf[0].length == 64
    assert result.metadata["magic_matches"] == 1


def test_elf_magic_not_searched_under_a_protocol_filter():
    data = bytearray(4096)
    data[1024:1088] = _elf_header()
    result = StructureScanAlgorithm().run(bytes(data), _make_context(protocol_version="13"))
    assert all(m.metadata["structure_name"] != "elf64_header" for m in result.matches)


def test_random_blob_is_skipped_as_bulk_quickly():
    data = np.random.default_rng(1).integers(0, 256, 4 * MIB, dtype=np.uint8).tobytes()
    # CPU time, not wall time: the bound is about the scan's computation (it
    # runs in-process, single-threaded), and a loaded box stretches wall time
    # without the scan doing any more work.
    start = time.process_time()
    result = StructureScanAlgorithm().run(data, _make_context())
    elapsed = time.process_time() - start
    assert elapsed < 3.0, elapsed  # ~0.15 s measured; generous for CI
    shape = _shape_matches(result)
    assert shape == {}
    assert result.metadata["skipped_bulk_regions"] == 1
    assert result.metadata["skipped_bulk_bytes"] == 4 * MIB
    # no fallback probes: a random blob yields no matches at all
    assert result.matches == []


def test_bulk_bytes_counted_once_across_overlapping_views(monkeypatch):
    monkeypatch.setattr(ss, "_CHUNK_BYTES", 64 * 1024)
    data = bytearray(512 * 1024)
    data[100_000:400_000] = np.random.default_rng(2).integers(0, 256, 300_000, dtype=np.uint8).tobytes()
    result = StructureScanAlgorithm().run(bytes(data), _make_context())
    assert result.metadata["skipped_bulk_regions"] == 1
    assert abs(result.metadata["skipped_bulk_bytes"] - 300_000) <= 2 * ss._SCAN_WINDOW


def test_keys_across_view_boundaries_found_once(monkeypatch):
    monkeypatch.setattr(ss, "_CHUNK_BYTES", 64 * 1024)
    keys = {64 * 1024 * i - 16: 32 for i in range(1, 8)}  # straddles a chunk edge
    keys.update({64 * 1024 * i + 1024: 48 for i in range(1, 8)})  # in the overlap
    result = StructureScanAlgorithm().run(_planted_heap(1 * MIB, keys), _make_context())
    offsets = [m.offset for m in result.matches if "size_class" in m.metadata]
    assert len(offsets) == len(set(offsets))
    found = _shape_matches(result)
    assert sum(1 for o, n in keys.items() if o in found and found[o].length == n) >= 13


def test_match_cap_sets_truncated(monkeypatch):
    monkeypatch.setattr(ss, "MAX_MATCHES", 5)
    keys = {8192 * i + 16: 32 for i in range(1, 30)}
    result = StructureScanAlgorithm().run(_planted_heap(1 * MIB, keys), _make_context())
    assert len(result.matches) == 5
    assert result.metadata["truncated"] is True


def test_magic_hits_capped(monkeypatch):
    monkeypatch.setattr(ss, "MAX_MAGIC_HITS", 3)
    data = bytearray(64 * 1024)
    for i in range(10):
        data[4096 * i + 2048:4096 * i + 2112] = _elf_header()
    result = StructureScanAlgorithm().run(bytes(data), _make_context())
    assert result.metadata["magic_matches"] == 3
    assert result.metadata["truncated"] is True


def test_mmap_and_memoryview_input_match_bytes(tmp_path):
    keys = {4096 * i + 16: (32, 48)[i % 2] for i in range(1, 20)}
    data = bytearray(_planted_heap(256 * 1024, keys))
    data[100_000:100_064] = _elf_header()
    data = bytes(data)
    path = tmp_path / "d.bin"
    path.write_bytes(data)
    expected = repr(StructureScanAlgorithm().run(data, _make_context()))
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        assert repr(StructureScanAlgorithm().run(mm, _make_context())) == expected
    assert repr(StructureScanAlgorithm().run(memoryview(data), _make_context())) == expected


def test_large_dump_memory_bounded_and_estimated():
    """256 MiB of heap with random 4 KiB pages and planted keys: peak heap
    stays far below the dump size (and below the working-set estimate)."""
    size = 256 * MIB
    page = quiet_heap(8 * MIB, seed=3)
    rng = np.random.default_rng(4)
    for p in rng.choice(len(page) // 4096, 200, replace=False):  # encrypted pages
        page[p * 4096:(p + 1) * 4096] = rng.integers(0, 256, 4096, dtype=np.uint8)
    buf = np.tile(page, size // len(page))
    keys = [int(o) * 4096 + 2048 + 16 for o in rng.choice(size // 4096, 64, replace=False)]
    for o in keys:
        buf[o:o + 32] = rng.integers(0, 256, 32, dtype=np.uint8)
    algo = StructureScanAlgorithm()
    tracemalloc.start()
    try:
        start = time.process_time()  # CPU time: load-independent, see above
        result = algo.run(memoryview(buf), _make_context())
        elapsed = time.process_time() - start
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 128 * MIB, peak / MIB
    assert peak <= algo.estimate_working_set(size), (peak, algo.estimate_working_set(size))
    assert elapsed < 120, elapsed  # ~25 s measured
    assert result.metadata["skipped_bulk_regions"] >= 32 * 200 * 0.9
    found = _shape_matches(result)
    assert sum(1 for o in keys if o in found and found[o].length == 32) >= 60


# --- helpers ----------------------------------------------------------------

def test_collision_limit_is_poisson_quantile():
    for size in (16, 32, 48, 64, 72):
        mean = ss._expected_collisions(size)
        limit = ss._collision_limit(size)
        assert limit > mean
        cdf = sum(math.exp(-mean) * mean ** k / math.factorial(k) for k in range(limit + 1))
        below = cdf - math.exp(-mean) * mean ** limit / math.factorial(limit)
        assert below < ss._COLLISION_QUANTILE <= cdf
    assert 1.5 < ss._expected_collisions(32) < 2.0


def test_random_windows_pass_and_heap_words_fail():
    rng = np.random.default_rng(9)
    passed = sum(ss._looks_random_block(rng.integers(0, 256, 8, dtype=np.uint8).tobytes())
                 for _ in range(4000))
    assert passed / 4000 > 0.98
    pointer = (0x7F3A5C001230).to_bytes(8, "little")
    for block in (pointer, b"session ", bytes(8), b"\x41" + bytes(7)):
        assert not ss._looks_random_block(block), block


def test_span_fit_tolerance():
    assert ss._span_fit(32 + 10, 32) == 1.0
    assert ss._span_fit(32 + ss._SPAN_TYPICAL, 32) == 1.0
    assert ss._span_fit(32 + ss._SPAN_ABOVE, 32) == pytest.approx(0.5)
    assert ss._span_fit(32 - ss._SPAN_BELOW, 32) == pytest.approx(0.5)
    assert ss._SPAN_ABOVE == 2 * (ss._SCAN_WINDOW - 1)


def test_measured_span_excess_within_tolerance():
    """Derivation check: planted keys' region span - size stays in [-BELOW, ABOVE],
    and almost always in the full-fit range [0, TYPICAL]."""
    rng = np.random.default_rng(5)
    for length in (32, 48, 64):
        keys = {int(i) * 2048 + 16 + 8 * int(rng.integers(0, 2)): length
                for i in rng.choice(512, 150, replace=False)}
        data = _planted_heap(1 * MIB, keys, seed=length)
        regions = list(ss._iter_regions(data))
        starts = np.array([r[0] for r in regions])
        excess = []
        for offset in keys:
            i = int(np.searchsorted(starts, offset + length)) - 1
            start, stop, _ = regions[i]
            assert start <= offset + length and stop >= offset
            excess.append((stop - start) - length)
        assert min(excess) >= -ss._SPAN_BELOW and max(excess) <= ss._SPAN_ABOVE
        typical = sum(0 <= e <= ss._SPAN_TYPICAL for e in excess) / len(excess)
        assert typical >= 0.97, (length, typical)


def test_tier_offsets_partition_the_range():
    seen = sorted(o for tier in ss._ALIGNMENT_TIERS for o in ss._tier_offsets(3, 41, tier))
    assert seen == list(range(3, 42))
    assert list(ss._tier_offsets(3, 41, 8)) == [8, 16, 24, 32, 40]
    assert all(o % 4 == 0 and o % 8 for o in ss._tier_offsets(3, 41, 4))


def test_iter_find_with_and_without_find_method():
    data = b"ab\x7fELF" + bytes(100) + b"\x7fELF"
    assert list(ss._iter_find(data, b"\x7fELF")) == [2, 106]
    assert list(ss._iter_find(memoryview(data), b"\x7fELF")) == [2, 106]


def test_infer_protocol_rules_unchanged():
    assert ss._infer_protocol("13") == "TLS"
    assert ss._infer_protocol("TLS1.2") == "TLS"
    assert ss._infer_protocol("2") == "SSH"
    assert ss._infer_protocol("SSH-2") == "SSH"
    assert ss._infer_protocol("unknown") == ""


def test_structures_by_size_excludes_magic_and_unconstrained():
    from memdiver.core.structure_library import get_structure_library
    groups = ss._structures_by_size(get_structure_library(include_user=False).list_all())
    names = {n.name for lib in groups.values() for n in lib.list_all()}
    assert "elf64_header" not in names and "aes_gcm_iv" not in names
    assert {"aes256_key", "tls13_master_secret"} <= {s.name for s in groups[32].list_all()}
    assert "tls12_master_secret" in {s.name for s in groups[48].list_all()}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
