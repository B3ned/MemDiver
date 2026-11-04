"""Performance benchmarks for Phase B optimizations.

These tests verify correctness AND measure speedup of numpy variance
and Aho-Corasick search vs the original pure-Python implementations.
Not run in CI by default (use: pytest tests/test_benchmarks.py -v).
"""

from __future__ import annotations

import os
import time

import numpy as np
import pytest

from memdiver.core.variance import ByteClass, compute_variance, classify_variance


# --- Variance benchmarks ---


def _cpu_timed(fn):
    """Run ``fn`` once; return ``(result, CPU seconds it took)``.

    CPU time, not wall time: these bounds are about in-process computation, and
    a loaded box (parallel ``pytest -n auto`` runs) stretches wall time without
    the code doing any more work.
    """
    start = time.process_time()
    result = fn()
    return result, time.process_time() - start


def _generate_dump_buffers(n_dumps: int, size: int) -> list[bytes]:
    """Generate synthetic dump buffers with mixed byte patterns."""
    rng = np.random.default_rng(42)
    return [rng.integers(0, 256, size=size, dtype=np.uint8).tobytes() for _ in range(n_dumps)]


def test_variance_correctness_small():
    """Verify numpy variance matches expected values on small input."""
    buf_a = bytes([10, 20, 30, 40])
    buf_b = bytes([10, 20, 30, 40])  # identical
    result = compute_variance([buf_a, buf_b], 4)
    assert len(result) == 4
    assert all(v == 0.0 for v in result), "Identical buffers should have zero variance"


def test_variance_correctness_different():
    """Verify variance is nonzero for differing buffers."""
    buf_a = bytes([0, 0, 0, 0])
    buf_b = bytes([255, 255, 255, 255])
    result = compute_variance([buf_a, buf_b], 4)
    assert all(v > 0 for v in result), "Different buffers should have positive variance"


def test_classify_variance_correctness():
    """Verify classification boundaries."""
    variance = np.array([0.0, 100.0, 1000.0, 5000.0], dtype=np.float32)
    classes = classify_variance(variance)
    assert classes[0] == ByteClass.INVARIANT
    assert classes[1] == ByteClass.STRUCTURAL
    assert classes[2] == ByteClass.POINTER
    assert classes[3] == ByteClass.KEY_CANDIDATE


def test_variance_performance():
    """Benchmark: numpy variance on 1MB buffers (5 dumps)."""
    buffers = _generate_dump_buffers(5, 1_000_000)
    result, elapsed = _cpu_timed(lambda: compute_variance(buffers, 1_000_000))
    assert len(result) == 1_000_000
    # Should complete in well under 1 second with numpy
    assert elapsed < 2.0, f"Variance on 5x1MB took {elapsed:.2f}s (expected <2s)"


def test_classify_performance():
    """Benchmark: classify 1M-element variance array."""
    variance = np.random.default_rng(42).uniform(0, 10000, 1_000_000).astype(np.float32)
    classes, elapsed = _cpu_timed(lambda: classify_variance(variance))
    assert len(classes) == 1_000_000
    assert elapsed < 0.5, f"Classification of 1M elements took {elapsed:.2f}s"


# --- Aho-Corasick benchmarks ---


def test_aho_corasick_available():
    """Verify pyahocorasick is installed."""
    import ahocorasick
    assert hasattr(ahocorasick, "Automaton")


def test_search_correctness():
    """Verify Aho-Corasick search finds all expected hits."""
    from memdiver.core.models import CryptoSecret
    from memdiver.engine.correlator import SearchCorrelator

    # Plant known secrets in synthetic data
    data = bytearray(1000)
    secret_bytes = bytes.fromhex("deadbeefcafebabe")
    data[100:100 + len(secret_bytes)] = secret_bytes
    data[500:500 + len(secret_bytes)] = secret_bytes

    secrets = [CryptoSecret(
        secret_type="test_key",
        identifier=b"\x00" * 32,
        secret_value=secret_bytes,
        protocol="test",
    )]

    correlator = SearchCorrelator()
    hits = correlator.search_all(
        type("FakeDump", (), {"read_all": lambda self: bytes(data), "path": "test.dump"})(),
        secrets, library="test", phase="test", run_id=0,
    )
    assert len(hits) == 2
    assert hits[0].offset == 100
    assert hits[1].offset == 500


def test_search_performance():
    """Benchmark: search 1MB data for 20 secrets."""
    from memdiver.core.models import CryptoSecret
    from memdiver.engine.correlator import SearchCorrelator

    rng = np.random.default_rng(42)
    data = rng.integers(0, 256, size=1_000_000, dtype=np.uint8).tobytes()

    secrets = [
        CryptoSecret(
            secret_type=f"key_{i}",
            identifier=rng.integers(0, 256, size=32, dtype=np.uint8).tobytes(),
            secret_value=rng.integers(0, 256, size=32, dtype=np.uint8).tobytes(),
            protocol="test",
        )
        for i in range(20)
    ]

    correlator = SearchCorrelator()
    source = type("S", (), {"read_all": lambda self: data, "path": "bench.dump"})()

    hits, elapsed = _cpu_timed(
        lambda: correlator.search_all(source, secrets, library="bench", phase="test", run_id=0))

    assert elapsed < 1.0, f"Search 1MB with 20 secrets took {elapsed:.2f}s"


# --- Auto-floor candidate-enumeration cost (item B4) ---
#
# Pins the numbers measured by tools/bench_auto_floor_memory.py so the three
# cost fixes it justified cannot silently regress. Marked `slow` (this file is
# already excluded from CI by default; the marker keeps it out of an explicit
# `pytest tests/test_benchmarks.py` sweep too unless asked for).
#
# Ceilings are expressed PER CANDIDATE so they hold at any --candidates size,
# and each sits roughly halfway between the measured "after" value and the
# pre-fix value it replaced -- tight enough to catch a revert, loose enough not
# to flake on a slower box:
#
#   term                          pre-fix   post-fix   ceiling
#   step-3 peak (2nd enum pass)   235 B/c    57 B/c    120 B/c
#   step-4 live (default_set)     160 B/c    33 B/c     80 B/c
#   sweep live peak (`seen`)      267 B/c   132 B/c    200 B/c
#
# Measured 2026-08-25 on macOS/arm64, CPython 3.11, at 700k candidates.

_B4_CANDIDATES = 150_000
_B4_MAX_SECOND_PASS_PEAK_BYTES = 120
_B4_MAX_DEFAULT_SET_LIVE_BYTES = 80
_B4_MAX_SWEEP_LIVE_BYTES = 200
# Untraced, null-oracle enumeration budget. ~0.5 us/candidate was measured; the
# 5x headroom guards against an algorithmic regression (e.g. a re-materialised
# candidate list or a per-candidate rescan), not against a slow CI box.
_B4_MAX_ENUMERATION_US_PER_CANDIDATE = 2.5


def _b4_bench():
    """Import the bench module from tools/ (not a package) by file path."""
    import importlib.util
    import sys
    from pathlib import Path

    name = "bench_auto_floor_memory"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parent.parent / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Register BEFORE exec: the bench uses `from __future__ import annotations`,
    # so @dataclass resolves its string annotations via sys.modules[__module__].
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.slow
def test_auto_floor_enumeration_memory_ceiling():
    """The enumeration terms stay lean at scale (tracemalloc, Python objects)."""
    bench = _b4_bench()
    case = bench.build_case(_B4_CANDIDATES)
    result = bench.measure(case, traced=True)

    assert result.maximal > _B4_CANDIDATES * 0.99, (
        f"synthetic case degenerated: {result.maximal} candidates")
    assert result.tried == result.maximal, "the sweep must be exhaustive"
    per_candidate = 1024.0 * 1024.0 / result.maximal

    second_pass = result.step("3_enumerate_maximal_dflt").traced_peak_mb * per_candidate
    assert second_pass < _B4_MAX_SECOND_PASS_PEAK_BYTES, (
        f"second enumerate_maximal pass peaked at {second_pass:.0f} B/candidate "
        f"(ceiling {_B4_MAX_SECOND_PASS_PEAK_BYTES}); did the streaming "
        f"np.fromiter path or the shared entropy_cache regress?")

    default_set = result.step("4_default_set").traced_current_mb * per_candidate
    assert default_set < _B4_MAX_DEFAULT_SET_LIVE_BYTES, (
        f"default_set is live at {default_set:.0f} B/candidate (ceiling "
        f"{_B4_MAX_DEFAULT_SET_LIVE_BYTES}); did it revert to set(zip(...))?")

    sweep = result.sweep_live_peak_mb * per_candidate
    assert sweep < _B4_MAX_SWEEP_LIVE_BYTES, (
        f"sweep held {sweep:.0f} B/candidate (ceiling {_B4_MAX_SWEEP_LIVE_BYTES}); "
        f"`seen` alone should account for ~132 B/candidate")


@pytest.mark.slow
def test_auto_floor_enumeration_time_ceiling():
    """Enumeration stays roughly linear in the candidate count."""
    bench = _b4_bench()
    case = bench.build_case(_B4_CANDIDATES)
    # traced=False: tracemalloc taxes every allocation and would make an
    # allocation-dense enumeration look ~5x slower than it runs in production.
    result = bench.measure(case, traced=False)

    us_per_candidate = result.enumeration_ms() * 1000.0 / result.maximal
    assert us_per_candidate < _B4_MAX_ENUMERATION_US_PER_CANDIDATE, (
        f"enumeration cost {us_per_candidate:.2f} us/candidate (ceiling "
        f"{_B4_MAX_ENUMERATION_US_PER_CANDIDATE}) over "
        f"{result.maximal} candidates")
