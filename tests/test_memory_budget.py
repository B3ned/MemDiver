"""Tests for core.memory_budget (host-independent via injected readers)."""

import logging
from types import SimpleNamespace

import pytest

from memdiver.core import memory_budget as mb
from memdiver.core.memory_budget import (
    GIB, KIB, MIB, MemoryBudget, MemoryEstimate, MemoryReading,
    adaptive_chunk_positions, available_memory_bytes, check_budget,
    format_bytes, memory_budget_bytes, parse_cgroup_limit, parse_meminfo,
    parse_vm_stat, resolve_memory_budget,
)
from memdiver.core.service_errors import CapabilityError, ErrorCategory

MEMINFO = """MemTotal:       16303508 kB
MemFree:          812344 kB
MemAvailable:    9876543 kB
Buffers:          123456 kB
Cached:          4567890 kB
"""
MEMINFO_OLD = "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 20 kB\nCached: 30 kB\n"
VM_STAT = """Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                                    33240.
Pages active:                                1045221.
Pages inactive:                              1042798.
Pages speculative:                              1796.
Pages throttled:                                   0.
Pages purgeable:                               12034.
"""


def _files(mapping):
    return lambda path: mapping.get(path)


def _commands(mapping):
    return lambda argv: mapping.get(tuple(argv))


def _no_commands(argv):
    return None


# --- format_bytes ---------------------------------------------------------

@pytest.mark.parametrize("n, expected", [
    (0, "0 B"), (1023, "1023 B"), (1536, "1.5 KiB"), (5 * MIB, "5.0 MiB"),
    (3 * GIB, "3.00 GiB"), (2048 * GIB, "2.00 TiB"), (-2048, "-2.0 KiB"),
])
def test_format_bytes(n, expected):
    assert format_bytes(n) == expected


# --- parsers --------------------------------------------------------------

def test_parse_meminfo_mem_available():
    assert parse_meminfo(MEMINFO) == 9876543 * KIB


def test_parse_meminfo_old_kernel_fallback():
    assert parse_meminfo(MEMINFO_OLD) == 150 * KIB


def test_parse_meminfo_garbage():
    assert parse_meminfo("nonsense\n") is None


def test_parse_vm_stat():
    pages = 33240 + 1042798 + 1796 + 12034
    assert parse_vm_stat(VM_STAT) == pages * 16384


@pytest.mark.parametrize("text", ["", "Pages free: 12.\n", "page size of 4096 bytes\n"])
def test_parse_vm_stat_incomplete(text):
    assert parse_vm_stat(text) is None


@pytest.mark.parametrize("max_text, cur, expected", [
    ("max\n", "100", None),
    (None, None, None),
    ("1073741824\n", "268435456\n", 805306368),
    ("1000", None, 1000),
    ("1000", "5000", 0),
    ("junk", "1", None),
])
def test_parse_cgroup_limit(max_text, cur, expected):
    assert parse_cgroup_limit(max_text, cur) == expected


# --- available_memory_bytes -----------------------------------------------

def test_psutil_preferred():
    fake = SimpleNamespace(virtual_memory=lambda: SimpleNamespace(available=123 * MIB))
    r = available_memory_bytes(platform="darwin", psutil_module=fake,
                               read_file=_files({}), run_command=_no_commands)
    assert r == MemoryReading(123 * MIB, "psutil")


def test_psutil_failure_falls_through():
    def boom():
        raise RuntimeError("x")
    fake = SimpleNamespace(virtual_memory=boom)
    r = available_memory_bytes(platform="linux", psutil_module=fake,
                               read_file=_files({mb.PROC_MEMINFO: MEMINFO}),
                               run_command=_no_commands)
    assert r.source == "meminfo"


def test_linux_meminfo():
    r = available_memory_bytes(platform="linux", psutil_module=None,
                               read_file=_files({mb.PROC_MEMINFO: MEMINFO}),
                               run_command=_no_commands)
    assert r == MemoryReading(9876543 * KIB, "meminfo")


def test_linux_cgroup_lower_wins():
    files = {mb.PROC_MEMINFO: MEMINFO, mb.CGROUP_V2_MAX: str(2 * GIB),
             mb.CGROUP_V2_CURRENT: str(GIB)}
    r = available_memory_bytes(platform="linux", psutil_module=None,
                               read_file=_files(files), run_command=_no_commands)
    assert r == MemoryReading(GIB, "meminfo+cgroup")


def test_linux_cgroup_higher_ignored():
    files = {mb.PROC_MEMINFO: MEMINFO, mb.CGROUP_V2_MAX: str(100 * GIB)}
    r = available_memory_bytes(platform="linux", psutil_module=None,
                               read_file=_files(files), run_command=_no_commands)
    assert r.source == "meminfo"


def test_linux_cgroup_unlimited_ignored():
    files = {mb.PROC_MEMINFO: MEMINFO, mb.CGROUP_V2_MAX: "max\n"}
    r = available_memory_bytes(platform="linux", psutil_module=None,
                               read_file=_files(files), run_command=_no_commands)
    assert r.source == "meminfo"


def test_cgroup_not_applied_on_macos():
    files = {mb.CGROUP_V2_MAX: "1000"}
    r = available_memory_bytes(platform="darwin", psutil_module=None,
                               read_file=_files(files),
                               run_command=_commands({("vm_stat",): VM_STAT}))
    assert r.source == "vm_stat"


def test_macos_vm_stat():
    r = available_memory_bytes(platform="darwin", psutil_module=None,
                               read_file=_files({}),
                               run_command=_commands({("vm_stat",): VM_STAT}))
    assert r.source == "vm_stat" and r.bytes == parse_vm_stat(VM_STAT)


def test_macos_sysctl_total_fallback():
    cmds = {("sysctl", "-n", "hw.memsize"): "17179869184\n"}
    r = available_memory_bytes(platform="darwin", psutil_module=None,
                               read_file=_files({}), run_command=_commands(cmds))
    assert r == MemoryReading(16 * GIB, "total")
    assert r.is_approximate


def test_sysconf_total_fallback(monkeypatch):
    monkeypatch.setattr(mb, "_probe_total", lambda: 8 * GIB)
    r = available_memory_bytes(platform="sunos", psutil_module=None,
                               read_file=_files({}), run_command=_no_commands)
    assert r == MemoryReading(8 * GIB, "total")


def test_unknown_when_nothing_works(monkeypatch):
    monkeypatch.setattr(mb, "_probe_total", lambda: None)
    r = available_memory_bytes(platform="sunos", psutil_module=None,
                               read_file=_files({}), run_command=_no_commands)
    assert r == MemoryReading(0, "unknown")


def test_default_command_runner_handles_missing_binary():
    assert mb._run_command(["memdiver-definitely-not-a-binary"]) is None


def test_real_host_smoke():
    r = available_memory_bytes()
    assert r.bytes > 0 and r.source
    assert memory_budget_bytes(env={}) > 0


# --- budget -----------------------------------------------------------------

READING = MemoryReading(10 * GIB, "meminfo")


def test_budget_safety_fraction_only():
    b = resolve_memory_budget(reading=READING, env={})
    assert b.bytes == int(10 * GIB * 0.7)
    assert b.cap_bytes is None


def test_budget_settings_cap_lower_wins():
    b = resolve_memory_budget(SimpleNamespace(max_rss_mb=1024), reading=READING, env={})
    assert b.bytes == GIB and b.cap_source == "max_rss_mb"
    assert "max_rss_mb" in b.describe()


def test_budget_cap_higher_than_available_ignored():
    b = resolve_memory_budget(SimpleNamespace(max_rss_mb=100_000), reading=READING, env={})
    assert b.bytes == int(10 * GIB * 0.7) and b.cap_bytes is None


def test_budget_env_override():
    b = resolve_memory_budget(SimpleNamespace(max_rss_mb=4096), reading=READING,
                              env={mb.BUDGET_ENV_VAR: "512"})
    assert b.bytes == 512 * MIB and b.cap_source == mb.BUDGET_ENV_VAR


def test_budget_env_read_from_process_env(monkeypatch):
    monkeypatch.setenv(mb.BUDGET_ENV_VAR, "256")
    assert memory_budget_bytes(reading=READING) == 256 * MIB


@pytest.mark.parametrize("raw", ["abc", "", "0", "-5"])
def test_budget_env_invalid_ignored(raw):
    assert memory_budget_bytes(reading=READING, env={mb.BUDGET_ENV_VAR: raw}) == int(10 * GIB * 0.7)


def test_budget_explicit_cap_bytes():
    b = resolve_memory_budget(cap_bytes=100 * MIB, reading=READING, env={})
    assert b.bytes == 100 * MIB and b.cap_source == "cap_bytes"


def test_budget_unknown_reading_uses_cap():
    b = resolve_memory_budget(cap_bytes=MIB, reading=MemoryReading(0, "unknown"), env={})
    assert b.bytes == MIB
    assert resolve_memory_budget(reading=MemoryReading(0, "unknown"), env={}).bytes == 0


def test_budget_bad_fraction():
    with pytest.raises(ValueError):
        resolve_memory_budget(reading=READING, safety_fraction=0, env={})


# --- check_budget -----------------------------------------------------------

BUDGET = MemoryBudget(bytes=GIB, reading=READING, safety_fraction=0.7)
OVER = MemoryEstimate(peak_bytes=3 * GIB, operation="consensus",
                      breakdown={"accumulators": 2 * GIB, "reads": GIB})


def test_check_budget_within():
    assert check_budget(MemoryEstimate(GIB, "x"), budget=BUDGET) is None


def test_check_budget_raises():
    with pytest.raises(CapabilityError) as ei:
        check_budget(OVER, budget=BUDGET)
    err = ei.value
    assert err.category is ErrorCategory.PRECONDITION
    assert err.code == "memory_budget_exceeded"
    msg = str(err)
    for needle in ("3.00 GiB", "1.00 GiB", "meminfo", "heap,stack", "fewer dumps",
                   "force", "accumulators"):
        assert needle in msg
    assert err.details["estimate_bytes"] == 3 * GIB
    assert err.details["source"] == "meminfo"


def test_check_budget_force_returns_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="memdiver.core.memory_budget"):
        warning = check_budget(OVER, force=True, budget=BUDGET)
    assert warning and "3.00 GiB" in warning and "force" in warning
    assert any("consensus" in r.getMessage() for r in caplog.records)


def test_check_budget_int_budget():
    with pytest.raises(CapabilityError, match="explicit budget"):
        check_budget(OVER, budget=GIB)


def test_check_budget_zero_budget_does_not_block():
    assert check_budget(OVER, budget=0) is None


def test_check_budget_resolves_default(monkeypatch):
    monkeypatch.setenv(mb.BUDGET_ENV_VAR, "1")
    with pytest.raises(CapabilityError):
        check_budget(MemoryEstimate(10 * MIB, "x"))


# --- adaptive_chunk_positions ----------------------------------------------

PAGE = 4096


def test_chunk_fits_budget_and_aligned():
    chunk = adaptive_chunk_positions(10, 8, 256 * MIB, page_size=PAGE)
    assert chunk % PAGE == 0
    assert 10 * chunk * 8 <= 256 * MIB * 0.5
    assert 64 * KIB <= chunk <= 16 * MIB


def test_chunk_clamped_to_max():
    assert adaptive_chunk_positions(1, 1, 100 * GIB, page_size=PAGE) == 16 * MIB


def test_chunk_clamped_to_min():
    assert adaptive_chunk_positions(1000, 16, MIB, page_size=PAGE) == 64 * KIB


def test_chunk_accepts_memory_budget():
    assert adaptive_chunk_positions(2, 4, BUDGET, page_size=PAGE) == \
        adaptive_chunk_positions(2, 4, GIB, page_size=PAGE)


def test_chunk_min_rounded_up_to_page():
    chunk = adaptive_chunk_positions(1000, 16, 1, min_chunk=100, max_chunk=50,
                                     page_size=16384)
    assert chunk == 16384


def test_chunk_default_page_size_alignment():
    import mmap
    assert adaptive_chunk_positions(3, 3, 777 * MIB) % mmap.PAGESIZE == 0


@pytest.mark.parametrize("n, bpp", [(0, 1), (1, 0), (-1, 1)])
def test_chunk_invalid_args(n, bpp):
    with pytest.raises(ValueError):
        adaptive_chunk_positions(n, bpp, GIB)


def test_check_budget_recommends_the_region_filter_by_default():
    from memdiver.core.memory_budget import MemoryEstimate, check_budget
    from memdiver.core.service_errors import CapabilityError

    with pytest.raises(CapabilityError) as refused:
        check_budget(MemoryEstimate(100, "op"), budget=1)
    assert "apply a region filter" in refused.value.message


def test_check_budget_takes_the_suggestions_of_a_route_without_a_filter():
    from memdiver.core.memory_budget import MemoryEstimate, check_budget
    from memdiver.core.service_errors import CapabilityError

    with pytest.raises(CapabilityError) as refused:
        check_budget(MemoryEstimate(100, "op"), budget=1, suggestions="use fewer dumps.")
    assert refused.value.message.endswith("Suggestions: use fewer dumps.")
