"""Memory-budget foundation: measure available RAM, derive a budget, gate work.

Stdlib-only (``psutil`` is used opportunistically when importable but is not a
dependency). ``core`` never imports ``api``: callers that hold the API
``Settings`` pass them (or just ``cap_bytes``) in; anything with a
``max_rss_mb`` attribute works.

Public API:

* :func:`available_memory_bytes` -> :class:`MemoryReading` (bytes + how measured)
* :func:`resolve_memory_budget` -> :class:`MemoryBudget` (budget + provenance)
* :func:`memory_budget_bytes` -> ``int`` (convenience wrapper)
* :class:`MemoryEstimate` + :func:`check_budget` (raise / force-warn)
* :func:`adaptive_chunk_positions` (slab size for streaming consensus)
* :func:`format_bytes` (binary human units)

Every probe takes injectable readers (``read_file`` / ``run_command`` /
``psutil_module``) so parsing is testable without depending on the host.
"""

from __future__ import annotations

import logging
import mmap
import os
import re
# Fixed argv (vm_stat / sysctl), no shell.
import subprocess  # nosec B404
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Union

from memdiver.core.service_errors import CapabilityError, ErrorCategory

logger = logging.getLogger("memdiver.core.memory_budget")

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB

DEFAULT_SAFETY_FRACTION = 0.7
DEFAULT_CHUNK_BUDGET_FRACTION = 0.5
BUDGET_ENV_VAR = "MEMDIVER_MEMORY_BUDGET_MB"
CGROUP_V2_MAX = "/sys/fs/cgroup/memory.max"
CGROUP_V2_CURRENT = "/sys/fs/cgroup/memory.current"
PROC_MEMINFO = "/proc/meminfo"
_COMMAND_TIMEOUT_S = 2.0
# Sentinel: "try to import psutil" (distinct from None = "psutil unavailable").
_AUTO = object()

FileReader = Callable[[str], Optional[str]]
CommandRunner = Callable[[Sequence[str]], Optional[str]]


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MemoryReading:
    """Available memory and how it was measured.

    ``source`` is one of ``psutil``, ``meminfo``, ``vm_stat``, ``sysctl``,
    ``total`` (physical RAM fallback, overestimates what is free), optionally
    suffixed ``+cgroup`` when a container limit lowered the figure, or
    ``unknown`` (``bytes == 0``) when nothing could be measured.
    """

    bytes: int
    source: str

    @property
    def is_approximate(self) -> bool:
        return self.source.startswith(("total", "unknown"))


@dataclass(frozen=True)
class MemoryBudget:
    """The analysis memory budget plus the inputs that produced it."""

    bytes: int
    reading: MemoryReading
    safety_fraction: float
    cap_bytes: Optional[int] = None
    cap_source: Optional[str] = None

    def describe(self) -> str:
        parts = [
            f"{format_bytes(self.bytes)} "
            f"(available {format_bytes(self.reading.bytes)} via "
            f"{self.reading.source} x {self.safety_fraction:g}"
        ]
        if self.cap_bytes is not None:
            parts.append(f", capped at {format_bytes(self.cap_bytes)} by {self.cap_source}")
        return "".join(parts) + ")"


@dataclass(frozen=True)
class MemoryEstimate:
    """Predicted peak memory of an operation, with a per-component breakdown."""

    peak_bytes: int
    operation: str
    breakdown: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def format_bytes(n: Union[int, float]) -> str:
    """Format a byte count in binary units (``512 B``, ``1.5 MiB``, ``2.00 GiB``).

    Kept local rather than reusing ``ui.components.html_builder.format_size``
    because ``core`` must not import the ``ui`` layer.
    """
    n = float(n)
    sign = "-" if n < 0 else ""
    n = abs(n)
    if n < KIB:
        return f"{sign}{int(n)} B"
    for unit, scale, digits in (("KiB", KIB, 1), ("MiB", MIB, 1), ("GiB", GIB, 2)):
        if n < scale * 1024:
            return f"{sign}{n / scale:.{digits}f} {unit}"
    return f"{sign}{n / (GIB * 1024):.2f} TiB"


# ---------------------------------------------------------------------------
# Default (host) readers
# ---------------------------------------------------------------------------


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="ascii", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _run_command(argv: Sequence[str]) -> Optional[str]:
    try:
        proc = subprocess.run(  # nosec B603
            list(argv), capture_output=True, text=True,
            timeout=_COMMAND_TIMEOUT_S, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _import_psutil() -> Any:
    try:
        import psutil  # type: ignore[import-not-found]
    except Exception:  # ImportError, or a broken install
        return None
    return psutil


# ---------------------------------------------------------------------------
# Parsers (pure)
# ---------------------------------------------------------------------------


def parse_meminfo(text: str) -> Optional[int]:
    """Return ``MemAvailable`` (bytes) from ``/proc/meminfo`` text.

    Older kernels (< 3.14) lack ``MemAvailable``; fall back to
    ``MemFree + Buffers + Cached``.
    """
    fields: Dict[str, int] = {}
    for line in text.splitlines():
        m = re.match(r"^(\w+):\s+(\d+)\s*(kB)?", line.strip())
        if m:
            fields[m.group(1)] = int(m.group(2)) * (KIB if m.group(3) else 1)
    if "MemAvailable" in fields:
        return fields["MemAvailable"]
    if "MemFree" in fields:
        return fields["MemFree"] + fields.get("Buffers", 0) + fields.get("Cached", 0)
    return None


_VM_STAT_PAGES = ("Pages free", "Pages inactive", "Pages speculative", "Pages purgeable")


def parse_vm_stat(text: str) -> Optional[int]:
    """Return free+inactive+speculative+purgeable bytes from ``vm_stat`` output."""
    m = re.search(r"page size of (\d+) bytes", text)
    if not m:
        return None
    page_size = int(m.group(1))
    counts: Dict[str, int] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        digits = value.strip().rstrip(".")
        if sep and digits.isdigit():
            counts[key.strip()] = int(digits)
    if "Pages free" not in counts:
        return None
    return sum(counts.get(k, 0) for k in _VM_STAT_PAGES) * page_size


def parse_cgroup_limit(max_text: Optional[str], current_text: Optional[str]) -> Optional[int]:
    """Return remaining cgroup-v2 headroom (``memory.max - memory.current``).

    ``None`` when unlimited (``max``) or unreadable.
    """
    if max_text is None:
        return None
    raw = max_text.strip()
    if not raw.isdigit():
        return None
    limit = int(raw)
    used = 0
    if current_text is not None and current_text.strip().isdigit():
        used = int(current_text.strip())
    return max(limit - used, 0)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


def _probe_psutil(psutil_module: Any) -> Optional[int]:
    if psutil_module is None:
        return None
    try:
        return int(psutil_module.virtual_memory().available)
    except Exception:
        return None


def _probe_macos(run_command: CommandRunner) -> Optional[MemoryReading]:
    out = run_command(["vm_stat"])
    value = parse_vm_stat(out) if out else None
    if value:
        return MemoryReading(value, "vm_stat")
    out = run_command(["sysctl", "-n", "hw.memsize"])
    if out and out.strip().isdigit():
        return MemoryReading(int(out.strip()), "total")
    return None


def _probe_total() -> Optional[int]:
    try:
        return int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
    except (AttributeError, ValueError, OSError):
        return None


def _host_reading(platform: str, read_file: FileReader, run_command: CommandRunner,
                  psutil_module: Any) -> MemoryReading:
    value = _probe_psutil(psutil_module)
    if value:
        return MemoryReading(value, "psutil")
    if platform.startswith("linux"):
        text = read_file(PROC_MEMINFO)
        value = parse_meminfo(text) if text else None
        if value:
            return MemoryReading(value, "meminfo")
    if platform == "darwin":
        reading = _probe_macos(run_command)
        if reading is not None:
            return reading
    value = _probe_total()
    if value:
        return MemoryReading(value, "total")
    return MemoryReading(0, "unknown")


def _apply_cgroup(reading: MemoryReading, read_file: FileReader) -> MemoryReading:
    headroom = parse_cgroup_limit(read_file(CGROUP_V2_MAX), read_file(CGROUP_V2_CURRENT))
    if headroom is None or (reading.bytes and headroom >= reading.bytes):
        return reading
    return MemoryReading(headroom, f"{reading.source}+cgroup")


def available_memory_bytes(
    *,
    platform: Optional[str] = None,
    read_file: FileReader = _read_text,
    run_command: CommandRunner = _run_command,
    psutil_module: Any = _AUTO,
) -> MemoryReading:
    """Measure memory currently available to this process.

    Order: psutil (if importable) -> Linux ``/proc/meminfo`` -> macOS
    ``vm_stat`` (then ``sysctl hw.memsize`` as total) -> ``sysconf`` total.
    On Linux a lower cgroup-v2 ``memory.max`` headroom wins (containers).
    Never raises; ``bytes == 0`` / ``source == "unknown"`` if nothing works.
    """
    platform = platform or sys.platform
    if psutil_module is _AUTO:
        psutil_module = _import_psutil()
    reading = _host_reading(platform, read_file, run_command, psutil_module)
    if platform.startswith("linux"):
        reading = _apply_cgroup(reading, read_file)
    return reading


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------


def _env_cap_bytes(env: Mapping[str, str]) -> Optional[int]:
    raw = env.get(BUDGET_ENV_VAR, "").strip()
    if not raw:
        return None
    try:
        mb = float(raw)
    except ValueError:
        logger.warning("Ignoring non-numeric %s=%r", BUDGET_ENV_VAR, raw)
        return None
    return int(mb * MIB) if mb > 0 else None


def _settings_cap_bytes(settings: Any) -> Optional[int]:
    mb = getattr(settings, "max_rss_mb", None) if settings is not None else None
    if isinstance(mb, (int, float)) and mb > 0:
        return int(mb * MIB)
    return None


def _configured_cap(cap_bytes: Optional[int], settings: Any,
                    env: Mapping[str, str]) -> tuple:
    candidates = [
        (cap_bytes if cap_bytes and cap_bytes > 0 else None, "cap_bytes"),
        (_settings_cap_bytes(settings), "max_rss_mb"),
        (_env_cap_bytes(env), BUDGET_ENV_VAR),
    ]
    present = [(v, s) for v, s in candidates if v is not None]
    return min(present) if present else (None, None)


def resolve_memory_budget(
    settings: Any = None,
    *,
    cap_bytes: Optional[int] = None,
    safety_fraction: float = DEFAULT_SAFETY_FRACTION,
    reading: Optional[MemoryReading] = None,
    env: Optional[Mapping[str, str]] = None,
) -> MemoryBudget:
    """Budget = min(available x safety_fraction, configured caps).

    Configured caps (the smallest present wins): explicit ``cap_bytes``,
    ``settings.max_rss_mb`` (any object with that attribute, e.g. the API
    ``Settings``; passed in so ``core`` never imports ``api``), and the
    ``MEMDIVER_MEMORY_BUDGET_MB`` environment variable. If available memory
    is unknown, the cap alone is used (0 if there is no cap either).
    """
    if not 0 < safety_fraction <= 1:
        raise ValueError(f"safety_fraction must be in (0, 1], got {safety_fraction}")
    reading = reading or available_memory_bytes()
    cap, cap_source = _configured_cap(cap_bytes, settings, os.environ if env is None else env)
    derived = int(reading.bytes * safety_fraction) if reading.bytes else None
    values = [v for v in (derived, cap) if v is not None]
    budget = min(values) if values else 0
    capped = cap is not None and (derived is None or cap < derived)
    return MemoryBudget(
        bytes=budget, reading=reading, safety_fraction=safety_fraction,
        cap_bytes=cap if capped else None, cap_source=cap_source if capped else None,
    )


def memory_budget_bytes(settings: Any = None, **kwargs: Any) -> int:
    """Convenience wrapper returning only :attr:`MemoryBudget.bytes`."""
    return resolve_memory_budget(settings, **kwargs).bytes


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def _breakdown_text(estimate: MemoryEstimate) -> str:
    if not estimate.breakdown:
        return ""
    items = ", ".join(f"{k} {format_bytes(v)}" for k, v in estimate.breakdown.items())
    return f" [{items}]"


#: What a refusal recommends unless the route says otherwise.
DEFAULT_BUDGET_SUGGESTIONS = (
    "apply a region filter (e.g. heap,stack), use fewer dumps, raise "
    "MEMDIVER_MEMORY_BUDGET_MB / max_rss_mb, or pass force to override."
)


def check_budget(
    estimate: MemoryEstimate,
    *,
    force: bool = False,
    budget: Union[MemoryBudget, int, None] = None,
    suggestions: str = DEFAULT_BUDGET_SUGGESTIONS,
) -> Optional[str]:
    """Refuse an operation whose estimated peak exceeds the memory budget.

    Returns ``None`` when within budget. Over budget: raises
    :class:`CapabilityError` (PRECONDITION, code ``memory_budget_exceeded``)
    unless ``force``, in which case the warning is logged and returned.
    ``budget`` may be a :class:`MemoryBudget`, a raw byte count, or ``None``
    (resolved from the host and environment).
    """
    if budget is None:
        budget = resolve_memory_budget()
    limit = budget.bytes if isinstance(budget, MemoryBudget) else int(budget)
    if limit <= 0 or estimate.peak_bytes <= limit:
        return None
    where = budget.describe() if isinstance(budget, MemoryBudget) else (
        f"{format_bytes(limit)} (explicit budget)")
    head = (f"{estimate.operation}: estimated peak memory "
            f"{format_bytes(estimate.peak_bytes)}{_breakdown_text(estimate)} "
            f"exceeds the memory budget {where}.")
    if force:
        warning = f"{head} Proceeding anyway because force was requested."
        logger.warning(warning)
        return warning
    raise CapabilityError(
        f"{head} Suggestions: {suggestions}",
        category=ErrorCategory.PRECONDITION,
        code="memory_budget_exceeded",
        details={
            "estimate_bytes": estimate.peak_bytes,
            "budget_bytes": limit,
            "operation": estimate.operation,
            "breakdown": dict(estimate.breakdown),
            "source": budget.reading.source if isinstance(budget, MemoryBudget) else "explicit",
        },
    )


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------


def adaptive_chunk_positions(
    n_sources: int,
    bytes_per_position_per_source: float,
    budget: Union[MemoryBudget, int],
    min_chunk: int = 64 * KIB,
    max_chunk: int = 16 * MIB,
    *,
    budget_fraction: float = DEFAULT_CHUNK_BUDGET_FRACTION,
    page_size: int = mmap.PAGESIZE,
) -> int:
    """Positions per slab so ``n_sources * chunk * bpp <= budget_fraction * budget``.

    The result is page-aligned (rounded down) and clamped to
    ``[min_chunk, max_chunk]`` (both rounded to pages, min at least one page),
    so a tiny budget still yields ``min_chunk`` rather than zero.
    """
    if n_sources < 1 or bytes_per_position_per_source <= 0:
        raise ValueError("n_sources and bytes_per_position_per_source must be positive")
    limit = budget.bytes if isinstance(budget, MemoryBudget) else int(budget)
    lo = max(page_size, -(-min_chunk // page_size) * page_size)
    hi = max(lo, (max_chunk // page_size) * page_size)
    raw = int(limit * budget_fraction / (n_sources * bytes_per_position_per_source))
    aligned = (raw // page_size) * page_size
    return min(max(aligned, lo), hi)
