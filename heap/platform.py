"""Target platform and memory map of a dump, whatever its format.

MemDiver's dump sources each know their platform in a different way — the
``.msl`` file header (``os_type``/``arch_type``/``endianness``), the ELF core
``e_machine`` plus NT_FILE paths, a regioned dump's ``.maps`` names — and a
flat raw dump knows nothing at all. Allocator parsers need one answer
(pointer size, endianness, "is this Android?"), so this module asks each
source the way it can be asked and falls back to an ASSUMED x86_64
little-endian target.

:func:`memory_map_of` does the same for the mapping list: one
:class:`MappedRegion` shape over MSL region blocks, ``.maps`` sidecars and
PT_LOAD tables.

Nothing here raises for an unknown or unopened source: the answers are
:data:`ASSUMED_PLATFORM` and ``[]``. Sources are expected to be open.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Literal, Optional, Tuple

logger = logging.getLogger("memdiver.heap.platform")

Endianness = Literal["little", "big"]


@dataclass(frozen=True)
class TargetPlatform:
    """OS / CPU facts an allocator parser needs. ``source`` says how we know."""

    os: str
    arch: str
    pointer_size: int
    endianness: Endianness
    source: str

    @property
    def is_android(self) -> bool:
        return self.os == "android"


ASSUMED_PLATFORM = TargetPlatform("unknown", "x86_64", 8, "little", "assumed")


@dataclass(frozen=True)
class MappedRegion:
    """One mapping of the dumped process. ``perms`` is ``"rwx"``-style."""

    va: int
    size: int
    perms: str
    name: str
    module_path: Optional[str]
    captured: bool

    @property
    def end(self) -> int:
        return self.va + self.size


# -- vocabulary ---------------------------------------------------------------

_OS_NAMES = {0x0000: "windows", 0x0001: "linux", 0x0002: "macos",
             0x0003: "android", 0x0004: "ios", 0x0005: "freebsd"}
_ARCH_NAMES = {0x0000: "x86", 0x0001: "x86_64", 0x0002: "arm64", 0x0003: "arm32"}
_POINTER_SIZES = {"x86": 4, "arm32": 4}

# Path fragments that betray the CPU of a Linux-family process, in order.
_ARCH_PATH_HINTS = (
    ("aarch64", "arm64"), ("arm64", "arm64"), ("x86_64", "x86_64"),
    ("i386", "x86"), ("i686", "x86"), ("arm-linux-gnueabi", "arm32"),
)


def _pointer_size(arch: str) -> int:
    return _POINTER_SIZES.get(arch, 8)


def _make_platform(os_name: str, arch: str, endianness: Endianness,
                   source: str) -> TargetPlatform:
    return TargetPlatform(os_name, arch, _pointer_size(arch), endianness, source)


def _perms_string(readable: bool, writable: bool, executable: bool) -> str:
    return (("r" if readable else "-") + ("w" if writable else "-")
            + ("x" if executable else "-"))


def _arch_from_names(names: Iterable[Optional[str]], os_name: str) -> str:
    """CPU guessed from mapping paths; Android with ``lib64`` means arm64."""
    present = [n for n in names if n]
    for name in present:
        for fragment, arch in _ARCH_PATH_HINTS:
            if fragment in name:
                return arch
    if os_name == "android" and any("/lib64/" in n for n in present):
        return "arm64"
    return ASSUMED_PLATFORM.arch


# -- source probes ----------------------------------------------------------------


def _msl_reader(source: Any) -> Any:
    """The open MslReader behind *source*, or ``None``."""
    from memdiver.core.dump_source import MslDumpSource

    if not isinstance(source, MslDumpSource):
        return None
    try:
        return source.get_reader()
    except RuntimeError:
        return None


def _gcore_info(source: Any) -> Any:
    """Parsed ElfCoreInfo of an open gcore source, or ``None``."""
    from memdiver.core.dump_sources.gcore import GCoreDumpSource

    if not isinstance(source, GCoreDumpSource):
        return None
    reader = source._reader  # noqa: SLF001 — no public accessor for the info
    return reader.info if reader._mmap is not None else None  # noqa: SLF001


def _regioned_maps(source: Any) -> Optional[list]:
    """The parsed ``.maps`` MapRegion list of a regioned raw source, or ``None``."""
    from memdiver.core.dump_sources._regioned_base import _RegionedRawSource

    if not isinstance(source, _RegionedRawSource):
        return None
    return list(source._regions)  # noqa: SLF001 — no public accessor


def _msl_platform(source: Any) -> Optional[TargetPlatform]:
    reader = _msl_reader(source)
    if reader is None:
        return None
    hdr = reader.file_header
    os_name = _OS_NAMES.get(int(hdr.os_type), "unknown")
    if os_name == "unknown":
        os_name = _names_os(r.name for r in _msl_region_infos(reader))
    arch = _ARCH_NAMES.get(int(hdr.arch_type), "unknown")
    endianness: Endianness = "big" if int(hdr.endianness) == 0x02 else "little"
    return _make_platform(os_name, arch, endianness, "msl_header")


def _gcore_platform(source: Any) -> Optional[TargetPlatform]:
    from memdiver.core.binary_formats.elf_core_reader import machine_to_arch_type

    info = _gcore_info(source)
    if info is None:
        return None
    arch = _ARCH_NAMES.get(int(machine_to_arch_type(info.machine)), "unknown")
    os_name = _names_os(m.path for m in info.file_mappings)
    # ElfCoreReader only accepts ELFDATA2LSB cores.
    return _make_platform(os_name, arch, "little", "elf_header")


def _regioned_platform(source: Any) -> Optional[TargetPlatform]:
    regions = _regioned_maps(source)
    if not regions:
        return None
    names = [r.path for r in regions]
    os_name = _names_os(names)
    return _make_platform(os_name, _arch_from_names(names, os_name), "little",
                          "mapping_names")


def _names_os(names: Iterable[Optional[str]]) -> str:
    from memdiver.msl.import_preview import names_platform

    return names_platform(names)[0]


_PLATFORM_PROBES: Tuple[Callable[[Any], Optional[TargetPlatform]], ...] = (
    _msl_platform, _gcore_platform, _regioned_platform,
)


def platform_of(source: Any) -> TargetPlatform:
    """Best-known :class:`TargetPlatform` of *source* (never raises)."""
    for probe in _PLATFORM_PROBES:
        found = _safe_call(probe, source)
        if found is not None:
            return found
    return ASSUMED_PLATFORM


def _safe_call(func: Callable[[Any], Any], source: Any) -> Any:
    try:
        return func(source)
    except Exception:  # noqa: BLE001 — a broken source must not break callers
        logger.debug("%s failed on %r", func.__name__, source, exc_info=True)
        return None


# -- memory map ---------------------------------------------------------------


def _msl_region_infos(reader: Any) -> list:
    from memdiver.core.region_view_filter import stored_region_infos

    return stored_region_infos(reader)


def _msl_map(source: Any) -> Optional[List[MappedRegion]]:
    reader = _msl_reader(source)
    if reader is None:
        return None
    vas = _msl_vas_entries(reader)
    return [_msl_mapped_region(info, vas) for info in _msl_region_infos(reader)]


def _msl_vas_entries(reader: Any) -> List[Tuple[int, int, str]]:
    """``(start, end, mapped_path)`` of every effective VAS_MAP entry, sorted.

    :func:`stored_region_infos` only names regions when the VAS_MAP passes
    the *classification* trust rule (``msl_classification_context``), so an
    IMPORTED file without a ``region_names=1`` provenance note comes back
    nameless. The heap layer needs the mapping names whatever that rule
    says, so it joins the VAS_MAP itself.
    """
    entries = [(int(e.base_addr), int(e.base_addr) + int(e.region_size),
                e.mapped_path or "")
               for vas in _safe_call(_msl_vas_maps, reader) or ()
               for e in vas.entries]
    return sorted(entries)


def _msl_vas_maps(reader: Any) -> list:
    """The effective VAS map (last one wins, spec 5.8) as a 0/1-item list."""
    vas_map = reader.effective_vas_map()
    return [vas_map] if vas_map is not None else []


def _vas_name(vas: List[Tuple[int, int, str]], va: int, end: int) -> str:
    """Path of the named VAS entry overlapping ``[va, end)`` the most, or ``""``."""
    best, best_overlap = "", 0
    for start, stop, path in vas:
        if start >= end:
            break
        overlap = min(stop, end) - max(start, va)
        if path and overlap > best_overlap:
            best, best_overlap = path, overlap
    return best


def _module_path_of(name: str) -> Optional[str]:
    """*name* when it is a file path (starts with ``/``), else ``None``."""
    return name if name.startswith("/") else None


def _msl_mapped_region(info: Any, vas: List[Tuple[int, int, str]]
                       ) -> MappedRegion:
    prot = int(info.protection)
    va, size = int(info.base_addr), int(info.size)
    vas_name = "" if info.name else _vas_name(vas, va, va + max(size, 1))
    named_path = info.name or vas_name  # a non-imported .msl names the file here
    module_path = info.module_path or _module_path_of(named_path)
    return MappedRegion(
        va=va, size=size,
        perms=_perms_string(bool(prot & 0x01), bool(prot & 0x02),
                            bool(prot & 0x04)),
        name=info.name or vas_name or info.module_path or "",
        module_path=module_path, captured=info.captured_bytes > 0,
    )


def _regioned_map(source: Any) -> Optional[List[MappedRegion]]:
    regions = _regioned_maps(source)
    if regions is None:
        return None
    usable = source._usable_region_count  # noqa: SLF001
    return [
        MappedRegion(va=r.start, size=r.size, perms=r.perm[:3], name=r.path,
                     module_path=_module_path_of(r.path),
                     captured=idx < usable)
        for idx, r in enumerate(regions)
    ]


def _gcore_map(source: Any) -> Optional[List[MappedRegion]]:
    from memdiver.core.binary_formats.elf_core_reader import PF_R, PF_W, PF_X

    info = _gcore_info(source)
    if info is None:
        return None
    result = []
    for seg in info.segments:
        path = _nt_file_path(info.file_mappings, seg.vaddr)
        result.append(MappedRegion(
            va=seg.vaddr, size=seg.memsz,
            perms=_perms_string(bool(seg.flags & PF_R), bool(seg.flags & PF_W),
                                bool(seg.flags & PF_X)),
            name=path or "", module_path=path, captured=seg.filesz > 0,
        ))
    return result


def _nt_file_path(mappings: Iterable[Any], va: int) -> Optional[str]:
    for mapping in mappings:
        if mapping.start <= va < mapping.end:
            return mapping.path or None
    return None


_MAP_PROBES: Tuple[Callable[[Any], Optional[List[MappedRegion]]], ...] = (
    _msl_map, _gcore_map, _regioned_map,
)


def memory_map_of(source: Any) -> List[MappedRegion]:
    """Every mapping of *source*, sorted by VA; ``[]`` when unknown."""
    for probe in _MAP_PROBES:
        found = _safe_call(probe, source)
        if found is not None:
            return sorted(found, key=lambda r: r.va)
    return []


def module_paths(source: Any) -> List[str]:
    """Distinct file paths mapped into the process (modules), first-seen order."""
    paths = [r.module_path for r in memory_map_of(source) if r.module_path]
    reader = _safe_call(_msl_reader, source)
    if reader is not None:
        paths.extend(m.path for m in _safe_call(_msl_modules, reader) or ()
                     if m.path)
    return list(dict.fromkeys(paths))


def _msl_modules(reader: Any) -> list:
    return list(reader.collect_modules())
