"""ISF producers: pakunoda probes on a full image, and ISF drafts (plan T4.2).

Library layer only. Two families of ``*_result`` producers, each returning a
:class:`~memdiver.core.service_result.ServiceResult` whose payload is plain JSON:

* :func:`isf_probe_result` runs ONE pakunoda probe on a memory image and, when
  given ``case_dir`` + ``draft``, feeds the finding into that
  :class:`~memdiver.isf.draft.IsfDraftStore` draft.
* ``isf_draft_*_result`` wrap the draft store (create / list / get / set /
  import / retract / versions / diff / validate / export).

Honesty rules:

* **Coordinates are explicit.** A physical offset is a ``Location`` with space
  ``physical``, a kernel address one with ``kernel_va``; ``capture_id`` is the
  image sha256.
* **Big outputs say so.** kallsyms (100k symbols), BTF (10k types) and layout
  claims return counts plus a ``limit``-row sample with ``truncated`` set; the
  draft import always receives the complete set.
* **init_task is verified, not guessed.** The base comes from pakunoda's
  ``probes.find_init_task``, given the kallsyms runtime symbols and the swept
  vmcoreinfo note, and is trusted only when it reports ``verified`` (page-table
  walk or exact self-reference agreement). The older banner-delta derivation
  (``init_task`` VA minus the banner's VA->phys delta) can land on a stale,
  never-booted kernel copy; it was retired 2026-10-27 and is no longer computed
  (the ``banner_delta`` / ``disagreement`` payload keys remain, always ``None``).
  The layout legs REFUSE an unverified base (``isf.init_task_unverified``); ``init_task`` still
  reports it, with a warning.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
import time
from collections import Counter
from functools import partial
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from memdiver.core.image.context import file_sha256, require_pakunoda
from memdiver.core.location import AddressSpace, Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory, require_file
from memdiver.core.service_result import ServiceResult
from memdiver.isf.draft import SECTIONS, IsfDraft, IsfDraftStore, Provenance

PROBES: Tuple[str, ...] = ("viability", "banner", "vmcoreinfo", "kallsyms", "btf", "init_task",
                           "page_table_root", "utsname", "ksymtab", "layout_legs")
#: Rows a probe / get / diff returns before it reports ``truncated``.
DEFAULT_LIMIT = 200
DEFAULT_AUTHOR = "tool:pakunoda"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"\d+\.\d+(?:\.\d+)?")
_BANNER_ARCH: Tuple[Tuple[str, str], ...] = (
    ("aarch64", "aarch64"), ("arm64", "aarch64"), ("x86_64", "x86_64"), ("amd64", "x86_64"),
    ("i686", "i386"), ("i386", "i386"), ("armv7", "arm"), ("riscv64", "riscv64"))
_OP_ARGS: Dict[str, Tuple[str, ...]] = {
    "symbol": ("name", "address"), "struct": ("name", "size"),
    "field": ("struct", "field", "offset", "type"),
    "base_type": ("name", "size", "signed", "kind", "endian"),
    "enum": ("name", "size", "base", "constants"), "remove": ("key",)}


# -- errors / small helpers ---------------------------------------------------

def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def _image_file(image_path: str) -> Path:
    return require_file(image_path, param="image_path", label="memory image",
                        code="image_not_found", resolve=True)


def _capture(capture_id: str) -> str:
    """A 64-hex capture id, or the sha256 of an existing image path."""
    text = str(capture_id or "").strip()
    if _HEX64.match(text):
        return text
    if text and Path(text).expanduser().is_file():
        return file_sha256(Path(text).expanduser())
    raise _invalid("capture_id must be an image sha256 (64 hex) or the path of the image",
                   "capture_id_invalid")


def _hex(value: Any) -> Any:
    return f"0x{value:x}" if isinstance(value, int) and not isinstance(value, bool) else value


def _plain(value: Any) -> Any:
    """JSON-safe copy: dataclasses/enums/bytes/sets flattened, ints kept."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _plain(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(v) for v in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if hasattr(value, "value") and hasattr(value, "name") and not isinstance(value, (int, str)):
        return value.value if isinstance(value.value, (int, str)) else value.name
    return value if isinstance(value, (int, float, str, bool, type(None))) else str(value)


def _loc(space: AddressSpace, value: int, capture: str) -> Dict[str, Any]:
    return Location(space, int(value), capture_id=capture).to_dict()


def _limit(params: Optional[Mapping[str, Any]]) -> int:
    value = (params or {}).get("limit", DEFAULT_LIMIT)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _invalid(f"limit must be a non-negative integer, got {value!r}", "invalid_limit")
    return value


def _sample(rows: Sequence[Any], limit: int) -> Tuple[List[Any], bool]:
    return list(rows[:limit]), len(rows) > limit


class _Timings(Dict[str, float]):
    """Stage timings that can also announce each stage as it starts and ends.

    ``on_stage(name, elapsed_s, done)`` is optional; plain ``dict`` timings (the
    draft producers) keep working with :func:`_timed`.
    """

    def __init__(self, on_stage: Optional[Callable[[str, float, bool], None]] = None) -> None:
        super().__init__()
        self.on_stage = on_stage


def _timed(timings: Dict[str, float], name: str, fn: Callable[[], Any]) -> Any:
    hook = getattr(timings, "on_stage", None)
    start = time.perf_counter()
    if hook is not None:
        hook(name, 0.0, False)
    try:
        return fn()
    finally:
        timings[name] = round(time.perf_counter() - start, 3)
        if hook is not None:
            hook(name, timings[name], True)


# -- probe session ------------------------------------------------------------

#: Architectures the paging self-test tries, in order.
_SELF_TEST_ARCHES: Tuple[str, ...] = ("x86_64", "aarch64")
#: Alternative init_task bases an anchor lists (best first).
_MAX_CANDIDATES = 8


def _candidate_row(candidate: Any) -> Dict[str, Any]:
    return {"phys": candidate.phys, "va": candidate.va, "score": candidate.score,
            "source": candidate.source, "checks": list(candidate.checks),
            "trusted": candidate.trusted}


class _Session:
    """One open dump plus the lazily computed anchors several probes share."""

    def __init__(self, image: Path, arch: str, params: Mapping[str, Any], *,
                 on_stage: Optional[Callable[[str, float, bool], None]] = None) -> None:
        from pakunoda import probes
        self.probes = probes
        self.image, self.params = image, params
        self.capture = file_sha256(image)
        self.timings: Dict[str, float] = _Timings(on_stage)
        self.warnings: List[str] = []
        self.dump = _timed(self.timings, "open", lambda: probes.open_dump(image))
        self._banner: Any = False
        self._kallsyms: Any = False
        self._init_task: Any = False
        self._init_task_view: Optional[Dict[str, Any]] = None
        try:
            self.arch_name, self.arch_source = self._resolve_arch(arch)
            self.arch = probes.resolve_arch(self.arch_name)
        except ValueError as exc:
            self.close()
            raise CapabilityError(f"unsupported architecture {arch!r}: {exc}",
                                  category=ErrorCategory.UNSUPPORTED,
                                  code="isf.unsupported_arch") from exc
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        try:
            self.dump.close()
        except Exception:     # a close failure must not mask the probe result
            pass

    # -- arch ---------------------------------------------------------------
    def _resolve_arch(self, arch: str) -> Tuple[str, str]:
        if arch and arch != "auto":
            return arch, "explicit"
        text = self.banner_text().lower()
        for needle, name in _BANNER_ARCH:
            if needle in text:
                return name, "banner_string"
        detected = self._arch_from_banner_probe(text)
        if detected:
            return detected, "pakunoda_banner"
        elf = self._arch_from_elf()
        if elf:
            return elf, "elf_header"
        tested = self._arch_from_paging_self_test()
        if tested:
            return tested, "paging_self_test"
        # Never guess: a wrong arch walks page tables at the wrong stride and can
        # return plausible wrong translations.
        raise CapabilityError(
            "could not determine the image's architecture (banner, ELF header and a "
            "verified page-table self-test all failed); pass arch explicitly",
            category=ErrorCategory.INVALID_INPUT, code="isf.arch_undetected")

    def _arch_from_paging_self_test(self) -> Optional[str]:
        """The arch under which pakunoda finds a VERIFIED kernel page-table root.

        Verification walks a known mapping (init_task's VA -> phys), which a
        wrong architecture's format cannot reproduce, so a hit is evidence, not
        a guess. Exactly one candidate must verify.
        """
        verified = []
        note = self._scan_vmcoreinfo_once()
        for name in _SELF_TEST_ARCHES:
            try:
                arch = self.probes.resolve_arch(name)
                root = _timed(self.timings, f"self_test_{name}",
                              partial(self.probes.find_page_table_root, self.dump, arch,
                                      vmcoreinfo=note))
            except Exception:  # noqa: BLE001 - a candidate that cannot walk is simply not it
                continue
            if root is not None and getattr(root, "verified", False):
                verified.append(name)
        if len(verified) == 1:
            return verified[0]
        if verified:
            self.warnings.append(f"page-table self-test verified several arches: {verified}")
        return None

    def _scan_vmcoreinfo_once(self) -> Any:
        """The image's first vmcoreinfo note, swept once and shared by every candidate arch
        (``None`` when absent or unscannable: each candidate then scans for itself)."""
        try:
            first = self.probes.resolve_arch(_SELF_TEST_ARCHES[0])
            return _timed(self.timings, "self_test_vmcoreinfo",
                          lambda: next(iter(self.probes.scan_vmcoreinfo(self.dump, first)), None))
        except Exception:  # noqa: BLE001
            return None

    def _arch_from_banner_probe(self, text: str) -> Optional[str]:
        from pakunoda.arch.detection import detect_arch_from_banner
        found = detect_arch_from_banner(text) if text else None
        return getattr(found, "name", None)

    def _arch_from_elf(self) -> Optional[str]:
        machines = {0x3E: "x86_64", 0xB7: "aarch64", 0x28: "arm", 0x03: "i386", 0xF3: "riscv64"}
        with open(self.image, "rb") as fh:
            head = fh.read(20)
        if head[:4] == b"\x7fELF":
            return machines.get(int.from_bytes(head[18:20], "little"))
        return None

    # -- anchors ------------------------------------------------------------
    def banner(self) -> Any:
        if self._banner is False:
            self._banner = _timed(self.timings, "banner", lambda: self.probes.best_banner(self.dump))
        return self._banner

    def banner_text(self) -> str:
        banner = self.banner()
        text = (banner.metadata.get("banner_text") if banner else "") or ""
        return text.decode(errors="replace") if isinstance(text, bytes) else text

    def banner_hints(self) -> List[int]:
        banner = self.banner()
        return [banner.offset] if banner else []

    def kallsyms(self) -> Any:
        """The kallsyms ScanResult (or ``None``), scanned once."""
        if self._kallsyms is False:
            def scan() -> Any:
                found = self.probes.scan_kallsyms(
                    self.dump, self.arch_name, banner_hints=self.banner_hints())
                return found[0] if found else None
            self._kallsyms = _timed(self.timings, "kallsyms", scan)
        return self._kallsyms

    def symbols(self) -> Dict[str, int]:
        found = self.kallsyms()
        return dict(found.metadata.get("symbols", {})) if found else {}

    def kernel_version(self) -> Optional[str]:
        match = _VERSION.search((self.banner().metadata.get("kernel_version") or "")
                                if self.banner() else "")
        return match.group(0) if match else None

    def init_task_result(self) -> Any:
        """pakunoda's ``InitTaskResult`` (or ``None``), computed ONCE per session.

        Fed the kallsyms runtime VAs and the once-swept vmcoreinfo note so it can
        place ``init_task`` by symbol and verify it, instead of guessing.
        """
        if self._init_task is False:
            self._init_task = _timed(self.timings, "init_task_probe", lambda: self.probes.find_init_task(
                self.dump, self.arch_name, runtime_symbols=self.symbols() or None,
                vmcoreinfo=self._scan_vmcoreinfo_once()))
        return self._init_task

    def init_task(self) -> Dict[str, Any]:
        """The init_task anchor every row shares.

        Keys: ``va``/``phys``/``source``/``verified``/``checks``/``va_to_pa_delta``
        come from pakunoda's result; ``candidates`` are its alternatives (plain
        dicts, at most :data:`_MAX_CANDIDATES`); ``probe`` is pakunoda's raw
        ``{va, phys}`` (``None`` when it found nothing). ``banner_delta`` and
        ``disagreement`` are RETIRED 2026-10-27 and always ``None`` (keys kept for
        payload compatibility): the banner delta picked stale copies on fedora-40
        aarch64 / alma-9. When pakunoda finds nothing there is NO base (va/phys
        ``None``) and ``message`` says so.
        """
        if self._init_task_view is None:
            self._init_task_view = self._build_init_task_view()
        return self._init_task_view

    def _build_init_task_view(self) -> Dict[str, Any]:
        found = self.init_task_result()
        out: Dict[str, Any] = {
            "va": None, "phys": None, "source": None, "verified": False, "checks": [],
            "va_to_pa_delta": None, "candidates": [], "probe": None,
            "banner_delta": None, "disagreement": None, "message": None}
        if found is None:
            out["message"] = ("pakunoda find_init_task found no init_task; there is no base "
                              "(the banner-delta fallback was retired 2026-10-27)")
            return out
        out.update(
            va=found.va, phys=found.phys, source=found.source,
            verified=bool(found.verified), checks=list(found.checks),
            va_to_pa_delta=found.va_to_pa_delta, probe={"va": found.va, "phys": found.phys},
            candidates=[_candidate_row(c) for c in found.candidates[:_MAX_CANDIDATES]])
        return out

    # retired 2026-10-27: picked stale copies on fedora-40 aarch64 / alma-9; pakunoda's
    # verified find_init_task is the only source. Kept commented per repo convention.
    # def _build_init_task_view(self) -> Dict[str, Any]:
    #     found = self.init_task_result()
    #     derived = self._derive_init_task_phys()
    #     fallback = (None if derived is None else {
    #         "phys": derived, "va": self.symbols()["init_task"],
    #         "source": "banner_delta", "verified": False})
    #     out: Dict[str, Any] = {
    #         "va": None, "phys": None, "source": None, "verified": False, "checks": [],
    #         "va_to_pa_delta": None, "candidates": [], "probe": None,
    #         "banner_delta": fallback, "disagreement": None}
    #     if found is not None:
    #         out.update(
    #             va=found.va, phys=found.phys, source=found.source,
    #             verified=bool(found.verified), checks=list(found.checks),
    #             va_to_pa_delta=found.va_to_pa_delta, probe={"va": found.va, "phys": found.phys},
    #             candidates=[_candidate_row(c) for c in found.candidates[:_MAX_CANDIDATES]])
    #         if fallback and fallback["phys"] != found.phys:
    #             out["disagreement"] = {"probe_phys": found.phys, "derived_phys": fallback["phys"],
    #                                    "delta": found.phys - fallback["phys"]}
    #     elif fallback:
    #         out.update(va=fallback["va"], phys=fallback["phys"], source="banner_delta")
    #     return out
    #
    # def _derive_init_task_phys(self) -> Optional[int]:
    #     symbols, banner = self.symbols(), self.banner()
    #     if banner is None or "init_task" not in symbols or "linux_banner" not in symbols:
    #         return None
    #     return symbols["init_task"] - (symbols["linux_banner"] - banner.offset)


# -- probe row builders -------------------------------------------------------

def _row_viability(s: _Session, limit: int) -> Dict[str, Any]:
    from pakunoda.core.dump_viability import assess_dump_viability
    view = _timed(s.timings, "viability", lambda: assess_dump_viability(s.dump))
    return {"rows": [_plain(view)], "counts": {"rows": 1}}


def _row_banner(s: _Session, limit: int) -> Dict[str, Any]:
    found = _timed(s.timings, "scan_banners", lambda: s.probes.scan_banners(s.dump))
    rows = [{"location": _loc(AddressSpace.PHYSICAL, b.offset, s.capture),
             "banner": b.metadata.get("banner_text"),
             "kernel_version": b.metadata.get("kernel_version"),
             "confidence": _plain(b.confidence)} for b in found]
    shown, cut = _sample(rows, limit)
    return {"rows": shown, "counts": {"banners": len(rows)}, "truncated": cut}


def _vmcoreinfo_scan(s: _Session) -> Any:
    found = _timed(s.timings, "vmcoreinfo",
                   lambda: s.probes.scan_vmcoreinfo(s.dump, s.arch_name))
    return found[0] if found else None


def _row_vmcoreinfo(s: _Session, limit: int) -> Dict[str, Any]:
    info = _vmcoreinfo_scan(s)
    if info is None:
        return {"rows": [], "counts": {"vmcoreinfo": 0}, "truncated": False}
    symbols = dict(info.metadata.get("symbols", {}))
    shown, cut = _sample(sorted(symbols.items()), limit)
    row = {"location": _loc(AddressSpace.PHYSICAL, info.offset, s.capture),
           "osrelease": info.metadata.get("osrelease"),
           "pagesize": info.metadata.get("pagesize"),
           "kernel_offset": _hex(info.metadata.get("kernel_offset")),
           "phys_base": _hex(info.metadata.get("phys_base")),
           "numbers": _plain(info.metadata.get("numbers", {})),
           "symbols": [{"name": n, "location": _loc(AddressSpace.KERNEL_VA, a, s.capture)}
                       for n, a in shown]}
    return {"rows": [row], "counts": {"symbols": len(symbols)}, "truncated": cut,
            "_symbols": symbols}


def _row_kallsyms(s: _Session, limit: int) -> Dict[str, Any]:
    found = s.kallsyms()
    if found is None:
        return {"rows": [], "counts": {"symbols": 0}, "truncated": False}
    symbols = s.symbols()
    shown, cut = _sample(sorted(symbols.items(), key=lambda kv: kv[1]), limit)
    summary = {k: _plain(found.metadata.get(k)) for k in (
        "num_symbols", "relative_base", "base_strategy", "base_frame", "decoded_entries")}
    rows = [{"name": n, "location": _loc(AddressSpace.KERNEL_VA, a, s.capture)}
            for n, a in shown]
    return {"rows": rows, "summary": summary, "counts": {"symbols": len(symbols)},
            "truncated": cut, "_symbols": symbols}


def _btf_isf(s: _Session) -> Tuple[Any, Dict[str, Any]]:
    from pakunoda.generators.isf_generator import ISFGenerator
    from pakunoda.parsers.btf.parser import BTFParser
    found = _timed(s.timings, "scan_btf", lambda: s.probes.scan_btf(
        s.dump, s.arch_name, banner_hints=s.banner_hints()))
    if not found:
        return None, {}
    hit = found[0]
    raw = _timed(s.timings, "read_btf", lambda: s.dump.read(hit.offset, hit.metadata["total_size"]))
    table = _timed(s.timings, "parse_btf",
                   lambda: BTFParser(endianness=s.arch.endianness).parse(raw))
    banner = s.banner()
    store = _timed(s.timings, "generate_isf", lambda: ISFGenerator(
        table, s.arch, symbols=None,
        banner_bytes=banner.metadata.get("banner_bytes") if banner else None,
        kernel_release=banner.metadata.get("kernel_version") if banner else None).generate())
    return hit, store.to_isf_dict()


def _row_btf(s: _Session, limit: int) -> Dict[str, Any]:
    hit, isf = _btf_isf(s)
    if hit is None:
        return {"rows": [], "counts": {"btf": 0}, "truncated": False}
    counts = {k: len(isf.get(k, {})) for k in ("base_types", "user_types", "enums")}
    names, cut = _sample(sorted(isf.get("user_types", {})), limit)
    row = {"location": _loc(AddressSpace.PHYSICAL, hit.offset, s.capture),
           "total_size": hit.metadata.get("total_size"), "evidence": _plain(hit.evidence),
           "user_type_sample": names}
    return {"rows": [row], "counts": counts, "truncated": cut, "_isf": isf}


def _row_init_task(s: _Session, limit: int) -> Dict[str, Any]:
    found = s.init_task()
    row = dict(found, va=_hex(found["va"]),
               probe=None if found["probe"] is None
               else dict(found["probe"], va=_hex(found["probe"]["va"])),
               candidates=[dict(c, va=_hex(c["va"])) for c in found.get("candidates") or []])
    if found["phys"] is not None:
        row["location"] = _loc(AddressSpace.PHYSICAL, found["phys"], s.capture)
        row["va_location"] = _loc(AddressSpace.KERNEL_VA, found["va"], s.capture)
    # retired 2026-10-27: the banner-delta disagreement warning (picked stale copies).
    if found["phys"] is not None and not found.get("verified", False):
        s.warnings.append(f"init_task base (source={found['source']}) is UNVERIFIED and will "
                          "not be used by the layout legs")
    return {"rows": [row], "counts": {"init_task": int(found["phys"] is not None)}}


def _row_page_table_root(s: _Session, limit: int) -> Dict[str, Any]:
    it = s.init_task_result()
    paging = _timed(s.timings, "page_table_root",
                    lambda: s.probes.find_page_table_root(s.dump, s.arch_name, it))
    if paging is None:
        return {"rows": [], "counts": {"page_table_root": 0}}
    row = {"location": _loc(AddressSpace.PHYSICAL, paging.pgd_phys, s.capture),
           "pgd_phys": paging.pgd_phys, "levels": paging.levels, "va_bits": paging.va_bits,
           "page_size": paging.page_size, "source": paging.source,
           "la57_source": paging.la57_source, "verified": paging.verified}
    return {"rows": [row], "counts": {"page_table_root": 1}}


def _row_utsname(s: _Session, limit: int) -> Dict[str, Any]:
    from pakunoda.recovery.utsname import carve_utsname
    facts = _timed(s.timings, "utsname", lambda: carve_utsname(s.dump))
    rows = [{"location": _loc(AddressSpace.PHYSICAL, c.name_phys, s.capture),
             **{k: getattr(c, k) for k in ("sysname", "nodename", "release", "version",
                                           "machine", "domainname")}}
            for c in facts.candidates]
    shown, cut = _sample(rows, limit)
    return {"rows": shown, "counts": {"candidates": len(rows)}, "truncated": cut}


def _row_ksymtab(s: _Session, limit: int) -> Dict[str, Any]:
    from pakunoda.config import PakunodaConfig
    from pakunoda.recovery.ksymtab import carve_ksymtab
    version = s.kernel_version()
    facts, reason = _timed(s.timings, "ksymtab", lambda: carve_ksymtab(
        s.dump, s.arch, PakunodaConfig(), version_hint=version,
        banner_phys_hints=s.banner_hints()))
    if facts is None:
        return {"rows": [], "counts": {"symbols": 0}, "truncated": False, "reason": reason}
    symbols = dict(getattr(facts, "symbols", {}) or {})
    shown, cut = _sample(sorted(symbols.items(), key=lambda kv: kv[1]), limit)
    summary = {"layout": _plain(facts.layout), "entry_count": facts.entry_count}
    rows = [{"name": n, "location": _loc(AddressSpace.KERNEL_VA, a, s.capture)}
            for n, a in shown]
    return {"rows": rows, "summary": summary, "counts": {"symbols": len(symbols)},
            "truncated": cut}


def _va_bits(s: _Session) -> Tuple[Optional[int], ...]:
    explicit = s.params.get("va_bits")
    if explicit:
        return (explicit,) if isinstance(explicit, int) else tuple(explicit)
    paging = s.probes.find_page_table_root(s.dump, s.arch_name, None)
    return (paging.va_bits,) if paging is not None and paging.verified else (None,)


def _claim_row(claim: Any) -> Dict[str, Any]:
    return {"struct": claim.struct, "member": claim.member, "offset": claim.offset,
            "width": claim.width, "tier": claim.tier.value, "source": claim.source,
            "witnesses": claim.witnesses, "evidence": list(claim.evidence)}


def _run_legs(s: _Session) -> Tuple[Any, Dict[str, Any]]:
    from pakunoda.recovery.layout.leg import run_layout_legs
    from pakunoda.recovery.layout.reads import image_reads_for
    symbols = s.symbols()
    if not symbols:
        raise CapabilityError("layout legs need kallsyms and none were found in this image",
                              category=ErrorCategory.PRECONDITION, code="isf.kallsyms_required")
    anchor = s.init_task()
    if anchor["phys"] is None:
        raise CapabilityError(anchor.get("message") or "init_task could not be located",
                              category=ErrorCategory.PRECONDITION, code="isf.init_task_required")
    if not anchor.get("verified", False):
        top = "; ".join(f"phys=0x{c['phys']:x} source={c['source']} score={c['score']}"
                        for c in anchor.get("candidates", [])[:3]) or "none"
        raise CapabilityError(
            f"init_task base 0x{anchor['phys']:x} is unverified (source={anchor['source']}, "
            f"checks={anchor.get('checks') or []}); top candidates: {top}. Walking task_struct "
            "fields from an unverified base yields plausible wrong layouts",
            category=ErrorCategory.PRECONDITION, code="isf.init_task_unverified")
    reads, report = _timed(s.timings, "image_reads", lambda: image_reads_for(
        s.dump, s.arch, symbols, anchor["phys"]))
    if reads is None:
        raise CapabilityError(f"the image could not be read for the layout legs: {report}",
                              category=ErrorCategory.PRECONDITION, code="isf.image_reads_failed")
    run = _timed(s.timings, "layout_legs", lambda: run_layout_legs(
        image=reads, image_report=report, arch=s.arch, symbols=symbols,
        init_task_phys=anchor["phys"], kernel_version=s.kernel_version(),
        va_bits=_va_bits(s), page_size=s.params.get("page_size") or 4096))
    return run, anchor


def _row_layout_legs(s: _Session, limit: int) -> Dict[str, Any]:
    run, anchor = _run_legs(s)
    rows = [_claim_row(c) for c in run.claims]
    shown, cut = _sample(rows, limit)
    refusals = _plain(run.refusals)
    return {"rows": shown, "counts": {"claims": len(rows), "refusals": len(refusals)},
            "truncated": cut, "refusals": refusals, "init_task": _plain(anchor),
            "leg_timings": _plain(getattr(run, "timings", {})), "_claims": list(run.claims)}


_BUILDERS: Dict[str, Callable[[_Session, int], Dict[str, Any]]] = {
    "viability": _row_viability, "banner": _row_banner, "vmcoreinfo": _row_vmcoreinfo,
    "kallsyms": _row_kallsyms, "btf": _row_btf, "init_task": _row_init_task,
    "page_table_root": _row_page_table_root, "utsname": _row_utsname,
    "ksymtab": _row_ksymtab, "layout_legs": _row_layout_legs}


# -- draft feeding --------------------------------------------------------------

def _hint_types(store: IsfDraftStore, capture: str, draft: str,
                hint_isf: Optional[Mapping[str, Any]]) -> Dict[Tuple[str, str], Mapping[str, Any]]:
    """Field type descriptors for claims: the draft's own fields first, then a donor ISF."""
    hints: Dict[Tuple[str, str], Mapping[str, Any]] = {}
    current = store.materialize(capture, draft)
    for source in (hint_isf.get("user_types", {}) if hint_isf else {}, current.user_types):
        for struct, body in source.items():
            for name, field in (body.get("fields") or {}).items():
                if "type" not in field:
                    continue
                if source is current.user_types and _is_placeholder(
                        field["type"], current.provenance_of(("field", struct, name))):
                    continue      # an earlier untyped claim must not beat a donor type
                hints[(struct, name)] = field["type"]
    return hints


def _is_placeholder(field_type: Mapping[str, Any], origin: Any) -> bool:
    """The draft's own ``void`` stand-in (or anything flagged ``type_unknown``)."""
    if field_type == {"kind": "base", "name": "void"}:
        return True
    evidence = getattr(getattr(origin, "provenance", None), "evidence", ()) or ()
    return "type_unknown" in evidence


def _load_hint_isf(params: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    path = params.get("type_hints_isf")
    return _read_isf_file(path) if path else None


def _feed_draft(probe: str, built: Dict[str, Any], capture: str, params: Mapping[str, Any],
                store: IsfDraftStore, draft: str, author: str) -> Dict[str, Any]:
    """Feed a probe's ``built`` rows into ``draft``; needs only the capture id and params,
    so it works on data returned by a killable child as well as on a live session."""
    cap, evidence = capture, (f"image sha256 {capture}", f"probe {probe}")
    if probe in ("kallsyms", "vmcoreinfo"):
        prov = Provenance(probe, "probe", evidence, author)
        entry = store.import_symbols(cap, draft, built["_symbols"], prov)
        return {"draft": draft, "entries": [entry.id], "symbols": len(built["_symbols"])}
    if probe == "btf":
        prov = Provenance("btf", "imported", evidence, author)
        isf = {k: v for k, v in built["_isf"].items() if k in SECTIONS}
        entry = store.import_isf(cap, draft, isf, prov)
        return {"draft": draft, "entries": [entry.id], "counts": built["counts"]}
    hints = _hint_types(store, cap, draft, _load_hint_isf(params))
    entries = store.import_layout_claims(cap, draft, built["_claims"],
                                         type_hints=hints, author=author)
    return {"draft": draft, "entries": [e.id for e in entries], "claims": len(entries),
            "typed_from_hints": sum(1 for c in built["_claims"]
                                    if c.member and (c.struct, c.member) in hints)}


_FEEDABLE = frozenset({"kallsyms", "vmcoreinfo", "btf", "layout_legs"})


def _draft_arch(store: IsfDraftStore, capture: str, draft: str) -> Optional[str]:
    """The arch the draft was created for (feeding it with another arch makes no sense)."""
    for row in store.list_drafts(capture):
        if row.get("name") == draft:
            return row.get("arch") or None
    return None


def isf_probe_result(image_path: str, probe: str, *, arch: str = "auto",
                     params: Optional[Mapping[str, Any]] = None,
                     case_dir: Optional[str] = None, draft: Optional[str] = None,
                     author: str = DEFAULT_AUTHOR,
                     cancel: Optional[Callable[[], bool]] = None,
                     progress: Optional[Callable[[str, float], None]] = None) -> ServiceResult:
    """Run one pakunoda ``probe`` on a full image; optionally feed it into a draft.

    Payload: ``probe``, ``arch`` (+ ``arch_source``), ``capture_id``, ``rows``
    (with ``Location`` dicts), ``counts``, ``truncated``, ``timings``,
    ``warnings`` and, when fed, ``imported``. ``params``: ``limit`` (sample rows,
    default 200), ``va_bits``, ``page_size``, ``type_hints_isf`` (donor ISF whose
    field types label layout claims). ``case_dir`` and ``draft`` go together.
    With ``cancel`` the builder stage runs in a killable child process, so a cancel stops
    it mid-stage; ``cancel()`` is also checked right before the draft is fed. A cancel
    raises ``CapabilityError(code="cancelled")`` and feeds nothing. ``progress(stage,
    elapsed_s)`` is called as each timed stage starts and ends.
    """
    if probe not in PROBES:
        raise _invalid(f"unknown probe {probe!r}; choose one of: {', '.join(PROBES)}",
                       "isf.unknown_probe")
    if bool(case_dir) != bool(draft):
        raise _invalid("case_dir and draft must be given together", "isf.draft_target_incomplete")
    if draft and probe not in _FEEDABLE:
        raise _invalid(f"probe {probe!r} produces nothing a draft imports "
                       f"(feedable: {', '.join(sorted(_FEEDABLE))})", "isf.probe_not_feedable")
    params = dict(params or {})
    limit = _limit(params)
    image = _image_file(image_path)
    require_pakunoda()
    _check_cancel(cancel)
    store = _store(case_dir) if case_dir else None
    if store is not None and draft and (not arch or arch == "auto"):
        arch = _draft_arch(store, file_sha256(image), draft) or arch
    stage = _run_probe_stage(image, probe, arch, params, limit, cancel, progress)
    _check_cancel(cancel)
    built, capture = stage["built"], stage["capture"]
    imported = (_feed_draft(probe, built, capture, params, store, draft, author)
                if store is not None and draft else None)
    payload = {"probe": probe, "image": str(image), "capture_id": capture,
               "arch": stage["arch_name"], "arch_source": stage["arch_source"],
               **{k: v for k, v in built.items() if not k.startswith("_")},
               "limit": limit, "timings": stage["timings"], "warnings": stage["warnings"]}
    payload.setdefault("truncated", False)
    if imported is not None:
        payload["imported"] = imported
    return ServiceResult.ok(payload)


def _stage_bridge(progress: Optional[Callable[[str, float], None]]
                  ) -> Optional[Callable[[Dict[str, Any]], None]]:
    """``progress(stage, elapsed_s)`` -> the ``dict`` callback a stage / killable child uses."""
    if progress is None:
        return None
    return lambda info: progress(info["stage"], info["elapsed_s"])


def _probe_stage(image: str, probe: str, arch: str, params: Mapping[str, Any], limit: int,
                 progress: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
    """The builder stage: open the image, run ``_BUILDERS[probe]``, return all the parent needs.

    Module-level and picklable-in/out so it runs either in-process or in a killable
    child (:func:`~memdiver.engine.killable.run_killable`). ``progress`` receives
    ``{"stage", "elapsed_s", "done"}`` as each timed stage starts and ends.
    """
    hook: Optional[Callable[[str, float, bool], None]] = None
    if progress is not None:
        report = progress

        def on_stage(name: str, elapsed: float, done: bool) -> None:
            report({"stage": name, "elapsed_s": elapsed, "done": done})
        hook = on_stage
    session = _Session(Path(image), arch, params, **({"on_stage": hook} if hook else {}))
    try:
        built = _BUILDERS[probe](session, limit)
        return {"built": built, "capture": session.capture, "arch_name": session.arch_name,
                "arch_source": session.arch_source, "timings": dict(session.timings),
                "warnings": list(session.warnings)}
    finally:
        session.close()


def _run_probe_stage(image: Path, probe: str, arch: str, params: Mapping[str, Any], limit: int,
                     cancel: Optional[Callable[[], bool]],
                     progress: Optional[Callable[[str, float], None]]) -> Dict[str, Any]:
    """Run :func:`_probe_stage` in-process, or - when a ``cancel`` is given - in a killable
    child so a cancel stops a stage that never polls (kallsyms scan, vol3 stacking)."""
    bridge = _stage_bridge(progress)
    if cancel is None:
        return _probe_stage(str(image), probe, arch, params, limit, bridge)
    from memdiver.engine.killable import run_killable
    return run_killable(
        "memdiver.app.tools_isf:_probe_stage",
        {"image": str(image), "probe": probe, "arch": arch, "params": dict(params),
         "limit": limit},
        cancel=cancel, on_progress=bridge)


# -- draft producers ------------------------------------------------------------

def _check_cancel(cancel: Optional[Callable[[], bool]]) -> None:
    """Raise the ``cancelled`` outcome (same one the profile job uses) when asked to stop."""
    if cancel is not None and cancel():
        raise CapabilityError("cancelled", category=ErrorCategory.PRECONDITION,
                              code="cancelled")


def _case_root(case_dir: str, *, create: bool = False) -> Path:
    """The case directory: a bare name is ``cases_root()/<name>`` (as for image views).

    Only ``create=True`` (draft create / set / import) may make the case; every other
    caller gets ``case.not_found`` for a case that does not exist, and nothing is written.
    """
    from memdiver.analysis.case import MANIFEST, Case, case_path
    if not case_dir or not str(case_dir).strip():
        raise _invalid("case_dir is required", "case_dir_required")
    if create:
        return Case.init(case_dir).dir
    root = case_path(case_dir)
    if not (root / MANIFEST).is_file():
        raise CapabilityError(f"case not found: {root}", category=ErrorCategory.NOT_FOUND,
                              code="case.not_found")
    return Case.open(root).dir


def _store(case_dir: str, *, create: bool = False) -> IsfDraftStore:
    return IsfDraftStore(_case_root(case_dir, create=create))


def _entry_dict(entry: Any) -> Dict[str, Any]:
    return {"entry_id": entry.id, "created": entry.created, "label": entry.label,
            "op": entry.payload.get("op"), "provenance": entry.payload.get("provenance")}


def _hex_section(section: str, items: Mapping[str, Any]) -> Dict[str, Any]:
    if section != "symbols":
        return dict(items)
    return {n: {**body, "address": _hex(body.get("address"))} for n, body in items.items()}


def _origin_row(origin: Any) -> Optional[Dict[str, Any]]:
    if origin is None:
        return None
    return {"entry_id": origin.entry_id, "op": origin.op,
            "provenance": origin.provenance.to_dict()}


def _materialized_summary(draft: IsfDraft) -> Dict[str, Any]:
    return {"name": draft.name, "capture_id": draft.capture_id, "version": draft.version,
            "applied": draft.applied, "metadata": draft.metadata,
            "counts": {s: len(getattr(draft, s)) for s in SECTIONS},
            "size_bounds": dict(draft.size_bounds)}


def isf_draft_create_result(case_dir: str, capture_id: str, name: str, arch: str, *,
                            author: str = "human", banner: Optional[str] = None,
                            base_metadata: Optional[Mapping[str, Any]] = None) -> ServiceResult:
    entry = _store(case_dir, create=True).create(_capture(capture_id), name, arch=arch, author=author,
                                    banner=banner, base_metadata=base_metadata)
    return ServiceResult.ok({"draft": name, "capture_id": _capture(capture_id),
                             "entry": _entry_dict(entry)})


def isf_draft_list_result(case_dir: str, capture_id: str) -> ServiceResult:
    capture = _capture(capture_id)
    drafts = _store(case_dir).list_drafts(capture)
    return ServiceResult.ok({"capture_id": capture, "drafts": drafts, "count": len(drafts)})


_SECTION_TAG = {"symbols": "symbol", "user_types": "type", "enums": "enum",
                "base_types": "base_type"}


def _origin_row_created(origin: Any) -> Optional[Dict[str, Any]]:
    row = _origin_row(origin)
    if row is not None:
        row["created"] = origin.created
    return row


def _field_origins(draft: IsfDraft, shown: Sequence[str],
                   untyped: "set[Tuple[str, str]]") -> Dict[str, Any]:
    rows: Dict[str, Any] = {}
    for struct in shown:
        for field_name in draft.user_types[struct].get("fields", {}):
            row = _origin_row_created(draft.provenance_of(("field", struct, field_name)))
            if row is not None:
                row["untyped"] = (struct, field_name) in untyped
            rows[f"{struct}.{field_name}"] = row
    return rows


def _section_page(draft: IsfDraft, section: str, names: Sequence[str], search: Optional[str],
                  offset: int, limit: int, include_origins: bool,
                  untyped: "set[Tuple[str, str]]") -> Dict[str, Any]:
    available = getattr(draft, section)
    wanted = sorted(names) if names else sorted(available)
    needle = search.lower() if search else None
    matches = [n for n in wanted if n in available and (needle is None or needle in n.lower())]
    shown = matches[offset:offset + limit]
    chosen = {n: available[n] for n in shown}
    items = _hex_section(section, chosen)
    if section == "user_types":
        per_struct = Counter(struct for struct, _ in untyped)
        items = {n: {**body, "untyped_fields": per_struct.get(n, 0)} for n, body in items.items()}
    page: Dict[str, Any] = {
        "items": items, "total": len(matches), "offset": offset, "limit": limit,
        "truncated": offset + len(shown) < len(matches),
        "missing": [n for n in wanted if n not in available]}
    if include_origins:
        tag = _SECTION_TAG[section]
        page["origins"] = {n: _origin_row_created(draft.provenance_of((tag, n))) for n in shown}
        if section == "user_types":
            page["field_origins"] = _field_origins(draft, shown, untyped)
    return page


def isf_draft_get_result(case_dir: str, capture_id: str, name: str, *,
                         only: Optional[Mapping[str, Sequence[str]]] = None,
                         version: Optional[str] = None, include_origins: bool = False,
                         limit: int = DEFAULT_LIMIT, search: Optional[str] = None,
                         offset: int = 0) -> ServiceResult:
    """Materialized summary; ``sections`` only when ``only`` is given (``{section: [names]}``;
    an empty list selects the whole section).

    Per section (name-sorted, after ``only``): ``search`` keeps names containing the
    case-insensitive substring (names only, not field names); ``offset``/``limit`` page the
    matches. Each section is ``{items, total (matches before paging), offset, limit,
    truncated (more matches beyond this page), missing}``; top-level ``truncated`` is true if
    any section was cut. ``user_types`` items carry ``untyped_fields`` (count of untyped
    placeholder offsets, not exported). ``include_origins`` adds per section ``origins``
    ``{name: row}`` (symbols, user_types, base_types, enums) and, for user_types,
    ``field_origins`` ``{"struct.field": row}``. A row is ``{entry_id, created, op,
    provenance: {source, tier, evidence, author, witnesses}}`` (field rows add ``untyped``).
    """
    if offset < 0:
        raise _invalid(f"offset must be >= 0, got {offset}", "isf_offset_invalid")
    if limit < 1:
        raise _invalid(f"limit must be >= 1, got {limit}", "isf_limit_invalid")
    capture = _capture(capture_id)
    draft = _store(case_dir).materialize(capture, name, upto=version)
    payload: Dict[str, Any] = _materialized_summary(draft)
    if only is not None:
        for section in only:
            if section not in SECTIONS:
                raise _invalid(f"unknown ISF section {section!r}; expected one of {list(SECTIONS)}",
                               "isf_unknown_section")
        untyped = set(draft.untyped_fields())
        sections = {section: _section_page(draft, section, names, search, offset, limit,
                                           include_origins, untyped)
                    for section, names in only.items()}
        payload["sections"] = sections
        payload["truncated"] = any(s["truncated"] for s in sections.values())
    return ServiceResult.ok(payload)


def _address(value: Any) -> int:
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise _invalid(f"address is not a number: {value!r}", "isf_address_invalid") from exc
    return value


def _require_args(op: str, args: Mapping[str, Any]) -> None:
    missing = [a for a in _OP_ARGS[op] if a not in args]
    if missing:
        raise _invalid(f"op {op!r} needs {list(_OP_ARGS[op])}; missing {missing}",
                       "isf_missing_args")


def _apply_op(store: IsfDraftStore, capture: str, name: str, op: str,
              args: Mapping[str, Any], prov: Provenance) -> Any:
    if op == "symbol":
        return store.set_symbol(capture, name, args["name"], _address(args["address"]), prov,
                                type_descriptor=args.get("type"))
    if op == "struct":
        return store.set_struct(capture, name, args["name"], args["size"], prov,
                                kind=args.get("kind", "struct"))
    if op == "field":
        return store.set_field(capture, name, args["struct"], args["field"], args["offset"],
                               args["type"], prov)
    if op == "base_type":
        return store.set_base_type(capture, name, args["name"], size=args["size"],
                                   signed=args["signed"], kind=args["kind"],
                                   endian=args["endian"], provenance=prov)
    if op == "enum":
        return store.set_enum(capture, name, args["name"], size=args["size"], base=args["base"],
                              constants=args["constants"], provenance=prov)
    return store.remove(capture, name, tuple(args["key"]), prov)


def isf_draft_set_result(case_dir: str, capture_id: str, name: str, op: str,
                         args: Mapping[str, Any], *, source: str = "manual",
                         tier: str = "manual", evidence: Sequence[str] = (),
                         author: str = "human", witnesses: int = 1) -> ServiceResult:
    """One draft operation. ``op`` in symbol|struct|field|base_type|enum|remove."""
    if op not in _OP_ARGS:
        raise _invalid(f"unknown op {op!r}; choose one of: {', '.join(_OP_ARGS)}", "isf_unknown_op")
    _require_args(op, args)
    capture = _capture(capture_id)
    prov = Provenance(source, tier, tuple(evidence), author, witnesses)
    entry = _apply_op(_store(case_dir, create=True), capture, name, op, args, prov)
    return ServiceResult.ok({"draft": name, "op": op, "entry": _entry_dict(entry)})


def _read_isf_file(path: str) -> Dict[str, Any]:
    return _load_isf_file(path)[0]


def _load_isf_file(path: str) -> Tuple[Dict[str, Any], bytes]:
    """The parsed ISF document at *path* and its raw bytes (read once)."""
    import json
    target = Path(path).expanduser()
    if not target.is_file():
        raise CapabilityError(f"ISF file not found: {target}",
                              category=ErrorCategory.NOT_FOUND, code="isf_not_found")
    try:
        raw = target.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise _invalid(f"not a readable ISF JSON file: {target} ({exc})", "isf_unreadable") from exc
    if not isinstance(data, dict):
        raise _invalid(f"not an ISF document: {target}", "isf_unreadable")
    return data, raw


def isf_draft_import_result(case_dir: str, capture_id: str, name: str, isf_path: str, *,
                            only: Optional[Mapping[str, Sequence[str]]] = None,
                            source: str = "isf_import", tier: str = "imported",
                            evidence: Sequence[str] = (), author: str = "human"
                            ) -> ServiceResult:
    isf, raw = _load_isf_file(isf_path)
    sha = hashlib.sha256(raw).hexdigest()
    prov = Provenance(source, tier, (f"file sha256 {sha}", *evidence), author)
    entry = _store(case_dir, create=True).import_isf(_capture(capture_id), name, isf, prov, only=only)
    return ServiceResult.ok({"draft": name, "isf_path": str(Path(isf_path).expanduser()),
                             "isf_sha256": sha, "counts": entry.payload["counts"],
                             "entry": _entry_dict(entry)})


def isf_draft_retract_result(case_dir: str, capture_id: str, name: str, entry_id: str, *,
                             author: str = "human", reason: str = "") -> ServiceResult:
    entry = _store(case_dir).retract(_capture(capture_id), name, entry_id,
                                     author=author, reason=reason)
    return ServiceResult.ok({"draft": name, "retracted": entry_id,
                             "retraction_id": entry.id})


def isf_draft_versions_result(case_dir: str, capture_id: str, name: str, *,
                              limit: int = DEFAULT_LIMIT) -> ServiceResult:
    versions = _store(case_dir).versions(_capture(capture_id), name)
    shown, cut = _sample(versions, limit)
    return ServiceResult.ok({"draft": name, "versions": shown, "total": len(versions),
                             "truncated": cut})


def isf_draft_diff_result(case_dir: str, capture_id: str, name: str, *,
                          against_version: Optional[str] = None,
                          against_isf: Optional[str] = None,
                          only: Optional[Mapping[str, Sequence[str]]] = None,
                          limit: int = DEFAULT_LIMIT) -> ServiceResult:
    """Draft (current) vs the draft at ``against_version`` or vs an ISF file; direction
    is ``against -> draft`` (``added`` = only in the draft)."""
    if bool(against_version) == bool(against_isf):
        raise _invalid("give exactly one of against_version or against_isf",
                       "isf_diff_target")
    capture, store = _capture(capture_id), _store(case_dir)
    current = store.materialize(capture, name)
    if against_isf:
        other = IsfDraft.from_isf_dict(_read_isf_file(against_isf))
    else:
        other = store.materialize(capture, name, upto=against_version)
    diff = other.diff(current, only=only)
    return ServiceResult.ok({"draft": name, "against": against_isf or against_version,
                             "version": current.version, **_hex_diff(diff.to_dict(limit=limit))})


def _hex_diff(diff: Dict[str, Any]) -> Dict[str, Any]:
    """Symbol addresses in before/after as hex strings (JSON ints lose bits above 2**53)."""
    for item in diff["items"]:
        if item["key"] and item["key"][0] == "symbol":
            for side in ("before", "after"):
                if isinstance(item[side], Mapping):
                    item[side] = {**item[side], "address": _hex(item[side].get("address"))}
    return diff


def _readiness_row(item: Any) -> Dict[str, Any]:
    return {"plugin": item.plugin, "verdict": _plain(item.verdict),
            "required_missing": [_plain(m) for m in item.required_missing],
            "optional_missing": len(item.optional_missing),
            "indeterminate": len(item.indeterminate),
            "upstream_defects": len(item.upstream_defects), "reason": item.reason}


def isf_draft_validate_result(case_dir: str, capture_id: str, name: str, *,
                              check_schema: bool = False,
                              limit: int = DEFAULT_LIMIT) -> ServiceResult:
    require_pakunoda()
    from pakunoda.generators.isf_validator import document_plugin_readiness, validate_isf
    capture = _capture(capture_id)
    draft = _store(case_dir).materialize(capture, name)
    isf = draft.to_isf_dict()
    timings: Dict[str, float] = {}
    result = _timed(timings, "validate", lambda: validate_isf(isf, check_schema=check_schema))
    arch = (draft.metadata.get("arch") or None)
    readiness = _timed(timings, "readiness",
                       lambda: document_plugin_readiness(isf, arch=arch))
    rows = [_readiness_row(r) for r in readiness]
    verdicts: Dict[str, int] = {}
    for row in rows:
        verdicts[str(row["verdict"])] = verdicts.get(str(row["verdict"]), 0) + 1
    errors, e_cut = _sample(list(result.errors), limit)
    warnings, w_cut = _sample(list(result.warnings), limit)
    return ServiceResult.ok({
        "draft": name, "version": draft.version, "is_valid": bool(result.is_valid),
        "errors": _plain(errors), "warnings": _plain(warnings),
        "error_count": len(result.errors), "warning_count": len(result.warnings),
        "truncated": e_cut or w_cut, "plugins": rows, "verdicts": verdicts,
        "timings": timings})


def isf_draft_export_result(case_dir: str, capture_id: str, name: str, *,
                            version: Optional[str] = None,
                            out_path: Optional[str] = None) -> ServiceResult:
    path = _store(case_dir).export_isf(
        _capture(capture_id), name, upto=version,
        out_path=Path(out_path).expanduser() if out_path else None)  # new *.isf.json only
    data = path.read_bytes()
    return ServiceResult.ok({"draft": name, "path": str(path), "size": len(data),
                             "sha256": hashlib.sha256(data).hexdigest()})


ISF_TRY_KIND = "isf_try"


def _run_try(image: Path, target: Path, cancel: Optional[Callable[[], bool]],
             progress: Optional[Callable[[str, float], None]],
             **kwargs: Any) -> Dict[str, Any]:
    """``try_isf`` in-process, or - when a ``cancel`` is given - in a killable child."""
    from memdiver.isf.tryloop import try_isf
    if cancel is None:
        return try_isf(image, target, **kwargs)
    from memdiver.engine.killable import run_killable
    return run_killable("memdiver.isf.tryloop:try_isf_stages",
                        {"image_path": image, "isf_path": target, **kwargs},
                        cancel=cancel, on_progress=_stage_bridge(progress))


def isf_try_result(image_path: str, *, case_dir: Optional[str] = None,
                   draft: Optional[str] = None, version: Optional[str] = None,
                   isf_path: Optional[str] = None, plugin: str = "linux.pslist",
                   ground_truth: Optional[str] = None, timeout_s: float = 120.0,
                   min_recall: float = 0.95, min_precision: float = 0.95,
                   author: str = "agent",
                   cancel: Optional[Callable[[], bool]] = None,
                   progress: Optional[Callable[[str, float], None]] = None) -> ServiceResult:
    """Try a draft (``case_dir`` + ``draft`` [+ ``version``]) or an ISF file on the image (T4.4).

    The outcome (verdict, comparison, implicated entries) is returned and, for a
    draft, appended to the analysis record as an ``isf_try`` entry supported by
    the draft version and the ground-truth file, so the workbench keeps the
    history of what was tried and why it failed. With ``cancel`` the try runs in a killable
    child process (a cancel stops it mid-stage) and ``cancel()`` is checked again right
    before the record append; ``progress(stage, elapsed_s)`` reports build / run / compare.
    A cancel raises ``CapabilityError(code="cancelled")``
    and records nothing.
    """
    from memdiver.analysis.record import AnalysisEntry, Support
    from memdiver.analysis.record_store import AnalysisRecord
    image = _image_file(image_path)
    if (draft is None) == (isf_path is None):
        raise _invalid("pass exactly one of draft (with case_dir) or isf_path",
                       "isf.try_target")
    capture = file_sha256(image)
    truth = Path(ground_truth).expanduser() if ground_truth else None
    if truth is not None and not truth.is_file():
        raise _invalid(f"ground truth {truth} is not a file", "isf.ground_truth_missing")
    if draft is not None:
        if not case_dir:
            raise _invalid("a draft try needs case_dir", "isf.try_target")
        store = _store(case_dir)
        state = store.materialize(capture, draft, upto=version)
        target = store.export_draft(state)  # the SAME materialized state is exported + recorded
        version, state_id = state.version, state.state_id
    else:
        target, state_id = Path(str(isf_path)).expanduser(), None
    _check_cancel(cancel)
    outcome = _run_try(image, target, cancel, progress, plugin=plugin, ground_truth=truth,
                       timeout_s=timeout_s, min_recall=min_recall, min_precision=min_precision,
                       capture_id=capture)
    outcome.update(draft=draft, version=version, state_id=state_id, capture_id=capture)
    _check_cancel(cancel)
    if draft is not None and case_dir:
        support = [Support("entry", version)] if version else []
        if truth is not None:
            support.append(Support("ground_truth", str(truth)))
        entry = AnalysisRecord(_case_root(case_dir)).append(AnalysisEntry(
            capture_id=capture, kind=ISF_TRY_KIND, author=author,
            label=f"{plugin} on draft {draft}: {outcome['verdict']}",
            payload={"draft": draft, "version": version, "state_id": state_id,
                     "isf_file": target.name, "plugin": plugin,
                     "verdict": outcome["verdict"], "stage": outcome["stage"],
                     "implicated": outcome["implicated"],
                     "comparison": outcome.get("comparison"), "error": outcome.get("error")},
            support=tuple(support)))
        outcome["record_entry"] = entry.id
    return ServiceResult.ok(outcome)
