# Adding a heap allocator

A *heap allocator* plugin teaches MemDiver to recognise one allocator in a dump
and walk its heap. Once registered, an allocator works everywhere at the same
time: `memdiver heap …`, `/api/heap/*`, the `heap_*` MCP tools, consensus heap
roles, `locate-key` hit annotation and the web heap mode. All of these call
`analyze_heap`, and `analyze_heap` asks the registry.

Read [the heap architecture](../architecture/heap.md) first. The data model and
the coordinate rules there are the contract.

## 1. Pick a kind

The registry is keyed by `memdiver.heap.AllocatorKind`, a closed `str` enum
(`ptmalloc2`, `dlmalloc`, `scudo`, `mallocng`, `jemalloc`, `generic`, `unknown`).

- **Replacing a built-in.** An out-of-tree package can do this. Reuse its kind,
  because registering an existing kind replaces the descriptor. A typical case
  is a full jemalloc parser that walks the rtree.
- **A new allocator family.** This needs a new `AllocatorKind` member in
  `heap/model.py`, and so an in-tree change. `AllocatorKind("foo")` raises for
  an unknown value. Add the member, its `heap.json` label in
  `frontend/src/i18n/locales/en/heap.json` (`allocators.<kind>`), and the CLI
  choice in `HEAP_ALLOCATOR_CHOICES` (`cli/heap.py`).

The examples below use a fictional `FOO` member. Substitute your kind.

## 2. Write a detector

A detector gets a `DetectContext` and returns a `DetectScore(score, evidence)`
with `score` in `[0, 1]`. The context computes every field lazily, so use the
cheapest signal that answers the question:

| Field / helper | What it gives you |
|---|---|
| `ctx.platform` | `TargetPlatform` (`os`, `arch`, `pointer_size`, `endianness`, `is_android`) |
| `ctx.regions`, `ctx.region_names`, `ctx.has_region("[anon:foo:*")` | The memory map. Pattern matching is fnmatch with a literal `[`. |
| `ctx.modules`, `ctx.matching_modules("libfoo*")` | Mapped module paths / basenames |
| `ctx.memory` | A `VaMemory` for content probes (`read`, `u32`, `u64`, `ptr`) |

```python
from memdiver.heap import DetectScore, Evidence

def detect_foo(ctx):
    evidence = [Evidence("module", f"libfoo mapped: {m}", 0.7)
                for m in ctx.matching_modules("libfoo*.so*")[:1]]
    if ctx.has_region("[anon:foo:*"):
        evidence.append(Evidence("region", "[anon:foo:*] regions present", 0.6))
    return DetectScore(min(1.0, sum(e.weight for e in evidence)), evidence)
```

Rules:

- **Be cheap.** Detection runs for every registered allocator on every
  analysis. Look at names first, and read bytes only to break ties.
- **Explain yourself.** Every point of score should come from an `Evidence`
  line. `memdiver heap detect` prints these lines, and they are the only way a
  user can tell why your allocator won.
- **Never raise on purpose.** `run_detector` catches exceptions and scores them
  0 with a `detector_error` line. A crash costs your allocator the detection
  but does not break the others.

## 3. Write a parser

```python
from memdiver.heap import (AllocatorKind, ChunkState, HeapChunk, HeapLayout,
                           HeapRegion, HeapRole)

def parse_foo(memory, ctx, options):
    chunks, regions, notes = [], [], []
    for region in ctx.regions:
        if not region.name.startswith("[anon:foo:") or not options.selects(region):
            continue
        regions.append(HeapRegion(region.va, region.size, region.name, "foo-arena"))
        va = region.va
        while va + 16 <= region.end and len(chunks) < options.max_chunks:
            size = memory.u64(va)                 # None = page not captured
            if size is None or size < 16 or va + size > region.end:
                notes.append(f"foo: stopped at {va:#x}")
                break
            in_use = bool(size & 1)
            size &= ~0xF
            chunks.append(HeapChunk(
                va=va, size=size, header_len=16, user_va=va + 16,
                user_len=size - 16,
                state=ChunkState.IN_USE if in_use else ChunkState.FREE,
                # optional: paint a free-list pointer at user+0
                roles=None if in_use else ((16, 8, HeapRole.FREE_LINK),),
            ))
            va += size
    return HeapLayout(AllocatorKind.FOO, platform=ctx.platform,
                      regions=tuple(regions), chunks=tuple(chunks),
                      confidence=0.8 if chunks else 0.0,
                      diagnostics=tuple(notes),
                      coverage={"regions_walked": len(regions)})
```

The contract every parser must honour:

- **Think in virtual addresses.** Read only through `memory` (`VaMemory`).
  Never compute file offsets yourself. A read returns `None` for bytes the
  dump never captured, so treat that as a gap, not as zero.
- **Strip pointer tags.** Pass every pointer you follow through
  `memdiver.heap.strip_tag(ptr, memory.platform)` (arm64 TBI). Use
  `memory.platform.pointer_size` and `endianness` instead of hard-coding
  64-bit LE.
- **Chunks never overlap.** `HeapLayout` sorts them, but overlap is a bug, and
  the real-dump test asserts against it.
- **Roles.** The defaults (header, user / free data, slack) come from
  `header_len`, `user_va`, `user_len` and `state`. Set `HeapChunk.roles` only
  for sub-ranges you know better, as `(offset_from_va, length, HeapRole)`.
  Mark a whole chunk as metadata with `extra={"meta": True}`, or as the top
  chunk with `bin="top"`.
- **Honour `ParseOptions`.** Stop at `options.max_chunks`, and skip regions for
  which `options.selects(region)` is false.
- **Diagnose instead of guessing.** If you cannot decode a structure, add a
  line to `diagnostics` and leave it out. Do not invent chunks.
- **Raising is allowed but costly.** `analyze_heap` catches the exception,
  records `parser raised …` and falls back to the next candidate.

### Segment-based parsers (recommended)

The flat loop above is fine for a first parser. Allocators with more than one
arena or more than one kind of mapping are easier to get right with the shared
shape in `heap/segments.py`. A parser then works in three steps:

1. **Discover** the allocator's arenas (`HeapArena`) and the contiguous
   segments (`HeapSegment(va, end, walk_start, arena_id, kind, name)`) each
   arena owns: the main heap, thread heaps, mmapped chunks, size-class
   regions, groups.
2. **Walk** each segment from its `walk_start`. A single `ChunkBudget` shared
   by all segments enforces `ParseOptions.max_chunks` the same way for every
   allocator (`budget.take(n)` returns `False` and sets `truncated` once the
   budget runs out).
3. **Assemble** with a `LayoutAssembler`. It records each segment as a
   `HeapRegion`, stamps the segment's `arena_id` onto chunks that do not set
   one themselves, accumulates the standard coverage keys and builds the
   `HeapLayout`.

```python
from memdiver.heap import AllocatorKind
from memdiver.heap.model import ARENA_MAIN, REGION_MAIN_HEAP, Evidence, HeapArena
from memdiver.heap.segments import ChunkBudget, HeapSegment, LayoutAssembler

def parse_foo(memory, ctx, options):
    asm = LayoutAssembler(AllocatorKind.FOO, ctx.platform)
    budget = ChunkBudget(options.max_chunks)
    for arena, segments in discover_foo_arenas(memory, ctx, options):
        asm.add_arena(arena)            # e.g. HeapArena(0, ARENA_MAIN, va=...)
        for seg in segments:            # HeapSegment(..., kind=REGION_MAIN_HEAP)
            chunks, walked, skipped = walk_foo_segment(memory, seg, budget)
            asm.add_segment(seg, chunks, walked=walked, skipped=skipped)
        for free_list in foo_free_lists(memory, arena):
            asm.add_free_list(free_list)   # FreeList(..., arena_id=arena.arena_id)
    if budget.truncated:
        asm.mark_truncated(budget.max_chunks)   # adds the shared diagnostic once
    asm.evidence(Evidence("foo_magic", "arena magic matched", 0.9))
    return asm.build(version_hint=None)   # confidence defaults to walked / total
```

Use `asm.diagnose(message)` for anything you could not decode. `build()` takes
`extra_coverage` (allocator-specific keys, merged last), `extra_evidence` and an
explicit `confidence`.

Conventions:

- **Arena kinds.** `HeapArena.kind` is one of `ARENA_MAIN` (`"main"`),
  `ARENA_THREAD` (`"thread"`) or `ARENA_MMAP` (`"mmap"`, a pseudo arena that
  owns mmapped chunks). Allocator-specific strings are allowed when none fits.
- **Region kinds.** Reuse `REGION_MAIN_HEAP` (`"heap"`), `REGION_THREAD_HEAP`
  (`"thread_heap"`) and `REGION_MMAPPED_CHUNK` (`"mmapped_chunk"`) for the
  common cases. Allocator-specific kinds (`"arena"`, `"group"`, scudo
  size-class regions, ...) are allowed too.
- **`HeapArena.top_va`** is the address of the arena's `top` *field* (the slot
  inside the control structure; ptmalloc2: `&arena.top`), not the top chunk.
  Put the top chunk's VA in `extra["top_chunk_va"]`. `va` is the control
  structure (e.g. `malloc_state`) when known, and `region_vas` lists the
  regions the arena owns.
- **`arena_id`** links chunks, regions and free lists to their arena.
  `HeapChunk.arena_id` and `HeapRegion.arena_id` are filled from the segment;
  set `FreeList.arena_id` yourself, because bin `kind` / `index` repeat across
  arenas.
- **Standard coverage keys** (`HeapLayout.coverage`): `regions` (segment
  names, or hex VAs for nameless segments), `arenas` (count), `bytes_total`,
  `bytes_walked`, `bytes_skipped`, `bytes_uncaptured`, `chunk_count` and
  `truncated`.

The reference implementation is ptmalloc2: `heap/allocators/ptmalloc2.py`
(probe and parse orchestration), `ptmalloc2_walk.py` (chunk walker),
`ptmalloc2_bins.py` (tcache, fastbins and bins, `main_arena`),
`ptmalloc2_arenas.py` (thread-arena discovery),
`ptmalloc2_segments.py` (segments, fenceposts, `assemble_layout`) and
`ptmalloc2_mmapped.py` (mmapped-chunk scan).

## 4. Register a descriptor

```python
from memdiver.heap import AllocatorDescriptor, AllocatorKind, register_allocator

register_allocator(AllocatorDescriptor(
    kind=AllocatorKind.FOO,
    detect=detect_foo,
    parse=parse_foo,           # None = detect-only
    priority=45,               # dispatch order among equal scores
    levels=frozenset({"L0", "L1", "L2"}),
    partial=False,             # True: only part of the allocator is parsed
    heuristic=False,           # True: structure is guessed, not read
))
```

Be honest with `levels` / `partial` / `heuristic`. They are shown to the user in
every summary and as badges in the web UI.

**In-tree** allocators use a different path: add a module under
`heap/allocators/` that exports `DESCRIPTOR_OVERRIDES = {AllocatorKind.FOO:
(probe_foo, parse_foo)}`, and a `BuiltinSpec` row in `heap/builtin.py`.
`name_detector` then combines your probe with the name signals you add to
`NAME_SIGNALS` in `heap/detect.py`.

## 5. (Optional) out-of-tree via entry point

An installed package registers through the `memdiver.allocators` entry-point
group. The registry loads it once per process, right after the built-ins:

```toml
# pyproject.toml of your out-of-tree package
[project.entry-points."memdiver.allocators"]
# a module whose import calls register_allocator(...)
foo = "my_pkg.memdiver_allocator"
# ...or a callable that self-registers when invoked
# foo = "my_pkg.memdiver_allocator:register"
```

Discovery is additive and failure-isolated. A broken entry point is logged and
skipped. Because built-ins register *before* plugins load, and a plugin's
`register_allocator` call replaces by default, a plugin that reuses a built-in
kind replaces that built-in. Out-of-tree packages can only reuse existing kinds
(see step 1).

## 6. Test

Build the expected answer by hand, then check that the parser recovers it.
`tests/fixtures/synth_heap.py` is the pattern to follow:

- A builder writes the allocator's structures field by field from the upstream
  struct definitions and returns a `SynthHeap`: the region bytes plus the list
  of `ExpectedChunk(va, size, state, header_len, user_len, bin)` a correct
  parser must report. There is no allocation simulation, and the result is
  deterministic.
- `as_regioned_raw(tmp_path, [heap], modules=[...])` writes it as a
  `.gdb_raw.bin` + `.maps` pair (add module mappings to drive name detection),
  and `open_regioned(path)` opens it through `open_dump`.

```python
from memdiver.heap import analyze_heap
from tests.fixtures.synth_heap import as_regioned_raw, open_regioned

def test_foo_recovers_every_chunk(tmp_path):
    heap = foo_heap(base_va=0x7F00_0010_0000)          # your builder
    source = open_regioned(as_regioned_raw(tmp_path, [heap]))
    try:
        layout = analyze_heap(source, "foo")
    finally:
        source.close()
    got = [(c.va, c.size, c.state) for c in layout.chunks]
    assert got == [(c.va, c.size, c.state) for c in heap.chunks]
```

Cover at least:

- exact chunk boundaries, states and role runs;
- 32-bit and big-endian, if the allocator supports them;
- a corrupt header (the parser resyncs and reports a diagnostic);
- a negative control: `random_region()` must not be detected as your allocator,
  with a false-positive rate under 1 % for content probes;
- registry isolation (see `tests/test_heap_registry.py` for the
  `restore_registry` fixture that snapshots and restores the registry).

Then run the surface parity tests (`tests/test_heap_surfaces.py`,
`tests/test_tools_heap.py`) and, if you have real captures, the opt-in
`MEMDIVER_REAL_HEAP_DUMPS` suite described in the
[user guide](../user_guide/heap.md#real-dump-opt-in-tests).

## 7. Opting into allocator-aware reduction

`search-reduce` and `consensus-begin --allocator` only accept allocators whose
descriptor sets `reduce_ready=True`, because a wrong heap role there can mask
the key you are looking for. The flag defaults to `False`. Opt in only when:

- [ ] the parser follows the segment-based shape above (arenas, segments,
      `arena_id`, standard coverage keys);
- [ ] synthetic tests cover every arena and segment kind it reports, including
      negative controls (random bytes and look-alike regions are not
      detected, and no chunks are invented);
- [ ] the descriptor sets `reduce_ready=True`: in a `BuiltinSpec` row of
      `heap/builtin.py` (`_spec(..., reduce_ready=True)`) for in-tree
      allocators, or in `AllocatorDescriptor(..., reduce_ready=True)` for
      plugins;
- [ ] the name is added to `cli/_shared.SEARCH_REDUCE_ALLOCATOR_CHOICES`. Its
      concrete names (everything except `auto` and `off`) must equal
      `memdiver.heap.registry.reduce_ready_kinds()`, and
      `test_search_reduce_allocator_choices_match_reduce_ready_kinds` in
      `tests/test_cli_heap_policy.py` enforces it
      (`tests/test_heap_registry.py` pins the built-in set).

ptmalloc2 (`heap/allocators/ptmalloc2*.py`) is currently the only
`reduce_ready` allocator and the reference to follow.
