# heap/

The allocator layer. It turns any dump source into a `HeapLayout`, meaning
chunks, free lists, regions, evidence and a per-byte role projection, without
callers knowing which allocator produced the heap. For the researcher view, see
[Heap allocator awareness](../user_guide/heap.md).

## Module map

| Module | Responsibility |
|---|---|
| `heap/model.py` | Plain data types: `AllocatorKind`, `ChunkState`, `HeapRole` (stable `IntEnum` values), `HeapChunk`, `HeapRegion`, `FreeList`, `Evidence`, `HeapArena`, `HeapLayout` (`chunk_at`, `role_runs`, `role_counts`, `to_dict`, `arenas`); arena kinds `ARENA_MAIN` / `ARENA_THREAD` / `ARENA_MMAP` and shared region kinds `REGION_MAIN_HEAP` / `REGION_THREAD_HEAP` / `REGION_MMAPPED_CHUNK`. Chunks, regions and free lists carry an optional `arena_id`. |
| `heap/segments.py` | The shared parser shape: `HeapSegment` (one contiguous range of an arena, walked from `walk_start`), `ChunkBudget` (`max_chunks` across all segments), `LayoutAssembler` (stamps `arena_id`, accumulates the standard coverage keys, builds the `HeapLayout`), the shared truncation diagnostic |
| `heap/platform.py` | `TargetPlatform` (os, arch, pointer size, endianness, *how we know*) and `memory_map_of` → `MappedRegion` list, read from the MSL header and region blocks, the ELF core `e_machine` + NT_FILE, or `.maps` names. Falls back to `ASSUMED_PLATFORM` (x86_64 LE) and never raises. |
| `heap/memory.py` | `VaMemory`: reads by virtual address over any source; `strip_tag` (arm64 TBI) |
| `heap/registry.py` | `AllocatorDescriptor`, `DetectContext`, `DetectScore`, `ParseOptions`, `register_allocator`, `run_detector`, and the `memdiver.allocators` entry-point group |
| `heap/detect.py` | Name / module / OS signals per allocator; `detect_allocator` ranks every registered detector into a `DetectionResult` |
| `heap/builtin.py` | The built-in descriptors (`BUILTIN_SPECS`): priority, levels, `partial` / `heuristic`; `name_detector` combines name signals with each parser's content probe |
| `heap/analyze.py` | `analyze_heap`, the single facade: detect, parse, fall back, annotate, cache |
| `heap/allocators/{ptmalloc2,scudo,mallocng,jemalloc,generic}.py` | One parser module per allocator family. Each exports `DESCRIPTOR_OVERRIDES = {kind: (probe, parse)}`. |
| `heap/allocators/ptmalloc2_walk.py` | ptmalloc2 / dlmalloc boundary-tag walker: geometry and flavours, paged reads, the chunk-header walk with resync and fencepost detection, and the per-chunk slot model |
| `heap/allocators/ptmalloc2_bins.py` | ptmalloc2 free-list decoding: tcache (plain / safe-linked), fastbins, unsorted / small / large bins, and locating `main_arena` in glibc's writable data |
| `heap/allocators/ptmalloc2_segments.py` | ptmalloc2 / dlmalloc segment bookkeeping: `WalkSpan`, glibc fencepost detection, the main arena (arena 0) and its `heap` segments, `assemble_layout` |
| `heap/allocators/ptmalloc2_arenas.py` | ptmalloc2 thread-arena discovery: the `main_arena.next` ring, or a `heap_info` scan of `HEAP_MAX_SIZE`-aligned anonymous maps; yields arenas 1..n with their `thread_heap` segments |
| `heap/allocators/ptmalloc2_mmapped.py` | ptmalloc2 mmapped-chunk scan: page-granular search of captured, writable, anonymous, non-heap / non-stack regions for `{prev_size, size \| IS_MMAPPED}` headers; hits become in-use `mmapped_chunk` segments of a pseudo arena of kind `mmap` |

Consumers outside the package:

| Module | Uses the layer for |
|---|---|
| `app/tools_heap.py` | The six `heap.*` producers (`detect`, `summary`, `chunks`, `chunk_at`, `free_lists`, `roles`) behind the CLI (`cli/heap.py`), web (`api/routers/heap.py`) and MCP tools |
| `engine/consensus_heap.py` | Projecting N layouts into slab coordinates (`ConsensusHeap`, `HeapRoleRuns`, `HeapChunkIndex`, `heap_roles.npz`) |
| `engine/consensus_service.py` | `build_consensus(..., allocator="auto")` attaches `cm.heap` |
| `engine/candidate_heap.py` | The `heap_policy` (`annotate` / `mask` / `off`) of `reduce_search_space` |
| `app/_pipeline_heap.py` | Persisting `heap_roles.npz` and the `"heap"` block of `consensus.json`, and loading them back for the reduce stages |
| `engine/heap_hits.py` | The `heap` annotation of `locate_key` hits |

## Data flow

```{mermaid}
flowchart LR
    Src[DumpSource<br/>.msl · ELF core · regioned raw · flat raw] --> Plat[platform_of<br/>memory_map_of]
    Plat --> Ctx[DetectContext<br/>lazy platform · regions · modules · memory]
    Ctx --> Det[detect_in_context<br/>name signals ⊕ content probe]
    Det --> Order[attempt order<br/>hint, or ranked candidates, then generic]
    Order --> Parse[descriptor.parse<br/>VaMemory reads]
    Parse --> Layout[HeapLayout<br/>chunks · free lists · coverage]
    Layout --> Runs[role_runs lo..hi]
    Runs --> Tools[app/tools_heap<br/>CLI · web · MCP · library]
    Runs --> Proj[consensus_heap<br/>slab projection + merge]
    Proj --> Cand[candidate_heap<br/>annotate / mask]
    Layout --> Hits[heap_hits<br/>locate-key annotation]
```

1. **Source → platform and memory map.** `platform_of` asks each source in the
   way that source can answer. `memory_map_of` returns one `MappedRegion` shape
   (`va, size, perms, name, module_path, captured`) whatever the format.
2. **Detect.** `DetectContext` computes each field on first use, so a detector
   that only needs region names never builds a `VaMemory`. A built-in detector
   scores name signals (weights summed, capped at 1.0) and combines them with
   its parser's content probe as independent evidence:
   `1 − (1 − names) · (1 − probe)`. `run_detector` clamps scores to `[0, 1]`
   and turns a raising detector into a 0 score with a `detector_error`
   evidence line, so one bad plugin cannot break detection.
3. **Parse with fallback.** `analyze_heap` tries the hinted allocator, or else
   every candidate with a positive score in rank order, and always `generic`
   last. The first layout that has chunks wins. If none has chunks, the first
   layout that parsed at all is used. Every attempt is recorded in
   `coverage["analysis"]`.
4. **Role runs.** `HeapChunk.role_segments` paints default layers (slack, then
   header, then user or free data, or `top` / `allocator_meta` for a whole
   chunk) and then the parser's `roles` overrides on top. An example override
   is the tcache `next` / `key` words as `FREE_LINK`. `HeapLayout.role_runs`
   clips these to a window, never lets them overlap, and coalesces adjacent
   equal runs.
5. **Consensus projection.** See [below](#consensus-projection).

## Registry and plugin contract

```python
@dataclass(frozen=True)
class AllocatorDescriptor:
    kind: AllocatorKind
    detect: Callable[[DetectContext], DetectScore]
    parse: Optional[Callable[[VaMemory, DetectContext, ParseOptions], HeapLayout]] = None
    priority: int = 0
    levels: FrozenSet[str] = frozenset({"L0"})
    partial: bool = False
    heuristic: bool = False
    reduce_ready: bool = False
```

- The registry is keyed by `AllocatorKind`. Registering a kind that is already
  present **replaces** it, so a plugin can override a built-in. Built-ins
  register with `replace=False`, so a plugin registered earlier is never
  overwritten.
- `registered_allocators()` sorts by descending `priority` and breaks ties by
  registration order. Built-in priorities: ptmalloc2 / scudo / mallocng 50,
  dlmalloc 40, jemalloc 30, generic 0.
- Loading is lazy and happens once per process: built-ins first, then
  `load_entry_point_registrations("memdiver.allocators")`. An entry point that
  resolves to a module is imported, and one that resolves to a callable is
  invoked.
- `parse=None` declares a detect-only allocator. `analyze_heap` records
  `no parser registered` and moves on.
- `partial` / `heuristic` / `levels` are surfaced verbatim in every summary
  payload and in the UI badges.
- `reduce_ready` opts an allocator in to heap-aware candidate reduction
  (`search-reduce`, `consensus-begin --allocator`). It defaults to `False`;
  `reduce_ready_kinds()` lists the opted-in kinds in priority order (today:
  `ptmalloc2`). `cli/_shared.SEARCH_REDUCE_ALLOCATOR_CHOICES` must name the
  same set, which `tests/test_cli_heap_policy.py` checks.
- A parser returns one `HeapLayout`. Besides chunks, regions and free lists it
  may fill `HeapLayout.arenas` (a tuple of `HeapArena`: `arena_id`, `kind`,
  `va` of the control structure, `top_va` = address of the arena's `top`
  field, not the top chunk, `region_vas`, `extra`), and tag chunks, regions and
  free lists with the owning `arena_id`. Parsers built on
  `heap/segments.LayoutAssembler` get this, and the standard coverage keys
  (`regions`, `arenas`, `bytes_total`, `bytes_walked`, `bytes_skipped`,
  `bytes_uncaptured`, `chunk_count`, `truncated`), for free.

See [Adding an allocator](../contributing/adding_allocator.md) for a worked
plugin.

## Caching

`analyze_heap` keeps a process-wide LRU of 8 layouts (`CACHE_SIZE`), keyed by
the resolved dump path, `st_mtime_ns`, `st_size`, the source's region-filter
note, the allocator hint, `base_va`, `max_chunks` and `regions`. It follows the
same pattern as `app/reader_cache.py`.

- A source that cannot be stat'ed is not cached, and neither is a pathless
  source.
- Encrypted sources, whether keyed or locked, **bypass** the cache. A layout
  derived from decrypted bytes must never be served to a caller without the key.
- Cached layouts are shared objects, so treat them as read-only.
  `clear_heap_cache()` drops every entry.

The frontend keeps its own cache. See [UI layer](#ui-layer).

## Coordinate spaces

Three coordinate systems meet in the heap layer. Mixing them up is the most
common bug.

| Space | Who uses it | Notes |
|---|---|---|
| **Virtual address (VA)** | Parsers, `HeapLayout`, `HeapChunk.va`, free-list pointers | What the allocator itself stores. Kernel-half VAs (≥ 2⁶³) are kept as `uint64` so they still sort. |
| **View offset** | Producers (`view_offset` columns), the hex viewer, `locate-key` offsets | Offset in a byte view: `vas` (dense captured memory), `raw` (the file), `va` (sparse VA view of an `.msl`). `VaMemory.va_to_view_offset` / `view_offset_to_va` translate. |
| **Slab offset** | Consensus, `HeapRoleRuns`, `HeapChunkIndex`, candidates | Index into the consensus vector. Aligned builds map via `cm.msl_layout` rows `(slab_offset, page_size, [va_per_dump])`, and flat builds via each source's `vas` runs. |

`VaMemory` reads by VA in three modes:

- **Sparse `va` view** (`.msl`) through `read_range_with_validity`. A page the
  dump never captured yields `None` instead of zero filler.
- **Dense `vas` projection** (gcore, gdb/lldb regioned raw), after checking that
  the whole range lies in contiguous captured runs.
- **Flat** (`RawDumpSource`, or any source with an explicit `base_va`):
  `offset = va - base_va`.

Every read returns exactly `n` captured bytes or `None`. Parsers treat `None`
as "not captured" and skip ahead, recording that in `coverage`.

## Consensus projection

`engine/consensus_heap.compute_consensus_heap(cm, sources, allocator)`:

1. Builds one VA → slab map per dump. Aligned builds use their `msl_layout`
   rows. Flat builds clip the source's captured `vas` runs to the slab, and a
   dump with no VA map is not projected. When no dump has a VA map, the result
   is `ConsensusHeap.unavailable("no_va_coordinate")`.
2. Projects each dump's `role_runs` through its map into `(starts, lengths,
   roles)` pieces.
3. Merges the pieces with run-based numpy interval arithmetic (nothing loops
   per byte). A byte takes role *R* when every dump with a non-`NONE` role there
   agrees, and is `MIXED` otherwise. `agree` counts the dumps whose role equals
   the anchor's (the first projected dump), `NONE` included.
4. Projects the anchor's chunks into a `HeapChunkIndex`
   (`slab_starts, sizes, states, agree`).

Bytes no dump assigns a role are not stored. `HeapRoleRuns.window` paints them
with `fill`, which is `NONE` for a computed result and `UNCOVERED` for an
unavailable one. `save_heap_npz` / `load_heap_npz` persist runs and chunks
together in `heap_roles.npz`, with the chunk arrays under a `chunk_` key prefix.

`engine/candidate_heap.py` consumes the runs and chunk index:
`region_heap_annotation` builds the `CandidateRegion.heap` block, and
`metadata_mask` plus `heap_score_adjustment` implement `mask`. The heap layer
is imported only when a caller passes heap runs, so `candidate_pipeline` stays
heap-free under `off`.

`aligned_window_from_vector` adds `heap_status`, `heap_roles` (one role code
per byte, parallel to `classes`; `255` = uncovered) and a `heap_role_names`
legend whenever the consensus vector carries heap roles.

## UI layer

The heap mode is described from the user's side in the
[web UI tour](../user_guide/web_ui_tour.md#heap-mode). Its architecture:

- **App mode.** `APP_MODES = ["verification", "exploration", "heap"]` in
  `stores/app-store.ts`. Heap mode is exploration plus the heap panels, so
  every consumer that gates on "not verification" treats it like exploration.
  `useHeapModeLayer` mirrors "heap mode and an active dump" into the heap store
  and turns the layer off again when the mode or dump changes.
- **`stores/heap-store.ts`** holds per-dump state (detection, summary, a
  chunk-page cache keyed by filters, view and page, free lists, `layerEnabled`,
  `selectedChunk`). It fetches through `api/heap.ts` (`/api/heap/*`). A
  per-dump generation counter turns a response that arrives after an allocator
  change into a no-op, so a stale answer cannot overwrite the new one.
- **Role windows.** The hex layer is deliberately *not* a set of
  `highlightedRegions`. The left-walk lookup in `highlight-utils` collapses on
  a 100 KiB top chunk. Instead the store fetches `/api/heap/roles` in windows
  aligned to `HEAP_ROLE_WINDOW_SIZE` (64 KiB), keyed by
  `(dumpPath, view, windowStart)`, and keeps at most `HEAP_MAX_ROLE_WINDOWS`
  (48) of them. Every window arrival bumps `roleWindowsVersion`, which is the
  single value a viewer subscribes to.
- **Binary-search lookup.** `utils/heap-roles.ts` indexes each window's
  sorted, non-overlapping runs. The run covering a byte is the last one whose
  start is ≤ the byte, found with one `upperBound` (O(log n)). The answer is
  one packed number per byte: the role code in the low byte, OR-ed with
  `HEAP_CHUNK_START_BIT` (`0x100`) at a chunk start. The memoised `HexRow`
  therefore allocates nothing per cell.
- **Ground classes.** Roles map to `heap-header`, `heap-user`, `heap-freelink`,
  `heap-free`, `heap-meta`, `heap-top` and `heap-slack`, which are registered
  in `components/hex/ground-classes.ts` with rules in `styles/hex.css` and
  `--md-hl-heap-*` tokens for the light, dark and high-contrast themes in
  `styles/globals.css`. The chunk-start tick (`heap-chunk-start`) is a
  box-shadow, not a ground, so it combines with any role color. `HexRow` asks
  the heap layer only after the existing highlights.
- **Panels.** `HeapOverview` (side tab), `HeapPanel` (bottom tab: chunk table,
  size histogram, free lists, chunk inspector) and `HeapLegend` /
  `HeapLayerToggle` in the hex toolbar. Navigation goes through
  `heap-navigation.ts`. A `view_offset` goes straight to
  `hex-store.scrollToOffset`, and a bare VA is first translated by
  `/api/heap/chunk-at`.
- **i18n.** Every string lives in the `heap` namespace
  (`i18n/locales/en/heap.json`).

- **Consensus overlay.** `OVERLAY_RENDER_MODES` gains `"heap"`, which
  paints the aligned window's `heap_roles` with the same ground classes plus
  `heap-mixed` for bytes the dumps disagree on. It is disabled, with a
  localized reason, whenever `heap_status` is not `ok`. `OverlayByteInspector`
  shows the inspected byte's role. The candidate table adds chunk-state,
  residual and offset-in-chunk columns when candidates carry a `heap` block,
  and `HeapPolicySelect` sets `heap_policy` in the candidate filters and the
  pipeline's search-reduce thresholds.
