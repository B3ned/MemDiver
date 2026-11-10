---
myst:
  html_meta:
    "description lang=en": "Heap allocator awareness in MemDiver: detect the allocator, walk its chunks and free lists, and label every heap byte with its role."
---

# Heap allocator awareness

Older MemDiver releases understood heap memory only at the region level. A
mapping named `[heap]` or `[anon:scudo:primary]` was tagged *heap*, and that was
all. Since 0.10.0 MemDiver also reads the **allocator's own structures**: chunk
headers, free lists, tcache, arenas and slot metadata. That gives three things
a researcher could not get before:

- **Chunk context for every byte.** For any address you can ask which chunk owns
  it, whether that chunk is in use or freed, and what the byte is for: header,
  user data, free-list link, allocator metadata.
- **Less consensus noise.** Allocator fields such as safe-linked tcache `next`
  pointers, the random `tcache_key` and fd/bk links vary from dump to dump
  without ever being key material. Consensus now labels them, and can mask them
  if you ask it to.
- **Residual keys.** A key that sits in a *freed* chunk is stale memory, not live
  state. Candidates and located-key hits that fall in freed chunks are flagged.

Everything goes through one analysis facade,
`memdiver.heap.analyze_heap`. The CLI, the web API, the MCP server and
the library all call it, so every surface returns the same answer.

## Supported allocators

Analysis levels: **L0** detection, **L1** attribution of regions to the
allocator, **L2** chunk walk, **L3** free-list walk.

| Allocator | Typical platforms | Detection signals | Levels | What is decoded | Flags |
|---|---|---|---|---|---|
| `ptmalloc2` | glibc Linux (x86_64, arm64, 32-bit) | glibc mapped (`libc.so.6`, `libc-2.*.so`), a `[heap]` region on a non-Android target, content probe | L0–L3 | Boundary-tag chunk walk of `[heap]` (flags `PREV_INUSE` / `IS_MMAPPED` / `NON_MAIN_ARENA`), `tcache_perthread_struct` (size `0x290` means glibc ≥ 2.30, `0x250` means 2.26–2.29), tcache bins with and without safe-linking (glibc ≥ 2.32), `main_arena` located in glibc's writable mapping, then fastbins and the unsorted / small / large bins. Thread arenas (via the `main_arena.next` ring, or a `heap_info` scan of `HEAP_MAX_SIZE`-aligned anonymous maps) walked as `thread_heap` regions of arenas 1..n. mmapped chunks found by a page-granular header scan (pseudo arena of kind `mmap`). | — |
| `dlmalloc` | embedded heaps, older bionic (`[anon:libc_malloc]`) | content probe only (dlmalloc has no naming convention) | L0–L2 | Same boundary-tag walker; bit 2 is `CINUSE`. Free chunks are labelled `smallbin` / `treebin` by size. | — |
| `scudo` | Android ≥ 11, LLVM standalone scudo | `[anon:scudo:*]` regions, `libscudo*` mapped, Android OS prior, content probe | L0–L2 | Primary-region chunks. The packed 64-bit header (`ClassId`, `State`, size, `Offset`, checksum) is judged on **structure** because the checksum cookie is per-process. Stride and slot phase are inferred from the bytes. | **partial** |
| `mallocng` | musl ≥ 1.2.1 (Alpine and static musl builds) | musl loader / libc mapped (`ld-musl-*.so.1`, `libc.musl-*`) | L0–L2 | Groups found through the `meta->mem == group` back-pointer check, slot state from `avail_mask` / `freed_mask`, in-band slot headers decoded to recover the requested size | — |
| `jemalloc` | FreeBSD, Firefox, Redis, pre-11 Android bionic | `libjemalloc*` mapped, `jemalloc`-named regions, `[anon:libc_malloc]` on Android when no scudo regions exist | L0–L1 (+ slot inference) | Region attribution, plus one slot stride per mapping inferred from the jemalloc 5.x small size-class table. Slots are headerless, in state `unknown`, with confidence ≤ 0.6. | **partial** |
| `generic` | anything else with in-band size words | weak fallback whenever a memory map exists | L0–L1 | Boundary-tag size chains of at least 4 links. State is always `unknown` and confidence is capped at 0.3. | **heuristic** |

**partial** means only part of the allocator's structures are parsed, so chunks
outside them are not listed. **heuristic** means chunk boundaries are inferred,
not read from allocator metadata. Both flags are reported in every summary
payload (`partial`, `heuristic`, `levels`). The web UI shows them as badges.

### Known limitations

These come from the parser modules (`heap/allocators/*.py`). Each one produces
a diagnostic instead of a guess.

- **ptmalloc2.** The main heap is the region named `[heap]` (for dlmalloc
  also `[anon:libc_malloc]`), walked as arena 0.
  - *Thread arenas* are found through the `main_arena.next` ring or, when
    `main_arena` is not available, by scanning `HEAP_MAX_SIZE`-aligned
    (64 MiB on 64-bit, 1 MiB on 32-bit) anonymous writable maps for a valid
    `heap_info`. Each of their heaps is walked as a `thread_heap` region of
    arena 1..n, and the arena's tcache is decoded. Coverage reports
    `thread_arenas` and `arena_discovery` (`ring` or `heap_info_scan`).
  - *mmapped chunks* (ptmalloc2 only) are found by a page-granular scan of
    captured, writable, anonymous regions that are neither the heap nor a
    stack, looking for a `{prev_size = correction, size | IS_MMAPPED}` header.
    Each hit is an in-use chunk with bin `mmapped` in a pseudo arena of kind
    `mmap`, recorded as a region of kind `mmapped_chunk`. With an explicit
    `--regions`, only the selected regions are scanned (and only selected
    thread heaps are walked). Coverage reports the count as `mmapped_chunks`.
  - Remaining limitations: `main_arena` is not found in statically linked
    binaries, so thread arenas then come from the `heap_info` scan and their
    bins (fastbins, unsorted / small / large) are not decoded. The offset of
    `top` inside `malloc_state` is learnt once from the arena ring and assumed
    to be the same for every arena. dlmalloc mmapped chunks are not
    enumerated. An i386 glibc built with `MALLOC_ALIGNMENT == 16` is not
    handled. Corrupt headers are skipped by resyncing to the next plausible
    header, and the diagnostic names the address.
- **scudo.** `[anon:scudo:secondary]` mappings are listed but their
  `LargeBlock::Header` is not decoded. BatchClass blocks (ClassId 0) and the
  per-class `TransferBatch` free lists are not walked, so no free lists are
  produced. A ClassId needs at least two headers on its stride to be walked.
  Realigned (`memalign`) chunks may come out as `unknown`.
- **mallocng.** mallocng has no free lists (state lives in the masks), so none
  are reported. The `malloc_context` is not located.
- **jemalloc.** The rtree and the `edata_t` extent metadata are not walked. A
  mapping whose stride cannot be inferred is reported as a region only.
- **generic.** Nothing about allocation state, free lists or metadata is inferred.
- Windows NT / segment heap and macOS libmalloc are not supported.

### Fallback

`analyze_heap` never raises on a parse failure. It tries the detected allocator
first, then the other candidates in score order, and finally `generic`. Every
attempt is recorded in `coverage.analysis` (`requested`, `detected`, `chosen`,
`fell_back`, `attempts`), and every failed attempt adds a line to
`diagnostics`. The only error is an unknown allocator name.

## Roles and states

### Chunk states

| State | Meaning |
|---|---|
| `in_use` | Allocated and handed to the program |
| `free` | Released to a bin or free list (or marked free in a mask) |
| `cached` | Parked in a fast cache (glibc tcache, fastbin). Its in-use bit still says *allocated* although the program freed it. |
| `quarantined` | Held back from reuse (scudo quarantine) |
| `unknown` | Boundaries known, state not (jemalloc slots, `generic`, low-confidence scudo slots) |

`free`, `cached` and `quarantined` count as **freed**. Bytes in a freed chunk
are stale.

### Byte roles

Each heap byte has exactly one role. The numeric values are stable, because
they are stored in role maps and in `heap_roles.npz`.

| Value | Role | Meaning |
|---|---|---|
| 1 | `chunk_header` | Allocator header in front of the user bytes (and mallocng's in-band slot header) |
| 2 | `user_data` | Bytes handed to the program in an in-use chunk |
| 3 | `free_link` | fd/bk pointers, tcache `next` / `key`, fastbin `fd` |
| 4 | `free_data` | Stale payload left in a freed chunk |
| 5 | `allocator_meta` | `tcache_perthread_struct`, mallocng `meta` / group headers |
| 6 | `top` | glibc top chunk (the unallocated tail of the heap) |
| 7 | `slack` | Bytes of a chunk after its user data |
| 254 | `mixed` | Consensus only: the dumps disagree about this byte |
| 255 | `uncovered` | Consensus only: no heap coordinate is known here |

Bytes outside every chunk have role `none` and are left out of role runs.

## Workflows

### CLI

`memdiver heap <action> DUMP` takes the same options for every action:
`--allocator {auto,ptmalloc2,dlmalloc,scudo,mallocng,jemalloc,generic}`,
`--base-va` (for flat raw dumps), `--json`, `-o FILE`, and the usual key-material
flags for encrypted `.msl` files.

```bash
# Which allocator is this? Ranked candidates with their evidence.
memdiver heap detect capture.msl

# Overview: chunk counts and bytes per state, size histogram, metadata bytes.
memdiver heap summary capture.msl

# One page of the chunk table, filtered.
memdiver heap chunks capture.msl --state cached --min-size 0x20 --page-size 50

# Who owns this address? Role, offset in chunk and user data, neighbours.
memdiver heap at capture.msl --va 0x55d0c0a012a0

# Walked free lists with cycle / corruption flags.
memdiver heap free-lists capture.msl --kind tcache

# Byte-role runs of a window in a byte view (vas, raw or va).
memdiver heap roles capture.msl --view vas --offset 0x10000 --length 0x2000
```

Output is a text report by default. `--json` emits the producer payload
unchanged. See the [CLI reference](cli_reference.md) for every flag.

### Web UI: heap mode

The **mode banner** at the top of the workspace now has a third mode, **Heap**,
next to verification and exploration. Heap mode is exploration plus:

- a **Heap** side tab (opened on entering the mode) with the allocator badge,
  its confidence, the *Partial* / *Heuristic* tags, the platform and version
  hint, other candidates with their evidence, the heap regions (click one to
  jump there) and chunk counts by state;
- a **Heap** bottom tab with the chunk table (filter by state, size and address
  range; click a row to jump the hex view to the chunk), a size histogram, the
  free-list tree, and a chunk inspector with header fields, the user range and
  the neighbouring chunks;
- a **hex heap layer** that colors every byte by its role and marks chunk starts
  with a tick, and a heap legend. The **Heap layer** button in the hex toolbar
  hides the layer if you want to read the plain bytes.

The allocator selector defaults to *Auto-detect*. Choosing another allocator
discards everything derived from the previous one. See the
[web UI tour](web_ui_tour.md#heap-mode).

The REST routes behind the mode are `GET /api/heap/{detect,summary,chunks,chunk-at,free-lists,roles}`.
Each takes `dump_path`, `allocator`, `base_va` and the usual key material. Bad
input (unknown allocator, view or state) returns `400` and a missing dump
returns `404`.

### MCP

Six tools mirror the CLI actions: `heap_detect` (start here), `heap_summary`,
`heap_chunks`, `heap_chunk_at`, `heap_free_lists` and `heap_roles`. See the
[MCP reference](mcp_reference.md). A typical agent loop is to run
`heap_detect`, then `heap_summary`, then `heap_chunk_at` on each candidate
offset that `search_reduce` or `locate_key` returned.

### Library

```python
from memdiver import analyze_heap, HeapRole

layout = analyze_heap("capture.msl")            # allocator="auto"
print(layout.allocator.value, layout.confidence, layout.version_hint)
for line in layout.diagnostics:
    print("note:", line)

chunk = layout.chunk_at(0x55D0C0A012A0)
if chunk is not None:
    print(chunk.state.value, hex(chunk.va), chunk.size, chunk.bin)

# Coalesced (va, length, role) runs over a VA window.
for va, length, role in layout.role_runs(0x55D0C0A00000, 0x55D0C0A04000):
    if role is HeapRole.FREE_LINK:
        print(f"free-list pointer at {va:#x} (+{length})")

print(layout.role_counts(0x55D0C0A00000, 0x55D0C0A04000))
```

`analyze_heap(source, allocator="auto", *, base_va=None, max_chunks=200_000, regions=None)`
accepts a path or an already open `DumpSource`. `regions` restricts parsing to
mappings whose name matches one of the given fnmatch patterns (`[` is literal,
so `"[heap]"` works). The surface payloads are also available directly:
`memdiver.heap_summary_result(memdiver.ToolSession(), "capture.msl")`, and the
same pattern works for the other five producers. To rank allocators without
parsing, call `memdiver.detect_allocator(source)`.

Layouts are cached per dump file (path, mtime, size, region filter and every
option), and the cache holds 8 entries. Treat a returned layout as read-only.
Encrypted sources are never cached.

## Consensus integration

When `build_consensus(..., allocator="auto")` runs, every dump's heap is parsed
and its role runs are projected into consensus (slab) coordinates. The
projections are merged per byte:

- a byte takes role *R* when every dump that has a heap role there says *R*;
- when the dumps disagree, the byte is `mixed`;
- `agree` counts the dumps whose role matches the anchor dump (dump 0). It
  works as a per-byte measure of **layout stability**. A deterministic workload
  gives full agreement, and allocation jitter gives `mixed` and lower agreement.

The heap annotation never changes the consensus itself. A failure becomes a
report entry (`status`: `ok`, `no_va_coordinate`, `empty_consensus` or `error`).
A corpus of pure raw dumps with no memory map has no virtual addresses to
project through and reports `no_va_coordinate`. Pass `allocator="off"` to skip
the annotation entirely.

The pipeline's consensus stage writes the merged runs and the anchor's chunk
index to `heap_roles.npz` beside `variance.npy`, and adds a `"heap"` block to
`consensus.json`. The reduce stages read the file back.

The allocator is chosen with `--allocator` on the CLI (`consensus`,
`consensus-window`, `consensus-regions`, `analyze-candidates`, `locate-key`),
the `allocator` field on the matching web requests, and the `allocator`
parameter on the MCP tools (`consensus`, `aligned_window`, `consensus_regions`,
`analyze_candidates`, `locate_key`). Values: `auto` (default), `off`, or an
allocator name.

The candidate stages (`search-reduce`, `analyze-candidates`) take a **heap
policy**:

| Policy | Effect |
|---|---|
| `annotate` (default) | Every candidate region gets a `heap` block: `role_counts`, `chunk` (`slab_start`, `size`, `state`, `agree`, `offset_in_chunk`), `residual` and `agreement`. **The candidate set and every score are unchanged.** |
| `mask` | Additionally removes bytes whose consensus role is `chunk_header`, `free_link`, `allocator_meta` or `top` before the reduction. A region touching metadata gets a `-0.5` score adjustment, and one lying entirely in live user data gets `+0.1`. `mixed` is never masked, because disagreement is not evidence of metadata. Requires `heap_roles.npz`; without it the stage fails with a precondition error. |
| `off` | Ignores heap roles. The output is exactly what it was before 0.10.0. |

```bash
memdiver consensus snapshots/*.msl -o consensus.json --allocator auto
memdiver analyze-candidates snapshots/*.msl --heap-policy mask -o candidates.json
```

`--heap-policy` (CLI), `heap_policy` (web candidates request, MCP
`analyze_candidates` / `search_reduce`) select the policy. For
`search-reduce` over a saved `--state` session, see
[Allocator-aware search-reduce](#allocator-aware-search-reduce).

**`residual: true`** means the region starts in a freed chunk (`free`, `cached`
or `quarantined`). A high-entropy residual is often a real key that the program
freed without wiping, so it is evidence about the key's lifecycle, not live
state. Masking does not remove residuals. Only allocator-owned bytes are
masked.

### Allocator-aware search-reduce

`search-reduce` reduces the variance of an incremental (Welford) session
(`consensus-begin` / `consensus-add`). It takes `--allocator {auto,ptmalloc2,off}`
(default `auto`) next to `--heap-policy`. Only ptmalloc2 (glibc) heap roles feed
the reduction; another detected allocator reports `unsupported_allocator`.

Android Scudo dumps taken across cold boots use a different method, because
Scudo re-places every chunk each run and byte positions do not line up. That
path pairs heap chunks by allocator signature and content instead of reading
heap roles; see
[Android Scudo heaps across cold boots](../quickstart/cli.md#android-scudo-heaps-across-cold-boots).

The heap roles come from one of two sources:

- **session** (preferred): `consensus-begin --allocator auto|ptmalloc2` makes
  every `consensus-add` project that dump's heap onto the session slab and store
  it as `<state stem>.heap/<index>.npz`. `search-reduce` merges the stored
  projections the same way the batch consensus does, so `agree` counts the
  dumps (out of N) that give a byte the same role. Re-running `consensus-begin`
  on the same `--state` removes the old `NNNN.npz` projections (four or more
  digits).
- **reference** (fallback): a session without projections (begun before heap
  support or with `--allocator off`) falls back to the `--reference-dump`
  alone. Every `agree` is then 1, and the report names the reason
  (`fallback_reason`).

stderr names the source and then prints a single status line, for example
`memdiver: heap source=session (dumps_recorded=4, dumps_folded=4)` and
`memdiver: heap status=ok allocator=ptmalloc2 chunks=8 runs=17 residual=0/2`
(plus `heap_masked=N` under `--heap-policy mask`). If some recorded
projection files are missing, the merge runs over the rest; the report lists
them in `missing_projections` and stderr adds a warning.

| `--allocator` | `annotate` (default) | `mask` | `off` |
|---|---|---|---|
| `auto` / `ptmalloc2`, heap `ok` | regions get `heap` blocks; payload gains `heap`, `heap_status`, `thresholds.allocator` | metadata bytes removed (`stages.heap_masked`) | historical payload |
| `auto` / `ptmalloc2`, heap unavailable (raw dumps, other allocator, error) | stderr warning, regions unannotated, `heap.status` says why | precondition error naming the status, exit 2 | historical payload |
| `off` | historical payload (no `heap` key) | argument error, exit 2 | historical payload |

The payload's `heap` block holds the status, the merge report (`allocator`,
`coordinate`, `source`, `dumps_recorded`, `dumps_folded`, `chunk_count`,
`role_counts`, `min_agree`, `fallback_reason` when it applies) and `per_dump`
records. It never embeds the run or chunk arrays. `thresholds.allocator` is
the requested value (`auto` stays `auto`), and `heap.allocator` is the
resolved one.

```bash
memdiver consensus-begin --state s.json --size 4096 --allocator auto
for d in snapshots/*.msl; do memdiver consensus-add --state s.json "$d"; done
memdiver search-reduce --state s.json --reference-dump snapshots/run1.msl \
    --allocator auto -o candidates.json
memdiver search-reduce --state s.json --reference-dump snapshots/run1.msl \
    --heap-policy mask -o masked.json
```

### Located-key hits

`locate-key` annotates each hit with its chunk:
`{allocator, chunk_va, chunk_size, state, offset_in_chunk, role}`. The value is
`null` when the hit lies outside every chunk or has no virtual address. The
per-dump row carries a `heap` list parallel to `offsets`. Annotation is soft: a
parser failure never makes a searched dump unreadable. Pass `allocator="off"`
to disable it. See [Locating a known key](locate_key.md).

On every surface the option is `--allocator` / `allocator` (default `auto`).

## Real-dump opt-in tests

The unit tests run against hand-built synthetic heaps (`tests/fixtures/synth_heap.py`).
To check detection and parsing on your own captures, point
`MEMDIVER_REAL_HEAP_DUMPS` at a directory of dumps:

```bash
MEMDIVER_REAL_HEAP_DUMPS=~/captures/heaps pytest tests/test_heap_real_dumps.py -v
```

Every dump in the directory (`.msl`, ELF cores, `*.gdb_raw.bin` /
`*.lldb_raw.bin`, raw `.bin` / `.dump`) is opened. The tests assert that
detection returns candidates, that chunks never overlap and that coverage is
reported. To tighten the assertions, add a sidecar `<dump>.expect.json`:

```json
{"allocator": "ptmalloc2", "min_chunks": 100}
```

Without the variable, the tests are skipped.

## Troubleshooting

**Detected as `unknown` or `generic` on a dump you know is glibc / Android.**
Detection mostly relies on mapping and module names. `.msl` files store region
names only when the capture recorded them. Check with `memdiver heap detect
DUMP` and look at the evidence lines. If there are no module or region signals,
the dump has no names. Re-capture with names, or force the allocator with
`--allocator ptmalloc2`. A fridump import without a `.maps` sidecar has no names
either.

**A flat raw dump gives no chunks.** A raw `.bin` / `.dump` without a memory
map is read with `offset = va - base_va`, and `base_va` defaults to 0. Heap
pointers are absolute virtual addresses, so pass the address of the dump's
first byte:

```bash
memdiver heap summary heap.bin --base-va 0x55d0c0a00000 --allocator ptmalloc2
```

Without `--base-va` the pointers land nowhere and the parsers find nothing.

**arm64 Android pointers look like `0xb400007a…`.** Those are Top-Byte-Ignore
tags. The heap layer strips bits 56–63 on arm64 before following a pointer
(`memdiver.heap.strip_tag`), so you do not need to clean them. If
the target's architecture is not detected as arm64 (no MSL header, no ELF
machine, no `lib64` paths), tags are not stripped. In that case use an `.msl` or
core file, which records the architecture.

**`partial` or `heuristic` badge.** This is expected for scudo, jemalloc and
`generic`. Chunks the parser cannot see are not listed, and their bytes have
role `none`. Read the diagnostics before concluding that a region is unused.

**Fell back to another allocator.** `coverage.analysis.fell_back` is `true` and
a diagnostic such as `fell back from ptmalloc2 to generic` explains why. This
usually means the heap region was not captured, or its first header is
corrupt.

See also: [heap architecture](../architecture/heap.md) and
[adding an allocator](../contributing/adding_allocator.md).
