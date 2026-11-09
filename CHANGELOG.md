# Changelog

All notable changes to MemDiver are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `search-reduce --allocator {auto,ptmalloc2,off}` (default `auto`): the CLI reduction
  is heap-aware. Candidate regions get `heap` annotations, `--heap-policy mask` works on
  a `--state` session, and the payload gains a compact `heap` block (status, source,
  report, per-dump records), `heap_status` and `thresholds.allocator`. `--allocator off`
  keeps the historical payload; `off` with `mask` is an argument error.
- `consensus-begin --allocator {auto,ptmalloc2,off}`: every `consensus-add` stores a
  per-dump heap projection beside the state (`<stem>.heap/NNNN.npz`); re-beginning a
  session removes stale projections.
- Session-merged heap roles: `search-reduce` merges the stored projections (role
  agreement over N dumps) and falls back to the reference dump alone for sessions
  without them, naming the source on stderr.
- ptmalloc2 thread arenas: non-main arenas are found through the `main_arena.next` ring
  or, without `main_arena`, a `heap_info` scan of `HEAP_MAX_SIZE`-aligned anonymous
  maps. Their heaps are walked as `thread_heap` regions of arenas 1..n with their
  tcache (and, for ring discovery, their bins) decoded; coverage gains `thread_arenas`
  and `arena_discovery`.
- ptmalloc2 mmapped chunks: a page-granular scan of captured, writable, anonymous,
  non-heap / non-stack regions finds `{prev_size, size|IS_MMAPPED}` headers. Each hit is
  an in-use chunk (bin `mmapped`, region kind `mmapped_chunk`) in a pseudo arena of kind
  `mmap`; an explicit `--regions` limits the scan; coverage gains `mmapped_chunks`.
- Arena / segment parser interface: `HeapArena` and `HeapLayout.arenas`, `arena_id` on
  chunks, regions and free lists, the shared `ARENA_*` / `REGION_*` kinds, and
  `heap/segments.py` (`HeapSegment`, `ChunkBudget`, `LayoutAssembler`) with standard
  coverage keys. `AllocatorDescriptor.reduce_ready` / `reduce_ready_kinds()` gate which
  allocators `search-reduce` accepts (parity with the CLI choices is test-guarded). See
  `docs/contributing/adding_allocator.md`.
- `search-reduce` reduces Android Scudo heap dumps across cold boots: `consensus-begin --allocator scudo|auto` without `--size` collects the runs and `search-reduce --state` pairs their heap chunks by allocator signature and content. The chain ends at `brute-force`: Volatility 3 plugin generation is not supported yet with this method.
- The web pipeline offers the same method (`POST /api/pipeline/run` with `scudo: {allocator}`, an "Android Scudo" recipe and method choice in the wizard, a per-verdict results table). It runs up to brute-force: Volatility 3 plugin generation, the N-sweep, escalation and refine need the positional consensus and are refused with a stated reason.

### Changed
- The `heap_policy='mask'` precondition error names the unavailable status and its
  cause (`no_va_coordinate`, `unsupported_allocator`, ...).

## [1.0.7] — 2026-11-04

### Fixed
- DuckDB 2.0: `case query` again accepts trailing `;`s and leading or trailing comments.
  2.0 reports comments as tokens and drops leading ones from the parsed statement, which
  made the single-SELECT guard refuse valid queries. Rewritten statements (`PRAGMA`) are
  still refused.
- DuckDB 2.0: ibis array `.map()` / `.filter()` on `Case.table()` no longer fail with
  "Deprecated lambda arrow"; the notebook connection re-enables the arrow syntax ibis
  compiles to.
- `case query` works on DuckDB 1.3 / 1.4 again: results are fetched with
  `to_arrow_table()` where it exists (1.5+) and `fetch_arrow_table()` before; the
  declared floor had never been exercised.
- mypy 2.4: Optional narrowing in `tools_heap`, `tools_isf` and `tools_keyfinders`.

### Changed
- `duckdb>=1.3.1,<3` (ibis excludes 1.3.0; a new major is tested before it is allowed).
- CI pins ruff 0.17.3 / mypy 2.4.0 (dev extra `mypy>=2.4,<3`) and adds a
  `test-duckdb-min` job running the DuckDB-backed tests on the 1.3.1 floor.
- `app/tools_isf.py` and `app/tools_keyfinders.py` join the mypy typed island.

## [1.0.6] — 2026-10-27

### Added
- Full memory images (semantic workbench P1/P2): `.mdview` physical / kernel / process
  views over LiME/ELF/raw images through Volatility 3 (LA57 5-level paging supported),
  profile chain with optional pakunoda ISF extraction, process extraction to `.msl`,
  analysis record, case data lake (`case query`, `context-at`).
- Volatility 3 inside MemDiver: `memdiver vol3 list|describe|run|query|annotate|scaffold|
  check|import|write-config|source|fixture` on CLI, REST and MCP; plugin rows become case
  tables with address coordinate systems, annotations and hex highlights; saved queries
  (hidden processes, sockets, rwx mappings, …); web Image and Vol3 panels, plugin editor.
- `vol3 write-config` writes a `vol -c` config reproducing MemDiver's stack, so stock `vol`
  runs on LA57 images where its own automagic finds nothing.
- Hex view: bytes without captured content print `--` (both `.msl` and image views); the
  gutter shows absolute virtual addresses in the `va` view; image views work in
  side-by-side and overlay panes.

### Changed
- MCP: every tool is encoded and its errors presented at registration; errors from the
  newer tools are `{error, code, category}` like path-guard denials (the original inspect
  tools keep the flat `{error}` body). See the MCP reference.
- REST and MCP share one bare-case-name rule and one write-target containment check;
  case names containing a backslash are rejected on POSIX (`case.invalid`), as are blank ones.
- Analysis-record bulk imports (vol3/key-finder annotations, ISF layout claims) are written
  in one batch and are all-or-nothing; imports of 10k rows drop from minutes to well under a second.
- Keylog anchoring and semantic validation check all candidate secrets in one pass per dump;
  parsed ISF import blobs are cached (bounded by size).
- YARA errors use `yara.*` codes and wording instead of `keyfinders.*`.

### Fixed
- `--pid` narrowing of emitted plugins proven end-to-end on a real kernel image
  (`tests/test_vol3_pid_real_image.py`).
- Case data lake: directories under `<case>/tables/` whose names are not valid table
  names are ignored instead of being spliced into `CREATE VIEW` SQL.
- `strings_iocs` saved query uses DuckDB's `lambda x:` syntax (DuckDB 2.0 rejects the
  `x ->` arrow form); `duckdb>=1.3.0` is now required.
- Key finders, strings and YARA: the scan windows tile each run exactly, so hits near a
  run's end are no longer reported twice and `bytes_scanned` matches the captured bytes.
- Needle searches (anchor consensus, keylog anchoring, semantic validation) work on
  `.mdview` image views instead of failing with a `TypeError`.
- Heap analysis on an image view reads the view, not the raw image file; physical views
  are refused (`heap.physical_view_unsupported`).
- `case query` accepts SQL ending in a `--` or `/* */` comment.
- Web UI: an empty server response to a scan request shows a readable error.

## [1.0.1] — 2026-10-24

### Fixed
- VAS Map: the last map in file order wins (spec 1.1 §5.8), including maps in verified
  extension and sealed segments (`MslReader.effective_vas_map`); maps are no longer merged.
  Applies to classification, `inspect vas`/session, heap names; materialize keeps it effective.

## [1.0.0] — 2026-10-24

### Added
- MSL 1.1: EoC carries the exact block count (48-byte payload); `verify_chain` checks
  FileHash, header/EoC counts and extension segments; files read with version `0x0101`.
- Extension segments (`END_OF_EXTENSION` 0x0FFE): the pointer graph is now a chained,
  verified segment; `add_extension_segment`, `iter_extension_blocks`,
  `collect_end_of_extension`; materialize re-emits verified segments.
- VAS Map entries carry `name_source`; the trust rule prefers it over the
  provenance marker. Thread Context (0x0011) decoded per spec 1.1 Section 5.7.
- `PageState.NOT_RESIDENT` (value 3) shown as such in inspect output.
- Thread Context (0x0011) written: `MslWriter.add_thread_context` (sets CapBitmap
  bit 2); ELF-core (x86_64/aarch64) and minidump (AMD64/ARM64) imports emit one
  block per thread before the first Memory Region (`msl/import_threads.py`).
- Materialize folds every verified sealed extension segment (spec 10.8) into an
  ordinary segment of the copy (after the in-stream ones; blocks, Producer and
  WrittenAt kept; re-chained in plaintext copies, inside the new ciphertext in
  re-encrypted ones); provenance note gains `sealed_segments_folded=N`.
  `add_extension_segment(..., written_at_ns=)` sets a segment's WrittenAt.

### Changed
- `add_raw_appendix` raises; use `add_extension_segment`.
- Docs: `docs/file_formats/msl_v1_1_0.md` mirrors spec 1.1.

## [0.10.0] — 2026-10-23

### Added
- **Heap allocator awareness.** A new `heap/` layer detects the allocator
  behind a dump and parses its structures into chunks, free lists, regions and
  a role for every heap byte (`chunk_header`, `user_data`, `free_link`,
  `free_data`, `allocator_meta`, `top`, `slack`). Built-in parsers:
  - glibc **ptmalloc2** (L0–L3): tcache with and without safe-linking,
    `main_arena` discovery, then fastbins and the unsorted, small and large bins;
  - **dlmalloc** (L0–L2);
  - **scudo** (L0–L2, partial; headers are judged on structure because the
    checksum cookie is per-process);
  - musl **mallocng** (L0–L2);
  - **jemalloc** (partial: region attribution plus slot-stride inference);
  - a **generic** boundary-tag heuristic.

  Works on `.msl`, ELF cores, regioned raw dumps and flat raw dumps (with a
  base VA), strips arm64 TBI pointer tags, and never raises on a parse failure:
  it falls back to the next candidate and records why. Library:
  `memdiver.analyze_heap`, `detect_allocator`, `HeapLayout`, `HeapRole`,
  `register_allocator`.
- **`heap.*` on every surface.** The six capabilities `heap.detect`,
  `summary`, `chunks`, `chunk_at`, `free_lists` and `roles` are available as:
  - CLI `memdiver heap {detect,summary,chunks,at,free-lists,roles}`, with
    `--allocator`, `--base-va` and `--json`;
  - REST `GET /api/heap/{detect,summary,chunks,chunk-at,free-lists,roles}`;
  - MCP tools `heap_detect`, `heap_summary`, `heap_chunks`, `heap_chunk_at`,
    `heap_free_lists` and `heap_roles` (56 tools in total);
  - `memdiver.heap_*_result` producers.
- **Allocator plugins.** The `memdiver.allocators` entry-point group lets an
  installed package replace a built-in allocator parser. See
  `docs/contributing/adding_allocator.md`.
- **Heap roles in consensus.** `build_consensus(..., allocator="auto")`
  projects every dump's heap roles onto the consensus slab and merges them.
  Bytes where the dumps disagree become `mixed`, and a per-byte agreement count
  measures layout stability. Raw-only corpora report `no_va_coordinate`. The
  consensus itself is never changed. The pipeline writes `heap_roles.npz` and a
  `"heap"` block in `consensus.json`.
  Choose it with `--allocator` (CLI) / `allocator` (web, MCP).
- **`heap_policy` for candidate reduction** (`annotate` by default, `mask`,
  `off`):
  - `annotate` adds `role_counts`, the owning chunk, `residual` (the region
    starts in a freed chunk) and `agreement` to each region without changing
    candidates or scores;
  - `mask` drops allocator-owned bytes (headers, free links, metadata, top) and
    adjusts scores;
  - `off` reproduces the previous output byte for byte.
  Set with `--heap-policy` on `analyze-candidates` / `search-reduce` and
  `heap_policy` on the web candidates request and MCP tools.
- **`locate-key` hits name their chunk:**
  `heap: {allocator, chunk_va, chunk_size, state, offset_in_chunk, role}` per
  offset, so a key left in a freed chunk is visible as residual.
- **Heap mode in the web UI.** A third app mode next to verification and
  exploration. It has an allocator overview (confidence, evidence,
  partial/heuristic badges, regions), a chunk table with jump-to-chunk, a size
  histogram, a free-list tree, a chunk inspector, and a hex heap layer that
  colors bytes by role and ticks chunk starts, with a legend and a toolbar
  toggle. The layer is drawn in all three themes.
- **Docs:** `docs/user_guide/heap.md`, `docs/architecture/heap.md`,
  `docs/contributing/adding_allocator.md`, plus a heap mode section in the web
  UI tour. `MEMDIVER_REAL_HEAP_DUMPS` (with optional `<dump>.expect.json`
  sidecars) enables opt-in tests against real captures.
- **`capture`: one dump of a running process, locally, on a USB/Android
  device, or on a remote server.** CLI `memdiver capture <pid|name> <out>
  --tool --device local|usb|usb:<id>|remote:<host>[:<port>]`, REST
  `POST /api/experiment/capture`, MCP `capture_dump`, a web-UI form in the
  Experiment panel and `memdiver.capture_result()`. All of them use the same
  producer, which returns a capture report listing every region that was not
  captured (base, size, reason). The memslicer backend now calls
  `memslicer acquire … -o` with `-U` / `-D` / `-R`; the old `memslicer capture`
  call was not a valid memslicer command.
- **lldb captures large regions.** Readable regions are streamed in 8 MiB
  chunks instead of being dropped silently at 100 MB, and unreadable pages are
  isolated page by page. Non-writable regions of 100 MiB or more (the macOS
  shared cache) are skipped by default but reported (use
  `--include-large-readonly` to capture them). Skips, read failures and
  timeouts go into the report and into a `<dump>.capture.json` manifest,
  which `import` and the import preview turn into warnings.
- **fridump `.maps` sidecars carry real names and permissions** where they
  can be found: the target's `/proc/<pid>/maps`, read locally or through a
  short Frida session, else Frida's `enumerateRanges`. A sidecar without
  names is marked in the manifest, and the import preview warns about it.
- **`classification_basis_mixed` alignment warning on every consensus
  surface.** A region-filtered alignment that mixes dumps classified by
  mapping names (new imports / live captures with a named VAS map) with
  dumps classified by stored region type only can mis-pair `anon:` regions.
  This used to be only logged; it is now a structured diagnostic
  (`{code, message, severity, details}`, the `core.service_result.Diagnostic`
  shape) on `AlignmentReport.diagnostics` / `AlignmentCoverage.diagnostics` /
  `MslIncrementalBuilder.diagnostics`, in `alignment.diagnostics` of every
  aligned payload, hoisted as `diagnostics` on `POST /api/analysis/consensus`,
  the CLI `consensus` JSON (plus a stderr warning and hint on `consensus`,
  `consensus-window`, `consensus-regions`), the MCP `consensus` /
  `aligned_window` / `consensus_regions` / `analyze_candidates` outputs, and a
  localized web-UI banner suggesting the older dumps be re-imported.
- **Android-aware region classification by mapping name.** When a region's
  full mapping name is known (`/proc/<pid>/maps` path column, ELF `NT_FILE`
  path, or a trusted `.msl` VAS map entry), `msl/region_names.py` refines its
  category: Android native heaps (`[anon:scudo:*]`, `jemalloc`, `GWP-ASan`,
  ART heap spaces such as `[anon:dalvik-main space]`) → `heap`, bionic thread
  stacks (`[anon:stack_and_tls:*]`) → `stack`. A heap name on a shared mapping
  stays `shared`. The stored region type is unchanged, so alignment keys do
  not change. The rules and their deliberate exclusions (`[anon:.bss]`,
  binder, `/dev/shm`, app files) are specified in
  `docs/file_formats/msl_v1_0_0.md`; `tests/fixtures/region_name_vectors.json`
  holds the normative test vectors, shared byte-identical with memslicer.
- **New `runtime` region category, excluded by default.** It holds regions
  classified by name as runtime / system memory rather than app data: zygote
  and boot-image ART spaces, ART GC metadata, JIT caches, `linker_alloc`,
  `cfi shadow`, property areas, boot `.art/.oat/.vdex/.odex` and ICU data, and
  kernel / device mappings. It is accepted by `--regions` /
  `--exclude-regions`, MCP `region_types` / `region_filter` and REST
  `regions`, but it is not in the interactive default (`heap`, `stack`,
  `unclassified`) and is prompt number `8`. A selection naming the seven older
  categories means "all but `runtime`".
- **Import preview fields** `platform` (`android` / `linux` / `windows` / …),
  `platform_source` (`mapping_names` / `header` / `format`), `runtime_count`,
  `runtime_bytes` and `regions[].name`, plus a note on what the default
  selection drops. `--list-regions` prints a `platform:` line and a `runtime`
  row.
- **Mapping names persisted in the `.msl` VAS map.** ELF-core and
  regioned-raw imports now always write a `VAS_MAP` (0x1001) with every
  region's full mapping name as `mapped_path` and mark it with a
  `region_names=1` provenance note segment (`ProvenanceNoteFields.region_names`).
  Materialize copies the names and the marker. Readers trust the names only
  with that marker, or for a live memslicer capture (no provenance, `IMPORTED`
  clear) that has a VAS map, so older files classify exactly as before.
  ELF-core and regioned-raw imports whose names look Android write
  `os_type = ANDROID` in the header (previously always `LINUX`).
- **Alignment classification-basis warning.** A filtered alignment that mixes
  dumps classified by mapping names with dumps classified by stored type only
  logs a warning, since the same filter can keep a region in one dump and drop
  it in another. Live memslicer captures with name-based stored types are
  folded back to the legacy alignment key class, so old and new captures keep
  identical keys.

### Changed
- **`[vdso]`, `[vvar]` and device mappings now classify as `runtime` on new
  Linux imports too.** The kernel / device name rules are not Android-specific:
  ELF cores and maps-sidecar raw dumps imported from now on (and live
  memslicer captures with a VAS map) put `[vdso]`, `[vvar]`, `[vsyscall]`,
  `/dev/*` (except binder, `/dev/shm`, `/dev/zero`), `/dmabuf*` and
  `anon_inode:*` mappings into `runtime`, which the default selection
  excludes. Pass `--regions …,runtime` or `all` to keep them.
- **Version 0.10.0.** Heap allocator awareness is the headline feature. The
  `heap` CLI group brings the subcommand count to 35, and the heap router
  brings the router count to 19. The docs landing page and architecture
  overview now show these counts.

### Fixed
- **MCP tool count in the docs.** The docs landing page still said 48 MCP
  tools. It now says 56, matching `mcp_server/server.py` (which includes the
  six new `heap_*` tools).

## [0.9.5] — 2026-10-21

### Changed
- **MCP server migrated to the mcp 2.x SDK.** mcp 2.x removed
  `mcp.server.fastmcp`; the server is now built on
  `mcp.server.mcpserver.MCPServer` (FastMCP's successor) and reports the
  package version. The dependency is now `mcp>=2.2,<3`.
- **Frontend dependencies bumped:** i18next 26, react-i18next 17, jsdom 30,
  @types/node 26. jsdom 30 requires a newer Node, so the frontend `engines`
  range is now `^22.22.2 || ^24.15.0 || >=26` and every CI / publish /
  docs-screenshots workflow runs on Node 22. Two jsdom-30 test adjustments:
  computed `background` shorthands using `var()` are no longer resolved, so
  the affected tests assert on `background-color` / inline style instead.
- **Docs toolchain bumped** to Sphinx 8.2.3, myst-parser 5.1.0 and
  sphinx-design 0.7.0 (`docs/requirements.txt` and the `docs` extra).
- **`marimo` floor raised to `>=0.23.9`** (plus `pymdown-extensions>=11.0.1`)
  to clear pip-audit advisories. The old open floor let pip backtrack to
  marimo 0.15.1, which failed to import against the websockets version pinned
  by frida-tools.
- The pytest `test` CI job runs in parallel (`pytest-xdist`, `-n auto`).
- **Frontend is eslint-clean (0 errors).** All 22 `react-hooks/set-state-in-effect`
  findings were refactored to render-time state adjustment or to the new shared
  `useFetchJson` / `useFetchText` hooks (no `eslint-disable`); theme context and
  file-browser helpers moved out of component modules for fast refresh;
  `exhaustive-deps` warnings fixed via pure store helpers. The entropy tab no
  longer gets stuck on "loading" when left mid-fetch. The entropy / VAS
  fetch-failure notifications are now localized (`layout.entropyFetchFailed`,
  `layout.vasFetchFailed`) instead of hardcoded, as are the hex / consensus
  store fetch errors (`hex:fetchErrors.*`). A PipelinePanel test whose cold
  dynamic import straddled vitest's 5s default timeout no longer flakes.
- The REST API's OpenAPI `version` now reports the package version instead of
  a hard-coded `0.1.0`.

### Fixed
- **`memdiver mcp --sse --port N` crashed with a `TypeError`**: the port was
  passed to `run()`, which the 1.x SDK did not accept. With the 2.x SDK, host
  (`127.0.0.1`) and port are passed to `run()` explicitly.
- **A broken marimo install was reported as "Marimo not installed".** The
  `/notebook` mount now distinguishes a missing package from one that fails to
  import and logs the real error.
- **CI test fixtures were never committed**: the `*.json` ignore rule swallowed
  `tests/e2e/fixtures/pcap/manifest.json`, `keylog/expected.json`,
  `verify_key/verify-fixture.json` and `tests/fixtures/tshark/secrets.json`;
  they are now un-ignored.
- **The route-protection test failed on FastAPI ≥ 0.141**, whose included
  routers are no longer flattened into `app.routes`. The test walks routes via
  `fastapi.routing.iter_route_contexts` when available (falling back to the
  flat list) and asserts a minimum route count.
- The favicon test is skipped when no frontend build is present, and the
  e2e landing-page check targets the "Sessions" heading by role instead of an
  ambiguous text match.
- **`memdiver locate-key` treated a missing dump path as "searched and
  absent".** A path that did not exist was dropped with a log record and the
  remaining dumps were searched, so the command could answer `absent` (exit 3)
  over a dump nobody read. A missing path is now `INVALID_INPUT`:
  `memdiver: ERROR — Dump path(s) not found: …`, exit 2, no payload. Files
  directly inside a passed directory that match no dump pattern now get one
  `memdiver: note — skipped N file(s) in DIR with unrecognised extensions …`
  line on stderr (dotfiles and the sidecar suffixes in
  `cli/_shared.py:_NON_DUMP_SUFFIXES` excluded), and `locate-key --help` prints
  the exit-code table. Every other command that resolves dump paths
  (`consensus`, `scan-yara`, `export`, …) still skips a missing path, but now
  says so on stderr (`memdiver: WARNING — skipping non-existent path: X`)
  instead of in a log record, and prints the same unrecognised-files note.
- **`POST /api/analysis/locate-key` could not take a `pcap_field`.** The CLI
  (`--pcap-field`) and the MCP tool accepted the symbolic
  `{pcap_path, field_id, client_random?}` form; the HTTP route did not. It now
  forwards `pcap_field` to the producer, which validates it (an unknown key is a
  400) and existence-checks the capture.
- **`DELETE /api/oracles/orphans` answered 500 when no oracle directory was
  configured.** `OracleDisabled` escaped unhandled; it now maps to the same
  **503** every other writing oracle endpoint returns.
- **CORS refused `PUT`, which `PUT /api/settings/last-dir` needs.**
  `allow_methods` is now `GET`/`POST`/`PUT`/`DELETE`/`OPTIONS`; `PATCH` is still
  refused (no route uses it).
- **`MEMDIVER_PORT` never changed the port `memdiver web` bound.** `--port`
  defaulted to a literal `8080`, so the setting was only echoed in the startup
  log. Precedence is now `--port` > `MEMDIVER_PORT` / `.env` > `8080`, and the
  startup log reports the port actually bound.
- **The new-session dialog silently overwrote a saved session of the same
  name.** It now fetches the saved-session list when it opens and warns
  "A session named … already exists and will be overwritten." (The warning
  does not block saving.)
- **`locate-key` was missing from the README and the published CLI reference
  (#27).** `sphinx-argparse` and `autodoc` import the `memdiver` package, which
  the docs workflow never installed, so the CLI reference could not regenerate.
  `.github/workflows/docs.yml` now runs `pip install -e .`, `docs/dev/` and
  `docs/issue-drafts/` are excluded from the published site, and the README
  lists `locate-key`. New pages: a locate-key guide
  (`docs/user_guide/locate_key.md`) and a configuration page
  (`docs/user_guide/configuration.md`) listing every `MEMDIVER_*` variable.
- **The web server could not be shut down, so `kill -9` was the only way out —
  and that leaked semaphores and orphaned processes permanently.** Killing
  `memdiver` printed `resource_tracker: There appear to be 5 leaked semaphore
  objects`. The five are the fingerprint of exactly one un-finalized
  `ProcessPoolExecutor` (`_call_queue` contributes `_rlock`/`_wlock`/`_sem`,
  `_result_queue` two more) — the app-lifetime pool in `TaskManager`. They
  leaked because SIGKILL skips every `atexit` handler, and SIGKILL was only ever
  needed because a graceful shutdown could not finish. Four independent reasons,
  all now fixed:
  - `_gated_submit` awaited the pool future via
    `loop.run_in_executor(None, future.result)`, parking a thread of asyncio's
    **default** executor for a task's whole duration, and the progress drain
    parked a second one permanently in an unbounded `q.get()`. uvicorn serves
    under `asyncio.Runner`, whose `close()` calls
    `loop.shutdown_default_executor()` — and on Python 3.11 that joins its
    threads with **no timeout** (the `timeout` parameter only arrived in 3.12).
    One live task was enough to hang Ctrl-C forever. Now `asyncio.wrap_future`
    bridges the future with no thread at all, and the drain read is bounded by
    `DRAIN_POLL_S`.
  - `shutdown()` called `pool.shutdown(wait=False)`, which does not stop a
    worker that is already running — and `concurrent.futures.process._python_exit`
    joins it at interpreter exit with no timeout of its own, merely relocating
    the hang. Teardown is now ordered and bounded at every step: cancel events
    first (they are Manager proxies, so they must be set while the Manager still
    lives), then the drain, then the pool with its workers force-reaped, then the
    Manager in a `finally`. A new `aclose()` is the async twin the FastAPI
    lifespan uses; `shutdown()` stays synchronous for `reset_task_manager` and
    the test fixtures.
  - `ProgressBus.close_task` set `channel.closed = True` but pushed nothing, and
    `subscribe` only re-checks that flag *before* `await q.get()` — so a
    subscriber already parked there never woke: its iterator leaked for the life
    of the process, and the WebSocket handler, still suspended inside the
    `async for`, never called `receive()` and so never saw the disconnect.
    `close_task` now posts a `None` sentinel, so a task reaching a terminal
    event releases its subscribers, and `close_all()` does the same for every
    channel. Known follow-up: this does **not** by itself unblock a WebSocket
    parked at shutdown. `close_all()` runs from `TaskManager.aclose()`, i.e.
    from the lifespan shutdown, and uvicorn's `Server.shutdown()` drains open
    connections *before* it runs that — so the sentinel necessarily arrives
    after the moment it would have to act. What bounds that wait today is
    `timeout_graceful_shutdown` (see below); the real fix is for the WebSocket
    handler (`api/ws/progress.py`) to await `websocket.receive()` concurrently
    with the subscribe loop so it notices the close frame itself.
  - `memdiver web` ran uvicorn with no `timeout_graceful_shutdown` (it defaults
    to waiting forever) and no `finally`. It now bounds that window — from the
    new `Settings.web_graceful_timeout_s` (10s, `MEMDIVER_WEB_GRACEFUL_TIMEOUT_S`),
    so every launch path and deployment sees the same knob — and tears the task
    manager down on the force-exit path, where uvicorn skips
    `lifespan.shutdown()` entirely.
- **A hard kill orphaned the `multiprocessing.Manager` process forever.**
  CPython's `BaseManager` does not start its server as a daemon and
  `Server.serve_forever()` has no parent-death check, so every `kill -9` left a
  Manager running with its unix socket and `pymp-*` temp dir — 8 such orphans (up
  to 18 days old) and 147 stale directories had accumulated. New
  `core/process_guard.py` arms a parent-death watchdog inside the Manager server
  and every pool worker via the documented `start(initializer=...)` /
  `ProcessPoolExecutor(initializer=...)` hooks: a daemon thread notices the
  process has been reparented and exits, running multiprocessing's finalizers
  first so the temp dir goes with it. Nothing based on `atexit` can cover
  SIGKILL; the child has to notice on its own.
- **The oracle smoke test could never go green, so it proved nothing.** The web
  UI built its 16 samples client-side as a hard-coded arithmetic ramp
  (`bytes[j] = (i * 31 + j) & 0xff`) and posted them to `/dry-run`. They were
  never key material and never touched a dump, so a correct oracle scored
  0 pass / 16 fail — and so did an oracle whose `verify()` was wired to
  `return False`. The bar could not distinguish the two, which is the one
  thing a smoke test exists to do. It also looked identical armed and unarmed,
  because the input and the code path were byte-identical (`dry_run` ignores
  `armed` by design, so a user can triage before committing to arming).
  - New `POST /api/oracles/{id}/smoke-test` composes the samples **server-side**:
    one positive control — the master key the run's `meta.json` records, found
    via the same `RunDiscovery.meta_for_dump` the config autofill already uses —
    plus N candidates read at random offsets from the dump itself.
  - The result is a **verdict**, not a pass count: `discriminates`,
    `accepts_noise` (the oracle accepts arbitrary memory — a non-detector that
    would flood a real sweep), `never_accepts`, `no_positive_control` (no ground
    truth was available; reported as its own state, never as a failure — the
    `positive.ok` field is tri-state and stays `null`) and `inconclusive`
    (the key was accepted but nothing was rejected, so only half the claim
    holds).
  - Negatives are read in the **`vas` view**. Raw offsets into an `.msl` address
    the container — file and block headers, the hash chain — not process memory,
    and `va` pads unmapped pages with synthesized `0x00`; either would have fed
    the oracle bytes the dump never captured.
  - A drawn sample equal to the positive control is resampled. The real key
    genuinely occurs in these dumps, so an unguarded draw yields a bogus
    "accepts noise" verdict.
  - The response **never contains sample bytes**: the positive control *is* the
    run's master key.
  - `dry_run` keeps its exact contract; the grading and loading halves were
    extracted into shared helpers rather than duplicated.
- **Per-sample oracle errors were computed and then thrown away.** The backend
  already returned `{"index": i, "ok": false, "error": repr(exc)}`, but the UI
  used `error` only as a boolean to pick a grey dot colour. The message now has
  a rendering site.
- **The Oracle stage's Next button was invisible**, sitting below the entire
  pcap block, and the stepper deliberately disables forward jumps — so the way
  forward could not be found at all. The advance controls are now pinned, the
  pcap alternative is collapsed by default, and a disabled Next says why.
- **The oracle registry was memory-only.** `config` and `armed` lived solely in
  `_entries`, so a restart dropped every config, orphaned the `.py` files and
  made the pipeline's stored `oracleId` 404 mid-run — with the wizard's Next
  button silently going dead because its entry had vanished. Entries now
  persist to a `<uuid>.json` sidecar (`0o600`, written via `atomic_write_text`,
  which gained a `mode=` kwarg applied to the tmp file *before* the replace) and
  rehydrate at startup.
  - The `.py` is **re-hashed on rehydrate** and a mismatch is refused: the
    stored sha exists to give `arm()`'s display-vs-disk check something
    truthful to compare against.
  - `shape` is read from the sidecar, never re-derived — `_detect_shape`
    imports the user module, which would execute every stored oracle at boot.
  - `armed` always rehydrates as `False`. Arming is an authorization act bound
    to a sha the user saw and to a strict sandbox replay of a filesystem state
    that may have changed while the server was down; restoring the entry is
    what fixes the 404, and re-arming costs one click. `previously_armed`
    reports the earlier consent so the UI can say so.
  - Orphaned files are logged, never auto-deleted; `GET /api/oracles/status`
    lists them and `DELETE /api/oracles/orphans` removes them on request.

### Security
- **The upload directory is no longer a hardcoded, world-writable `/tmp` path.**
  `api/config.py` defaulted `upload_dir` to `/tmp/memdiver_uploads` and
  `api/main.py`'s lifespan `mkdir`'d it on every `create_app()`, so a
  predictable, `drwxrwxrwt`-parented directory was created eagerly — holding
  uploaded packet captures and memory dumps, and doubling as the containment
  root every server-side write path is checked against (`ensure_within`). It
  was the repository's only MEDIUM bandit finding (B108).
  `upload_dir` is now **configure-on-first-use**: unset by default, and the
  first upload asks the user where to store data rather than silently picking
  another location for them.
  - Unconfigured **fails closed**. There is no permissive fallback, because a
    fallback would widen the write-containment checks instead of failing them.
    `api/dependencies.upload_dir_or_409()` is the single guarded entry point and
    returns HTTP **409** with a token-prefixed detail
    (`upload_dir_unconfigured: …`) — 409 because the request is well-formed and
    nothing is broken; the user simply has to choose. `None`, not `Path("")`, is
    the unset sentinel: `Path("") / "pcaps"` is the *relative* path `pcaps`, so
    an unguarded consumer would have written into the server's CWD, whereas
    `None / "pcaps"` raises loudly.
  - The chosen directory is **validated**, not just accepted: absolute only, and
    rejected if it is or sits inside a system location, `sys.prefix` (a write
    into `site-packages` is a `.pth` import-hijack primitive), **or any
    temporary directory** (`tempfile.gettempdir()`, `/tmp`, `/var/tmp`) — the
    last rule being the whole point, since swapping one world-writable temp
    default for a user-chosen temp path would be theatre. Bare `$HOME` is
    refused in favour of a subdirectory. Writability is *proven* with a real
    temp-file write rather than inferred from `os.access(W_OK)`, which lies
    under POSIX ACLs, read-only mounts and macOS SIP. The directory is created
    and pinned `0o700`.
  - The one-time migration out of the legacy `/tmp` directory is hardened
    against a world-writable source: it refuses if that directory is a symlink
    or is not owned by the current user, **skips any entry that is itself a
    symlink** (otherwise "migrate" would relocate an attacker's link into the
    user's new private directory), skips name collisions instead of clobbering,
    and removes the old directory only once it is genuinely empty.
  - The choice is persisted in the **user-local, git-untracked**
    `~/.memdiver/config.json` — never the repo-root tracked `config.json` that
    `dataset_root` merges from, since writing a tracked file would dirty every
    clone. The write is read-modify-write and atomic (`.json.tmp` chmod 0o600,
    then `replace`), so a crash cannot truncate the file and lose the setup
    wizard's `skip_duckdb_setup` flag that shares it.
  - `MEMDIVER_UPLOAD_DIR` (and `.env`) still always wins. When it is set, the
    settings endpoint reports `env_pinned` and **refuses** to persist a value
    from the UI: writing a file that would then be silently shadowed forever is
    worse than refusing.

### Fixed
- **A vol3 export disagreed with the YARA rule it embeds.**
  `app/export_service.py::_render_content` passed `key_offset`/`key_length` to
  `YaraExporter` but not to `Volatility3Exporter`, which takes no such parameters
  and reads them off the pattern dict -- defaulting to `0` and to the *full*
  pattern length. So a padded-window export emitted a plugin whose embedded rule
  said `key_offset = 256` while its own constants said `KEY_OFFSET = 0` /
  `KEY_LENGTH = 560`. Run under real Volatility3 it reported the **entire window**
  as the key: `KeyOffset == PatternOffset`, `KeyHex` the whole padded window, and
  `KeyEntropy` diluted by the padding (2.04 instead of 5.42) -- looking successful
  while finding something useless. Affected every `--format volatility3` export
  through `auto_export_pattern` / `manual_export_pattern` / `located_export_pattern`;
  `engine/vol3_emit.py` was never affected because it enriches the dict itself.
  Found by actually running the emitted plugin against the reference corpus.
  Fixed by enriching a **copy** of the pattern (the original is returned in the
  producer payload and must not be mutated), and pinned by
  `test_vol3_plugin_constants_agree_with_its_embedded_yara_rule`, which asserts the
  constants and the embedded rule's meta agree.

- **The emitted Volatility3 plugin: three real bugs, and its `_version` goes
  `(1, 1, 0)` → `(2, 0, 0)`.** All three were found by running the emitted
  artifact instead of `ast.parse`-ing it (`engine/vol3_verify.py` in-process,
  `engine/vol3_subproc.py` through a real `vol`). Everyone who re-emits a plugin
  gets different bytes, hence the major bump and the regenerated review artifact
  `tests/fixtures/vol3_plugin_pin/default_pad_plugin.py.golden`. The YARA golden
  beside it is **unchanged** — none of this touches the pattern, only the plugin.
  `_required_framework_version` stays `(2, 0, 0)`.
  - **(a) The emitted plugin did not import.** The template imported
    `renderers` and then used `renderers.format_hints.Hex` at module level in
    `_COLUMNS` and `_generator`. `renderers` is a *package*: importing it does
    not bind its `format_hints` submodule, so a bare import raised
    `AttributeError: module 'volatility3.framework.renderers' has no attribute
    'format_hints'`. It only ever worked by accident of import order — 111 files
    under `volatility3/framework/plugins/` do
    `from volatility3.framework.renderers import format_hints`, and once vol3's
    own `import_files` plugin walk has run the submodule is bound on the parent
    for the rest of the process, which is exactly what happens when a user runs
    `vol`. The template now does that import itself.
    `tests/test_vol3_verify.py::test_emitted_plugin_module_level_format_hints_is_a_bug`
    was `xfail(strict=True)` and is now green with the marker removed; its
    control test proves the `monkeypatch.delattr` is what makes it non-vacuous.
  - **(b) `--pid` was dead code that silently scanned everything.** The emitted
    requirements carried no `kernel` ModuleRequirement, so `_try_pid_scan`'s
    `config.get("vmlinux")` / `config.get("nt_symbols")` were always `None`; and
    it called `list_tasks`/`list_processes` as
    `(context, layer_name, symbol_table_string)` while 2.27.x wants
    `(context, <module name>, filter_func)` — argument 2 raised
    `KeyError: 'primary'` and argument 3 raised
    `TypeError: 'str' object is not callable`. Both were swallowed by
    `except Exception: continue`, so `--pid 1234` scanned the whole layer and
    said nothing. Now: an **optional** `requirements.ModuleRequirement(name=
    "kernel", …)` (optional is load-bearing — a mandatory one would fail
    `PluginInterface.__init__`'s requirement gate on exactly the flat process
    dumps this plugin exists to scan, while vol3's `KernelModule` automagic
    calls `requirement.unsatisfied()` directly and so still *fills* an optional
    one when a kernel image and symbols exist); a `_pid_scan(pid)` that passes
    `config["kernel"]` as the module name and each `PsList`'s own
    `create_pid_filter([pid])` callable as `filter_func` (which filters out
    non-matches, so the old manual `proc.pid == pid` comparison is gone); and an
    OS branch chosen from the kernel symbol table's metadata class
    (`LinuxMetadata` / `WindowsMetadata`), falling back to trying both in order.
    When a `--pid` was asked for and could not be honoured, `run()` now emits a
    **loud** `vollog.warning` naming the PID and saying the results are *not*
    restricted to that process, instead of quietly returning a whole-layer scan.
    - **PID narrowing itself remains unproven.** What is covered: the declared
      requirement set, that the plugin validates and scans with no kernel module,
      that the automagic does not skip an optional `ModuleRequirement`, the loud
      warning, and the argument *shape* (via a stub `pslist` injected into
      `sys.modules`). What is **not**: `proc.add_process_layer()` and the
      process-layer scan after it, which need a real kernel memory image plus a
      matching ISF that neither this repository nor the development machine has.
      Do not read the new tests as end-to-end `--pid` coverage.
      *Update (Unreleased, semantic workbench P2):* `--pid` narrowing is now proven
      end-to-end on a real LA57 kernel image — `tests/test_vol3_pid_real_image.py`.
  - **(c) The plugin scanned the wrong layer — the default scan target is now
    the physical/file layer.** MemDiver's raw dumps begin with `7f 45 4c 46` and
    have `e_type = ET_DYN`, so they *look* like an ELF to vol3's `LayerStacker`
    while carrying no PT_LOAD table covering the dump. Measured two independent
    ways on one 11,223,040-byte ground-truth dump: in-process the stack came out
    `['base_layer', 'primary']` with `primary` an `Elf64Layer` exposing ~6 KB
    (`max 0x232b`), so the plugin scanned ~6 KB of an 11 MB dump; out-of-process
    the real `vol` printed
    `Scan Failure: Sections have no size, nothing to scan` and returned `[]` for
    the pad-128 plugin that finds the key in 0.02 s in-process. The template now
    walks `layer.dependencies` down to the lowest layer — complete, and addressed
    in *file* offsets, which is the space MemDiver's own output is in — with a
    `seen` set against cycles and a `vollog.info` naming the chosen layer and its
    size. A new `--virtual` (`BooleanRequirement`, optional, default `False`)
    opts back into the configured translation layer, which is the right choice
    for a genuine kernel image. Verified: the real `vol` CLI now returns exactly
    one row at `KeyOffset 370672`, `PatternOffset 370544`, with key hex identical
    to `data[370672:370720]`, where the same invocation previously returned `[]`
    (`tests/test_vol3_subproc.py`, against both the 2.27.0 console script and the
    2.27.1 source checkout); and in-process a CI-runnable model of the truncated
    stack finds the key only once the walk reaches the lowest layer, while
    `--virtual` on the same stack finds nothing (`tests/test_vol3_verify.py`).
    Flipping the default is safe because nobody can have been relying on zero
    hits where the key demonstrably is.
  - **Four of five bare `except Exception` swallows narrowed; the fifth kept.**
    The rule applied was *keep the degrade that is legitimate, kill the one that
    hides an API mismatch.* Both per-hit `layer.read` guards are now
    `except exceptions.InvalidAddressException` (a window straddling the end of a
    mapped section is expected; anything else is a bug). The `RegExScanner` guard
    now covers only the regex's **construction** (`except re.error`, with a
    warning) and leaves `layer.scan` unguarded — a `layer.scan` API mismatch used
    to degrade to the weaker `BytesScanner` and report "no results", which is
    indistinguishable from "the key is not there". The single
    `import yara` / `yara.compile` guard is split: `except ImportError` warns and
    disables YARA verification (legitimate — the plugin runs in the *user's* vol3
    environment, which need not carry yara-python), while
    `except yara.SyntaxError` logs at **error** (a rule that will not compile is
    a defect in MemDiver's own emitter). `_pid_scan`'s OS loop catches
    `ImportError` for the module import and
    `(SymbolError, InvalidAddressException, KeyError, TypeError)` for the
    listing, each at `vollog.debug`, because the wrong-OS branch legitimately
    raises those.

### Changed
- **`POST`/`GET /api/settings/upload-dir` and a Settings → Storage panel.** New
  `api/routers/settings.py` reports where uploads are stored (path, source,
  `env_pinned`, quota, and any offerable legacy directory) and accepts a chosen
  path, returning **400** with the specific validation reason on rejection. The
  cached `Settings` singleton is mutated **in place** rather than
  `cache_clear()`-ed, because the API-token middleware and the startup
  `ArtifactStore` hold that exact instance and would otherwise be stranded on a
  stale object. In the UI, a passive Storage section shows and edits the path;
  the load-bearing path is the pcap upload itself, which catches the 409, prompts
  for a directory, and then **re-runs the upload with the same file** so the user
  never loses the capture they just dropped. There is deliberately no blocking
  first-run modal — inspect, analysis, consensus, brute-force, structures and
  sessions never touch `upload_dir`.
- **Brute-force `--stride` now defaults to `1` (was `8`).** The candidate grid
  is absolute, so the old default handed the oracle only 8-aligned offsets and
  a secret at, e.g., offset `585148` was never tested — the run ended
  *successfully* with zero hits, indistinguishable from "the key is not in this
  dump". The new default sweeps every offset (`coverage_fraction == 1.0`) on
  every product surface (CLI, MCP, web API, pipeline runner, engine, frontend);
  the Phase-A experiment (`engine/candidate_stats.py::run_phase_a` and
  `scripts/phase_a_experiment.py`) stays at `8` as frozen paper reproduction.
  Raising the stride is now an opt-in speed tradeoff. The web UI's
  *Replicate gocryptfs IMF* recipe still pins `stride 8` to reproduce the
  published result.
  - **Existing browser sessions are migrated.** The pipeline wizard's form is
    persisted to `localStorage`, so a browser that had already stored the old
    `stride: 8` would have gone on running at 15.7 % coverage no matter what
    the shipped default said — the new default only ever applied to a fresh
    profile. The pipeline store moves to schema `version 2` with a targeted
    migration that rewrites *only* a stale `bruteForce.stride === 8` to `1`.
    A hand-picked stride (2, 4, 16, …) is left alone, and every other saved
    field — selected dumps, armed oracle/pcap, reduce thresholds, wizard
    stage, in-flight task id — is carried across untouched. Nobody has to
    clear site data to get the fix.
  - **The candidate pre-count is now closed-form.** `count_candidate_slices`
    ran a full discard-iteration over the grid before every sweep purely to
    produce a progress denominator — ~700k wasted steps per run at the new
    default, and once per N in an n-sweep. It now delegates to the O(1)
    `count_region_grid` that already backed `count_possible_candidates`
    (~37 s → sub-millisecond on a 4·10⁸-window span). Counts are unchanged;
    the two functions are the same arithmetic and the equivalence is pinned.
- **The brute-force stage is cancellable mid-sweep on the web and MCP
  surfaces.** The producer passed only `progress_callback` to the engine and
  consulted `is_cancelled` exactly once, *before* the first candidate, which
  left `engine.progress.check_cancel` dead code on those paths — so a cancel
  was ignored for the whole run. Tolerable over 110k candidates; not over the
  ~700k the stride-1 default now enumerates. The cancel token is threaded into
  the sweep and the engine's `Cancelled` is re-expressed as the app layer's
  canonical `code="cancelled"` signal, so it is indistinguishable from one
  observed at a stage boundary.
- **MSL implementation declares conformance with the official Memory Slice
  Specification v1.0.0** (<https://github.com/MemorySlice/memslice-spec>):
  - Reader rejects unknown MSL major versions per spec §3.4 and rejects any
    Endianness byte other than `0x01` per spec §3.1 (strict consumer rules).
  - Writer now sets the Capability Bitmap accurately per spec §9 (MUST), with
    bits OR'd in for every emitted data category (MemoryRegions, ModuleList,
    CryptoHints, RelatedDumps, ProcessIdentity, SystemContext, Process /
    Network / Handle tables).
  - Writer validates `PageSizeLog2 ∈ [10, 40]` and `RegionSize % PageSize == 0`
    per spec §5.1; the decoder rejects out-of-range `PageSizeLog2` per
    spec §14.2 rule 10.
  - Writer adds full Investigation-mode support per spec §6: Process Identity
    (Block 0), Module List Index + Module Entry children (Block 1), System
    Context (Block 2), and Process/Connection/Handle table children. Block
    ordering is enforced at `write()` time.
  - Writer emits the spec's three-state page model (CAPTURED / FAILED /
    UNMAPPED) when `add_memory_region(..., page_states=...)` is supplied;
    legacy callers without `page_states` continue to get all-CAPTURED maps.
  - `msl/importer.py` zero-pads raw `.dump` inputs to a page boundary so
    imported regions satisfy spec §5.1; the original size is preserved in
    `IMPORT_PROVENANCE.orig_file_size`.
  - Documentation file `docs/file_formats/msl_v1_1_0.md` renamed to
    `msl_v1_0_0.md` to reflect the spec document version (the on-wire
    binary format byte at file header offset `0x0A` remains `0x0101`,
    which the spec calls "format 1.1").
- **Interface deps moved to extras (breaking):** `pip install memdiver` now
  installs only the library + CLI core. The FastAPI web UI + REST API
  (`fastapi`/`uvicorn`/`pydantic-settings`) live behind `[api]`, the MCP server
  behind `[mcp]`, and the legacy Marimo UI behind `[marimo]`. `[all]`
  (= `memdiver[api,mcp,marimo]`) reproduces the
  previous all-in-one install. `kaitaistruct` and the crypto stack remain base
  deps; `[experiment]` and `[dev]` are unchanged.
- `memdiver experiment` now surfaces an actionable install hint
  (`pip install memdiver[experiment]`) when the experiment extras are missing,
  instead of raising a bare ImportError.
- `LICENSE` file replaced with the canonical Apache License 2.0 text (was
  previously MIT). The `pyproject.toml` classifier was updated to
  `License :: OSI Approved :: Apache Software License` to match.
- Install-hint messages in `memdiver web` / `app` / `mcp` / `ui` now point at
  the specific extra (`memdiver[api]` / `[mcp]` / `[marimo]`) when
  the corresponding dependency is not installed.
- **YARA rule names, tags and meta strings are now unconditionally sanitized —
  a caller-supplied `rule_name` can change.** `YaraExporter.export` used to
  sanitize the name only on the branch where `rule_name` was `None` (it read
  `rule_name or _sanitize_identifier(pattern["name"])`), so a name the *caller*
  supplied went into the rule verbatim. YARA's grammar wants an identifier
  there, so a name containing a hyphen, a dot, a space, or one that happens to
  be a reserved word (`filesize`, `condition`, `ascii`, …) produced a rule that
  **does not compile** — and nothing in the tree ever compiled the emitted rule,
  so the breakage only showed up when the operator fed the `.yar` to
  `yara`/`yara-python` themselves. `POST /api/architect/export` passes
  `rule_name` straight from the request body, so that endpoint could emit an
  unusable rule for any name a user typed. Now every caller-supplied string is
  normalised on the way in: the name becomes an identifier (ASCII
  `[A-Za-z0-9_]`, never leading-digit, never a reserved word, capped at
  libyara's 128-character identifier limit), each tag is put through the same
  filter, and `description` / `static_ratio` are escaped for a double-quoted
  meta string (backslashes doubled first, then quotes escaped, then every
  control or line-breaking character collapsed to a space) so a quote or a
  newline can no longer terminate the literal early. **The visible consequence
  is that a name like `my-rule.v2` is silently rewritten to `my_rule_v2`**, so
  a downstream tool matching on the exact rule name must expect the sanitized
  form. Two deliberate asymmetries are worth knowing: a reserved word in the
  *name* position is **rescued** with an `r_` prefix (`filesize` → `r_filesize`)
  because a rule must have some name, whereas a reserved-word *tag* is
  **dropped** entirely — a tag is decorative, and silently renaming it to
  `r_ascii` would be more surprising than losing it. Blank and duplicate tags
  are dropped for the same reason. The keyword list was verified against
  yara-python 4.5.4 rather than copied from the docs.
- **`yara-python` is now a base dependency**, so `pip install memdiver` grows a
  compiled C extension (libyara). It is deliberately *not* an extra: MemDiver
  has been able to emit YARA rules since the architect layer landed but never to
  run one, and an emitted detector you cannot scan with is a detector you cannot
  evaluate — the new `engine/yara_scan.py` closes that loop, and it is useless
  behind an install flag the evaluation path cannot assume. This also keeps the
  install contract intact: `pip install memdiver` ships everything, with
  `marimo` the only genuinely optional component.
- YARA rules gained optional `key_offset` / `key_length` metas, locating the key
  bytes *within* the matched pattern window. This matters because
  `PatternGenerator` builds `wildcard_pattern` as one flat wildcarded byte
  string spanning a whole region, so libyara reports the start of the *window
  that contains* the key, not the key's own offset — without the metas a
  detector's positional claim cannot be scored at all (see
  `engine/detector_metrics.py`). **Scope, honestly:** the metas are emitted only
  when a caller actually knows the locator. The three paths that compute it from
  the hit pass it directly — `engine/vol3_emit.py::emit_plugin_for_hit`
  (exact, the hit defined the window), `app/export_service.py`'s auto export
  (`best.start - offset`) and manual export (`0`, because there the caller's
  offset *is* the key start), and `app/experiment_orchestration.py`'s plugin
  emit (`best.start - exp_offset`). The two remaining paths —
  `Volatility3Exporter.export`'s own YARA fallback and
  `POST /api/architect/export` — hold only a finished pattern dict, so they
  recover the locator from it via the new `key_locator_from_pattern()` and emit
  nothing when the dict does not carry one. A pattern that came from
  `POST /api/architect/generate-pattern` does not carry one, and there the metas
  are correctly omitted rather than invented; a non-integral value arriving in
  an HTTP body is coerced to `None` for the same reason.
- **A plain `pytest` no longer runs `slow`-marked tests.** The default
  `addopts` moved from `-m 'not e2e'` to `-m 'not e2e and not slow'`, because
  the `slow` tests either walk the machine-local corpus (~170 GB / 18,917
  dumps, `tests/test_pcap_oracle_real_dump.py`) or run cost benchmarks. They are
  **not** orphaned: the `test` job in `.github/workflows/ci.yml` now runs
  `pytest -m slow` as its own step, and `make test-slow` does the same locally.
  This is load-bearing because `tests/test_benchmarks.py` holds the auto-floor
  **cost ratchets** — the per-candidate memory and time ceilings that three
  optimisations were justified by. Before the addopts change those ran in the
  default sweep only *by accident*, since `-m 'not e2e'` never excluded `slow`;
  had the marker been deselected without adding the CI step, the ratchets would
  have stopped gating pushes silently. (The corpus-backed slow tests self-skip
  in CI — no runner has the dump tree.) Run `make test-slow` before touching
  `engine/auto_floor.py` or `engine/brute_force.py`.
- `DatasetScanner._has_capture` now counts a capture only when it is a
  **non-empty regular file**, so the fast scan agrees with
  `RunDiscovery._find_capture`'s three-state verdict. A zero-byte capture is
  `"unreadable"` there, and counting it as present here inflated
  `DatasetInfo.runs_with_capture` above the number of runs that can actually be
  proven against their capture — i.e. it overstated the corpus denominator,
  which is precisely what the three-state status exists to prevent. `stat()`
  costs the same syscall as `is_file()`, so the agreement is free.
- Two parity ratchets were tightened over work that was already shipped:
  `app/capabilities.py` registers the `pcap.inspect` capability, and
  `tests/test_architecture_invariants.py` adds `inspect_pcap` to
  `_MCP_TOOL_PRODUCERS`. The pcap arm/validate step has been wired on all four
  surfaces since Phase 1 (library `services.inspect_pcap`, CLI
  `memdiver inspect-pcap`, `POST /api/pcaps/validate`, MCP `inspect_pcap`) but
  was tracked by neither, so its four-surface parity and its MCP signature were
  both unguarded. Both additions are pure tightenings — neither needs a
  `KNOWN_PARITY_GAPS` or `_MCP_ALLOWED_OMISSIONS` entry.
- The unsupported-cipher-suite path in `engine/resources/tls_pcap.py` was
  promoted from `DEBUG` to `INFO`. Dropping a suite outside MemDiver's KDF/AEAD
  table discards an entire TLS session, which at default log levels used to
  leave no trace whatsoever. The same event is now also reported structurally —
  see `skipped_sessions` under *Added*.
- `ResourceOracle` logs at `INFO` when `max_challenges` actually truncates
  (`max_challenges=N truncated M challenges to N`), so a capped run's
  "0 confirmed" can never be read as full coverage.
- **`records_returned` / `records_truncated` now count coverage through the same
  gate the challenge emitter uses.** They were derived from the raw
  application-data record totals, so a TLS 1.2 capture whose ChangeCipherSpec
  is missing — a truncated capture start, a dropped packet, a CCS seen on only
  one direction — reported *full* coverage while the oracle verified **zero**
  records. TLS 1.2 record keys only take effect after their direction's CCS, so
  that application data is not decryptable at all; the raw total was counting
  ciphertext no challenge could ever reach. That is a false `false` on the one
  field whose entire purpose is to stop a corpus number silently understating
  itself, which makes it worse than no field. `TlsPcapResource` now has exactly
  one gate per protocol version (`_tls12_gated` / `_tls13_gated`), shared by the
  emitter and by `describe_capture`'s accounting, so the two cannot drift: the
  report walks the same iterator the challenges come out of and counts what it
  yields. The coverage number therefore also reflects the record cap *and* an
  exhausted challenge budget, which is why `records_truncated` is now documented
  as "some session returned fewer records than it saw, whatever the cause"
  rather than as a statement about `max_records_per_direction`.
  **Measured across all 2,598 real captures in the corpus the numbers are
  unchanged** — every one carries a ChangeCipherSpec in both directions — so no
  published figure was ever wrong. It was a latent hazard, and it now surfaces
  as `records_returned: 0` plus an explained `skipped` entry instead of a
  confident lie.
- **`caps` now reports `max_challenges` as well, and the capture report gained
  `challenges_available` / `challenges_returned` / `challenges_truncated`.**
  Reporting only `max_records_per_direction` meant the *other* cap — the one
  that truncates across sessions and can therefore starve a whole session — was
  invisible in the arm step's own output: a run with `max_challenges=1` reported
  full coverage. The key is always present and is `null` when uncapped, so
  "uncapped" can never be read as "unreported". **This is a payload SHAPE
  change** on `POST /api/pcaps/validate`, the CLI `inspect-pcap` command and the
  MCP `inspect_pcap` tool: strictly additive, but a caller pinning the exact key
  set of `caps` (or of the capture report) will see new keys.
  The challenge counts are reported *separately from* the record counts, not
  derived from them, because the two units do not convert: a TLS 1.3 record is
  probed over a sequence-number window of up to 9 candidates
  (`_TLS13_SEQ_WINDOW = 8`, plus the record's own index), so one record yields
  several challenges. Across the corpus that works out at roughly **3.9
  challenges per record** (48,546 challenges for 12,463 records) — unintuitive
  enough to be worth a number, because it means a `pcap_max_challenges` of 50
  buys only about **13 records** of verification, not 50. That ratio is exactly
  why `challenges_available` had to be published: without it an operator sizing
  a cap has no way to know what fraction of the capture the cap actually buys.
- **Documented-reason correction: `inspect_pcap`'s `skipped_sessions` no longer
  advertises `no_cipher_suite` and `short_random` as expected outcomes.** The
  bundled dpkt cannot produce either: `TLSServerHello.unpack` falls back to
  `get_unknown_ciphersuite` rather than leaving the suite unreadable (so the
  code is always an int), and a ServerHello with a short random is rejected
  outright during unpacking, surfacing as `no_server_hello`. Both checks
  **remain in place** as defence against a different dpkt build — a caller
  should still tolerate the two values, and they stay in the frontend's closed
  `PcapSkipReason` union — but a UI or a corpus aggregate must not present them
  as reasons it expects to see, and no test can produce one to pin.
- **`RawDumpSource` now validates its `view` argument** on `size_for`,
  `read_all`, `read_range`, `find_all` and `find_first`. `"vas"` and `"va"` are
  accepted as aliases of `"raw"`, because a flat dump has no region table and
  its raw and virtual views genuinely coincide; anything else raises
  `ValueError`, as it already did on the MSL, gcore and regioned-raw sources.
  Previously this one source accepted a **typo** silently and served raw-view
  results, while the very same typo was a loud `ValueError` everywhere else — so
  a corpus sweep mixing formats got silently format-dependent behaviour out of
  one argument, and `RawDumpSource` backs every plain `.dump`/`.bin` in the
  corpus. A caller that was passing a misspelled view and getting away with it
  will now see the error it should always have seen.
- **Capture classification gained a readability probe.** `stat()` succeeds on a
  file the process cannot `open()` — mode `000`, a restrictive ACL, some
  read-only mount quirks — so a capture nobody can read reported `"present"` and
  inflated the corpus denominator, which is the exact overstatement the
  three-state `capture_status` exists to prevent. Both
  `RunDiscovery._find_capture` and `DatasetScanner._has_capture` now add one
  `os.access(..., os.R_OK)` check, so the slow per-run resolution and the
  stat-only fast scan still agree on every candidate; the fast scan's budget is
  preserved (one extra syscall per candidate).

- **The project database is now versioned, and an existing project file is
  migrated in place (schema v1 -> v3).** A `.duckdb` written by any earlier
  MemDiver carries no version marker at all, so `ProjectDB.open()` now creates
  a `schema_meta` key/value table, reads `schema_version` out of it (a file
  *without* that row is by definition v1), and brings the file forward to
  `_SCHEMA_VERSION = 3` before it hands back a connection. **This rewrites the
  user's own project file**, so it is worth stating exactly what it does. Whole
  new tables arrive through `CREATE TABLE IF NOT EXISTS`: `schema_meta`;
  `expected_secrets`, the *denominator* ledger holding one row per corpus run
  and secret type the run's key log declares; `survival`, the *observation*
  ledger at one row per dump and secret type; and `sweeps` / `sweep_units`, the
  resume watermark for a corpus-scale sweep and the single documented exception
  to this class's otherwise append-only rule (a unit row is updated in place as
  it moves `pending` -> `running` -> `done`). New columns arrive through
  `ALTER TABLE ... ADD COLUMN`: the corpus axes (`library`, `protocol_version`,
  `library_version`, `version_axis`, `scenario`, `protocol`) on `projects`;
  `phase`, `canonical_phase`, `run_number`, `library` and `run_id` on `dumps`;
  those plus `protocol_version`, `library_version`, `scenario`, `run_dir`,
  `keylog_path` and `pcap_path` on `analysis_runs`; `secret_type`, `kind`,
  `method`, `dump_path`, `phase`, `canonical_phase`, `library`, `run_number`
  and a deliberately **three-valued** `verified` (`NULL` = never verified,
  `FALSE` = a verifier rejected it, `TRUE` = confirmed) on `findings`; and
  `phase`, `canonical_phase`, `dump_id`, `dump_path`, `library_version`,
  `scenario`, `run_number`, `method` and `value_hex` on `ground_truth`. A
  migrated file ends up with the same column *order* as a freshly created one,
  because both are generated from the same table description rather than
  spelled out twice. Every added column is nullable or defaulted, which is what
  makes the two compatibility decisions below defensible rather than merely
  convenient:
  - **The migration probes `duckdb_columns()`** for the columns a table already
    has and emits an `ALTER TABLE` only for the ones genuinely missing, instead
    of leaning on `ADD COLUMN IF NOT EXISTS`. That clause is not available
    across the whole supported DuckDB range (`duckdb>=1.0.0`), so the shorter
    spelling would have made the migration itself silently DuckDB-version
    dependent — and the probe additionally gives the migration test something
    to assert against, which `IF NOT EXISTS` does not.
  - **A file written by a *newer* MemDiver warns and is used anyway**, for
    reads *and* writes, with the newer columns ignored rather than dropped;
    the stored version is left alone. Raising would lock an operator out of
    their own project file over a difference that the nullable/defaulted rule
    above already makes tolerable, and silently rewriting the version marker
    downward would lose information the newer build put there.
- **`survival` records an absence as a positive fact, and a missing row as "we
  never looked" — and that distinction must not be optimised away.** The table
  exists because `findings` structurally cannot express it: `findings` holds
  what was found, so reading "no row" as "the secret was gone" turns every dump
  nobody has scanned yet into a *confirmed* zeroization, which is precisely the
  claim a survival analysis is supposed to earn. The contract is three-state:
  `present = TRUE` means we looked and found it; `present = FALSE` means we
  opened this dump, searched for this secret and it was gone; **no row at all**
  means the cell was never attempted. `present` is therefore nullable with no
  default, and a companion `status` column guards it — only
  `status = 'searched'` requires a non-`NULL` `present` and only `'searched'`
  counts toward `runs_attempted`; `'unreadable'` leaves `present` `NULL` (a
  dump we could not open was not an observation), and `'error'` writes no row
  at all. A `NULL` `present` is excluded by both `WHERE present` and
  `WHERE NOT present`, so it can never quietly land on either side of a
  published fraction.
- **Both ledgers now have deterministic row identity, so a re-run or a resume
  corrects a cell instead of duplicating it.** `survival` and
  `expected_secrets` previously took a fresh uuid per row with no unique
  constraint behind it, which meant a second pass over the same corpus wrote a
  complete second copy of every observation *and* every denominator row. That
  failure is invisible to the obvious sanity check: the invariant
  `runs_found <= runs_attempted <= runs_expected` still holds with both sides
  doubled, so the published fractions look untouched while the counts under
  them are inflated. Row ids are now derived — blake3 over the
  length-prefixed identity parts, matching the repo-wide hashing convention
  rather than md5, because a collision here silently overwrites one
  observation with another — and backed by real unique indexes
  (`survival(sweep_id, dump_path, secret_type)` and
  `sweep_units(sweep_id, unit_key)`). Writes upsert with
  `ON CONFLICT ... DO UPDATE` rather than `DO NOTHING`, which is the
  behavioural half of the change: a resume that *corrects* an observation —
  a cell first written `present = FALSE` from a truncated read and then found
  present — now wins, where `DO NOTHING` would have counted the corrected
  write and discarded it. Only the observation columns are in the update list;
  identity and axis columns never are, so an upsert can never move a row to a
  different cell. If an index cannot be created the failure is recorded rather
  than swallowed: `degraded_indexes()` reports it, the survival writer falls
  back to a primary-key conflict target (naming an index that does not exist
  as the arbiter is a bind error), and a non-empty result means the counts
  behind the fractions are not publishable.
  - **`add_survival_batch` now rejects an empty `dump_path` outright**
    (`CapabilityError`, `INVALID_INPUT`), and this one is not theoretical.
    `dump_path` is part of the cell's identity, so with it blank every row in a
    batch hashes to the same handful of ids and the unique index collapses
    them: a real corpus pass of **63,481 cells left 6 rows** in the table while
    the writer cheerfully reported 63,481 written. A missing `sweep_id` is
    rejected the same way and for the same reason. Both are new writer-level
    rejections — a caller that was passing either as `""` and appearing to
    succeed will now see an error, which is the point.
- **`method` is a closed vocabulary, validated at every writer.** The permitted
  values are `keylog_substring`, `consensus_search`, `brute_force` and
  `oracle`, in increasing order of evidential strength, and they apply to
  `findings.method`, `ground_truth.method` and `survival.method` alike. The
  empty string is the only exemption and means "unclassified"; anything else,
  including a non-string such as `None` or `0`, is rejected as a typed
  `CapabilityError`. `add_findings_batch` validates the whole batch *before*
  writing any row, so a bad method in the tail cannot leave a half-written
  batch behind. This is a new rejection at the writers, so a caller that was
  inventing its own method spelling will now be told.
  - **A corpus survival pass may never claim decryption-backed provenance.**
    The survival scan proves exactly one thing — that these key-log bytes are
    or are not present in this dump — and it runs no decryption at all, so
    labelling its rows `confirmed_by = 'pcap'` or `'oracle'` would pad the
    proof ledger with claims nothing verified. The rule is enforced
    structurally rather than by review: `survival` has no `confirmed_by`
    column, and `add_survival_batch` restricts `method` to
    `keylog_substring` alone. The two decryption-backed labels stay the
    exclusive property of `record_ground_truth_run` and the pcap oracle path,
    which is also why that method deriving its own value from `confirmed_by`
    is not an oversight.
- **`ProjectDB.persist_report` now files ground-truth labels by default
  (`persist_ground_truth_labels` flipped from `False` to `True`) — a
  behaviour change for every existing caller.** As opt-in, and with nothing in
  the tree passing it, the W5 proof ledger was permanently empty in production:
  a table whose entire purpose is to accumulate confirmed recoveries had no way
  to accumulate anything. The flip is safe because only hits that already carry
  `verified` or `confirmed` are written, so the ordinary run — no verifier, no
  oracle, no capture — still adds exactly zero rows and the change is invisible
  to it. What *does* change is that a verified run now writes to
  `ground_truth` without being asked. The parameter is kept, so a caller that
  genuinely wants a report persisted without its labels can still say so.

### Security
- **`POST /api/analysis/export-keylog` contains `output_path` to the upload
  directory.** The handler passed the request string straight to
  `keylog_result`, which does `Path(output_path).write_text(...)` — an
  unauthenticated caller on a token-less localhost instance could write a
  file of largely chosen content to any path the server user owns (a shell rc,
  `~/.ssh/authorized_keys`, a `.pth` in site-packages). It now resolves through
  `ensure_within(settings.upload_dir, …)` and rejects an escape with 400,
  disclosing no server layout. This API's *read* path parameters remain an
  accepted, documented localhost risk; a write is a different class. The shared
  producer is deliberately unchanged, so the CLI and MCP surfaces still write
  wherever the operator's own shell can.

### Fixed
- **A typed server-side capture can be armed again.**
  `POST /api/pcaps/validate` contained `pcap_path` to the upload directory while
  `POST /api/pipeline/run` — the same parameter, the same capture — only checked
  existence. Since the UI's manual *Arm / re-validate* control routes through
  `/validate`, the "type a server-side path instead of uploading" flow
  documented in `docs/oracle/pcap_oracle.md` was broken: the capture could be
  run but never armed. Both endpoints now apply the same existence check.
- **`build_oracle` rejected nothing and mis-read `max_challenges: 0` as
  "uncapped".** The cap was read as `int(raw_cap) if raw_cap else None`, a
  *truthiness* test, so a config asking for `0` challenges got the exact
  opposite of the request — an unlimited run — while a negative value sailed
  through into `challenges[:max_challenges]`, i.e. `challenges[:-1]`, silently
  dropping the tail of the challenge list and logging the nonsense
  `max_challenges=-1 truncated 37 challenges to -1`. The test is now
  `is not None`, and a cap below 1 raises `ValueError` (matching the
  unknown-`resource_type` raise beside it) rather than being reinterpreted: a
  cap below 1 verifies nothing, so it could only ever turn a real recovered key
  into an unexplained "0 confirmed". `app/tools_pipeline.brute_force`
  additionally rejects both pcap caps as a typed `CapabilityError`
  (`INVALID_INPUT`) so every surface reports it identically, but `build_oracle`
  is the oracle-loader entry point and must not depend on that guard. Reachable
  before only through a builtin-resource-oracle config, which is why it went
  unnoticed.
  The rejection now has tests of its own, which it shipped without:
  `tests/test_resource_oracle.py` parametrises `0` and `-1` over
  `test_build_oracle_rejects_a_challenge_cap_below_one` (asserting the raise
  *and* that the message names the offending value), and
  `test_build_oracle_distinguishes_an_absent_cap_from_a_cap_of_zero` pins the
  actual behavioural difference against a throwaway registered resource type —
  three challenges uncapped, one at `max_challenges=1` — because that is the
  distinction the old truthiness test destroyed.
- **`find_first` could report `None` for a needle that IS present.**
  `mmap.find(sub)` defaults its start to the mapping's **current file
  position**, not `0` — unlike `bytes.find`, which has no position at all — so
  after anything that advances the mapping (`read_all()` is the common one) a
  bare `buf.find(needle)` searches only the tail and returns `-1` for a needle
  sitting before it. Reproduced on a real corpus dump: a TLS 1.3 traffic secret
  at offset `585148` was found by `find_all` and reported **missing** by
  `find_first` once `read_all()` had run — the worst possible failure for a
  presence query whose whole job is to answer "is this secret in this dump at
  all?" over ~170 GB. `find_all_offsets` was immune because it always passed an
  explicit `start`; every `find_first` site now does the same
  (`core/dump_io.py::find_first_offset` and
  `core/dump_sources/gcore.py::_find_first_in_bytes`, the latter reading the
  live mmap deliberately to avoid copying a multi-GB core, plus the explicit
  `0` in gcore's VAS window walk). Every existing test opened a fresh source, so
  the position was always `0` and the bug was invisible — the regression tests
  now read the source first.
- **`find_all_offsets(mmap, b"")` looped forever.** `mmap.find(b"", start)`
  **clamps** an out-of-range `start` to the buffer length instead of returning
  `-1` (on a 300-byte mapping, `mm.find(b"", 999)` is `300`), so the
  `start = idx + 1` cursor can never escape the buffer and the loop appends the
  same offset until memory runs out. `bytes.find` happens to terminate on the
  same input, so the hang reproduced only on the mmap-backed sources
  (`DumpReader`, and through it `RawDumpSource` / `MslDumpSource`) — precisely
  the ones a corpus sweep uses. An empty needle now returns `[]`, and
  `find_first_offset` returns `None` for the same input so the two can be
  swapped freely: searching for nothing is a caller error, not a query with a
  degenerate every-offset answer, and reporting offset `0` would let an empty
  secret masquerade as a hit at the start of every dump in the corpus.
- **`POST /api/architect/export` returned 200 with an uncompilable rule.** A
  client-supplied `pattern` dict using the wrong key names produced
  `$key = {  }` — an empty YARA hex string, which libyara rejects — and the
  endpoint happily served it with HTTP 200, so the breakage only appeared when
  the analyst fed the `.yar` to `yara`. The exporter's pattern validation now
  surfaces as **400** (mirroring the 400 `/architect/generate-pattern` raises
  for an unusable pattern), because `req.pattern` is free-form client input and
  a malformed one is a bad request, not a server fault. The endpoint's tests
  asserted only HTTP 200 — never that the rule they got back was usable — which
  is why the empty hex string went unnoticed for so long; the export tests now
  run every emitted rule through `yara.compile()`, and the new
  `tests/test_yara_exporter_compiles.py` does the same for the exporter itself.

- **Canonical phase labels could be assigned in the wrong chronological
  order.** `PhaseNormalizer.normalize_run` sorted a run's dumps by the raw
  timestamp *string* before handing out its generic canonical suffixes, and the
  suffixes are handed out **positionally** — first dump gets the first label,
  and so on. The timestamp's trailing microsecond field is captured by
  `core.discovery.DUMP_PATTERN` as `\d+`, i.e. **variable width, not
  zero-padded**, so a five-digit field sorts as text against a six-digit one
  and lands in the wrong place: `..._90000_pre_abort` (0.090 s) sorts *after*
  `..._606711_pre_shutdown` (0.607 s), because `"9" > "6"`. The consequence
  would not have been cosmetic — `canonical_phase` is what corpus consumers
  filter and group by, so a mis-ordered run would report one dump's survival
  numbers under another dump's lifecycle phase. The sort key is now
  `parse_phase_timestamp`, which splits the timestamp into a numeric
  `(date, time, microseconds)` tuple and returns a sentinel `(-1, -1, -1)`
  rather than raising for a shape it cannot parse — placing non-phased dataset
  dumps (`gcore.core`, `gdb_raw.bin`) first, which is where the old string
  ordering put their empty timestamp anyway. **This is a latent-correctness
  fix, not a corrected result:** all 18,917 dumps in the measured corpus carry
  six microsecond digits, so lexicographic and chronological order agree on
  every one of them and no shipped figure changes. The parse now lives in
  `core.phase_normalizer` and is re-exported by `engine.sweep_plan` (along with
  the sentinel) so labelling order and emission order cannot drift apart — the
  previous copy in `engine` documented a fix it could not deliver, because the
  normalizer went on sorting by the raw string.

### Added
- **PCAP verification oracle** — a first-party *trusted* oracle that proves a
  recovered secret by deriving record keys from it and AEAD-decrypting records
  of a real captured TLS session (TLS 1.3, TLS 1.2 GCM, TLS 1.2 CBC). Because
  it is MemDiver's own code and the capture is only ever parsed as data, never
  executed, it runs **outside** the untrusted-oracle sandbox that
  bring-your-own oracle scripts require. Capture parsing lives in
  `engine/resources/tls_pcap.py` (`TlsPcapResource` emits one
  `DecryptionChallenge` per encrypted application-data record); derivation and
  the AEAD/CBC checks stay in the oracle. Hits it confirms are stamped
  `verified: true` and `confirmed_by: "pcap"`. Parsing needs `dpkt`, behind the
  new `memdiver[pcap]` extra (`[all]` now expands to `api,mcp,marimo,pcap`);
  without it the arm/run steps surface an `INVALID_INPUT` capability error.
- `brute-force --pcap <capture>` on every surface, **mutually exclusive with
  `--oracle`** — a run confirms candidates either through a BYO script or
  against a capture, never both. `--tls-client-random <hex>` restricts matching
  to one session; `n-sweep` and `escalate` remain oracle-only.
- `inspect_pcap` — the "arm" producer that summarises a capture's TLS sessions
  (`client_random`, `server_random`, version, cipher suite, per-direction
  application-record counts, `has_app_records`), backed by
  `TlsPcapResource.describe_sessions()` and exposed on all four surfaces: CLI
  `memdiver inspect-pcap`, MCP `inspect_pcap`, web `POST /api/pcaps/validate`,
  library `memdiver.services.inspect_pcap`.
- `api/routers/pcaps.py` — `POST /api/pcaps/upload` streams a `.pcap` /
  `.pcapng` / `.cap` in 1 MiB chunks to `settings.upload_dir/pcaps/`, creating
  the file `0o600` via an `O_CREAT|O_EXCL` opener so a secret capture is never
  briefly group/world-readable, rejects a disallowed suffix with 400 and an
  over-cap upload with 413 (`PCAP_UPLOAD_MAX_BYTES` = 512 MiB, partial file
  removed), then LRU-prunes the persisted dir back under
  `settings.pcap_quota_bytes` (default 5 GiB) oldest-mtime-first, never
  evicting the just-uploaded capture. `POST /api/pcaps/validate` arms a
  persisted capture, `ensure_within`-confined to the upload dir.
- `POST /api/pipeline/run` accepts `pcap_path` + `tls_client_random` as a
  mutually exclusive alternative to `oracle_id` — exactly one oracle source is
  required (400 otherwise), and a pcap run carries `oracle_path: None` because
  there is no BYO oracle file to hash.
- Web pcap flow in the pipeline wizard's oracle stage: `PcapUpload`
  drag-and-drop uploader with a TLS-session picker (click a session to pin its
  `client_random`, or "match any session"; sessions without application-data
  records are marked unusable), driven by the shared `usePcapArm` hook
  (`frontend/src/components/pipeline/oracle/use-pcap-arm.ts`) reused by
  `StageOracle` for the manual-path re-validate control.
- Multi-secret NSS key-log composer in `KeyVerificationPanel` — add one row per
  secret (NSS label dropdown, `client_random`, secret hex), prefill the
  `client_random` from a selected pcap session, and export the whole set as one
  Wireshark-loadable key log.
- Provenance reaches the results UI: `frontend/src/components/results/provenance.ts`
  narrows the backend `confirmed_by` label to `pcap` / `oracle` / `verifier`
  (anything else falls back to a generic label rather than leaking a raw i18n
  key), and `VerificationBadge` renders it — a pcap-confirmed hit reads
  "Verified via pcap capture".
- `--persist-ground-truth` (CLI and MCP `brute_force`, opt-in) files
  pcap-confirmed hits into the project's DuckDB ground-truth ledger via
  `ProjectDB.record_ground_truth_run(..., confirmed_by="pcap")`, mapping each
  recovered key to its byte value for the survival/labelling analytics; a no-op
  when the DuckDB backend is unavailable.
- `docs/oracle/pcap_oracle.md` — walkthrough of the arm/run model, the
  four-surface table, and the two traps: `--key-sizes` (the candidate must
  match the *secret* — 32 for a TLS 1.3 traffic secret, 48 for a TLS 1.2 master
  secret) and `--stride` (the absolute grid, with measured coverage numbers
  from a real corpus dump).
- `pip install memdiver[experiment]` extra, pinning `frida-tools>=12.0` and
  `memslicer` for the dump-collection flow.
- GitHub Actions workflows:
  - `ci.yml` — pytest matrix (Python 3.11 / 3.12) on push / PR.
  - `publish.yml` — OIDC trusted publishing to PyPI on `v*` tag push, plus
    TestPyPI dry-runs via `workflow_dispatch`. Includes a `npm ci && npm run
    build` step so the React bundle is baked into every wheel.
- `MANIFEST.in` — ensures `LICENSE`, `README.md`, `CHANGELOG.md`, algorithm
  patterns, and the full `frontend/dist/` tree ship in the sdist.
- `frontend/dist/**/*` added to `[tool.setuptools.package-data]` so the built
  React bundle ships in the wheel; it is served once the web UI is installed via
  `pip install memdiver[api]`.
- Sphinx documentation site under `docs/` (Read the Docs theme, MyST-parser),
  published to <https://memoryslice.github.io/MemDiver/> via GitHub Pages.
  Covers quickstart, full user guide, ten-subsystem architecture walkthrough,
  eight algorithm reference pages, nine visualization pages, `.msl` v1.1.0
  file-format spec, Oracle interface + examples, and a 12-module Python API
  reference generated via `autodoc` + `napoleon`.
- `.github/workflows/docs.yml` — strict Sphinx build on every push and PR,
  Pages deploy gated to `main` (re-enabled after one-time repo Settings
  configuration).
- `.github/workflows/docs-screenshots.yml` — nightly Playwright refresh of
  the 11 baseline screenshots under `docs/_static/screenshots/`, opening a
  pull request on visual drift.
- Logo pipeline: `docs/_static/{logo,logo_simple}.svg` (both with `<title>`,
  `<desc>`, `role="img"` for accessibility), `docs/_static/favicon.ico`
  (multi-resolution 16/32/48), `docs/_static/logo_readme.png` (PyPI-safe
  512×512 raster), regenerator at `scripts/build_logo.py --check`.
- Playwright screenshot harness under `docs/screenshots/` — `capture.py`
  (deterministic Chromium driver with 10 flake-reduction techniques),
  `seed_data.py` (wraps the six `tests/fixtures/generate_*.py` generators),
  `captions.json` (per-slug alt text + viewport), and
  `generate_placeholders.py` for fresh clones.
- `docs` extra (`pip install memdiver[docs]`) pinning Sphinx 7.4,
  `sphinx-rtd-theme`, `myst-parser`, `sphinx-copybutton`, `sphinx-design`,
  `sphinxcontrib-mermaid`, `sphinx-argparse`, `cairosvg`, `pillow`.
- `cli.py` — public `build_parser()` alias exposed for `sphinx-argparse` and
  external tooling.
- Repo-root `__init__.py` — `__version__` now resolves dynamically via
  `importlib.metadata.version("memdiver")` instead of the drifted hard-coded
  `"0.1.0"`.
- `pyproject.toml` — canonical project URLs updated to
  `github.com/MemorySlice/MemDiver`; added a `Documentation` URL pointing at
  the GitHub Pages site.
- README overhaul — accurate capability counts (8 algorithms, 20 CLI
  subcommands, 12 FastAPI routers, 15 MCP tools), Apache-2.0 badge, MCP
  one-line wiring snippet, thumbnail gallery linking into the docs site.
- **`brute_force` gained `pcap_max_records` / `pcap_max_challenges`, wired on
  all four surfaces** — library
  `tools_pipeline.brute_force(pcap_max_records=…, pcap_max_challenges=…)`, CLI
  `--pcap-max-records` / `--pcap-max-challenges`, `POST /api/pipeline/run`
  (both validated `>= 1`), and the MCP `brute_force` tool. `None` on every
  surface preserves today's behaviour exactly: 16 application-data records per
  direction, no total challenge cap. These two knobs already existed inside
  `TlsPcapResource` (`max_records_per_direction`) and the builtin resource
  oracle's config schema (`max_challenges`), but **no surface could reach
  them**: the pcap branch of `brute_force` built its `oracle_config` dict from
  scratch with only `resource_type` / `pcap` / `client_random`, and the pcap
  branch ignores `oracle_config_path` entirely, so there was not even a TOML
  back door. The consequence was a capture that could be silently under-read
  with no way to widen it — a chatty session contributing only its first 16
  records per direction, and a `verified_count: 0` that said nothing about the
  rest of the capture. Only a cap the caller actually supplied is forwarded, so
  an unset knob leaves the resource and oracle defaults untouched rather than
  re-asserting them. **A challenge cap truncates *across* sessions, not per
  session** (`TlsPcapResource.challenges()` yields session-by-session and
  `ResourceOracle` keeps the first N of the flattened sequence), so a small cap
  on a multi-session capture can be consumed entirely by the first session in
  parse order — pair it with `--tls-client-random` when you want a bounded run
  that still targets a chosen session. Documented in
  `docs/oracle/pcap_oracle.md`.
- **`inspect_pcap` (and therefore `POST /api/pcaps/validate`, which returns the
  producer's payload verbatim) now also reports what the parse *dropped*:**
  `skipped_sessions`, `flow_count`, `caps` and `records_truncated`, plus
  `app_records_seen` / `records_returned` on each kept session. All are purely
  additive — every key the producer returned before is unchanged, including a
  zero-session capture's `session_count: 0`. The motivation is that a TLS
  session negotiating a cipher suite outside MemDiver's KDF/AEAD table used to
  vanish with nothing but a `DEBUG` log line, so at corpus scale a "0 confirmed"
  result was indistinguishable from "we never looked at 40 % of the capture".
  Each `skipped_sessions` entry carries a machine-readable `reason` —
  `no_client_hello`, `no_server_hello`, `no_cipher_suite`, `short_random`, or
  `unsupported_cipher_suite`, plus the two added below
  (`no_change_cipher_spec`, `client_random_mismatch`); see *Changed* for why
  `no_cipher_suite` and `short_random` are defensive guards rather than
  expected outcomes — the directional `flow` it was seen on, and
  reason-specific context (the IANA `cipher_suite` code, or the two random
  lengths). `flow_count` gives `session_count` a denominator, so "1 session out
  of 40 flows" is no longer reported the same way as "1 out of 2".
  `records_truncated` is true when `caps.max_records_per_direction` clipped a
  direction, i.e. some session's `records_returned` is below its
  `app_records_seen` — widened before release to fire on *every* cause of
  under-coverage, not the record cap alone; see *Changed*.
  The accounting lives on the new
  `TlsPcapResource.describe_capture()`, built *around* the frozen
  `describe_sessions()` (which the web router and the React frontend read)
  rather than by widening it, and it is reset on every `_parse_sessions()` call
  so a drop log always describes exactly one pass.
- **Two further `skipped` reasons, neither of which drops a whole session.**
  `no_change_cipher_spec` reports a TLS 1.2 direction whose application data no
  ChangeCipherSpec unlocks, carrying `direction` and that direction's own
  `app_records_seen`; the session is **kept**, but its records are uncoverable,
  so this is what turns a bare `records_returned: 0` into an explained one.
  `client_random_mismatch` closed a real gap rather than adding polish:
  `TlsPcapResource.challenges()` skips every session that fails the
  `client_random` filter, while `describe_capture` counted those same sessions
  as fully covered — and `builtin_oracle` passes that filter through today, so
  the inconsistency was reachable from a real run. The entry carries the hex
  `client_random` of the session that was passed over, so the report says
  *which* one. Both are emitted from the shared session filter
  (`_excluded_by_filter`), which is now the single place that decides whether a
  session is in scope, so the stream and the report cannot disagree about it.
- `DatasetMeta.library_version` — an optional `library_version` key in a run's
  `meta.json`, naming the **build** of the library under test (e.g. `"3.0.13"`).
  Forward-compatibility only: today's corpus holds each library at one build, so
  no run emits it and every axes record resolves to `"unknown"`. It is
  load-bearing anyway, because `core/corpus_axes.py` reads exactly this
  attribute to decide which dimension the corpus varies (`version_axis`), and
  the attribute **did not exist** — so the documented generic-version-axis hook
  could never fire, and a future multi-build corpus would have silently
  collapsed every build into `"unknown"` instead of splitting on it. That is a
  statistics-merging bug rather than a missing feature, which is why the field
  is added now rather than when the second build appears.
- The dataset scan reports a packet-capture inventory: `runs_with_capture` (how
  many runs own a capture) and `captures` (per-`"ver/scenario/library"` counts)
  ride the existing `scan_dataset` payload via
  `serialize_dataset_info`, so there is no new producer and no new capability.
  Per-run, `RunDirectory` gained `capture_path` and a **three-state**
  `capture_status` (`"present"` / `"absent"` / `"unreadable"`), resolved by the
  new `RunDiscovery._find_capture` and surfaced on
  `GET /api/dataset/runs` as `capture: {path, status}`. Three states rather than
  an `Optional[Path]` because a zero-byte or un-stat-able capture must not be
  counted as present: it is a corpus defect, and folding it into "absent" hides
  it while folding it into "present" overstates the number of runs that can
  actually be proven against their own capture. Resolution prefers a `capture`
  relative path declared in the run's `meta.json` (new, forward-compatible
  field — no corpus emits it yet) over the hardcoded `run_data/traffic.{pcap,
  pcapng,cap}` probe; a declared path that is absolute or escapes the run
  directory is logged and ignored, since `meta.json` is corpus-authored data and
  must not be able to point the scanner at an arbitrary file. Like
  `load_run_meta`, the probe never raises — scan paths have to tolerate partial
  datasets.
- `find_first_offset()` (`core/dump_io.py`), `DumpReader.find_first()`, a
  `find_first()` on every built-in dump source (raw, `.msl`, gcore, the
  regioned base) and the tolerant module-level `find_first_in()`
  (`core/dump_source.py`) — presence-only byte search with an early exit, for
  the corpus-scale question "is this secret in this dump at all?" over ~170 GB
  of dumps, where `find_all`'s scan-to-EOF is pure waste. **Design rationale,
  recorded here and not only in a code comment: `find_first` is deliberately
  NOT a member of the `DumpSource` Protocol.** That Protocol is
  `runtime_checkable`, and such a check verifies method *presence*, so adding a
  member would instantly make every duck-typed or third-party source registered
  via `register_dump_source()` fail `isinstance(obj, DumpSource)` — a silent
  break in third-party code that never changed. A default body would not help
  either: Protocol defaults are inherited only by explicit subclasses, and the
  isinstance check still only looks at attribute presence. Callers therefore go
  through `find_first_in(source, needle, view=…)`, which uses the source's own
  `find_first` when present and otherwise falls back to the first element of
  `find_all`. `view` is forwarded only when the caller supplies one, so each
  implementation keeps its own default (`"raw"` for raw/regioned sources,
  `"vas"` for `.msl`). The `.msl` implementation mirrors `find_all`'s
  per-captured-run semantics exactly, including the existing limitation that a
  needle straddling two captured runs is reported by neither.
- `core/corpus_axes.py` — the canonical corpus-axis vocabulary: the frozen
  `CorpusAxes` record plus `axes_from_run_dir()`, `axes_from_dump_path()` and
  `with_canonical_phase()`. Every corpus-scale consumer needs to agree on what a
  dump is an instance of (protocol, protocol version, library, library build,
  scenario, run, lifecycle phase); historically each one re-derived that from
  the path with its own regex and its own spelling of the field names, so this
  module derives it exactly once and nothing invents a second spelling.
  Resolution walks *up* from the run directory and cross-checks the version
  encoded in the run directory name against the protocol directory prefix in
  `core.protocols.REGISTRY`; a path that does not conform returns `None` rather
  than raising, which callers read as "not a corpus run". Two design points are
  recorded in the module: every record carries both a `library_version` and a
  `version_axis` label naming *which* dimension the corpus varies (today always
  `protocol_version`, since each library is held at one build), so a future
  multi-build corpus needs no consumer change; and `canonical_phase` is
  deliberately left **empty** by both path parsers, because it is not a property
  of a single path — `PhaseNormalizer` derives it from the set of *sibling*
  dumps in the run, so guessing it from a filename would make it a mutating
  identity key that silently splits or merges corpus statistics when an
  unrelated sibling appears. Only a caller that has already run the normalizer
  over the whole run may set it, via `with_canonical_phase()`.
- `engine/yara_scan.py` — compiles a MemDiver-emitted YARA rule and scans a dump
  source with it, closing the emit-but-never-run loop (the only `yara.compile`
  in the tree previously lived inside the *generated* Volatility3 plugin
  template and was never executed in-process). Exposes `compile_rules()` with a
  content-addressed rule cache, `scan_source()` / `scan_chunked()`,
  `rule_names()`, `max_pattern_length()` and `RuleMatch` / `ScanResult` records
  that lift the `key_offset` / `key_length` metas onto every hit. Two scan
  strategies are chosen by dump format: a plain raw dump is scanned by handing
  libyara the file path (for a raw dump the file offset *is* the default view
  offset, so libyara's own zero-copy mapping is both correct and fastest), while
  every other format (`.msl`, gcore, regioned raw) is scanned chunk-by-chunk
  through `read_range` because those bytes must be decrypted and/or
  VAS-projected first — for a gcore core the file offset is not the VAS offset,
  and for an encrypted `.msl` the on-disk bytes are not the plaintext at all.
  The module does no scoring of its own.
- `engine/truth_labels.py` — the truth-label locators, keeping the two available
  truth sources explicit and visibly distinct via `TruthInterval.source`.
  `locate_keylog_truth()` is the **authoritative** set: every corpus run ships a
  `keylog.csv` listing every secret that existed in that TLS session, so the
  true byte offsets are computable exactly by substring search and the truth set
  is complete by construction — a detector that misses a key is genuinely
  charged a false negative. `ledger_truth()` reads the DuckDB `ground_truth`
  table and is **corroboration only**: it is opt-in and therefore sparse, and it
  only ever contains offsets some earlier sweep already visited, so it is
  stride-dependent and recall measured against it is silently *inflated*. Both
  functions are pure compute — reading the keylog and opening the dump stay the
  caller's job. Written rather than reusing `DumpSearcher.search_secrets()`
  because that helper is `DumpReader`-based and only ever sees the *raw* byte
  view, which would mis-locate truth for the `.msl` VAS projections scanners
  actually run against.
  - **A ledger truth interval whose extent nothing attests is dropped, and a
    length the key bytes refute loses to the key.** This is not tidiness: a
    zero-length truth is actively corrupting, because
    `engine.detector_metrics`'s containment test
    (`start <= t_start and t_start + length <= end`) is satisfied for
    `length == 0` by *any* match window covering the start — so one junk row
    counts as a covered truth **and** promotes the match to a true positive,
    inflating recall and precision to 1.0 at once. `ledger_truth()` therefore
    drops rows with no offset and rows resolving to a non-positive length, and
    reports the drop count at `WARNING` rather than quietly shrinking the
    truth set. Where a row carries key bytes, those bytes decide the extent:
    an absent `length` becomes the key width, and a `length` that disagrees
    with it is overridden — the row's `length` is bookkeeping, the key it
    carries is evidence. An explicit `length = 0` beside a real key is
    recovered at key width rather than discarded. Only a row that has neither
    key bytes nor a usable `length` is dropped. This matters downstream
    because corroboration keys on `(start, length)`: a `length = 48` row
    wrapped around a 32-byte key could never match the key log's
    `(start, 32)` interval, so the corroboration was silently lost and the
    ledger-only truth count correspondingly inflated.
- `engine/detector_metrics.py` — interval-based precision/recall for an emitted
  detector, scoring match *windows* against known-true key *intervals* under
  three criteria (`containment`, `key_offset` with a byte tolerance, and `exact`
  = zero tolerance, whose relation is a subset of `key_offset`'s). Deliberately
  a new metric type rather than a widening of `engine/convergence.py`'s
  `DetectionMetrics`, which would be wrong three ways: it is an exact set
  intersection over individual byte offsets, so it scores `tp=0` on every
  genuine window match; its byte-set semantics makes precision a property of
  how much padding the emitted window carries rather than of whether the key was
  found; and it is frozen into a `ConvergencePoint` the web surface reads.
  Because the match/truth relation is genuinely many-to-many, precision is
  match-indexed and recall is truth-indexed — both bounded by 1.0 by
  construction, and not recombinable into a single confusion matrix — with
  `max_matches_per_truth` (fan-in) and `max_truths_per_match` (fan-out)
  published alongside so a recall of 1.0 reached by one enormous window cannot
  be laundered into a flattering score. A match carrying no `key_offset` meta
  makes no positional claim and is excluded from the positional criteria rather
  than charged as a false positive.
- `engine/sweep_plan.py` — the work units and idempotency digests for a
  **resumable** full-corpus sweep (2,600 runs / 18,917 dumps / ~170 GB cannot be
  one non-restartable process). Provides a lazy `enumerate_units()`, a cheap
  separate `count_units()` for a progress denominator, and the three digests
  that make skip-if-already-done *correct* rather than merely plausible:
  `unit_key()`, `inputs_digest()` (notices the inputs changed) and
  `config_digest()` (notices the settings changed). The unit is **one dump
  file** — the granularity at which a scan result exists is the granularity at
  which work can be skipped. Two identity decisions are documented at length:
  `canonical_phase` is **not** part of the unit key, because `PhaseNormalizer`
  derives it positionally from a run's *sibling* dumps, so adding one unrelated
  file would silently re-key every already-scanned dump in that run and leave
  orphan ledger rows (the `dump_filename` used instead already carries the raw
  phase plus a microsecond timestamp and depends on nothing but that one file);
  and `corpus_id` is a *label* (`Path(root).name`) rather than a path or a
  realpath hash, so copying the corpus to another drive or mounting it elsewhere
  does not invalidate all 18,917 units for bytes that never changed — the
  absolute root is still recorded, as informational data.
  - The unit-key format is `u2`: `library_version` joined the key, between
    `library` and `run_number`, because a future multi-build corpus varies the
    build *within* a library and `openssl_run_13_1` compiled against two
    OpenSSL releases would otherwise collide on one key and one ledger row.
    Every run in today's corpus resolves to the unknown-version sentinel, so
    the collision cannot occur yet — which is exactly why the bump is free
    now and would be a ledger migration once 18,917 rows exist under `u1`.
  - `normalize` is folded into `config_digest` alongside `expand_keys`,
    `algorithms`, `keylog_filename`, `template_name`, `min_secret_len`, the
    MemDiver version and the sweep schema version. It has to be: it
    re-resolves a run's dumps through the phase normalizer before scanning, so
    it changes *which* dump a phase request lands on and therefore what the
    sweep finds — and it is deliberately not in the unit key, since the key
    names a concrete dump file rather than a phase request. Absent from both,
    flipping it would have left a resumed sweep skipping every unit as
    "already done" against results produced under the other setting. Purely
    operational knobs (`workers`, `use_processes`, `max_inflight`,
    `fsync_policy`, `output_dir`) are ignored by name rather than by accident,
    so changing the worker count does not invalidate a half-finished sweep;
    an unrecognised key is ignored with a warning.
  - `count_units()` is genuinely cheap now: a directory listing per run plus
    one `RunDiscovery.dump_file_for` call per filename, and that seam reads no
    file. No `load_run_directory`, no key-log parse, no `meta.json` probe, no
    capture probe — the axis resolution it used to do reached the filesystem
    twice per run, roughly 5,200 syscalls over the measured corpus, to recover
    a `library_version` that is unknown for every run in it and a keylog path
    a count cannot use. An unrecognised protocol directory drops its whole
    subtree unlisted. A `canonical_phases` filter is the one case needing more
    than a filename, and it runs the normalizer over the names already in
    hand — pure CPU, still no extra I/O.
  - The count and the enumeration are admitted by the **same** rule, through
    the public `RunDiscovery.dump_file_for` seam, and share one directory
    walk whose only parameter is how a run directory becomes its axes. They
    previously disagreed: the counter kept a local copy of the rule that
    tested `name.endswith(suffix)` over `DATASET_DUMP_SUFFIXES`, whose entries
    carry a **leading dot**, while discovery matches without one — so a bare
    `gdb_raw.bin` / `lldb_raw.bin` was enumerated but never counted. Unfiltered
    that merely under-counts; under a `canonical_phases` filter the drift
    *inverts*, because the filter re-parses the short name list and the
    denominator then promises units the enumeration never yields.
- `frontend/src/api/pipeline.ts` — the typed client now carries the fields the
  backend added, so the operator can actually see an under-read capture in the
  Arm / re-validate UI, which is the one place it matters: `PcapValidateResult`
  gained `skipped_sessions` (typed by a closed `PcapSkipReason` union),
  `flow_count`, `caps` and `records_truncated`; `PcapSession` gained
  `app_records_seen` / `records_returned`; and `PipelineRunRequest` gained
  `pcap_max_records` / `pcap_max_challenges`. All new fields are optional, so
  nothing that already built a request or read a response breaks.
  - Caught up with the accounting changes above: `PcapCaps` gained
    `max_challenges` (`number | null`), `PcapSkipReason` gained
    `no_change_cipher_spec` and `client_random_mismatch`, `PcapSkippedSession`
    gained the reason-specific `direction` / `app_records_seen` /
    `client_random` context, `PcapSession` gained `challenges_available` /
    `challenges_returned`, and `PcapValidateResult` gained the capture-level
    `challenges_available` / `challenges_returned` / `challenges_truncated`.
    Runtime was never affected — extra JSON keys are simply ignored — but a
    field the client has no type for is a field the operator-facing UI cannot
    render, and a **closed** union missing two live backend values is worse
    than that: narrowing on `reason` would silently fail to match the two rows
    that explain a `records_returned: 0`. The doc comments say which reasons are
    reachable from the arm response at all (`client_random_mismatch` needs a
    pinned resource, which the arm producer does not do) and which two are
    defensive guards, so the optionality is informative rather than a blanket
    hedge. `tests/frontend/api/pipeline.test.ts` pins the seven reason
    literals against the Python call sites and asserts a representative payload
    for the missing-ChangeCipherSpec and challenge-capped cases.

- `parse_keylog_with_status()` in `core/keylog.py` — the same parse as
  `KeylogParser.parse`, reporting *why* the result looks the way it does.
  `parse` swallows every failure and returns a possibly-empty list, which makes
  an unreadable key log indistinguishable from a session that genuinely logged
  nothing — and downstream that difference is load-bearing, because a survival
  sweep renders "zero secrets available" as *not observed*, the same cell a
  real post-KeyUpdate gap produces. A wholly corrupted key log therefore used
  to report clean. The new `KeylogParseResult` carries a status from a closed
  four-value vocabulary in increasing severity order — `ok` (read end to end,
  every secret row well formed), `partial` (secrets recovered but content was
  lost: a malformed row, or an error part-way through), `unreadable` (present
  but nothing recoverable — no CSV header, no `line` column, or a failure
  before the first secret), `missing` (no such file) — alongside `rows_read`,
  `rows_malformed` and `secrets_available`. Two details are deliberate. **An
  unknown secret type is malformed, not filtered:** the type token is checked
  against the whole protocol registry, never against the caller's template, so
  a type the registry does not know is a row nothing can ever read and is
  counted as damage, while a type the registry knows but the caller's template
  excludes was filtered on purpose and leaves the status `ok`. And an abort
  part-way through the file charges the row in flight, so `rows_malformed` is
  never a reassuring `0` beside a truncated file; both counters are documented
  as lower bounds. **`KeylogParser.parse` is unchanged for its existing
  callers** — it delegates here and returns `.secrets` — including its exact
  log surface: it passes `log_structure_warnings=False` so the new structural
  diagnostics stay at `DEBUG` on that path and only the two historical
  `WARNING`s remain. That matters because `parse` runs once per run over a
  multi-thousand-run corpus, where a systematically headerless corpus would
  otherwise emit one new warning per run from a path that was always quiet.
  The status is still returned either way. On the measured corpus the parse is
  clean (2,598/2,598 headers exactly `id,line`, 7,790/7,790 secret lines
  exactly three fields, zero malformed rows), so this costs nothing today — it
  is what keeps that true.
- `core/artifact_util.atomic_write_text()` — the `unique tmp + os.replace`
  primitive lifted out of `api.services.task_manager.TaskManager._persist`, so
  the task manager and the sweep ledger share one implementation instead of
  growing a second copy. It lives in `core/` rather than `api/` specifically
  because `app/` — where the sweep ledger writes its `manifest.json` — must not
  import `api/`. Three properties are load-bearing and documented as such: the
  tmp name is unique **per write** (a shared `<name>.tmp` let two writers
  interleave into torn output, or made the second `os.replace` raise
  `FileNotFoundError` because the tmp had already been moved), `os.replace`
  onto the final path is atomic on POSIX and Windows so a reader sees the old
  file or the new one and never a partial one, and cleanup catches
  `BaseException` rather than `Exception` so a `KeyboardInterrupt` or a worker
  cancellation mid-write leaves no stray tmp behind. It deliberately does
  **not** `fsync`, matching the original: it guards against a *torn* file, not
  against power loss, and fsyncing every record write would serialise the hot
  progress-drain path on disk latency. It is equally deliberately not for large
  append-only files — it rewrites the whole file every call, so appending to a
  growing `results.jsonl` this way would be O(n^2) and push roughly 450 GB of
  writes over a 30,000-line sweep. `TaskManager.load_from_disk`'s startup sweep
  now removes both the legacy fixed `record.json.tmp` and the per-write
  `record.json.<hex>.tmp` spelling.

### Deferred follow-ups
- **`user_regex` confidence calibration** —
  `algorithms/unknown_key/user_regex.py:48` returns `min(total / 10.0, 1.0)`,
  an arbitrary heuristic that inflates confidence on dense matches.
  Track a calibration task: parameterize the divisor via context, or
  compute confidence per-pattern from match density × pattern complexity.
- **e2e dataset gate** — 24 of 25 Playwright specs in `tests/e2e/specs/`
  skip when no private dataset is mounted (`test.skip(!datasetAvailable, ...)`).
  CI cannot exercise the SPA without it. Track a task to either (a) build a
  minimal synthetic `.msl` fixture under `tests/e2e/fixtures/synthetic_msl/`
  or (b) tag specs `requires-dataset` and document the CI strategy.

## [0.5.1] — 2026-04-14

- TLS polymorphic structures + FTUE tour framework
  (841 tests).
- (packaging/ops) resolved — MemDiver is now PyPI-publishable.
