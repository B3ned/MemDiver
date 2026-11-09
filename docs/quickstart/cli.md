# CLI quickstart

MemDiver exposes a single console script `memdiver` with 52 subcommands. The most common entry points:

```bash
# One-shot analysis on a library directory
memdiver analyze <library_dirs> --phase post_handshake_end --protocol-version TLS13

# Dataset sweep
memdiver scan --root /path/to/dataset

# Batch of analysis jobs
memdiver batch --config batch.json

# Already know the key? Find where it sits in every dump
memdiver locate-key runs/ --key-hex '<hex>' -o loc.json
```

`locate-key` exits `0` when the secret is found, `3` when it is proven absent
and `2` when nothing could be searched or the input is invalid (for example a
dump path that does not exist). See
[Locating a known key](../user_guide/locate_key.md) for the full workflow.

:::{tip}
Run `memdiver scan --root <dataset>` first to see which phases your dataset
actually contains. Canonical phases are defined in
`core/phase_normalizer.py:CANONICAL_PHASE_ORDER`
(`pre_handshake_end`, `post_handshake_end`, `pre_close`, `post_close`, …).
:::

## Recording what you concluded

`annotations` keeps a versioned, append-only record per capture inside a case
directory (`--case` is required for now). `supersede` and `retract` never edit
history; they append.

```bash
memdiver annotations add --case ./case --capture <sha256> --label "session key" \
  --location '{"space":"physical","value":4096}' --length 32
memdiver annotations list --case ./case --capture <sha256>
```

## Querying a case

`case` is the case data lake: every tabular output is a Parquet table with the
standard columns `capture_id, image_sha256, pid, space, addr, size, run_id`.
`query` runs ONE read-only SELECT (`--sql`, or SQL on stdin with `-`; bind
values with repeatable `--param`); `context-at` answers "what contains this
address" across every table plus the annotations, outermost layer first.
`export` fills the case from a dump (an `.mdview` view or an `.msl`): `--what`
(repeatable) picks `view_regions`, `msl_regions`, `page_states` or `heap_chunks`;
the default `auto` exports everything applicable and skips heap when no allocator
is detected. Over REST it is a job (`POST /api/case/export`).

```bash
memdiver case init mycase            # a bare name -> ~/.memdiver/cases/mycase
memdiver case status --case ./case
memdiver case schema --case ./case
memdiver case query --case ./case --sql "SELECT * FROM annotations WHERE pid = ?" --param 1
memdiver case export --case ./case ./process.msl
memdiver case context-at --case ./case \
  --location '{"space":"physical","value":4096,"capture_id":"<sha256>"}'
```

## Memory images

`image` opens a whole memory image (needs `pip install "memdiver[image]"`).
`probe` is cheap (no hashing, no pakunoda); `profile` resolves the kernel ISF
(pakunoda extraction takes ~15 s and maps the whole image); `open` writes a
`.mdview` descriptor that opens like any dump; `processes` lists its tasks;
`extract` writes a process view out as an `.msl`.

```bash
memdiver image probe alma-9.lime
memdiver image profile alma-9.lime
memdiver image open alma-9.lime --view process --pid 22176 --case ./case
memdiver image processes ./case/views/alma-9.process.pid22176.isf-<sha8>.mdview
memdiver image extract ./case/views/alma-9.process.pid22176.isf-<sha8>.mdview --out sshd.msl
```

## YARA rule editor

`isf` is the ISF workbench: `isf probe IMAGE kallsyms` runs a pakunoda probe, `isf draft create|set|import|get|diff|validate|export` edits a versioned ISF draft in a case, and `isf try IMAGE --case C --draft D` tries it with a Volatility plugin. `isf code-evidence IMAGE FUNCTION [--isf FILE]` decodes which struct fields a kernel function touches (`current`/deref accesses, joined to ISF members).
`disasm` (`disasm DUMP ADDRESS LENGTH`) decodes captured bytes only (`--arch`, `--mode thumb`, `--max-insns`, `--case`).

`yara` is the editor backend. `yara check RULE.yar` compiles a rule and prints its names, or the failing line
(`errors: [{line, message}]`, exit 1). `yara scan RULE.yar DUMP` scans only the
**captured** bytes of one `.msl`, `.mdview` or flat file, optionally a window
(`--view`, `--offset`, `--length`), so a pattern straddling a capture gap is never
found in invented zeros. Each row carries its coordinate system (`addr` + `space`,
`va`, `vas_offset`), and the result reports `coverage` and `truncated` (a cut by
`--limit`), plus a `warnings` entry when a wildcard string is wider than libyara
will verify (such a rule matches nothing). `scan-yara` is the many-dump census;
the web UI's YARA tab drives the same two producers.

```bash
memdiver yara check rule.yar
memdiver yara scan rule.yar dump.msl --limit 100
```

Rules can be stored and reused by name. `yara rules put NAME [FILE]` (stdin by default) saves a rule in
the per-user library (`~/.memdiver/yara_rules`) or, with `--scope case --case DIR`, in the case's
`yara_rules/`; a draft that does not compile is saved and flagged (`compiles: false`). `rules list` shows
both scopes (a case rule `shadows` a library one), `rules get NAME` prints the source, and `rules delete NAME`
removes it while keeping the last source under `history/`. `--scope` is explicit: `put`/`delete` default to
`case` when `--case` is given (else `library`) and `delete` touches exactly the scope it names; `get --scope
library|case|auto` (default `auto`: case first). `rules list` with a missing case keeps the library rows and
sets `case_error`. `check` and `scan` take `--rule-name NAME`
(+ `--case DIR`) instead of a file (giving both is an error); the result echoes `rule_name` and `scope`.

```bash
memdiver yara rules put keylog rule.yar
memdiver yara scan --rule-name keylog dump.msl
```

## Key finders

`keys` recognises key material by structure, with no ground truth: `keys list`
names the finders (today `aes_schedule`) and the `--params` each reads;
`keys scan DUMP` scans only the **captured** bytes of an `.msl`, `.mdview` or flat
file, one VA-contiguous run at a time, so a structure straddling a capture gap
is never found in invented zeros. Every row carries its coordinate system
(`addr` + `space`), heap-chunk and region context (`--heap-policy
off|annotate|mask`), and the result reports `coverage` and `truncated` (a cut by
`--limit`). `--case DIR` files the hits as the `key_hits` case table (join it to
`heap_chunks` / `msl_regions` with `case query`) plus `key_hit` annotations;
`--candidates-out FILE` writes a `candidates.json` for verify / brute-force. REST
runs inline up to 64 MiB of captured bytes and as a task beyond that (or with
`async`); the MCP server always runs inline.

```bash
memdiver keys list
memdiver keys scan dump.msl --finder aes_schedule --heap-policy annotate --case ./case
```

## Detector fixtures

`fixtures` gives a YARA rule or a key finder positive controls and decoys with a
verdict (`pass` / `fail` / `indeterminate`; no fixtures is `indeterminate`, never a
pass). `fixtures run --kind keyfinder aes_schedule` runs the bundled synthetic
AES-schedule fixtures; `fixtures run --kind yara RULE.yar --case ./case` runs the
stored fixtures that name a rule of the file and exits 0 / 1 / 2 for pass / fail /
indeterminate. `fixtures add`, `fixtures list` and `fixtures remove` manage the
fixtures stored in a case (`remove` archives, never loses).

```bash
memdiver fixtures run --kind keyfinder aes_schedule
memdiver fixtures add my_hit --kind yara --case ./case --artifact my_rule \
  --sample-hex 00000000deadbeef --expect '{"matches": [{"offset": 4}]}'
```

## Strings as a table

`strings table` lists every string of the captured bytes (`ascii`, `utf-8`,
`utf16le`; default ascii + utf16le), one row each with `addr` + `space`, region and
`iocs` badges. A string never crosses a capture gap, and `truncated` / `coverage` are
always reported. `--case` files the `strings` table; the `strings_iocs` saved query
(`memdiver vol3 query --saved strings_iocs`) then adds URL / email / IPv4 / path /
exe / archive / PEM / base64 columns. REST runs inline up to 64 MiB of captured bytes
and as a task beyond that (or with `async`). `memdiver inspect strings` is the
separate streaming extractor.

```bash
memdiver strings table dump.msl --min-len 6 --case ./case
```

## Volatility 3 plugins

`vol3` runs Volatility 3 plugins over a `.mdview` (needs `pip install
"memdiver[image]"`). `run --case` files the rows as the case table
`vol3__<os>_<plugin>` with the standard `addr`/`size`/`space` columns; `query`
runs SQL or a built-in `--saved` query over those tables (neither flag lists
the saved queries); `annotate` files one annotation per row; `scaffold`,
`check`, `write-config` and `import` support writing your own plugin or
importing an external `vol` output. A plugin given with `--source FILE` runs
**unsandboxed in this process** (its SHA-256 is logged); only run source you
trust. REST runs inline up to `timeout_s` 30 / `limit` 10000 and as a task
beyond that (or with `async`); the MCP server always runs inline.

```bash
memdiver vol3 list
memdiver vol3 run --view ./case/views/alma-9.kernel.isf-<sha8>.mdview --plugin linux.pslist --case ./case
memdiver vol3 run --view p.mdview --plugin linux.psscan --arg pid=[1,2] --case ./case
memdiver vol3 query --case ./case --saved hidden_processes
memdiver vol3 scaffold my_plugin > scaffold.json
memdiver vol3 check --source my_plugin.py --view p.mdview
memdiver vol3 source put my_plugin --case ./case --file my_plugin.py
memdiver vol3 source list --case ./case
memdiver vol3 run --view p.mdview --source-name my_plugin --case ./case
memdiver vol3 fixture put sshd_alive --case ./case --view p.mdview --plugin linux.pslist \
  --expect '{"row_where": {"COMM": "sshd", "PID": 22176}}'
memdiver vol3 fixture run sshd_alive --case ./case
```

`source put|get|list` keep plugin sources in the case (`plugins/<name>.py`, never
deleted: an overwrite archives the old text). `fixture put|list|run` check a
plugin against declarative row predicates (`min_rows`, `max_rows`, `row_where`,
`column_all`, `column_any`) and file a `pass`/`fail`/`indeterminate` verdict
(`fixture_verdict`) in the analysis record.

## Looking at the heap

`heap` finds the allocator that owns a dump's heap (glibc ptmalloc2,
dlmalloc, Scudo, musl mallocng, jemalloc, or a generic fallback) and walks
its chunks:

```bash
# Which allocator, how sure, chunk counts by state and a size histogram
memdiver heap summary dump.msl
# Ranked allocator candidates with their evidence
memdiver heap detect dump.msl
# Free (cached) chunks between 64 and 256 bytes, as JSON
memdiver heap chunks dump.msl --state cached --min-size 64 --max-size 256 --json
# The chunk that holds an address, and its neighbours
memdiver heap at dump.msl --va 0x555555559300
# Walked free lists (tcache, fastbins, ...)
memdiver heap free-lists dump.msl --kind tcache
# Byte roles (header, user data, free link, ...) of the first 4 KiB, as JSON
memdiver heap roles dump.msl --view vas --offset 0 --length 0x1000 --json
```

Every action takes `--allocator` to skip detection, `--base-va` for a flat
raw dump that has no memory map, the same decryption flags as `inspect`, and
`--json` for the machine-readable payload.

The consensus-backed commands also use the heap. `consensus`,
`consensus-window`, `consensus-regions`, `analyze-candidates` and `locate-key`
take `--allocator {auto,ptmalloc2,dlmalloc,scudo,mallocng,jemalloc,generic,off}`
(default `auto`; `off` turns heap analysis off). `analyze-candidates` and
`search-reduce` also take `--heap-policy {annotate,mask,off}`:

```bash
# Default: tag each candidate with its heap chunk, ranking unchanged
memdiver analyze-candidates dumps/ -o cands.json
# Remove allocator metadata from the candidates (count in stages.heap_masked)
memdiver analyze-candidates dumps/ --heap-policy mask -o cands.json
# Which hits of a known key sit in freed (residual) chunks?
memdiver locate-key dumps/ --key-hex '<hex>' --allocator ptmalloc2 -o loc.json
```

The JSON payload carries the heap data as it is. On stderr, `consensus`
prints a `heap status=...` line, and `analyze-candidates` and `locate-key`
print one line per chunk-resident candidate or hit, with hits in freed chunks
marked `residual`. `search-reduce` takes `--allocator {auto,ptmalloc2,off}`
(default `auto`): it uses the heap projections a session begun with
`consensus-begin --size N --allocator auto` recorded, else the
`--reference-dump` alone, and `--allocator off` keeps the historical payload.
See [Allocator-aware search-reduce](../user_guide/heap.md#allocator-aware-search-reduce).

## Android Scudo heaps across cold boots

Across Android cold boots a positional consensus does not line up — Scudo
re-places every heap chunk each run — so `search-reduce` takes a second kind of
`--state` session. Begin it with `consensus-begin --allocator scudo` (or
`auto`) instead of `--size`, record each cold-boot run with `consensus-add`
(the reference among them), then run `search-reduce --state …` as usual: it
pairs heap chunks by allocator signature and content across the runs, keeping
the reference's chunks that can hold a per-run value. `--allocator scudo`
forces the Scudo path; `--allocator auto` defers to memdiver's own allocator
detection on the reference at `search-reduce` time and requires Scudo (any
other allocator is refused — use `--size` for the generic pipeline). With
`--size`, `--allocator` keeps its generic meaning and only sets which heap roles
the session records.
`search-reduce`'s CLI surface is unchanged (`--state --reference-dump -o`); the
session's kind selects the pipeline, and the output is the same
`candidates.json` contract `brute-force` reads:

```bash
memdiver consensus-begin --state scudo.json --allocator scudo
for run in rnd-*.msl; do memdiver consensus-add --state scudo.json "$run"; done
memdiver search-reduce --state scudo.json --reference-dump rnd-1.msl \
  --key-sizes 48 -o cand.json
memdiver brute-force --candidates cand.json --dump rnd-1.msl --pcap "$PWD/rnd-1.pcap" \
  --key-sizes 48 --stride 1 -o hits.json
```

`--key-sizes` only sizes the reported window estimate; it never filters a
region. A short funnel — how the reference's chunks were judged, what is kept,
what could not be judged — goes to stderr. The positional flags such as
`--min-variance` do not apply to a Scudo session and are reported as ignored.

The chain ends at `brute-force`. Volatility 3 plugin generation is not supported
yet with this method: a plugin is built from the per-byte variance around a hit,
and this method compares whole heap chunks across runs instead of byte positions.

The web UI runs the same reduction; see the [web UI tour](../user_guide/web_ui_tour.md#android-scudo-heaps-across-cold-boots).

## Importing only some regions

```bash
# What would an import keep? (dry run, nothing written)
memdiver import core.1234 --list-regions --regions heap,stack
# Import only heap + stack (scripts / CI never prompt; without flags they import everything)
memdiver import core.1234 -o capture.msl --regions heap,stack
```

Run `memdiver import core.1234` in a terminal without region flags to pick
categories interactively (heap, stack and unclassified are preselected). See
[Import region selection](../user_guide/cli_reference.md) for every flag,
including `--materialize` for `.msl` input.

## When a consensus is too big for memory

Consensus-building commands (`consensus`, `consensus-window`, `consensus-regions`,
`analyze-candidates`, `analyze`, `batch`, `export --auto`, `experiment`) check
the estimated peak memory first and refuse when it exceeds the budget (70 % of
available RAM, or `MEMDIVER_MEMORY_BUDGET_MB`). Narrow the input
(`--regions heap,stack`, fewer dumps) or override the refusal:

```bash
memdiver consensus dumps/ --force-memory -o consensus.json
```

See [Memory budget](../user_guide/cli_reference.md) for details.

## Complete subcommand list

Detection &amp; analysis
: `analyze`, `scan`, `batch`, `verify`, `inspect`, `inspect-pcap`, `heap`

Consensus (incremental Welford)
: `consensus`, `consensus-begin`, `consensus-add`, `consensus-finalize`, `consensus-window`, `consensus-regions`

Pipeline (Phase-25 orchestration)
: `search-reduce`, `analyze-candidates`, `brute-force`, `n-sweep`, `auto-floor`, `emit-plugin`

Semantic layout &amp; artifact model
: `propose-layout`, `model-build`, `model-export`, `model-validate`, `consensus-anchor`, `xref-pointers`

Known secret &amp; detectors
: `locate-key`, `locate-field-pairs`, `export-key-pattern`, `scan-yara`, `verify-plugin`, `score-detector`

Format conversion
: `export`, `export-keylog`, `gen-kem-key`, `import`, `import-dir`

Runtime shells
: `web`, `ui`, `notebook`, `mcp`, `experiment`, `capture`

Run `memdiver <subcommand> --help` for flags, or see the full autogenerated [CLI reference](../user_guide/cli_reference.md).
