# Web UI tour

A guided walk through the React SPA. Each screenshot below is regenerated deterministically by the Playwright harness documented in [](../contributing/index.md) — they stay in sync with the code, not a moving memory.

## Session landing

First screen when you open `http://127.0.0.1:8080`. Pick a saved session (**Load** / **Delete**) or click **New Session** to open the wizard. If you previously discarded unsaved work, a **Recovered work** entry (badge **RECOVERED**) is pinned to the top of the list — it is the only copy, so delete it deliberately.

```{figure} /_static/screenshots/01_landing.png
:alt: MemDiver session landing page, listing previously saved analysis sessions
:align: center

The session-landing view enumerates `.memdiver` SessionStore entries and offers a "New Session" entry point into the wizard.
```

## Starting a new session

**New Session** in the workspace toolbar (or `Ctrl+N`) resets the workspace. If the workspace has changes that were not saved yet, a **Start a new session?** dialog lists what is at stake (dumps loaded, analysis results, bookmarks) and offers:

- **Save and start new** — saves under the name in **Save as** (default: `<input folder>-YYYY-MM-DD-HHmm`) and then resets. Saving under an existing name replaces that session, so when the name matches a saved session the dialog warns *"A session named “…” already exists and will be overwritten."* The saved-session list is fetched each time the dialog opens; if that fetch fails, the warning is simply not shown. The warning does not block saving.
- **Discard and start new** — keeps the discarded workspace as the **Recovered work** session on the landing page, then resets.
- **Cancel**.

A clean workspace resets without asking. Closing or reloading the browser tab with unsaved changes triggers the browser's own "leave this page?" confirmation.

## Wizard — select data

Type a path or click **Browse** to open the file-browser modal.

The browser opens in the folder you last picked from (falling back to your home directory). Click **☆ Favourite** in the path bar to save the current folder; it then reads **Favourited**, and clicking it again removes it. Saved folders appear in the collapsible **Favourites** section — click one to jump there, or hover and press **✕** to remove it. Favourites and the last-browsed folder are stored per user on the server in `~/.memdiver/config.json` (or `$XDG_DATA_HOME/memdiver/config.json`), next to the upload and oracle directories, so they survive browser resets.

```{figure} /_static/screenshots/02_wizard_select_data.png
:alt: Wizard step one, showing path input and a file-browser modal
:align: center

Accepted input types: a single `.dump` or `.msl` file, a run directory (auto-detected), or a full dataset root.
```

## Wizard — analysis algorithms

```{figure} /_static/screenshots/03_wizard_analysis.png
:alt: Wizard step three, showing the 8-algorithm checkbox grid with availability hints
:align: center

Algorithms unavailable for the selected mode (verification vs exploration) are dimmed. Defaults match the recommended set from [](../algorithms/index.md).
```

## Workspace — default layout

```{figure} /_static/screenshots/04_workspace_default.png
:alt: MemDiver workspace in dark theme, showing hex viewer, sidebar, and bottom analysis panel
:align: center

The IDA-Pro-style dockable workspace: main hex panel, sidebar with six tabs, detail overlay, and a mode-gated bottom-tabs row.
```

## Hex viewer with structure overlay

```{figure} /_static/screenshots/05_hex_with_overlay.png
:alt: Hex viewer with a TLS-13 structure overlay highlighting bytes by classification
:align: center

Structural fields are colored by class (`static`, `dynamic`, `key_material`); overlays drive the investigation panel on the right.
```

The toolbar's search box finds a byte sequence typed as hex, text, UTF-16LE text, base64, or a 32/64-bit integer, and previews the resolved bytes before searching — see [Byte search](../visualizations/hex.md#byte-search) for the accepted formats. With two or more dumps selected, the **Main view layout** switcher offers **Single**, **Side by side**, and **Overlay**.

## Entropy profile

```{figure} /_static/screenshots/06_entropy_tab.png
:alt: Entropy profile chart with Shannon entropy plotted against byte offset and high-entropy regions shaded
:align: center

Sliding-window Shannon entropy: a min–max band per pixel column over every window position, with the maximum drawn as a line so a single key-sized spike stays visible. Shaded regions reach the threshold (default 4.5 bits/byte at the 32-byte window; a 32-byte window can reach at most log2(32) = 5.0, marked as a dashed line). Large dumps show a sampled preview first and refine to full resolution.
```

## Consensus view

```{figure} /_static/screenshots/07_consensus_tab.png
:alt: Consensus view — stacked bars showing per-byte classification counts across N dumps
:align: center

Consensus over multiple dumps from the same library and phase. Classification bands: `INVARIANT`, `STRUCTURAL`, `POINTER`, `KEY_CANDIDATE`.
```

The same consensus vector can be painted onto the hex bytes: switch the main view to **Overlay**, then use the **Regions** tab to list runs by class, filter them to an exact key size (`16 B`, `24 B`, `32 B`, `48 B`) and sort **Longest first**. See [Hex overlay](../visualizations/consensus.md#hex-overlay).

## Pipeline — wizard

The **pipeline** bottom tab is a six-step wizard: **Recipe** → **Dumps** → **Oracle** → **Thresholds** → **Run** → **Results**.

- **Recipe** — **Start blank** (store defaults) or **Replicate gocryptfs IMF result** (a preset that also turns on the N-sweep).
- **Dumps** — paste paths and **Add paths**, or **Browse folder…**. At least one dump is required; three or more make variance filtering meaningful. Dump 1 is marked **reference**: only its bytes are verified against the oracle.
- **Oracle** — **Upload** a `.py` oracle and **Arm oracle** it, or pick one from **Examples** (**Use this example**; examples that need config ask for it, then offer **Load + arm**). Alternatively, verify against a pcap instead of a BYO oracle. A smoke test (below) checks the oracle before you continue.
- **Thresholds** — search-reduce and brute-force parameters, plus optional **Emit a Volatility 3 plugin from the best hit** and **Run the N-sweep harness and build the interactive report**. **Run pipeline** submits the job.

## Pipeline — oracle smoke test

```{figure} /_static/screenshots/08_pipeline_oracle.png
:alt: Pipeline oracle-stage wizard showing uploaded decryption oracle with dry-run status
:align: center

Upload a bring-your-own decryption oracle (Python module matching the [oracle interface](../oracle/interface.md)), arm it, and smoke-test it before committing to a full sweep.

The smoke test (**Test on 16 samples**) is a *discrimination* test, not a pass count. The server feeds the oracle one candidate it must accept — the master key the run's `meta.json` records — and fifteen it must reject, read at random offsets from the dump itself. The verdict is shown as a sentence; its id (`discriminates`, `accepts_noise`, `never_accepts`, `no_positive_control`, `inconclusive`) is what the API returns. A green **discriminates** verdict means both halves held, and only then does **Continue to Thresholds →** appear. **accepts_noise** means the oracle accepted arbitrary memory and would flood a real sweep with false positives; **never_accepts** means it rejected its own known-good key, so the oracle or its config is wrong. When the dump has no `meta.json` there is no ground truth to test against, and the verdict says **no_positive_control** ("Half-tested") rather than pretending to a result. **inconclusive** means the run did not produce enough clean signal to judge the oracle; check the listed errors.

The positive control uses the dataset's recorded answer key, so it proves the oracle works — it is not itself a finding.
```

## Pipeline — run dashboard

```{figure} /_static/screenshots/09_pipeline_run.png
:alt: Live pipeline run dashboard with funnel chart, stage timings, and live oracle log
:align: center

Stages: `consensus` → `search_reduce` → `brute_force`, then the optional `escalate`, `nsweep`, and `emit_plugin`. The **Reduction funnel** shows candidates surviving each step (Raw → Variance → Aligned → Entropy → Candidates → Verified); the live log streams oracle hits, and **Verified hits** rows offer **Open in hex**.
```

### Android Scudo heaps across cold boots

After an Android cold boot Scudo has placed every heap chunk somewhere else, so the positional consensus compares unrelated bytes. Pick the **Android Scudo (cold boots)** recipe, or set **Reduction method** on the Thresholds step, to run the same chunk-consensus reduction as the [CLI](../quickstart/cli.md#android-scudo-heaps-across-cold-boots). It needs `.msl` dumps from at least two runs, and dump 1 is the reference, so the oracle or capture must belong to that run.

- **Allocator**: *Detect on dump 1* refuses a dump whose heap is not recognised as Scudo; *Force Scudo* skips that check.
- **Key sizes**: the window sizes brute-force tries, for example `48` for a SHA-384 TLS 1.3 traffic secret.
- **Scudo chunk verdicts** replaces the funnel: every chunk of the reference gets one verdict and counts as kept, dropped or *not judged*. A chunk whose signature is absent from another run was never compared, so it is not judged rather than ruled out. Warnings about the scan appear below the table.

The method stops at brute-force. **Volatility 3 plugin generation is not supported yet with it**, because a plugin is built from the per-byte variance around a hit and this method compares whole chunks across runs instead of byte positions. The N-sweep, escalation and Refine need the positional consensus for the same reason.

## Pipeline — results

```{figure} /_static/screenshots/10_pipeline_results.png
:alt: Pipeline results with survivor-curve chart and downloadable artifacts
:align: center

Downloadable artifacts include the finalized consensus state (`consensus/state.json`, which points at the Welford `mean.npy` / `m2.npy` arrays written next to it), the variance vector, `search_reduce/candidates.json`, the `brute_force/hits.json` catalog, the N-sweep report, and the synthesized Volatility 3 plugin with its YARA rule. The results view has **Plugin**, **Report**, and **Raw** tabs.
```

## Heap mode

The mode banner offers a third mode, **Heap**, next to verification and
exploration. Heap mode is exploration plus allocator-aware panels:

- The **Heap** side tab opens on entering the mode. It shows the detected
  allocator with its confidence and evidence, a *Partial* or *Heuristic* tag
  when the parser covers only part of the allocator, the platform and version
  hint, the heap regions (click one to jump there) and the chunk counts by
  state.
- The **Heap** bottom tab holds the chunk table (filter by state, size and
  address range; click a row to jump to the chunk), a size histogram, the
  free-list tree and a chunk inspector with the header fields and neighbouring
  chunks.
- The hex viewer paints a **heap layer**: every byte is colored by its role
  (chunk header, user data, free-list link, freed data, allocator metadata, top
  chunk, slack), and a tick marks each chunk start. The heap legend explains the
  colors. The **Heap layer** toolbar button hides the layer while you stay in
  the mode.

Allocators, roles and limitations are covered in
[Heap allocator awareness](heap.md).

## Theme triptych

```{figure} /_static/screenshots/11_theme_triptych.png
:alt: Three workspace panels side by side in light, dark, and dark-plus-high-contrast themes
:align: center

Light, dark, and dark+high-contrast modes. High-contrast mode passes WCAG AAA for text legibility.
```

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+N` | New session |
| `Ctrl+S` | Save the workspace as the session `autosave` |
| `Ctrl+G` | Go to offset |
| `Ctrl+B` | Toggle sidebar |
| `Arrow`, `Shift+Arrow` | Hex navigation / selection |
| `PageUp`, `PageDown` | Page-wise scrolling |
| `Home`, `End` | Start / end of the row; with `Ctrl`, start / end of the file |
| `n`, `p` | Jump to the next / previous region of the class chosen in the **Regions** panel |
| `Tab` | Move focus from the hex to the ASCII column (a second `Tab` leaves the grid) |
| `Esc` | Clear selection / back in wizard |

On macOS, `⌘` works wherever `Ctrl` is listed.

## Guided tours

The first time you reach the workspace a short layout tour runs, followed by a structure-overlay tour; the pipeline tab has its own tour the first time it opens. Dismissed or finished tours are remembered in the browser. Replay one from **Settings** → **Run onboarding tour**.
