import path from "node:path";
import os from "node:os";
import { existsSync, readdirSync } from "node:fs";

/**
 * Two fixture tiers gate the e2e specs:
 *
 *  - SMOKE specs (load an MSL + assert inspect/blocks/tabs render) should
 *    gate on `syntheticMslAvailable` and load `syntheticMslPath`. The
 *    synthetic fixture is committed (see tests/e2e/fixtures/synthetic_msl/
 *    sample.msl, regenerated via generate.py), so `syntheticMslAvailable`
 *    is effectively always true and these flows run on any machine / CI.
 *
 *  - DEEP / analysis specs that need the large real capture keep gating on
 *    `datasetAvailable` and load `MSL` (the private run_0001 dataset). They
 *    skip automatically when the dataset is absent.
 *
 * Both flags coexist; nothing below removes the real-dataset path.
 */
const DEFAULT =
  "/Users/danielbaier/research/projects/github/issues/2024 fritap issues/2026_success/mempdumps/dataset_memory_slice";

export const DATASET_ROOT = process.env.MEMDIVER_DATASET ?? DEFAULT;
// The directory of decrypted run_* dirs — a "Dataset" in wizard terms.
export const DATASET_DIR = path.join(DATASET_ROOT, "gocryptfs/dataset_gocryptfs");
export const RUN_0001 = path.join(DATASET_DIR, "run_0001");
export const MSL = path.join(RUN_0001, "memslicer.msl");
export const GDB_RAW = path.join(RUN_0001, "gdb_raw.bin");
export const LLDB_RAW = path.join(RUN_0001, "lldb_raw.bin");
export const GCORE = path.join(RUN_0001, "gcore.core");
export const datasetAvailable = existsSync(MSL);

/**
 * How many `run_*` dirs the real corpus actually holds, counted from disk.
 *
 * The pagination specs used to assert a hardcoded `toHaveCount(100)`. That is a
 * fact about a PRIVATE corpus, not about the product, so it went red the moment
 * the corpus changed size (it is 95 today) — and a permanently-red spec hides
 * the real regressions it was written to catch. Counting here keeps the strong
 * assertion ("every run accumulated", not "more than a page") while being
 * immune to the corpus growing or shrinking.
 *
 * 0 when the dataset is absent; those specs skip on `datasetAvailable` anyway.
 */
export const datasetRunCount = datasetAvailable
  ? readdirSync(DATASET_DIR).filter((n) => /^run_\d+$/.test(n)).length
  : 0;

/** Page size the dataset-runs endpoint is called with (see DatasetOverview). */
export const DATASET_PAGE_SIZE = 50;

// Synthetic, committed MSL fixture for smoke flows (no private dataset needed).
// Regenerate with: python tests/e2e/fixtures/synthetic_msl/generate.py
export const syntheticMslPath = path.join(
  __dirname,
  "synthetic_msl",
  "sample.msl",
);
export const syntheticMslAvailable = existsSync(syntheticMslPath);

// Committed live-capture .msl with exactly one heap and one stack region (and a
// VAS_MAP listing both) for the materialize import spec: unticking "stack"
// excludes exactly one 4 KiB region. Its dump UUID is fixed (HEAP_STACK_MSL_UUID).
// Regenerate with: python tests/e2e/fixtures/heap_stack_msl/generate.py
export const heapStackMslPath = path.join(__dirname, "heap_stack_msl", "sample.msl");
export const heapStackMslAvailable = existsSync(heapStackMslPath);
export const HEAP_STACK_MSL_UUID = "5eedc0de-0000-4000-8000-00000000beef";

// Committed live-capture .msl holding a REAL synthetic glibc ptmalloc2 [heap]
// (tests/fixtures/synth_heap.glibc_heap: tcache struct, in-use + tcache'd
// chunks, top chunk) plus libc.so.6 in the module list, so the heap analysis
// resolves to ptmalloc2 and recovers every chunk. expected.json is the
// builder's chunk oracle the heap-mode spec asserts against.
// Regenerate with: python tests/e2e/fixtures/glibc_heap_msl/generate.py
export const glibcHeapMslPath = path.join(__dirname, "glibc_heap_msl", "sample.msl");
export const glibcHeapExpectedPath = path.join(__dirname, "glibc_heap_msl", "expected.json");
export const glibcHeapMslAvailable =
  existsSync(glibcHeapMslPath) && existsSync(glibcHeapExpectedPath);

// Regenerate with: python tests/e2e/fixtures/scudo_msl/generate.py
export const scudoMslPaths = [1, 2, 3].map((run) =>
  path.join(__dirname, "scudo_msl", `scudo_run_${run}.msl`),
);
export const scudoExpectedPath = path.join(__dirname, "scudo_msl", "expected.json");
export const scudoMslAvailable =
  scudoMslPaths.every((p) => existsSync(p)) && existsSync(scudoExpectedPath);

// Committed ASLR-shifted .msl PAIR for the multi-dump specs (side-by-side
// panes + cross-dump overlay). Regenerate with:
//   python tests/e2e/fixtures/aslr_msl/generate.py
// The two runs carry the SAME regions at DIFFERENT bases, and the two regions
// move by DIFFERENT run-to-run deltas (0x1000 vs 0x10000000), so a viewer that
// assumes one scalar VA delta per dump cannot align them — which is exactly
// what makes an alignment bug visible in the pane/overlay assertions.
export const aslrMslRun1Path = path.join(__dirname, "aslr_msl", "run_1.msl");
export const aslrMslRun2Path = path.join(__dirname, "aslr_msl", "run_2.msl");
export const aslrMslPairAvailable =
  existsSync(aslrMslRun1Path) && existsSync(aslrMslRun2Path);

// Committed pcap-oracle fixture (see tests/e2e/fixtures/pcap/generate.py): a
// self-verifying (matched.msl, session_tls13.pcap) pair whose recovered
// SERVER_TRAFFIC_SECRET_0 decrypts the real captured TLS 1.3 session, plus the
// manifest describing the embedded secret. CI-runnable wherever the backend
// has the ``pcap`` extra (dpkt); the spec skips otherwise.
export const pcapMatchedMslPath = path.join(__dirname, "pcap", "matched.msl");
export const pcapCapturePath = path.join(__dirname, "pcap", "session_tls13.pcap");
export const pcapManifestPath = path.join(__dirname, "pcap", "manifest.json");
// manifest.json is read at module top by pcap-upload-run.spec.ts, so a missing
// manifest must skip cleanly rather than error at collection.
export const pcapFixtureAvailable =
  existsSync(pcapMatchedMslPath) &&
  existsSync(pcapCapturePath) &&
  existsSync(pcapManifestPath);

// --- The phase-series TLS corpus (A6 candidate-table spec) ---
//
// A run directory of same-size `.dump` files captured from ONE process at
// consecutive phases -- the shape the differential workflow exists for, and
// the corpus the all-non-invariant class default was measured on (an OpenSSL
// TLS 1.2 run whose real 48-byte secret classifies as 22 KEY_CANDIDATE + 18
// POINTER + 8 STRUCTURAL). Private, like the dataset above, so specs gate on
// `tlsPhaseDumpsAvailable` and skip elsewhere.
//
// Override the root with MEMDIVER_TLS_DUMPS. Filenames carry capture
// timestamps, so they are DISCOVERED and sorted rather than hardcoded.
const TLS_DUMPS_DEFAULT = path.join(os.homedir(), "Desktop", "tls_dumps");
export const TLS_DUMPS_ROOT = process.env.MEMDIVER_TLS_DUMPS ?? TLS_DUMPS_DEFAULT;
const TLS_PHASE_RUN_DIR = path.join(
  TLS_DUMPS_ROOT,
  "TLS12",
  "100_iterations_Abort",
  "openssl",
  "openssl_run_12_1",
);

/**
 * The first N phase dumps of that run, sorted (their names are timestamps, so
 * sort order is capture order). N must be >= 3: below
 * `MIN_N_FOR_VARIANCE` the backend declares the cross-dump variance
 * untrustworthy and skips the class gate entirely, which would leave a
 * class-filter assertion testing nothing.
 */
export function tlsPhaseDumps(count = 3): string[] {
  try {
    return readdirSync(TLS_PHASE_RUN_DIR)
      .filter((name) => name.endsWith(".dump"))
      .sort()
      .slice(0, count)
      .map((name) => path.join(TLS_PHASE_RUN_DIR, name));
  } catch {
    return [];
  }
}

export const tlsPhaseDumpsAvailable = tlsPhaseDumps(3).length === 3;
