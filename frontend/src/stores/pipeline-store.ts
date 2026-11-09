/**
 * Pipeline tab Zustand store.
 *
 * Owns the entire state machine for the "Pipeline" bottom tab: which
 * wizard stage the user is on, the form values they've filled in, the
 * in-flight task id, live-progress rollups (funnel stage counts,
 * n-sweep survivor curve, timings), verified hits, registered
 * artifacts, and terminal status.
 *
 * State that should survive a tab-switch re-mount (form values,
 * stage, taskId, lastSeq) is persisted to localStorage via Zustand's
 * ``persist`` middleware; live event state (funnel, timings, hits) is
 * not persisted and is recovered on reconnect by two complementary
 * mechanisms. The WebSocket ring buffer replays the last 512 events,
 * which covers a SHORT gap (a tab switch, a blip). It does not cover a
 * long one: a stride-1 brute-force run emits thousands of progress
 * events, so anything older has already been evicted. For that case the
 * canonical ``TaskRecord`` is the source of truth, folded in by
 * ``hydrateFromRecord``.
 *
 * The ``ingestEvent`` reducer translates backend TaskProgressEvents into
 * state deltas. The hook ``useTaskProgress`` wires events into this
 * reducer; ingestEvent itself is pure and trivially unit-testable.
 */

import { create } from "zustand";
import { persist } from "zustand/middleware";

import type {
  ArtifactSpec,
  BruteForceParams,
  EmitParams,
  NSweepParams,
  PcapPair,
  PcapSession,
  PipelineRunRequest,
  ReduceParams,
  ScudoParams,
  StageRecord,
  TaskRecord,
  TaskStatus,
} from "@/api/pipeline";
import {
  isBruteForceStageEnd,
  isConsensusStageEnd,
  isEmitPluginStageEnd,
} from "@/api/websocket";
import type {
  BruteForceHitPayload,
  OracleHitExtra,
  TaskProgressEvent,
} from "@/api/websocket";
// ``StageDiagnostic`` is only declared in the wire-schema module and is not
// part of the ``@/api/websocket`` re-export surface, so it is imported from
// its defining module rather than redeclared here.
import type { ScudoReduceSummary, StageDiagnostic } from "@/api/progress-events";
import { isScudoReduceStageEnd } from "@/api/progress-events";
import { runPipeline } from "@/api/pipeline";
import { readableFailure } from "@/api/client";
import {
  offerForcedResubmit,
  withForceMemory,
  type TaskFailureSource,
} from "@/api/memory-budget";

// v1 -> v2: the brute-force stride default changed 8 -> 1 (full coverage).
// v2 -> v3: the brute-force jobs default changed 1 -> 0 (auto-parallel).
// The bump is REQUIRED for `migrate` to run at all -- zustand only invokes it
// when the stored version differs from this one, so a migration shipped under
// the previous version would never fire for the very blobs it needs to fix.
const PIPELINE_STORE_VERSION = 3;

/** The brute-force stride default that shipped with schema v1. */
const STALE_V1_STRIDE = 8;

/** The brute-force jobs default that shipped with schema v1 and v2. */
const STALE_V2_JOBS = 1;

export type WizardStage =
  | "recipe"
  | "dumps"
  | "oracle"
  | "thresholds"
  | "running"
  | "results";

/** Narrow set of survivor counts we animate in the funnel viz. */
export interface FunnelCounts {
  raw: number;
  variance: number;
  aligned: number;
  high_entropy: number;
  candidates: number;
  verified: number;
}

export interface StageTimings {
  consensus_ms: number;
  reduce_ms: number;
  brute_force_ms: number;
}

/** A single convergence measurement after folding N dumps. */
export interface ConvergencePoint {
  n: number;
  staticCount: number;
  dynamicCount: number;
}

/** One (N, counts) sample from an n-sweep run, for the survivor curve. */
export interface NSweepPoint {
  n: number;
  stages: Record<string, number>;
  candidates: number;
  hits: number;
  hit_offset: number | null;
  timing_ms: Partial<StageTimings>;
}

/**
 * How much of the brute-force search space the run actually examined.
 *
 * The stage tests candidate offsets on an absolute ``stride`` grid: at
 * stride=N only offsets that are multiples of N are ever handed to the
 * oracle. A secret sitting at an unaligned offset is therefore invisible to
 * the run -- and a zero-hit result is indistinguishable from "the key is not
 * in this dump" unless the coverage is surfaced. The default is stride=1
 * (full coverage) precisely so that never happens silently, but the user can
 * raise the stride to trade coverage for speed. Reported on every run, not
 * just failing ones: "1 hit" out of a 16%-covered space is a very different
 * forensic claim from "1 hit" out of an exhaustive one.
 */
export interface BruteForceCoverage {
  /** Windows actually tested (same number the backend calls total_candidates). */
  tested: number;
  /** Windows a stride-1 grid would have tested. */
  possible: number;
  /** The offset step the grid used. */
  stride: number;
  /** ``tested / possible``; 1.0 when the search was exhaustive. */
  fraction: number;
}

/**
 * Live candidates/sec rate and remaining-time estimate for the brute-force
 * stage, derived entirely in the frontend from the `tried` / `total`
 * counters the engine already puts on every `brute_force:progress` event.
 *
 * Deliberately NOT computed server-side: no non-web surface consumes
 * progress events, so an engine-side ETA would be discarded on three of the
 * four surfaces, and a server-stamped ETA goes stale the moment it sits in
 * the replay ring waiting for a reconnect.
 *
 * ``lastTs`` / ``lastTried`` are the previous sample, kept so the next event
 * can form a delta. ``lastTs`` is the SERVER clock (``event.ts``), never
 * ``Date.now()``: a reconnect replays up to 512 ring events back-to-back, and
 * wall-clock deltas across that burst would report a fictitious rate.
 */
export interface Throughput {
  /** Smoothed candidates per second (EWMA); 0 until a second sample lands. */
  perSec: number;
  /** Seconds of work left, or ``null`` while it cannot yet be estimated. */
  etaSeconds: number | null;
  /** ``event.ts`` of the sample this was computed from (server seconds). */
  lastTs: number;
  /** ``extra.tried`` of that same sample. */
  lastTried: number;
}

export interface HitRecord {
  offset: number;
  size: number;
  region_index: number;
  key_hex: string;
  neighborhood_start: number;
  neighborhood_variance: number[];
  /** True when the backend proved this key (vs. merely scoring it). */
  verified?: boolean;
  /**
   * How the key was proven ("pcap" / "oracle" / "verifier" / ...), or
   * ``null`` when the emitter said nothing. Kept a plain ``string`` so an
   * unrecognised backend label degrades to a UI fallback rather than a
   * type error -- see the note on ``BruteForceHitPayload.confirmed_by``.
   */
  confirmedBy?: string | null;
}

/**
 * The union of the two wire shapes that carry a hit: brute-force
 * ``stage_end`` payloads and ``oracle_hit`` extras. They overlap on
 * everything except the size key (``length`` vs. ``size``), so one
 * intersection type covers both call sites.
 */
type WireHitPayload = BruteForceHitPayload & OracleHitExtra;

/**
 * Normalize one wire hit payload into a ``HitRecord``. Pure; shared by
 * the brute-force ``stage_end`` and ``oracle_hit`` branches of the
 * reducer so the two mappings can't drift apart.
 */
export function toHitRecord(h: WireHitPayload): HitRecord {
  return {
    offset: Number(h.offset ?? 0),
    // The two emitters disagree on the size key: a brute-force stage_end
    // hit carries ``length`` while ``oracle_hit`` carries ``size``. Read
    // both, or one of the two paths silently normalizes every hit to 0.
    size: Number(h.length ?? h.size ?? 0),
    region_index: Number(h.region_index ?? 0),
    key_hex: String(h.key_hex ?? ""),
    neighborhood_start: Number(h.neighborhood_start ?? 0),
    neighborhood_variance: Array.isArray(h.neighborhood_variance) ? h.neighborhood_variance : [],
    verified: h.verified,
    confirmedBy: typeof h.confirmed_by === "string" ? h.confirmed_by : null,
  };
}

export interface InferredField {
  offset: number;
  length: number;
  type: "static" | "key_material" | "dynamic";
  label: string;
  mean_variance: number;
}

export interface PipelineFormValues {
  sourcePaths: string[];
  oracleId: string | null;
  oracleSha256: string | null;
  // Alternative to a BYO oracle: a pcap/pcapng of the same TLS session, routed
  // through the first-party trusted pcap oracle. Mutually exclusive with
  // oracleId. tlsClientRandom (hex) optionally restricts matching to one session.
  pcapPath: string | null;
  tlsClientRandom: string | null;
  // The C3 alternative to the single ``pcapPath`` above: N explicit
  // ``(dump, capture)`` pairings, so each dump is searched for a field taken
  // from ITS OWN capture. ``null`` -- the default -- means "no explicit
  // pairing", which is today's behaviour unchanged: ``sourcePaths`` plus one
  // ``pcapPath``. It is deliberately additive rather than a replacement,
  // because a single capture remains the overwhelmingly common case and the
  // pipeline run itself still takes exactly one.
  pcapPairs: PcapPair[] | null;
  reduce: ReduceParams;
  bruteForce: BruteForceParams;
  nsweep: NSweepParams | null;
  emit: EmitParams | null;
  // The server refuses ``nsweep`` and ``emit`` for the Scudo method, so
  // everything that selects it clears those two as well.
  scudo: ScudoParams | null;
}

export interface PipelineState {
  // persisted
  stage: WizardStage;
  form: PipelineFormValues;
  taskId: string | null;
  lastSeq: number;
  // TLS sessions the server parsed out of the armed pcap (form.pcapPath).
  // Drives the Oracle-stage session picker and the key-log composer's
  // "prefill client_random from pcap" synergy. NOT persisted: it would
  // re-serialize on every WS progress tick (a hot path) and would go stale
  // after a server restart, so the list simply re-populates when the user
  // re-validates ``form.pcapPath`` (which is persisted) with the Oracle
  // stage's "Arm / re-validate" button (``data-testid="pcap-arm-btn"``).
  pcapSessions: PcapSession[];
  /**
   * The (unforced) body of the run this tab last submitted. NOT persisted and
   * NOT cleared by ``setTaskId``: it is what ``offerForcedRerun`` re-sends with
   * ``force_memory: true`` when the run fails on the server memory guard.
   */
  lastRunRequest: PipelineRunRequest | null;

  // ephemeral (rebuilt from the WS replay on reconnect)
  status: TaskStatus | "idle";
  funnel: FunnelCounts;
  nsweepPoints: NSweepPoint[];
  timings: StageTimings;
  hits: HitRecord[];
  /**
   * Search-space coverage reported by the brute_force stage, or ``null``
   * when the run has not reached that stage yet (or ran against an older
   * backend that does not report it).
   */
  coverage: BruteForceCoverage | null;
  /**
   * Live candidates/sec + ETA for the in-flight brute_force stage, or
   * ``null`` outside it. Deliberately NOT persisted: it updates on every
   * progress tick, and writing it through ``partialize`` would re-serialize
   * localStorage thousands of times per run.
   */
  throughput: Throughput | null;
  /**
   * Non-fatal notes the brute_force stage attached to its result, e.g.
   * ``brute_force.partial_coverage``. Each ``message`` is a complete English
   * sentence composed by the backend and is rendered verbatim.
   */
  warnings: StageDiagnostic[];
  /** Holds its own diagnostics because the brute_force ``stage_end`` replaces ``warnings``. */
  scudoSummary: ScudoReduceSummary | null;
  inferredFields: InferredField[];
  artifacts: ArtifactSpec[];
  activeStage: string | null;
  activeStagePct: number;
  activeStageMsg: string;
  error: string | null;

  // refine workflow (Phase C)
  convergenceHistory: ConvergencePoint[];
  refineLoading: boolean;
  consensusNumDumps: number;

  // actions
  setStage: (stage: WizardStage) => void;
  updateForm: (patch: Partial<PipelineFormValues>) => void;
  setPcapSessions: (sessions: PcapSession[]) => void;
  setTaskId: (taskId: string | null) => void;
  ingestEvent: (event: TaskProgressEvent) => void;
  hydrateFromRecord: (record: TaskRecord) => void;
  resetRun: () => void;
  setLastRunRequest: (body: PipelineRunRequest | null) => void;
  /**
   * If the current run failed on the memory guard (terminal ``error`` event or
   * task record), offer the "Run anyway" dialog and re-submit the last body
   * with ``force_memory: true``. A no-op for any other failure.
   */
  offerForcedRerun: (source: TaskFailureSource) => Promise<void>;
  addConvergencePoint: (point: ConvergencePoint) => void;
  setRefineLoading: (loading: boolean) => void;
}

/**
 * Only the Scudo method has a key-size control, so leaving it restores this.
 * A leftover 48 would otherwise apply to a positional run with no field showing it.
 */
export const DEFAULT_KEY_SIZES: number[] = [32];

const DEFAULT_FORM: PipelineFormValues = {
  sourcePaths: [],
  oracleId: null,
  oracleSha256: null,
  pcapPath: null,
  tlsClientRandom: null,
  pcapPairs: null,
  reduce: {
    alignment: 8,
    block_size: 32,
    density_threshold: 0.5,
    min_variance: 3000.0,
    entropy_window: 32,
    entropy_threshold: 4.5,
    min_region: 16,
  },
  bruteForce: {
    key_sizes: DEFAULT_KEY_SIZES,
    stride: 1,
    // 0 = auto: the backend (engine.brute_force.resolve_jobs) stays serial for
    // a small or first-hit sweep and uses a small worker pool for a large
    // exhaustive one. Any explicit value the user picks is used verbatim.
    jobs: 0,
    exhaustive: true,
    top_k: 10,
  },
  nsweep: null,
  emit: null,
  scudo: null,
};

export const DEFAULT_SCUDO: ScudoParams = { allocator: "auto" };

const DEFAULT_FUNNEL: FunnelCounts = {
  raw: 0,
  variance: 0,
  aligned: 0,
  high_entropy: 0,
  candidates: 0,
  verified: 0,
};

const DEFAULT_TIMINGS: StageTimings = {
  consensus_ms: 0,
  reduce_ms: 0,
  brute_force_ms: 0,
};

function baseRunState(): Pick<
  PipelineState,
  | "status"
  | "funnel"
  | "nsweepPoints"
  | "timings"
  | "hits"
  | "coverage"
  | "throughput"
  | "warnings"
  | "scudoSummary"
  | "inferredFields"
  | "artifacts"
  | "activeStage"
  | "activeStagePct"
  | "activeStageMsg"
  | "error"
  | "convergenceHistory"
  | "refineLoading"
  | "consensusNumDumps"
> {
  return {
    status: "idle",
    funnel: { ...DEFAULT_FUNNEL },
    nsweepPoints: [],
    timings: { ...DEFAULT_TIMINGS },
    hits: [],
    coverage: null,
    throughput: null,
    warnings: [],
    scudoSummary: null,
    inferredFields: [],
    artifacts: [],
    activeStage: null,
    activeStagePct: 0,
    activeStageMsg: "",
    error: null,
    convergenceHistory: [],
    refineLoading: false,
    consensusNumDumps: 0,
  };
}

/**
 * Maps a ``TaskRecord`` stage name onto its ``StageTimings`` slot. Only the
 * three stages the timing table renders are listed; ``escalate`` / ``nsweep``
 * / ``emit_plugin`` have no row of their own and are skipped.
 */
const RECORD_STAGE_TO_TIMING: Record<string, keyof StageTimings> = {
  consensus: "consensus_ms",
  search_reduce: "reduce_ms",
  brute_force: "brute_force_ms",
};

/**
 * Wall-clock stage durations, rebuilt from the record's per-stage
 * ``started_at`` / ``ended_at`` timestamps (server seconds -> ms).
 *
 * A stage that is still mid-flight has no ``ended_at`` and contributes
 * nothing: a half-finished duration would understate the run and then jump.
 */
function deriveTimings(stages: StageRecord[]): StageTimings {
  const timings: StageTimings = { ...DEFAULT_TIMINGS };
  for (const stage of stages) {
    const slot = RECORD_STAGE_TO_TIMING[stage.name];
    if (!slot) continue;
    if (stage.started_at == null || stage.ended_at == null) continue;
    timings[slot] = Math.max(0, (stage.ended_at - stage.started_at) * 1000);
  }
  return timings;
}

/**
 * The stage whose progress bar the run dashboard should show: the one still
 * running, or -- when the record was fetched between stages -- the last one
 * that finished, so the panel never blanks out mid-run.
 */
function pickActiveStage(stages: StageRecord[]): StageRecord | null {
  const running = [...stages].reverse().find((s) => s.status === "running");
  if (running) return running;
  const succeeded = [...stages].reverse().find((s) => s.status === "succeeded");
  return succeeded ?? null;
}

/** Weight given to the newest instantaneous rate by the EWMA smoother. */
const THROUGHPUT_SMOOTHING = 0.2;

/**
 * Fold one ``brute_force:progress`` sample into the running throughput
 * estimate, or return ``null`` when the sample carries no usable delta.
 *
 * The first sample of a stage only seeds the baseline: there is nothing to
 * divide by yet, so it reports ``perSec: 0`` rather than inventing a rate.
 * A later sample is only usable when BOTH clocks moved forward. A replayed
 * ring burst arrives with identical ``ts`` values (dt === 0) and a rewound
 * ``tried`` can arrive out of order (dTried <= 0); either would divide by
 * zero or go negative, so such a sample is dropped and the caller keeps the
 * previous estimate untouched.
 */
function nextThroughput(
  prev: Throughput | null,
  tried: number,
  total: number | undefined,
  ts: number,
): Throughput | null {
  if (prev === null) {
    return { perSec: 0, etaSeconds: null, lastTs: ts, lastTried: tried };
  }
  const dt = ts - prev.lastTs;
  const dTried = tried - prev.lastTried;
  if (dt <= 0 || dTried <= 0) {
    return null;
  }
  const inst = dTried / dt;
  const perSec =
    prev.perSec > 0
      ? THROUGHPUT_SMOOTHING * inst + (1 - THROUGHPUT_SMOOTHING) * prev.perSec
      : inst;
  const etaSeconds =
    perSec > 0 && total != null && total > tried ? (total - tried) / perSec : null;
  return { perSec, etaSeconds, lastTs: ts, lastTried: tried };
}

/**
 * Apply one TaskProgressEvent to the current state. Pure function; no
 * Zustand ``set`` call inside. Exported so unit tests can verify
 * each event type in isolation without mounting a store.
 */
export function reducePipelineEvent(
  state: PipelineState,
  event: TaskProgressEvent,
): Partial<PipelineState> {
  // Already-seen events (e.g. replayed from the ring on reconnect) never
  // produce a state change — dropping them here avoids re-rendering
  // every subscriber for a no-op update.
  if (event.seq > 0 && event.seq <= state.lastSeq) {
    return {};
  }
  const patch: Partial<PipelineState> = {};
  if (event.seq > state.lastSeq) {
    patch.lastSeq = event.seq;
  }

  switch (event.type) {
    case "stage_start": {
      if (state.status === "idle") {
        patch.status = "running";
      }
      if (event.stage) {
        patch.activeStage = event.stage;
        patch.activeStagePct = 0;
        patch.activeStageMsg = event.msg ?? "";
      }
      break;
    }
    case "progress": {
      if (event.stage) {
        patch.activeStage = event.stage;
      }
      if (typeof event.pct === "number" && event.pct >= 0) {
        patch.activeStagePct = event.pct;
      }
      if (event.msg) {
        patch.activeStageMsg = event.msg;
      }
      // Engine search_reduce sub-stages carry funnel counts via extra.
      const extra = event.extra;
      if (extra && typeof extra.survivor_bytes === "number") {
        const survivor = extra.survivor_bytes;
        const input = extra.input_bytes;
        const next: FunnelCounts = { ...state.funnel };
        if (event.stage === "search_reduce:variance") {
          next.variance = survivor;
          if (typeof input === "number") next.raw = input;
        } else if (event.stage === "search_reduce:aligned") {
          next.aligned = survivor;
        } else if (event.stage === "search_reduce:entropy") {
          next.high_entropy = survivor;
          next.candidates = survivor;
        }
        patch.funnel = next;
      }
      // The brute_force sub-stage carries candidate counters instead, which
      // is everything needed to derive a live rate + ETA client-side.
      if (
        event.stage?.startsWith("brute_force") &&
        extra &&
        typeof extra.tried === "number"
      ) {
        const throughput = nextThroughput(
          state.throughput,
          extra.tried,
          extra.total,
          event.ts,
        );
        // ``null`` means the sample had no usable delta (replayed burst, or
        // a non-advancing counter); leave the previous estimate standing.
        if (throughput !== null) {
          patch.throughput = throughput;
        }
      }
      break;
    }
    case "stage_end": {
      if (event.stage) {
        patch.activeStage = event.stage;
        patch.activeStagePct = 1;
        patch.activeStageMsg = event.msg ?? "";
      }
      if (isScudoReduceStageEnd(event)) {
        patch.scudoSummary = event.extra;
      }
      // brute_force stage_end carries the verified count + hits.
      if (isBruteForceStageEnd(event)) {
        // The stage is over, so the rate/ETA readout has nothing left to
        // describe. Cleared here rather than left frozen on its last sample,
        // which would keep claiming work remained.
        patch.throughput = null;
      }
      if (isBruteForceStageEnd(event) && event.extra) {
        const extra = event.extra;
        if (typeof extra.verified_count === "number") {
          patch.funnel = {
            ...state.funnel,
            verified: extra.verified_count,
          };
        }
        if (Array.isArray(extra.hits)) {
          const mappedHits = extra.hits.map(toHitRecord);
          patch.hits = mappedHits;
          // Seed the initial convergence point from the first hit's neighborhood
          if (mappedHits.length > 0 && mappedHits[0].neighborhood_variance.length > 0) {
            const nbv = mappedHits[0].neighborhood_variance;
            // Prefer the backend-emitted threshold; fall back to the default
            // (2000) only for pre-upgrade backends that omit the field.
            const vt = typeof extra.variance_threshold === "number" ? extra.variance_threshold : 2000;
            const sc = nbv.filter((v) => v <= vt).length;
            const numDumps = state.consensusNumDumps || 0;
            patch.convergenceHistory = [{ n: numDumps, staticCount: sc, dynamicCount: nbv.length - sc }];
          }
        }
        // How much of the offset grid the search actually examined. Both
        // counters are required before ``coverage`` is written at all: a
        // pre-upgrade backend omits every field here, and inventing a
        // 0-of-0 search would put a false "0% covered" claim on screen.
        if (
          typeof extra.candidates_tested === "number" &&
          typeof extra.candidates_possible === "number"
        ) {
          const tested = extra.candidates_tested;
          const possible = extra.candidates_possible;
          patch.coverage = {
            tested,
            possible,
            // A missing stride means the grid was walked byte-by-byte.
            stride: typeof extra.stride === "number" ? extra.stride : 1,
            // Prefer the backend's own ratio; recompute only when it is
            // absent, and never divide by an empty search space.
            fraction:
              typeof extra.coverage_fraction === "number"
                ? extra.coverage_fraction
                : possible > 0
                  ? tested / possible
                  : 0,
          };
        }
        if (Array.isArray(extra.warnings)) {
          patch.warnings = extra.warnings;
        }
      }
      // consensus stage_end carries total_bytes so we can seed the funnel's
      // ``raw`` bar before the variance filter has a chance to run.
      if (isConsensusStageEnd(event) && event.extra) {
        const extra = event.extra;
        if (typeof extra.total_bytes === "number") {
          patch.funnel = {
            ...state.funnel,
            raw: extra.total_bytes,
          };
        }
        if (typeof extra.num_dumps === "number") {
          patch.consensusNumDumps = extra.num_dumps;
        }
      }
      // emit_plugin stage_end carries inferred structure fields.
      if (isEmitPluginStageEnd(event) && event.extra) {
        const extra = event.extra;
        if (extra.fields && Array.isArray(extra.fields)) {
          patch.inferredFields = extra.fields;
        }
      }
      break;
    }
    case "funnel": {
      // intentionally ignored (no store effect)
      break;
    }
    case "nsweep_point": {
      if (event.extra) {
        const extra = event.extra;
        if (typeof extra.n === "number") {
          const point: NSweepPoint = {
            n: extra.n,
            stages: extra.stages ?? {},
            candidates: extra.candidates_tried ?? 0,
            hits: extra.hits ?? 0,
            hit_offset: extra.hit_offset ?? null,
            timing_ms: extra.timing_ms ?? {},
          };
          patch.nsweepPoints = [...state.nsweepPoints, point];
        }
      }
      break;
    }
    case "oracle_tick": {
      // intentionally ignored (no store effect)
      break;
    }
    case "oracle_hit": {
      if (event.extra) {
        const extra = event.extra;
        if (typeof extra.offset === "number") {
          patch.hits = [...state.hits, toHitRecord(extra)];
        }
      }
      break;
    }
    case "artifact": {
      if (event.artifact?.name) {
        const artifact: ArtifactSpec = {
          name: event.artifact.name,
          relpath: event.artifact.relpath ?? event.artifact.path ?? "",
          media_type: event.artifact.media_type ?? "application/octet-stream",
          size: event.artifact.size ?? 0,
          sha256: event.artifact.sha256 ?? null,
          registered_at: event.ts,
        };
        patch.artifacts = [...state.artifacts, artifact];
      }
      break;
    }
    case "done": {
      patch.status = "succeeded";
      patch.activeStagePct = 1;
      patch.throughput = null;
      break;
    }
    case "error": {
      // ``cancelled`` uses the error event with that specific payload
      // per TaskManager.cancel(); discriminate so the UI can show a
      // neutral "cancelled" status instead of a red error banner.
      if (event.error === "cancelled") {
        patch.status = "cancelled";
      } else {
        patch.status = "failed";
        patch.error = event.error ?? "unknown error";
      }
      patch.throughput = null;
      break;
    }
  }
  return patch;
}

/** The persisted slice -- exactly the shape ``partialize`` writes. */
export type PersistedPipelineState = Pick<
  PipelineState,
  "stage" | "form" | "taskId" | "lastSeq"
>;

/**
 * v1 -> v2: reset a stale brute-force stride, keep everything else.
 *
 * Schema v1 shipped ``bruteForce.stride: 8``, which enumerates only 8-aligned
 * offsets. On a real corpus dump that is 15.7% coverage: a TLS traffic secret
 * at offset 585148 (585148 % 8 === 4) is never handed to the oracle and the
 * run still reports "succeeded, 0 hits" -- indistinguishable from "the key is
 * not in this dump". A browser that had already persisted the form would
 * replay that forever, because ``DEFAULT_FORM`` only applies to a profile with
 * no stored blob. So the one stale value is rewritten in place.
 *
 * Only the exact old default is touched. A hand-picked 2/4/16 was typed
 * deliberately and survives, as does every other saved field: selected dumps,
 * armed oracle/pcap, reduce thresholds, wizard stage, in-flight task id.
 *
 * The spreads over ``DEFAULT_FORM`` also backfill fields added to
 * ``PipelineFormValues`` after a blob was written -- ``partialize`` stores
 * ``form`` wholesale and zustand's default merge is shallow, so without this
 * a newly added nested field rehydrates as ``undefined``.
 */
export function migratePipelineState(
  persisted: unknown,
  version: number,
): PersistedPipelineState {
  const state = (persisted ?? {}) as Partial<PersistedPipelineState>;
  const form = (state.form ?? {}) as Partial<PipelineFormValues>;
  const bruteForce = { ...DEFAULT_FORM.bruteForce, ...(form.bruteForce ?? {}) };

  if (version < 2 && bruteForce.stride === STALE_V1_STRIDE) {
    bruteForce.stride = DEFAULT_FORM.bruteForce.stride;
  }

  // Same failure mode as the stride reset above: a browser that has ever run
  // the pipeline holds jobs=1 in local storage, so without this every existing
  // client would stay pinned to the single-threaded sweep forever and never
  // see the auto-parallel default. Only the exact stale default is rewritten;
  // a user who deliberately picked another worker count keeps it.
  if (version < 3 && bruteForce.jobs === STALE_V2_JOBS) {
    bruteForce.jobs = DEFAULT_FORM.bruteForce.jobs;
  }

  return {
    stage: state.stage ?? "recipe",
    taskId: state.taskId ?? null,
    lastSeq: state.lastSeq ?? 0,
    form: {
      ...DEFAULT_FORM,
      ...form,
      reduce: { ...DEFAULT_FORM.reduce, ...(form.reduce ?? {}) },
      bruteForce,
    },
  };
}

export const usePipelineStore = create<PipelineState>()(
  persist(
    (set, get) => ({
      stage: "recipe",
      form: { ...DEFAULT_FORM },
      taskId: null,
      lastSeq: 0,
      pcapSessions: [],
      lastRunRequest: null,
      ...baseRunState(),

      setStage: (stage) => set({ stage }),
      updateForm: (patch) =>
        set((prev) => ({ form: { ...prev.form, ...patch } })),
      setPcapSessions: (sessions) => set({ pcapSessions: sessions }),
      setTaskId: (taskId) =>
        set({
          taskId,
          lastSeq: 0,
          ...baseRunState(),
          status: taskId ? "pending" : "idle",
        }),
      ingestEvent: (event) => {
        // Skip the set() entirely when the reducer short-circuits; an
        // empty patch would still allocate a fresh state object and
        // notify every subscriber on the hot path.
        const patch = reducePipelineEvent(get(), event);
        if (Object.keys(patch).length > 0) {
          set(patch);
        }
      },
      /**
       * Restore what a mid-run reload cannot recover from the event stream.
       *
       * The WebSocket ring holds only the last 512 events; a stride-1
       * brute-force run emits roughly 2,740 progress events on its own, so by
       * the time the user reloads the funnel/stage history has long fallen out
       * of the ring. The persisted ``TaskRecord`` is the only surviving record
       * of what already happened, so it -- not the replay -- repaints status,
       * artifacts, the active stage and the stage timings.
       *
       * DELIBERATELY DOES NOT READ OR WRITE ``lastSeq``. That cursor belongs
       * to the progress bus: ``reducePipelineEvent`` drops any event whose
       * ``seq <= lastSeq``, so advancing it here (the record carries no seq
       * numbers to advance it *to*) would silently swallow every real event
       * that arrives afterwards. Hydration is also kept out of ``ingestEvent``
       * for the same reason -- the reducer stays pure and seq-driven.
       */
      hydrateFromRecord: (record) => {
        const stages = record.stages ?? [];
        const active = pickActiveStage(stages);
        set({
          status: record.status,
          error: record.error ?? null,
          artifacts: record.artifacts ?? [],
          activeStage: active?.name ?? null,
          activeStagePct: active?.pct ?? 0,
          activeStageMsg: active?.msg ?? "",
          timings: deriveTimings(stages),
        });
      },
      resetRun: () =>
        set({
          taskId: null,
          lastSeq: 0,
          stage: "recipe",
          ...baseRunState(),
        }),
      addConvergencePoint: (point) =>
        set((s) => ({
          convergenceHistory: [...s.convergenceHistory, point],
        })),
      setRefineLoading: (loading) => set({ refineLoading: loading }),
      setLastRunRequest: (body) => set({ lastRunRequest: body }),
      offerForcedRerun: async (source) => {
        const { taskId, lastRunRequest } = get();
        if (!taskId || !lastRunRequest) return;
        try {
          await offerForcedResubmit(taskId, source, async () => {
            const resp = await runPipeline(withForceMemory(lastRunRequest, true));
            get().setTaskId(resp.task_id);
            set({ stage: "running" });
          });
        } catch (err) {
          set({ error: readableFailure(err) });
        }
      },
    }),
    {
      name: "memdiver-pipeline",
      version: PIPELINE_STORE_VERSION,
      partialize: (state) => ({
        stage: state.stage,
        form: state.form,
        taskId: state.taskId,
        lastSeq: state.lastSeq,
      }),
      migrate: migratePipelineState,
      // A persisted taskId means a run was in flight when this tab was
      // closed/reloaded. ``partialize`` does not persist ``status``, so the
      // initializer's ``baseRunState()`` would leave it at "idle" -- and the
      // only idle -> running transition is a ``stage_start`` event, which does
      // not arrive for MINUTES during a deep brute-force stage. For that whole
      // window the Cancel button and the "resuming" banner (both gated on
      // pending/running) would be invisible and the run would look dead.
      // "pending" is the honest state here: we know a task exists, we have not
      // heard from it yet. If the backend has actually forgotten the task, the
      // record fetch in PipelinePanel fails and its ``.catch`` calls
      // ``resetRun()``, which puts the status back to "idle".
      onRehydrateStorage: () => (state) => {
        if (state?.taskId) {
          state.status = "pending";
        }
      },
      // Deep-merge persisted form sections over the defaults. ``migrate`` only
      // runs when the stored version differs, so blobs already at v2 need the
      // same backfill for fields added later -- the same reason
      // settings-store.ts carries a custom merge.
      //
      // This is ALSO why a purely additive key needs no PIPELINE_STORE_VERSION
      // bump: ``current.form`` is DEFAULT_FORM, the persisted form spreads OVER
      // it, and a key the blob does not carry is therefore not overwritten. A
      // bump is required only to TRANSFORM stored data (the stride and jobs
      // rewrites in ``migrate``), because ``migrate`` never fires without one.
      // ``form.pcapPairs`` is the current example; the distinction is pinned by
      // tests/frontend/stores/pipeline-store.test.ts.
      merge: (persisted, current) => {
        const p = (persisted ?? {}) as Partial<PipelineState>;
        const form = (p.form ?? {}) as Partial<PipelineFormValues>;
        return {
          ...current,
          ...p,
          form: {
            ...current.form,
            ...form,
            reduce: { ...current.form.reduce, ...(form.reduce ?? {}) },
            bruteForce: {
              ...current.form.bruteForce,
              ...(form.bruteForce ?? {}),
            },
          },
        };
      },
    },
  ),
);

/**
 * Non-hook "is a run in flight?" probe. Reads the current status without
 * subscribing, so a caller does not re-render on every progress event.
 *
 * Currently has NO call sites -- it was written for a Workspace.tsx
 * auto-switch guard that never landed (`grep -rn "isPipelineRunning"
 * frontend/src/` finds only this definition). Kept as the intended
 * non-subscribing entry point for that check; read the store directly via
 * ``usePipelineStore.getState()`` only if you need more than the status.
 */
export function isPipelineRunning(): boolean {
  const status = usePipelineStore.getState().status;
  return status === "running" || status === "pending";
}
