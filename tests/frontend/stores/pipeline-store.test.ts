import { afterEach, beforeEach, describe, it, expect } from "vitest";

import {
  migratePipelineState,
  reducePipelineEvent,
  usePipelineStore,
  type PipelineState,
} from "@/stores/pipeline-store";
import type {
  TaskProgressEvent,
  TaskProgressEventType,
} from "@/api/websocket";
import type { TaskRecord } from "@/api/pipeline";

/**
 * A complete, default PipelineState to reduce against. Grabbing the live
 * store's initial state gives every field (incl. the action closures) so we
 * only override the few slots each case exercises.
 */
function baseState(overrides: Partial<PipelineState> = {}): PipelineState {
  return { ...usePipelineStore.getState(), ...overrides };
}

/**
 * Builds one variant of the TaskProgressEvent union. Generic over the
 * ``type`` literal so ``fields`` is checked against that variant's own
 * ``extra`` shape (e.g. passing `{ extra: { survivor_bytes: 1 } }` for
 * "progress" vs. `{ extra: { total_bytes: 1 } }` for a "consensus"
 * `stage_end`) instead of the flattened shape a plain
 * `Partial<TaskProgressEvent>` would produce. The `as` is confined to
 * this test helper: TypeScript can't verify that spreading a
 * `Partial<Variant>` over the four common fields reconstructs exactly
 * `Variant`, but every field on the right of the spread is itself
 * type-checked against that variant, so this can't smuggle in a
 * mismatched shape.
 */
function event<T extends TaskProgressEventType>(
  type: T,
  fields: Partial<Extract<TaskProgressEvent, { type: T }>> = {},
): Extract<TaskProgressEvent, { type: T }> {
  return {
    task_id: "t1",
    type,
    seq: 1,
    ts: 100,
    ...fields,
  } as Extract<TaskProgressEvent, { type: T }>;
}

describe("reducePipelineEvent seq handling", () => {
  it("drops already-seen events (seq <= lastSeq) with an empty patch", () => {
    const patch = reducePipelineEvent(
      baseState({ lastSeq: 5 }),
      event("done", { seq: 3 }),
    );
    expect(patch).toEqual({});
  });

  it("advances lastSeq for newer events", () => {
    const patch = reducePipelineEvent(
      baseState({ lastSeq: 5 }),
      event("done", { seq: 6 }),
    );
    expect(patch.lastSeq).toBe(6);
  });

  it("does not gate seq==0 events on the dedup check", () => {
    // seq 0 skips the `seq > 0 && seq <= lastSeq` guard, and since 0 is not
    // > lastSeq no lastSeq patch is written, but the event still reduces.
    const patch = reducePipelineEvent(
      baseState({ lastSeq: 5 }),
      event("done", { seq: 0 }),
    );
    expect(patch.lastSeq).toBeUndefined();
    expect(patch.status).toBe("succeeded");
  });
});

describe("reducePipelineEvent stage_start", () => {
  it("flips idle -> running and seeds the active stage", () => {
    const patch = reducePipelineEvent(
      baseState({ status: "idle" }),
      event("stage_start", { stage: "consensus", msg: "starting" }),
    );
    expect(patch.status).toBe("running");
    expect(patch.activeStage).toBe("consensus");
    expect(patch.activeStagePct).toBe(0);
    expect(patch.activeStageMsg).toBe("starting");
  });

  it("does not overwrite status when already running", () => {
    const patch = reducePipelineEvent(
      baseState({ status: "running" }),
      event("stage_start", { stage: "reduce" }),
    );
    expect(patch.status).toBeUndefined();
    expect(patch.activeStageMsg).toBe("");
  });
});

describe("reducePipelineEvent progress", () => {
  it("updates active stage, pct and message", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("progress", { stage: "reduce", pct: 0.5, msg: "half" }),
    );
    expect(patch.activeStage).toBe("reduce");
    expect(patch.activeStagePct).toBe(0.5);
    expect(patch.activeStageMsg).toBe("half");
  });

  it("ignores negative pct sentinels", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("progress", { stage: "reduce", pct: -1 }),
    );
    expect(patch.activeStagePct).toBeUndefined();
  });

  it("folds search_reduce:variance survivor/input bytes into the funnel", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("progress", {
        stage: "search_reduce:variance",
        extra: { survivor_bytes: 400, input_bytes: 1000 },
      }),
    );
    expect(patch.funnel?.variance).toBe(400);
    expect(patch.funnel?.raw).toBe(1000);
  });

  it("maps search_reduce:entropy survivors into both high_entropy and candidates", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("progress", {
        stage: "search_reduce:entropy",
        extra: { survivor_bytes: 128 },
      }),
    );
    expect(patch.funnel?.high_entropy).toBe(128);
    expect(patch.funnel?.candidates).toBe(128);
  });
});

describe("reducePipelineEvent stage_end", () => {
  it("marks the stage complete (pct=1)", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", { stage: "reduce", msg: "done reduce" }),
    );
    expect(patch.activeStage).toBe("reduce");
    expect(patch.activeStagePct).toBe(1);
    expect(patch.activeStageMsg).toBe("done reduce");
  });

  it("records verified count and maps hits from a brute_force stage_end", () => {
    const patch = reducePipelineEvent(
      baseState({ consensusNumDumps: 4 }),
      event("stage_end", {
        stage: "brute_force",
        extra: {
          verified_count: 2,
          variance_threshold: 100,
          hits: [
            {
              offset: 16,
              length: 32,
              region_index: 1,
              key_hex: "deadbeef",
              neighborhood_start: 8,
              neighborhood_variance: [50, 200, 50],
            },
          ],
        },
      }),
    );
    expect(patch.funnel?.verified).toBe(2);
    expect(patch.hits).toEqual([
      {
        offset: 16,
        size: 32,
        region_index: 1,
        key_hex: "deadbeef",
        neighborhood_start: 8,
        neighborhood_variance: [50, 200, 50],
        // No proof fields on the wire -> confirmedBy normalizes to null
        // (``verified`` stays undefined, which toEqual treats as absent).
        confirmedBy: null,
      },
    ]);
    // Two of three neighborhood values (50, 50) are <= threshold 100 -> static.
    expect(patch.convergenceHistory).toEqual([
      { n: 4, staticCount: 2, dynamicCount: 1 },
    ]);
  });

  it("carries verified/confirmed_by through from a brute_force stage_end", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", {
        stage: "brute_force",
        extra: {
          hits: [
            {
              offset: 16,
              length: 32,
              key_hex: "deadbeef",
              verified: true,
              confirmed_by: "pcap",
            },
          ],
        },
      }),
    );
    expect(patch.hits?.[0]).toMatchObject({
      offset: 16,
      // brute_force's size key is ``length`` -- the shared mapper must
      // still honour it after unification with the oracle_hit path.
      size: 32,
      verified: true,
      confirmedBy: "pcap",
    });
  });

  it("normalizes a brute_force hit with no proof fields to confirmedBy null", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", {
        stage: "brute_force",
        extra: { hits: [{ offset: 16, length: 32, key_hex: "deadbeef" }] },
      }),
    );
    expect(patch.hits?.[0].confirmedBy).toBeNull();
    expect(patch.hits?.[0].verified).toBeUndefined();
    expect(patch.hits?.[0].size).toBe(32);
  });

  it("keeps a non-string confirmed_by out of the store (maps to null)", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", {
        stage: "brute_force",
        extra: {
          hits: [
            // Wire garbage: the backend contract says string, but the
            // reducer is the trust boundary and must not propagate it.
            { offset: 16, length: 32, confirmed_by: 7 as unknown as string },
          ],
        },
      }),
    );
    expect(patch.hits?.[0].confirmedBy).toBeNull();
  });

  it("seeds funnel.raw and consensusNumDumps from a consensus stage_end", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", {
        stage: "consensus",
        extra: { total_bytes: 4096, num_dumps: 5 },
      }),
    );
    expect(patch.funnel?.raw).toBe(4096);
    expect(patch.consensusNumDumps).toBe(5);
  });

  it("captures inferred fields from an emit_plugin stage_end", () => {
    const fields = [
      {
        offset: 0,
        length: 4,
        type: "static" as const,
        label: "magic",
        mean_variance: 0,
      },
    ];
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", { stage: "emit_plugin", extra: { fields } }),
    );
    expect(patch.inferredFields).toEqual(fields);
  });
});

describe("reducePipelineEvent brute_force coverage", () => {
  it("captures coverage and warnings from a brute_force stage_end", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", {
        stage: "brute_force",
        extra: {
          verified_count: 0,
          total_candidates: 110326,
          hits: [],
          candidates_tested: 110326,
          candidates_possible: 701084,
          stride: 8,
          coverage_fraction: 0.1573,
          warnings: [
            {
              code: "brute_force.partial_coverage",
              message: "No candidate was confirmed.",
              severity: "warning",
              details: { stride: 8 },
            },
          ],
        },
      }),
    );
    expect(patch.coverage).toEqual({
      tested: 110326,
      possible: 701084,
      stride: 8,
      fraction: 0.1573,
    });
    expect(patch.warnings).toEqual([
      {
        code: "brute_force.partial_coverage",
        message: "No candidate was confirmed.",
        severity: "warning",
        details: { stride: 8 },
      },
    ]);
  });

  it("recomputes the fraction when the backend omits coverage_fraction", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", {
        stage: "brute_force",
        extra: { candidates_tested: 25, candidates_possible: 100 },
      }),
    );
    expect(patch.coverage).toEqual({
      tested: 25,
      possible: 100,
      // No stride on the wire -> assume a byte-by-byte grid.
      stride: 1,
      fraction: 0.25,
    });
  });

  it("never divides by an empty search space", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", {
        stage: "brute_force",
        extra: { candidates_tested: 0, candidates_possible: 0, stride: 8 },
      }),
    );
    expect(patch.coverage?.fraction).toBe(0);
  });

  it("leaves coverage/warnings untouched for a pre-upgrade backend", () => {
    // Regression guard: an older worker emits neither counter. Writing a
    // 0-of-0 coverage here would put a false "0% covered" claim on screen.
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", {
        stage: "brute_force",
        extra: { verified_count: 1, hits: [] },
      }),
    );
    expect(patch.coverage).toBeUndefined();
    expect(patch.warnings).toBeUndefined();
    expect(baseState().coverage).toBeNull();
    expect(baseState().warnings).toEqual([]);
  });

  it("clears coverage and warnings when a new run starts", () => {
    const store = usePipelineStore.getState();
    usePipelineStore.setState({
      coverage: { tested: 1, possible: 2, stride: 8, fraction: 0.5 },
      warnings: [{ code: "brute_force.partial_coverage", message: "stale" }],
    });
    store.setTaskId("task-2");
    expect(usePipelineStore.getState().coverage).toBeNull();
    expect(usePipelineStore.getState().warnings).toEqual([]);

    usePipelineStore.setState({
      coverage: { tested: 1, possible: 2, stride: 8, fraction: 0.5 },
      warnings: [{ code: "brute_force.partial_coverage", message: "stale" }],
    });
    usePipelineStore.getState().resetRun();
    expect(usePipelineStore.getState().coverage).toBeNull();
    expect(usePipelineStore.getState().warnings).toEqual([]);
  });
});

describe("reducePipelineEvent nsweep_point", () => {
  it("appends a normalized point with defaulted fields", () => {
    const patch = reducePipelineEvent(
      baseState({ nsweepPoints: [] }),
      event("nsweep_point", {
        extra: { n: 3, stages: { variance: 10 }, candidates_tried: 7, hits: 1 },
      }),
    );
    expect(patch.nsweepPoints).toEqual([
      {
        n: 3,
        stages: { variance: 10 },
        candidates: 7,
        hits: 1,
        hit_offset: null,
        timing_ms: {},
      },
    ]);
  });

  it("ignores a point missing its n", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("nsweep_point", { extra: { stages: {} } }),
    );
    expect(patch.nsweepPoints).toBeUndefined();
  });
});

describe("reducePipelineEvent oracle_hit", () => {
  it("appends a hit onto the existing hits", () => {
    const existing = baseState({
      hits: [
        {
          offset: 0,
          size: 0,
          region_index: 0,
          key_hex: "",
          neighborhood_start: 0,
          neighborhood_variance: [],
        },
      ],
    });
    const patch = reducePipelineEvent(
      existing,
      event("oracle_hit", {
        extra: { offset: 64, size: 32, key_hex: "cafe" },
      }),
    );
    expect(patch.hits).toHaveLength(2);
    expect(patch.hits?.[1]).toMatchObject({
      offset: 64,
      size: 32,
      key_hex: "cafe",
    });
  });

  it("carries verified/confirmed_by through onto the appended hit", () => {
    const patch = reducePipelineEvent(
      baseState({ hits: [] }),
      event("oracle_hit", {
        extra: {
          offset: 64,
          size: 32,
          key_hex: "cafe",
          verified: true,
          confirmed_by: "pcap",
        },
      }),
    );
    expect(patch.hits?.[0]).toMatchObject({
      offset: 64,
      // oracle_hit's size key is ``size`` (not ``length``) -- the shared
      // mapper must still honour it after unification.
      size: 32,
      verified: true,
      confirmedBy: "pcap",
    });
  });

  it("normalizes an oracle_hit with no proof fields to confirmedBy null", () => {
    const patch = reducePipelineEvent(
      baseState({ hits: [] }),
      event("oracle_hit", { extra: { offset: 64, size: 32, key_hex: "cafe" } }),
    );
    expect(patch.hits?.[0].confirmedBy).toBeNull();
    expect(patch.hits?.[0].verified).toBeUndefined();
    expect(patch.hits?.[0].size).toBe(32);
  });

  it("passes through a confirmed_by label the UI does not special-case", () => {
    // The wire field is deliberately a plain string: an unrecognised
    // label must survive into the store rather than being dropped.
    const patch = reducePipelineEvent(
      baseState({ hits: [] }),
      event("oracle_hit", {
        extra: { offset: 64, size: 32, confirmed_by: "manual_review" },
      }),
    );
    expect(patch.hits?.[0].confirmedBy).toBe("manual_review");
  });
});

describe("reducePipelineEvent artifact", () => {
  it("registers an artifact with defaulted metadata and the event ts", () => {
    const patch = reducePipelineEvent(
      baseState({ artifacts: [] }),
      event("artifact", {
        ts: 999,
        artifact: { name: "keys.json", relpath: "out/keys.json" },
      }),
    );
    expect(patch.artifacts).toEqual([
      {
        name: "keys.json",
        relpath: "out/keys.json",
        media_type: "application/octet-stream",
        size: 0,
        sha256: null,
        registered_at: 999,
      },
    ]);
  });

  it("ignores an artifact event without a name", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("artifact", { artifact: { name: "" } }),
    );
    expect(patch.artifacts).toBeUndefined();
  });
});

describe("reducePipelineEvent terminal events", () => {
  it("marks done as succeeded with a full progress bar", () => {
    const patch = reducePipelineEvent(baseState(), event("done"));
    expect(patch.status).toBe("succeeded");
    expect(patch.activeStagePct).toBe(1);
  });

  it("discriminates a cancelled error from a real failure", () => {
    const cancelled = reducePipelineEvent(
      baseState(),
      event("error", { error: "cancelled" }),
    );
    expect(cancelled.status).toBe("cancelled");
    expect(cancelled.error).toBeUndefined();

    const failed = reducePipelineEvent(
      baseState(),
      event("error", { error: "boom" }),
    );
    expect(failed.status).toBe("failed");
    expect(failed.error).toBe("boom");
  });

  it("defaults a failure with no message to 'unknown error'", () => {
    const patch = reducePipelineEvent(baseState(), event("error", {}));
    expect(patch.status).toBe("failed");
    expect(patch.error).toBe("unknown error");
  });
});

/**
 * Schema v1 -> v2 migration.
 *
 * The stride default changed 8 -> 1 (full coverage) but the wizard form is
 * persisted, so every browser that had already opened the pipeline tab would
 * have kept replaying stride 8 -- 15.7% coverage, and a silent "0 hits" on a
 * dump that does contain the key. These cases pin that the migration fires,
 * that it is surgical, and that it cannot fire twice.
 *
 * The store is restored between cases: ``baseState()`` above reads the live
 * store, so a leaked rehydrate would contaminate every other test in this file.
 */
describe("pipeline-store v1 -> v2 stride migration", () => {
  const KEY = "memdiver-pipeline";
  const PRISTINE = usePipelineStore.getState();

  const V1_FORM = {
    sourcePaths: ["/dumps/a.msl", "/dumps/b.msl"],
    oracleId: "oracle-abc",
    oracleSha256: "deadbeef",
    pcapPath: "/caps/session.pcap",
    tlsClientRandom: "aabb",
    reduce: {
      alignment: 8,
      block_size: 32,
      density_threshold: 0.5,
      min_variance: 1500.0,
      entropy_window: 32,
      entropy_threshold: 4.5,
      min_region: 16,
    },
    bruteForce: {
      key_sizes: [16, 32],
      stride: 8,
      jobs: 1,
      exhaustive: false,
      top_k: 25,
    },
    nsweep: null,
    emit: null,
  };

  function seedV1(form: unknown = V1_FORM, version = 1): void {
    localStorage.setItem(
      KEY,
      JSON.stringify({
        version,
        state: {
          stage: "thresholds",
          taskId: "task-42",
          lastSeq: 7,
          form,
        },
      }),
    );
  }

  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
    localStorage.clear();
  });

  it("rewrites a v1 stride of 8 to 1 and leaves every other field alone", async () => {
    seedV1();
    await usePipelineStore.persist.rehydrate();
    const s = usePipelineStore.getState();

    expect(s.form.bruteForce.stride).toBe(1);

    expect(s.form.bruteForce.key_sizes).toEqual([16, 32]);
    expect(s.form.bruteForce.exhaustive).toBe(false);
    expect(s.form.bruteForce.top_k).toBe(25);
    expect(s.form.sourcePaths).toEqual(["/dumps/a.msl", "/dumps/b.msl"]);
    expect(s.form.oracleId).toBe("oracle-abc");
    expect(s.form.pcapPath).toBe("/caps/session.pcap");
    expect(s.form.reduce.min_variance).toBe(1500.0);
    // --alignment is a different knob from --stride and must not be touched.
    expect(s.form.reduce.alignment).toBe(8);
    expect(s.stage).toBe("thresholds");
    expect(s.taskId).toBe("task-42");
    expect(s.lastSeq).toBe(7);
  });

  it("keeps a hand-picked non-default stride", async () => {
    seedV1({ ...V1_FORM, bruteForce: { ...V1_FORM.bruteForce, stride: 4 } });
    await usePipelineStore.persist.rehydrate();
    expect(usePipelineStore.getState().form.bruteForce.stride).toBe(4);
  });

  it("re-persists at the current version so the migration runs exactly once", async () => {
    seedV1();
    await usePipelineStore.persist.rehydrate();
    const stored = JSON.parse(localStorage.getItem(KEY) as string);
    expect(stored.version).toBe(3);
    expect(stored.state.form.bruteForce.stride).toBe(1);
    expect(stored.state.form.oracleId).toBe("oracle-abc");
  });

  it("backfills defaults for a truncated v1 blob instead of throwing", async () => {
    seedV1({ sourcePaths: ["/only.msl"] });
    await expect(usePipelineStore.persist.rehydrate()).resolves.not.toThrow();
    const s = usePipelineStore.getState();
    expect(s.form.bruteForce.stride).toBe(1);
    expect(s.form.reduce.alignment).toBe(8);
    expect(s.form.sourcePaths).toEqual(["/only.msl"]);
  });

  it("leaves the action closures callable after rehydrate", async () => {
    seedV1();
    await usePipelineStore.persist.rehydrate();
    expect(typeof usePipelineStore.getState().updateForm).toBe("function");
    expect(typeof usePipelineStore.getState().ingestEvent).toBe("function");
  });

  it("does not touch a stride of 8 that was chosen under v2", () => {
    // A v2 blob's 8 was typed by the user, not inherited from the old default.
    const out = migratePipelineState(
      {
        stage: "recipe",
        taskId: null,
        lastSeq: 0,
        form: V1_FORM,
      },
      2,
    );
    expect(out.form.bruteForce.stride).toBe(8);
  });

  /*
   * v2 -> v3: the jobs default changed 1 -> 0 (auto-parallel). Exactly the
   * same failure mode the stride migration above exists to fix -- without it
   * every browser that has ever opened the pipeline tab keeps replaying
   * jobs=1 and stays single-threaded forever, never seeing the measured
   * ~3.5x speedup on a large exhaustive sweep.
   */
  it("rewrites a stale jobs of 1 to 0 and leaves the other fields alone", () => {
    const out = migratePipelineState(
      { stage: "recipe", taskId: null, lastSeq: 0, form: V1_FORM },
      2,
    );
    expect(out.form.bruteForce.jobs).toBe(0);
    expect(out.form.bruteForce.key_sizes).toEqual([16, 32]);
    expect(out.form.bruteForce.top_k).toBe(25);
    expect(out.form.bruteForce.exhaustive).toBe(false);
  });

  it("rewrites a stale jobs of 1 from a v1 blob too", async () => {
    seedV1();
    await usePipelineStore.persist.rehydrate();
    expect(usePipelineStore.getState().form.bruteForce.jobs).toBe(0);
  });

  it("keeps a hand-picked non-default job count", () => {
    const out = migratePipelineState(
      {
        stage: "recipe",
        taskId: null,
        lastSeq: 0,
        form: { ...V1_FORM, bruteForce: { ...V1_FORM.bruteForce, jobs: 6 } },
      },
      2,
    );
    expect(out.form.bruteForce.jobs).toBe(6);
  });

  it("does not touch a jobs of 1 that was chosen under v3", () => {
    // A v3 blob's 1 was typed by the user, not inherited from the old default.
    const out = migratePipelineState(
      { stage: "recipe", taskId: null, lastSeq: 0, form: V1_FORM },
      3,
    );
    expect(out.form.bruteForce.jobs).toBe(1);
  });

  /*
   * C3 added ``form.pcapPairs`` (explicit ``(dump, capture)`` pairings) and
   * did NOT bump PIPELINE_STORE_VERSION. These three cases are the proof that
   * the omission is correct, and they are here rather than argued in a comment
   * because the opposite mistake -- a data REWRITE shipped without a bump,
   * which ``migrate`` then never runs -- has already been made on this exact
   * store twice (the stride and jobs cases above).
   *
   * The distinction: a bump is required to TRANSFORM stored data. A purely
   * additive key needs only a default, and the custom ``merge`` supplies that
   * on EVERY rehydrate by spreading ``current.form`` (i.e. DEFAULT_FORM) under
   * the persisted form. A blob still at the current version skips ``migrate``
   * entirely, so ``merge`` is the only backfill that runs for it -- which is
   * exactly the case the first test below pins.
   */
  /** A persisted form as it looked BEFORE ``pcapPairs`` existed. */
  function formWithoutPcapPairs(): Record<string, unknown> {
    const form: Record<string, unknown> = { ...V1_FORM };
    delete form.pcapPairs;
    return form;
  }

  it("backfills pcapPairs on a CURRENT-version blob, so no version bump is needed", async () => {
    // version = 3 = PIPELINE_STORE_VERSION, so ``migrate`` does not run at
    // all. If the backfill depended on it, this is the case that would
    // rehydrate ``pcapPairs`` as undefined and strand every existing user.
    seedV1(formWithoutPcapPairs(), 3);
    await usePipelineStore.persist.rehydrate();
    const s = usePipelineStore.getState();

    expect(s.form.pcapPairs).toBeNull();
    // ...and the backfill is surgical: every persisted field survives.
    expect(s.form.sourcePaths).toEqual(["/dumps/a.msl", "/dumps/b.msl"]);
    expect(s.form.pcapPath).toBe("/caps/session.pcap");
    expect(s.form.bruteForce.jobs).toBe(1);
  });

  it("backfills pcapPairs through migrate on an OLD blob too", () => {
    const out = migratePipelineState(
      {
        stage: "recipe",
        taskId: null,
        lastSeq: 0,
        form: formWithoutPcapPairs(),
      },
      1,
    );
    expect(out.form.pcapPairs).toBeNull();
  });

  it("keeps explicit pairs a user had already staged", async () => {
    const pairs = [{ dump_path: "/dumps/a.msl", pcap_path: "/caps/a.pcap" }];
    seedV1({ ...V1_FORM, pcapPairs: pairs }, 3);
    await usePipelineStore.persist.rehydrate();
    expect(usePipelineStore.getState().form.pcapPairs).toEqual(pairs);
  });

  /** The same additive rule for ``form.scudo``: no version bump. */
  it("backfills form.scudo as null on a CURRENT-version blob", async () => {
    seedV1(V1_FORM, 3);
    await usePipelineStore.persist.rehydrate();
    const { form } = usePipelineStore.getState();
    expect(form.scudo).toBeNull();
    expect(form.sourcePaths).toEqual(["/dumps/a.msl", "/dumps/b.msl"]);
  });

  it("keeps a Scudo selection across a reload", async () => {
    seedV1({ ...V1_FORM, scudo: { allocator: "scudo" } }, 3);
    await usePipelineStore.persist.rehydrate();
    expect(usePipelineStore.getState().form.scudo).toEqual({ allocator: "scudo" });
  });
});

/**
 * B1: candidates/sec + ETA.
 *
 * Every input is already on the wire -- `engine/brute_force.py:319-321` puts
 * `tried`/`total` in `extra` and `api/services/progress_bus.py:104` stamps
 * `event.ts` -- so the rate is derived here rather than in the engine.
 */
describe("reducePipelineEvent brute-force throughput", () => {
  const TOTAL = 701084;

  function bfProgress(seq: number, ts: number, tried: number, total = TOTAL) {
    return event("progress", {
      seq,
      ts,
      stage: "brute_force:progress",
      pct: tried / TOTAL,
      extra: { tried, total, hits: 0 },
    });
  }

  it("seeds the first sample without dividing", () => {
    const patch = reducePipelineEvent(
      baseState({ throughput: null }),
      bfProgress(1, 100, 256),
    );
    expect(patch.throughput).toEqual({
      perSec: 0,
      etaSeconds: null,
      lastTs: 100,
      lastTried: 256,
    });
  });

  it("derives a rate and an ETA from the second sample", () => {
    const seed = reducePipelineEvent(
      baseState({ throughput: null }),
      bfProgress(1, 100, 256),
    ).throughput!;

    const patch = reducePipelineEvent(
      baseState({ throughput: seed, lastSeq: 1 }),
      bfProgress(2, 101, 512),
    );

    // 256 candidates in 1.0s; no prior rate to smooth against, so the raw
    // instantaneous value is taken verbatim.
    expect(patch.throughput?.perSec).toBe(256);
    // (701084 - 512) / 256
    expect(patch.throughput?.etaSeconds).toBeCloseTo(2736.6, 1);
    expect(patch.throughput?.lastTs).toBe(101);
    expect(patch.throughput?.lastTried).toBe(512);
  });

  it("smooths a later sample with an EWMA instead of jumping", () => {
    const prev = { perSec: 256, etaSeconds: 2736, lastTs: 101, lastTried: 512 };
    const patch = reducePipelineEvent(
      baseState({ throughput: prev, lastSeq: 2 }),
      // 512 candidates in 1s = 512/sec instantaneous.
      bfProgress(3, 102, 1024),
    );
    // 0.2 * 512 + 0.8 * 256
    expect(patch.throughput?.perSec).toBeCloseTo(307.2, 5);
  });

  it("leaves throughput untouched across a replayed ring burst (identical ts)", () => {
    // On reconnect the server replays up to 512 buffered events back-to-back.
    // Each carries its ORIGINAL server ts, and a burst compressed into one
    // wall-clock instant would look like an absurd rate if Date.now() were
    // used. Same-ts samples must simply be dropped.
    const prev = { perSec: 256, etaSeconds: 2736, lastTs: 101, lastTried: 512 };
    let tried = 768;
    for (let seq = 3; seq < 10; seq += 1) {
      const patch = reducePipelineEvent(
        baseState({ throughput: prev, lastSeq: seq - 1 }),
        bfProgress(seq, 101, tried),
      );
      expect(patch.throughput).toBeUndefined();
      tried += 256;
    }
    expect(Number.isFinite(prev.perSec)).toBe(true);
    expect(prev.etaSeconds).toBe(2736);
  });

  it("drops a sample whose tried counter did not advance", () => {
    const prev = { perSec: 256, etaSeconds: 2736, lastTs: 101, lastTried: 512 };
    expect(
      reducePipelineEvent(
        baseState({ throughput: prev, lastSeq: 2 }),
        bfProgress(3, 102, 512),
      ).throughput,
    ).toBeUndefined();
    // ...and one that went backwards (out-of-order delivery).
    expect(
      reducePipelineEvent(
        baseState({ throughput: prev, lastSeq: 2 }),
        bfProgress(4, 103, 400),
      ).throughput,
    ).toBeUndefined();
  });

  it("reports no ETA while the total is unknown", () => {
    const prev = { perSec: 0, etaSeconds: null, lastTs: 100, lastTried: 256 };
    const patch = reducePipelineEvent(
      baseState({ throughput: prev, lastSeq: 1 }),
      // Built inline rather than via `bfProgress`: a default parameter would
      // put `total` back, and the point here is that it is genuinely absent.
      event("progress", {
        seq: 2,
        ts: 101,
        stage: "brute_force:progress",
        extra: { tried: 512 },
      }),
    );
    expect(patch.throughput?.perSec).toBe(256);
    expect(patch.throughput?.etaSeconds).toBeNull();
  });

  it("ignores progress from a non-brute-force stage", () => {
    const patch = reducePipelineEvent(
      baseState({ throughput: null }),
      event("progress", {
        seq: 1,
        ts: 100,
        stage: "search_reduce:variance",
        extra: { survivor_bytes: 10, input_bytes: 100 },
      }),
    );
    expect(patch.throughput).toBeUndefined();
  });

  it("clears throughput on the brute-force stage_end", () => {
    const prev = { perSec: 256, etaSeconds: 2736, lastTs: 101, lastTried: 512 };
    const patch = reducePipelineEvent(
      baseState({ throughput: prev, lastSeq: 2 }),
      event("stage_end", { seq: 3, stage: "brute_force", extra: {} }),
    );
    expect(patch.throughput).toBeNull();
  });

  it("clears throughput on done and on error", () => {
    const prev = { perSec: 256, etaSeconds: 2736, lastTs: 101, lastTried: 512 };
    expect(
      reducePipelineEvent(
        baseState({ throughput: prev, lastSeq: 2 }),
        event("done", { seq: 3 }),
      ).throughput,
    ).toBeNull();
    expect(
      reducePipelineEvent(
        baseState({ throughput: prev, lastSeq: 2 }),
        event("error", { seq: 4, error: "boom" }),
      ).throughput,
    ).toBeNull();
  });
});

/**
 * B2: mid-run resume.
 *
 * A reload during a long brute-force stage restores nothing from the event
 * stream — the WS ring holds 512 events and a stride-1 run emits thousands —
 * so the canonical TaskRecord is folded in instead.
 *
 * The store is restored between cases for the same reason the migration block
 * does it: ``baseState()`` reads the live store, so a leaked mutation would
 * contaminate every other test in this file.
 */
describe("hydrateFromRecord", () => {
  const PRISTINE = usePipelineStore.getState();

  const RUNNING_RECORD: TaskRecord = {
    task_id: "task-42",
    kind: "pipeline",
    status: "running",
    params: {},
    stages: [
      {
        name: "consensus",
        status: "succeeded",
        pct: 1,
        msg: "folded 4 dumps",
        started_at: 1000,
        ended_at: 1002.5,
      },
      {
        name: "search_reduce",
        status: "succeeded",
        pct: 1,
        msg: "reduced",
        started_at: 1002.5,
        ended_at: 1004,
      },
      {
        name: "brute_force",
        status: "running",
        pct: 0.12,
        msg: "tried=84000/701084 hits=0",
        started_at: 1004,
        ended_at: null,
      },
    ],
    artifacts: [
      {
        name: "variance",
        relpath: "consensus/variance.npy",
        media_type: "application/octet-stream",
        size: 4096,
        sha256: null,
        registered_at: 1002,
      },
    ],
    created_at: 999,
    started_at: 1000,
    ended_at: null,
    error: null,
    schema_version: 1,
  };

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
    localStorage.clear();
  });

  it("repaints status, artifacts and the in-flight stage", () => {
    usePipelineStore.getState().hydrateFromRecord(RUNNING_RECORD);
    const s = usePipelineStore.getState();

    expect(s.status).toBe("running");
    expect(s.error).toBeNull();
    expect(s.artifacts).toHaveLength(1);
    expect(s.artifacts[0].name).toBe("variance");
    expect(s.activeStage).toBe("brute_force");
    expect(s.activeStagePct).toBe(0.12);
    expect(s.activeStageMsg).toBe("tried=84000/701084 hits=0");
  });

  it("derives stage timings from started_at/ended_at", () => {
    usePipelineStore.getState().hydrateFromRecord(RUNNING_RECORD);
    const { timings } = usePipelineStore.getState();

    expect(timings.consensus_ms).toBeCloseTo(2500, 5);
    expect(timings.reduce_ms).toBeCloseTo(1500, 5);
    // Still running: no ended_at, so it contributes nothing rather than a
    // half-finished duration that would later jump.
    expect(timings.brute_force_ms).toBe(0);
  });

  it("falls back to the last succeeded stage when none is running", () => {
    usePipelineStore.getState().hydrateFromRecord({
      ...RUNNING_RECORD,
      stages: RUNNING_RECORD.stages.slice(0, 2),
    });
    expect(usePipelineStore.getState().activeStage).toBe("search_reduce");
  });

  it("surfaces the error on a failed record", () => {
    usePipelineStore.getState().hydrateFromRecord({
      ...RUNNING_RECORD,
      status: "failed",
      error: "oracle crashed",
    });
    const s = usePipelineStore.getState();
    expect(s.status).toBe("failed");
    expect(s.error).toBe("oracle crashed");
  });

  it("leaves lastSeq UNCHANGED (regression guard for the seq hazard)", () => {
    // The terminal-replay path numbers synthetic events off `lastSeq`. If
    // hydration advanced it past the real bus seqs, the reducer's
    // `seq <= lastSeq` guard would silently swallow every live event after.
    usePipelineStore.setState({ lastSeq: 7 });
    usePipelineStore.getState().hydrateFromRecord(RUNNING_RECORD);
    expect(usePipelineStore.getState().lastSeq).toBe(7);
  });

  it("does not cause the next real event to be dropped", () => {
    usePipelineStore.setState({ lastSeq: 7, funnel: { ...PRISTINE.funnel } });
    usePipelineStore.getState().hydrateFromRecord(RUNNING_RECORD);

    usePipelineStore.getState().ingestEvent(
      event("progress", {
        seq: 8,
        ts: 2000,
        stage: "brute_force:progress",
        pct: 0.5,
        msg: "tried=350000/701084 hits=0",
        extra: { tried: 350000, total: 701084 },
      }),
    );

    const s = usePipelineStore.getState();
    expect(s.lastSeq).toBe(8);
    expect(s.activeStageMsg).toBe("tried=350000/701084 hits=0");
    expect(s.throughput).not.toBeNull();
  });
});

describe("pipeline-store rehydrate status", () => {
  const KEY = "memdiver-pipeline";
  const PRISTINE = usePipelineStore.getState();

  function seed(taskId: string | null): void {
    localStorage.setItem(
      KEY,
      JSON.stringify({
        version: 2,
        state: {
          stage: "running",
          taskId,
          lastSeq: 12,
          form: PRISTINE.form,
        },
      }),
    );
  }

  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
    localStorage.clear();
  });

  it("marks a rehydrated in-flight task as pending, not idle", async () => {
    // `status` is not persisted, so without the onRehydrateStorage hook the
    // initializer leaves it "idle" and the Cancel button / resuming banner
    // stay hidden for the whole (minutes-long) brute-force stage.
    seed("task-42");
    await usePipelineStore.persist.rehydrate();
    expect(usePipelineStore.getState().status).toBe("pending");
    expect(usePipelineStore.getState().taskId).toBe("task-42");
  });

  it("stays idle when no task was in flight", async () => {
    seed(null);
    await usePipelineStore.persist.rehydrate();
    expect(usePipelineStore.getState().status).toBe("idle");
  });
});

describe("reducePipelineEvent Scudo search_reduce", () => {
  const SUMMARY = {
    source: "search-reduce:scudo" as const,
    num_regions: 1,
    num_dumps: 3,
    reference_dump: "/dumps/a.msl",
    funnel: { signature_unique: { chunks: 1, bytes: 40 } },
    totals: { regions: 1, bytes: 40, key_sizes: [40], stride: 1, windows: 1 },
    not_judged: { chunks: 0, bytes: 0 },
    diagnostics: [{ code: "scudo.scope_fallback", message: "fallback", severity: "warning" }],
  };

  it("keeps the verdict summary of a Scudo stage_end", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", { stage: "search_reduce", extra: SUMMARY }),
    );
    expect(patch.scudoSummary).toEqual(SUMMARY);
    expect(patch.activeStage).toBe("search_reduce");
  });

  it("ignores a positional search_reduce stage_end", () => {
    const patch = reducePipelineEvent(
      baseState(),
      event("stage_end", { stage: "search_reduce", extra: { num_regions: 4 } }),
    );
    expect(patch).not.toHaveProperty("scudoSummary");
  });

  it("does not let a brute_force stage_end touch the Scudo diagnostics", () => {
    const patch = reducePipelineEvent(
      baseState({ scudoSummary: SUMMARY }),
      event("stage_end", { stage: "brute_force", extra: { warnings: [] } }),
    );
    expect(patch.warnings).toEqual([]);
    expect(patch).not.toHaveProperty("scudoSummary");
  });

  it("starts every new run without a summary", () => {
    const PRISTINE = usePipelineStore.getState();
    try {
      usePipelineStore.setState({ scudoSummary: SUMMARY });
      usePipelineStore.getState().setTaskId("next-task");
      expect(usePipelineStore.getState().scudoSummary).toBeNull();
    } finally {
      usePipelineStore.setState(PRISTINE, true);
    }
  });

  it("defaults to the positional method", () => {
    expect(usePipelineStore.getState().form.scudo).toBeNull();
  });
});
