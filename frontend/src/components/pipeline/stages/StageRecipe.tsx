/**
 * Stage 0 — recipe picker.
 *
 * For v1 we ship two built-in starting points:
 *
 *  - **Blank**: empty form, user fills in everything. The default for
 *    power users who already know what they're pointing at.
 *  - **Replicate gocryptfs IMF**: pre-populated with the thresholds
 *    from the paper's section 4.2 *and* the N-sweep grid the published
 *    run used, so a peer reviewer can reproduce the published numbers
 *    in one click. The sweep has to be spelled out here because
 *    `NSweepParams` carries its own `key_sizes` / `stride` /
 *    `exhaustive` and inherits none of them from the brute-force
 *    stage — only `reduce_kwargs` is inherited (api/routers/
 *    pipeline.py). Dump paths remain empty — they need to come from
 *    disk.
 *
 * Recipe *save/load* (localStorage + JSON import/export) is deferred
 * to a later sub-phase when `recipe-store.ts` lands. This stage is the
 * placeholder that hooks in cleanly once that store exists.
 */

import { useTranslation } from "react-i18next";

import type { WizardStage } from "@/stores/pipeline-store";
import { DEFAULT_KEY_SIZES, DEFAULT_SCUDO, usePipelineStore } from "@/stores/pipeline-store";

const GOCRYPTFS_RECIPE = {
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
    key_sizes: [32],
    // Deliberately pinned: the product default is stride 1 (full coverage),
    // but the published IMF gocryptfs result was produced at stride 8, so
    // this recipe keeps 8 in order to keep reproducing that paper.
    stride: 8,
    // Pinned alongside the stride above for the same reason: the published
    // result was produced by a single-threaded sweep, so this recipe stays
    // serial rather than following the product default of 0 (auto-parallel).
    jobs: 1,
    // Deliberately the OPPOSITE of `nsweep.exhaustive` below, and not a typo:
    // the single-N brute force reproduces §4.2, where every hit is reported,
    // while the sweep reproduces §7, which the published CLI run drove with
    // --first-hit. The two stages share no settings (see the file header), so
    // the card copy names the stage each value belongs to — a reader who sees
    // "first verified key" on this card and "Exhaustive ✓" on the thresholds
    // screen would otherwise read the recipe as self-contradictory.
    exhaustive: true,
    top_k: 10,
  },
  // The sweep is part of the published result, not an extra: without it the
  // recipe produces no survivor curve and no report artifacts at all. Every
  // value below is pinned to the run that produced the committed reference
  // artifact tests/e2e/fixtures/pipeline/summary.json.
  nsweep: {
    n_values: [1, 3, 5, 10, 15, 20],
    // The sweep re-derives its own candidate grid and inherits only
    // `reduce_kwargs` from the form, so key_sizes/stride/exhaustive must be
    // repeated here or the sweep silently falls back to the Pydantic defaults
    // (stride 1, exhaustive true) and measures a different grid than the paper.
    key_sizes: [32],
    // Same reason as bruteForce.stride above: the published run was stride 8.
    stride: 8,
    // The published CLI run passed --first-hit, which the CLI forwards as
    // `exhaustive=not args.first_hit` (cli/pipeline.py), so the sweep stops at
    // the first verified key exactly as the reference artifact recorded it.
    exhaustive: false,
  },
};

interface Props {
  onAdvance: (next: WizardStage) => void;
}

export function StageRecipe({ onAdvance }: Props) {
  const { t } = useTranslation("pipeline");
  const updateForm = usePipelineStore((s) => s.updateForm);
  const bruteForce = usePipelineStore((s) => s.form.bruteForce);

  function startBlank(): void {
    updateForm({ scudo: null, bruteForce: { ...bruteForce, key_sizes: DEFAULT_KEY_SIZES } });
    onAdvance("dumps");
  }

  function startGocryptfs(): void {
    updateForm({
      reduce: GOCRYPTFS_RECIPE.reduce,
      bruteForce: GOCRYPTFS_RECIPE.bruteForce,
      nsweep: GOCRYPTFS_RECIPE.nsweep,
      scudo: null,
    });
    onAdvance("dumps");
  }

  function startScudo(): void {
    updateForm({
      scudo: DEFAULT_SCUDO,
      nsweep: null,
      emit: null,
      // A secret can sit anywhere in a chunk, and the gocryptfs recipe would
      // otherwise leave its stride of 8 behind.
      bruteForce: { ...bruteForce, stride: 1, exhaustive: true },
    });
    onAdvance("dumps");
  }

  return (
    <div className="p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold md-text-accent">
          {t("stages.recipe.title")}
        </h3>
        <p className="text-xs md-text-muted">
          {t("stages.recipe.subtitle")}
        </p>
      </div>

      <div
        className="grid grid-cols-1 md:grid-cols-2 gap-3"
        data-tour-id="pipeline-recipe-card"
      >
        <button
          type="button"
          onClick={startBlank}
          className="md-panel p-4 text-left hover:bg-[var(--md-bg-hover)] transition-colors"
        >
          <div className="md-text-accent font-semibold text-sm mb-1">
            {t("stages.recipe.blankTitle")}
          </div>
          <div className="text-xs md-text-muted">
            {t("stages.recipe.blankBody")}
          </div>
        </button>

        <button
          type="button"
          data-tour-id="pipeline-recipe-gocryptfs"
          onClick={startGocryptfs}
          className="md-panel p-4 text-left hover:bg-[var(--md-bg-hover)] transition-colors"
        >
          <div className="md-text-accent font-semibold text-sm mb-1">
            {t("stages.recipe.gocryptfsTitle")}
          </div>
          <div className="text-xs md-text-muted">
            {t("stages.recipe.gocryptfsBody")}{" "}
            <code>dataset_gocryptfs/run_*</code>{" "}
            {t("stages.recipe.gocryptfsBodyTail")}
          </div>
        </button>

        <button
          type="button"
          data-testid="pipeline-recipe-scudo"
          onClick={startScudo}
          className="md-panel p-4 text-left hover:bg-[var(--md-bg-hover)] transition-colors"
        >
          <div className="md-text-accent font-semibold text-sm mb-1">
            {t("stages.recipe.scudoTitle")}
          </div>
          <div className="text-xs md-text-muted">
            {t("stages.recipe.scudoBody")}
          </div>
        </button>
      </div>

      <p className="text-[10px] md-text-muted">
        {t("stages.recipe.saveLoadNote")}
      </p>
    </div>
  );
}
