/**
 * Stage 3 — threshold form + Run button.
 *
 * Exposes the `ReduceParams` numeric knobs and brute-force options
 * the user can tune before committing to a run. Sensible defaults
 * live in the store from {@link pipeline-store.ts}; the gocryptfs
 * recipe pre-populates these to the IMF paper values.
 *
 * The two optional tail stages are opted into from here as well:
 * ``emit`` (write a Volatility 3 plugin from the best hit, which is
 * what fills the results screen's Plugin tab) and ``nsweep`` (re-fold
 * a fresh consensus at every N and build the interactive report that
 * fills the Report tab). Both keys are omitted from the request body
 * entirely while their checkbox is off, so a run configured the way
 * runs were configured before they existed sends a byte-identical body.
 *
 * Hitting "Run pipeline" POSTs `/api/pipeline/run` with the current
 * form + oracle id, persists the returned ``task_id`` to the store
 * (which flips ``status`` to ``"pending"``), and advances the
 * wizard to the ``running`` stage. The run dashboard then takes
 * over via the WebSocket subscription in PipelinePanel.
 */

import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import type { EmitParams, NSweepParams, PipelineRunRequest } from "@/api/pipeline";
import { readableFailure } from "@/api/client";
import { runPipeline } from "@/api/pipeline";
import { withMemoryBudgetOverride, withForceMemory } from "@/api/memory-budget";
import type { WizardStage } from "@/stores/pipeline-store";
import { usePipelineStore } from "@/stores/pipeline-store";
import { HeapPolicySelect } from "@/components/charts/HeapPolicySelect";
import { defaultNValues, parseNValues } from "@/utils/n-values";

import { ScudoMethodPanel } from "./ScudoMethodPanel";

/** Caption + hover-help bubble shared by every field control below. */
function FieldLabel({ label, help }: { label: string; help: string }) {
  return (
    <div className="flex items-center gap-1.5 text-xs">
      <span className="md-text-secondary">{label}</span>
      <span
        className="inline-block w-3.5 h-3.5 text-[9px] text-center leading-[14px] rounded-full bg-[var(--md-bg-hover)] md-text-muted cursor-help"
        title={help}
      >
        ?
      </span>
    </div>
  );
}

const FIELD_INPUT_CLASS =
  "mt-0.5 w-full px-2 py-1 text-xs bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded font-mono";

interface NumericFieldProps {
  label: string;
  help: string;
  value: number;
  step?: number;
  min?: number;
  testId?: string;
  onChange: (value: number) => void;
}

function NumericField({
  label,
  help,
  value,
  step = 1,
  min,
  testId,
  onChange,
}: NumericFieldProps) {
  return (
    <label className="block">
      <FieldLabel label={label} help={help} />
      <input
        type="number"
        value={value}
        step={step}
        min={min}
        data-testid={testId}
        onChange={(e) => {
          if (e.target.value === "") return;
          const v = Number(e.target.value);
          if (!Number.isNaN(v)) onChange(v);
        }}
        className={FIELD_INPUT_CLASS}
      />
    </label>
  );
}

interface TextFieldProps {
  label: string;
  help: string;
  value: string;
  testId?: string;
  onChange: (value: string) => void;
}

function TextField({ label, help, value, testId, onChange }: TextFieldProps) {
  return (
    <label className="block">
      <FieldLabel label={label} help={help} />
      <input
        type="text"
        value={value}
        data-testid={testId}
        onChange={(e) => onChange(e.target.value)}
        className={FIELD_INPUT_CLASS}
      />
    </label>
  );
}

/**
 * Opt-in defaults for the emit stage, mirroring ``EmitParams`` in
 * api/routers/pipeline.py. Every backend field is already defaulted there,
 * so the checkbox alone is enough to enable the stage; these values only
 * pre-populate the controls with what the backend would have chosen.
 */
const DEFAULT_EMIT: EmitParams = {
  name: "memdiver_plugin",
  min_static_ratio: 0.3,
};


interface Props {
  onAdvance: (next: WizardStage) => void;
}

export function StageThresholds({ onAdvance }: Props) {
  const { t } = useTranslation("pipeline");
  const form = usePipelineStore((s) => s.form);
  const updateForm = usePipelineStore((s) => s.updateForm);
  const setTaskId = usePipelineStore((s) => s.setTaskId);

  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const patchReduce = (patch: Partial<typeof form.reduce>): void => {
    updateForm({ reduce: { ...form.reduce, ...patch } });
  };
  const patchBrute = (patch: Partial<typeof form.bruteForce>): void => {
    updateForm({ bruteForce: { ...form.bruteForce, ...patch } });
  };

  // Both optional stages are represented by `null` when off, which is exactly
  // what the backend's `Optional[...] = None` gating reads (api/routers/
  // pipeline.py `optional_stage_present`).
  const emitOn = form.emit !== null;
  // The N-sweep harness re-runs the oracle at every N, and since P2.2 that
  // oracle can be either source: `_run_nsweep` forwards `pcap_path` /
  // `tls_client_random` the same way `_run_brute_force` does, so a pcap run
  // sweeps against the capture with no BYO oracle file involved. `pcapOracle`
  // survives only to word the hint, not to gate the stage.
  const pcapOracle = Boolean(form.pcapPath?.trim());
  const nsweepOn = form.nsweep !== null;
  const scudoOn = form.scudo !== null;

  // The N list is edited as free text so intermediate states ("2," while
  // typing) do not have to round-trip through the store as numbers.
  const [nValuesText, setNValuesText] = useState<string>(() =>
    (form.nsweep?.n_values ?? defaultNValues(form.sourcePaths.length)).join(","),
  );

  const patchEmit = (patch: Partial<EmitParams>): void => {
    updateForm({ emit: { ...DEFAULT_EMIT, ...form.emit, ...patch } });
  };
  const toggleEmit = (on: boolean): void => {
    updateForm({ emit: on ? { ...DEFAULT_EMIT, ...form.emit } : null });
  };

  /** The grid the sweep last carried, kept across an off/on flick of the box. */
  const lastNSweep = useRef<NSweepParams | null>(form.nsweep);

  const resolvedNValues = (): number[] => {
    const parsed = parseNValues(nValuesText);
    return parsed.length > 0 ? parsed : defaultNValues(form.sourcePaths.length);
  };
  const patchNSweep = (patch: Partial<NSweepParams>): void => {
    updateForm({ nsweep: { n_values: resolvedNValues(), ...form.nsweep, ...patch } });
  };
  const toggleNSweep = (on: boolean): void => {
    // Re-checking the box must restore whatever the recipe (or the user) last
    // put in stride / exhaustive / key_sizes: rebuilding a bare `{ n_values }`
    // here silently dropped them, so an off/on flick quietly re-configured the
    // sweep's candidate grid. Same spread shape as `toggleEmit` above, over the
    // remembered grid instead of a constant -- the sweep has no equivalent of
    // DEFAULT_EMIT because `null` (not an empty object) is what "off" means on
    // the wire, so the previous values have to be held here.
    if (!on) lastNSweep.current = form.nsweep;
    updateForm({
      nsweep: on ? { n_values: resolvedNValues(), ...lastNSweep.current } : null,
    });
  };
  /**
   * `--first-hit` in CLI terms, and the inverse of the wire field: the user
   * asks to STOP at the first verified key, which is `exhaustive: false`.
   */
  const setStopAtFirstHit = (stopAtFirstHit: boolean): void => {
    patchNSweep({ exhaustive: !stopAtFirstHit });
  };

  async function submit(): Promise<void> {
    const pcapPath = form.pcapPath?.trim() ?? "";
    // Exactly one oracle source: an armed BYO oracle OR a pcap of the session.
    if (!form.oracleId && !pcapPath) {
      setSubmitError(t("stages.thresholds.noOracleError"));
      return;
    }
    if (form.sourcePaths.length === 0) {
      setSubmitError(t("stages.thresholds.noDumpsError"));
      return;
    }
    if (form.scudo && form.sourcePaths.length < 2) {
      setSubmitError(t("stages.thresholds.scudoNeedsTwoDumps"));
      return;
    }
    setSubmitError(null);
    setSubmitting(true);
    try {
      const clientRandom = form.tlsClientRandom?.trim() ?? "";
      const body: PipelineRunRequest = {
        source_paths: form.sourcePaths,
        // Exactly one reduction method: the server refuses thresholds that the
        // Scudo method could only ignore.
        ...(form.scudo ? { scudo: form.scudo } : { reduce: form.reduce }),
        brute_force: form.bruteForce,
        // Opt-in tail stages: the key is absent (not null) while the box is
        // off, so an unchanged form posts exactly the body it always did.
        ...(form.emit ? { emit: form.emit } : {}),
        // nsweep runs on either oracle source; the worker picks up the same
        // pcap_path / tls_client_random the brute-force stage uses.
        ...(form.nsweep ? { nsweep: form.nsweep } : {}),
        ...(pcapPath
          ? {
              pcap_path: pcapPath,
              ...(clientRandom ? { tls_client_random: clientRandom } : {}),
            }
          : { oracle_id: form.oracleId }),
      };
      const resp = await withMemoryBudgetOverride((force) =>
        runPipeline(withForceMemory(body, force)),
      );
      setTaskId(resp.task_id);
      // Kept so a memory-guard failure of the background run can be re-sent forced.
      usePipelineStore.getState().setLastRunRequest(body);
      onAdvance("running");
    } catch (err) {
      setSubmitError(readableFailure(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold md-text-accent">
          {t("stages.thresholds.title")}
        </h3>
        {!scudoOn && (
          <p className="text-xs md-text-muted">
            {t("stages.thresholds.subtitlePrefix")}{" "}
            <span className="md-text-accent">?</span>{" "}
            {t("stages.thresholds.subtitleTail")}
          </p>
        )}
      </div>

      <ScudoMethodPanel />

      {!scudoOn && (
        <div className="md-panel p-3 space-y-3">
          <div className="md-text-accent font-semibold text-xs uppercase tracking-wide">
            {t("stages.thresholds.searchReduce")}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <NumericField
              label={t("stages.thresholds.fields.minVariance")}
              help={t("stages.thresholds.fields.minVarianceHelp")}
              value={form.reduce.min_variance ?? 3000}
              step={100}
              onChange={(v) => patchReduce({ min_variance: v })}
            />
            <NumericField
              label={t("stages.thresholds.fields.alignment")}
              help={t("stages.thresholds.fields.alignmentHelp")}
              value={form.reduce.alignment ?? 8}
              step={1}
              min={1}
              onChange={(v) => patchReduce({ alignment: v })}
            />
            <NumericField
              label={t("stages.thresholds.fields.blockSize")}
              help={t("stages.thresholds.fields.blockSizeHelp")}
              value={form.reduce.block_size ?? 32}
              step={8}
              min={8}
              onChange={(v) => patchReduce({ block_size: v })}
            />
            <NumericField
              label={t("stages.thresholds.fields.density")}
              help={t("stages.thresholds.fields.densityHelp")}
              value={form.reduce.density_threshold ?? 0.5}
              step={0.05}
              min={0}
              onChange={(v) => patchReduce({ density_threshold: v })}
            />
            <NumericField
              label={t("stages.thresholds.fields.entropyWin")}
              help={t("stages.thresholds.fields.entropyWinHelp")}
              value={form.reduce.entropy_window ?? 32}
              step={8}
              min={8}
              onChange={(v) => patchReduce({ entropy_window: v })}
            />
            <NumericField
              label={t("stages.thresholds.fields.entropyMin")}
              help={t("stages.thresholds.fields.entropyMinHelp")}
              value={form.reduce.entropy_threshold ?? 4.5}
              step={0.1}
              min={0}
              onChange={(v) => patchReduce({ entropy_threshold: v })}
            />
            <NumericField
              label={t("stages.thresholds.fields.minRegion")}
              help={t("stages.thresholds.fields.minRegionHelp")}
              value={form.reduce.min_region ?? 16}
              step={1}
              min={1}
              onChange={(v) => patchReduce({ min_region: v })}
            />
            {/*
              Only written into `reduce` once chosen, so an untouched form posts
              the body it always did and the backend applies `"annotate"`.
            */}
            <div className="text-xs">
              <HeapPolicySelect
                testId="pipeline-heap-policy-select"
                value={form.reduce.heap_policy}
                onChange={(heap_policy) => patchReduce({ heap_policy })}
                selectClassName={FIELD_INPUT_CLASS}
              />
            </div>
          </div>
        </div>
      )}

      <div className="md-panel p-3 space-y-3">
        <div className="md-text-accent font-semibold text-xs uppercase tracking-wide">
          {t("stages.thresholds.bruteForce")}
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          <NumericField
            label={t("stages.thresholds.fields.stride")}
            help={t("stages.thresholds.fields.strideHelp")}
            value={form.bruteForce.stride ?? 1}
            step={1}
            min={1}
            onChange={(v) => patchBrute({ stride: v })}
          />
          {/* min={0} so the "auto" sentinel is reachable from the spinner. */}
          <NumericField
            label={t("stages.thresholds.fields.jobs")}
            help={t("stages.thresholds.fields.jobsHelp")}
            value={form.bruteForce.jobs ?? 0}
            step={1}
            min={0}
            onChange={(v) => patchBrute({ jobs: v })}
          />
          <NumericField
            label={t("stages.thresholds.fields.topK")}
            help={t("stages.thresholds.fields.topKHelp")}
            value={form.bruteForce.top_k ?? 10}
            step={1}
            min={0}
            onChange={(v) => patchBrute({ top_k: v })}
          />
        </div>
        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={form.bruteForce.exhaustive ?? true}
            onChange={(e) => patchBrute({ exhaustive: e.target.checked })}
          />
          <span className="md-text-secondary">
            {t("stages.thresholds.exhaustiveLabel")}
          </span>
        </label>
      </div>

      <div className="md-panel p-3 space-y-3">
        <div className="md-text-accent font-semibold text-xs uppercase tracking-wide">
          {t("stages.thresholds.emitPlugin")}
        </div>
        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            data-testid="emit-enable"
            checked={emitOn}
            disabled={scudoOn}
            onChange={(e) => toggleEmit(e.target.checked)}
          />
          <span className="md-text-secondary">
            {t("stages.thresholds.emitEnableLabel")}
          </span>
        </label>
        <p
          className={scudoOn ? "text-xs md-text-warning" : "text-[10px] md-text-muted"}
          data-testid="emit-hint"
        >
          {scudoOn ? t("scudo.pluginUnsupported") : t("stages.thresholds.emitHint")}
        </p>
        {emitOn && (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <TextField
              label={t("stages.thresholds.fields.pluginName")}
              help={t("stages.thresholds.fields.pluginNameHelp")}
              value={form.emit?.name ?? ""}
              testId="emit-name"
              onChange={(v) => patchEmit({ name: v })}
            />
            <NumericField
              label={t("stages.thresholds.fields.minStaticRatio")}
              help={t("stages.thresholds.fields.minStaticRatioHelp")}
              value={form.emit?.min_static_ratio ?? 0.3}
              step={0.05}
              min={0}
              testId="emit-min-static-ratio"
              onChange={(v) => patchEmit({ min_static_ratio: v })}
            />
          </div>
        )}
      </div>

      <div className="md-panel p-3 space-y-3">
        <div className="md-text-accent font-semibold text-xs uppercase tracking-wide">
          {t("stages.thresholds.nsweep")}
        </div>
        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            data-testid="nsweep-enable"
            checked={nsweepOn}
            disabled={scudoOn}
            onChange={(e) => toggleNSweep(e.target.checked)}
          />
          <span className="md-text-secondary">
            {t("stages.thresholds.nsweepEnableLabel")}
          </span>
        </label>
        <p className="text-[10px] md-text-muted">
          {scudoOn
            ? t("stages.thresholds.scudoNsweepUnsupported")
            : pcapOracle
              ? t("stages.thresholds.nsweepPcapHint")
              : t("stages.thresholds.nsweepHint")}
        </p>
        {nsweepOn && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <TextField
                label={t("stages.thresholds.fields.nValues")}
                help={t("stages.thresholds.fields.nValuesHelp")}
                value={nValuesText}
                testId="nsweep-n-values"
                onChange={(raw) => {
                  setNValuesText(raw);
                  const parsed = parseNValues(raw);
                  if (parsed.length > 0) patchNSweep({ n_values: parsed });
                }}
              />
              {/* The sweep's own stride: `NSweepParams` carries it separately and
                  inherits nothing from the brute-force panel above, so leaving it
                  uncontrolled let the sweep run a different grid than the form
                  displayed. `key_sizes` stays deliberately uncontrolled — it is
                  [32] on both the recipe and the backend default, so a third
                  field would be noise. */}
              <NumericField
                label={t("stages.thresholds.fields.nsweepStride")}
                help={t("stages.thresholds.fields.nsweepStrideHelp")}
                value={form.nsweep?.stride ?? 1}
                step={1}
                min={1}
                testId="nsweep-stride"
                onChange={(v) => patchNSweep({ stride: v })}
              />
            </div>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                data-testid="nsweep-first-hit"
                checked={!(form.nsweep?.exhaustive ?? true)}
                onChange={(e) => setStopAtFirstHit(e.target.checked)}
              />
              <span className="md-text-secondary">
                {t("stages.thresholds.nsweepFirstHitLabel")}
              </span>
            </label>
            <p className="text-[10px] md-text-muted">
              {t("stages.thresholds.nsweepGridHint")}
            </p>
          </>
        )}
      </div>

      {submitError && (
        <div className="md-panel p-2 text-xs border md-border-error md-text-error">
          {submitError}
        </div>
      )}

      <div className="flex justify-between items-center pt-2">
        <button
          type="button"
          onClick={() => onAdvance("oracle")}
          className="text-xs px-3 py-1.5 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
        >
          {t("stages.thresholds.back")}
        </button>
        <button
          type="button"
          disabled={submitting}
          onClick={() => void submit()}
          className="text-xs px-4 py-1.5 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50"
          title={
            scudoOn
              ? t("stages.thresholds.scudoRunTitle")
              : t("stages.thresholds.runTitle", {
                  optional:
                    (nsweepOn ? t("stages.thresholds.chainSweep") : "") +
                    (emitOn ? t("stages.thresholds.chainEmit") : ""),
                })
          }
        >
          {submitting ? t("stages.thresholds.submitting") : t("stages.thresholds.run")}
        </button>
      </div>
    </div>
  );
}
