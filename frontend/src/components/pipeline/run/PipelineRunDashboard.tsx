/**
 * Pipeline run dashboard — active-stage bar, reduction funnel, stage
 * timings, live oracle log, a hits list with "Open in hex" that
 * auto-loads the first consensus source on a cold pipeline tab, and the
 * run diagnostics (search coverage + backend warnings).
 */

import { useState, type JSX } from "react";
import { useTranslation } from "react-i18next";

import { inferFields } from "@/api/pipeline";
import { VerificationBadge } from "@/components/results/VerificationBadge";
import { useAppStore } from "@/stores/app-store";
import { useHexStore } from "@/stores/hex-store";
import { usePipelineStore, type HitRecord, type Throughput } from "@/stores/pipeline-store";
import { splitDuration } from "@/utils/duration";
import { notifyError } from "@/utils/errorNotifier";

import { FunnelChart } from "./FunnelChart";
import { LiveOracleLog } from "./LiveOracleLog";
import { StageTimingTable } from "./StageTimingTable";

async function openHitInHex(
  hit: HitRecord,
  fallbackDump: string | null,
  scudoRun: boolean,
) {
  const hex = useHexStore.getState();
  useAppStore.getState().setHexFocus({ offset: hit.offset, length: hit.size || 32 });

  // Navigate immediately so the jump feels responsive; the overlay (which
  // needs a network round-trip for the inferred fields) lands afterwards.
  if (scudoRun && fallbackDump) {
    // A Scudo hit is an offset into the flat VAS view of dump 1 and means
    // nothing in any other dump or view, so both are selected here. "msl" and
    // not "raw": the viewer only probes a dump's views when told it is one.
    if (hex.dumpPath !== fallbackDump) hex.setDumpPath(fallbackDump, 0, "msl");
    useHexStore.getState().showView("vas");
    queueMicrotask(() => useHexStore.getState().scrollToOffset(hit.offset));
  } else if (!hex.dumpPath && fallbackDump) {
    // setDumpPath seeds HexViewer with fileSize=0 and triggers a
    // metadata refetch; defer the scroll so it lands after HexViewer
    // remounts with the real size instead of flashing an empty view.
    hex.setDumpPath(fallbackDump, 0, "raw");
    queueMicrotask(() => useHexStore.getState().scrollToOffset(hit.offset));
  } else {
    hex.scrollToOffset(hit.offset);
  }

  // Wire up the neighborhood variance overlay when available. Fields are
  // inferred server-side (POST /api/pipeline/infer-fields); no client compute.
  if (hit.neighborhood_variance.length > 0) {
    const { fields } = await inferFields({
      neighborhood_variance: hit.neighborhood_variance,
      neighborhood_start: hit.neighborhood_start,
      offset: hit.offset,
      length: hit.size,
    });
    useHexStore.getState().setActiveNeighborhoodOverlay({
      hitOffset: hit.offset,
      hitSize: hit.size,
      neighborhoodStart: hit.neighborhood_start,
      variance: hit.neighborhood_variance,
      fields,
    });
  }
}

export function HitsList(): JSX.Element | null {
  const { t } = useTranslation("pipeline");
  const hits = usePipelineStore((s) => s.hits);
  const sources = usePipelineStore((s) => s.form.sourcePaths);
  const scudoRun = usePipelineStore((s) => s.form.scudo !== null);
  // Index of the hit whose overlay is currently being fetched, so a
  // double-click can't race two concurrent infer-fields calls.
  const [pendingHit, setPendingHit] = useState<number | null>(null);
  if (hits.length === 0) return null;
  const fallback = sources.length > 0 ? sources[0] : null;

  const handleOpen = async (hit: HitRecord, index: number) => {
    if (pendingHit !== null) return;
    setPendingHit(index);
    try {
      await openHitInHex(hit, fallback, scudoRun);
    } catch (err) {
      notifyError(
        t("run.dashboard.openFailed", {
          error: err instanceof Error ? err.message : String(err),
        }),
        "pipeline-open-hit",
      );
    } finally {
      setPendingHit(null);
    }
  };

  return (
    <div
      className="md-panel p-3 space-y-1"
      data-tour-id="pipeline-hits-list"
    >
      <div className="text-xs md-text-accent font-semibold mb-1">
        {t("run.dashboard.hitsTitle", { count: hits.length })}
      </div>
      <ul className="space-y-1">
        {hits.map((h, i) => (
          <li
            key={`${h.offset}-${i}`}
            className="flex items-center justify-between gap-2 text-xs"
            data-testid="pipeline-hit-row"
            data-hit-offset={h.offset}
          >
            <span className="flex items-center gap-2 min-w-0">
              <span className="font-mono md-text-secondary">
                0x{h.offset.toString(16).padStart(8, "0")}
                <span className="md-text-muted ml-1">{t("run.dashboard.hitSize", { size: h.size })}</span>
              </span>
              <VerificationBadge verified={h.verified ?? null} confirmedBy={h.confirmedBy} />
            </span>
            <button
              type="button"
              onClick={() => handleOpen(h, i)}
              disabled={pendingHit !== null}
              className="text-xs px-2 py-0.5 rounded bg-[var(--md-accent-blue)] md-text-on-accent hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
              title={t("run.dashboard.openInHexTitle")}
            >
              {pendingHit === i ? t("run.dashboard.opening") : t("run.dashboard.openInHex")}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * Search coverage + non-fatal backend warnings for the finished (or
 * in-flight) brute-force stage.
 *
 * The brute-force stage walks an *absolute* stride grid: at stride=N only
 * offsets that are multiples of N are ever tested. The default is stride=1
 * (full coverage), but a user who raises the stride for speed can no longer
 * reach an unaligned secret at all -- and without
 * this block the run reports "succeeded, 0 hits" and looks identical to a
 * dump that genuinely holds no key. ``HitsList`` self-hides on an empty run,
 * so this is the only thing standing between the user and a silent screen.
 *
 * The coverage line renders on successful runs too, deliberately: a hit
 * found inside a 16%-covered space is a lower bound, never a total.
 */
export function RunDiagnostics(): JSX.Element | null {
  const { t } = useTranslation("pipeline");
  const coverage = usePipelineStore((s) => s.coverage);
  const warnings = usePipelineStore((s) => s.warnings);
  const scudoSummary = usePipelineStore((s) => s.scudoSummary);
  const scudoDiagnostics = scudoSummary?.diagnostics ?? [];

  if (!coverage && warnings.length === 0 && scudoDiagnostics.length === 0) return null;
  const isExhaustive = coverage !== null && coverage.fraction >= 1;

  return (
    <div className="space-y-2" data-testid="pipeline-diagnostics">
      {coverage && (
        <div
          className="md-panel p-3 space-y-1"
          data-testid="pipeline-coverage"
          data-coverage-fraction={coverage.fraction}
        >
          <div className="text-xs md-text-accent font-semibold">
            {t("run.diagnostics.coverageTitle")}
          </div>
          <div className="text-xs md-text-secondary">
            {t("run.diagnostics.coverageLine", {
              // Pinned to en-US rather than the ambient locale: the UI is
              // English-only, and these two counts also appear inside the
              // backend-composed warning sentence right below, which groups
              // with commas. A host locale of de-DE would otherwise print
              // "110.326" here and "110,326" there for the same number.
              tested: coverage.tested.toLocaleString("en-US"),
              possible: coverage.possible.toLocaleString("en-US"),
              percent: (coverage.fraction * 100).toFixed(1),
              stride: coverage.stride,
            })}
          </div>
          <div className="h-1.5 rounded bg-[var(--md-bg-hover)] overflow-hidden">
            <div
              className={`h-full ${
                isExhaustive
                  ? "bg-[var(--md-accent-green)]"
                  : "bg-[var(--md-accent-orange)]"
              }`}
              style={{
                width: `${Math.max(0, Math.min(1, coverage.fraction)) * 100}%`,
              }}
            />
          </div>
          <div className="text-xs md-text-muted">
            {isExhaustive
              ? t("run.diagnostics.coverageExhaustive")
              : t("run.diagnostics.coveragePartial", { stride: coverage.stride })}
          </div>
        </div>
      )}

      {warnings.map((w, i) => (
        <div
          key={`${w.code}-${i}`}
          role="status"
          className="md-panel p-3 space-y-1 border md-border-warning md-text-warning"
          data-testid="pipeline-warning"
          data-warning-code={w.code}
        >
          <div className="text-xs font-semibold">
            {t("run.diagnostics.warningTitle")}
          </div>
          {/*
           * `w.message` is a complete English sentence composed by the
           * backend (numbers, stride, and the remediation hint already
           * folded in). It is rendered verbatim -- only the heading above
           * is translated.
           */}
          <div className="text-xs">{w.message}</div>
        </div>
      ))}

      {scudoDiagnostics.map((d, i) => {
        const isWarning = d.severity === "warning";
        return (
          <div
            key={`${d.code}-${i}`}
            role="status"
            className={`md-panel p-3 space-y-1 ${
              isWarning ? "border md-border-warning md-text-warning" : "md-text-secondary"
            }`}
            data-testid="pipeline-scudo-diagnostic"
            data-diagnostic-code={d.code}
            data-severity={d.severity ?? ""}
          >
            <div className="text-xs font-semibold">
              {t(isWarning ? "run.diagnostics.scudoWarningTitle" : "run.diagnostics.scudoNoteTitle")}
            </div>
            <div className="text-xs">{d.message}</div>
          </div>
        );
      })}
    </div>
  );
}

/**
 * Live candidates/sec + ETA for the brute-force stage.
 *
 * A stride-1 run enumerates ~701k candidates where the old stride-8 default
 * enumerated ~110k, so the stage now runs ~6.4x longer and a bare percentage
 * bar leaves the user with no idea whether "12%" means one more minute or one
 * more hour. Both numbers are derived in the store from counters the engine
 * already emits; this row only formats them.
 *
 * Self-hides until a rate exists: the first progress sample has nothing to
 * divide by, and showing "0 candidates/sec" would read as a stalled run.
 */
function ThroughputRow({ throughput }: { throughput: Throughput }): JSX.Element {
  const { t } = useTranslation("pipeline");
  const { h, m, s } = splitDuration(throughput.etaSeconds ?? 0);

  // Pinned to en-US for the same reason the coverage counts are: the UI is
  // English-only and a host locale of de-DE would print "1.024" for 1024.
  const rate = t("run.dashboard.rate", {
    rate: Math.round(throughput.perSec).toLocaleString("en-US"),
  });

  let eta: string;
  if (throughput.etaSeconds === null) {
    eta = t("run.dashboard.etaUnknown");
  } else if (h > 0) {
    eta = t("run.dashboard.etaHours", { h, m });
  } else if (m > 0) {
    eta = t("run.dashboard.etaMinutes", { m, s });
  } else {
    eta = t("run.dashboard.etaSeconds", { s });
  }

  return (
    <div
      className="flex justify-between text-xs md-text-muted"
      data-testid="pipeline-throughput"
      data-eta-seconds={throughput.etaSeconds ?? ""}
    >
      <span>{rate}</span>
      <span>{eta}</span>
    </div>
  );
}

export function PipelineRunDashboard(): JSX.Element {
  const { t } = useTranslation("pipeline");
  const status = usePipelineStore((s) => s.status);
  const error = usePipelineStore((s) => s.error);
  const activeStage = usePipelineStore((s) => s.activeStage);
  const activeStagePct = usePipelineStore((s) => s.activeStagePct);
  const activeStageMsg = usePipelineStore((s) => s.activeStageMsg);
  const throughput = usePipelineStore((s) => s.throughput);

  const isRunning = status === "running" || status === "pending";
  const pctClamped = Math.max(0, Math.min(1, activeStagePct));

  return (
    <div className="space-y-3 text-xs md-text-secondary">
      {status === "failed" && (
        <div className="md-panel p-3 border md-border-error md-text-error">
          <div className="font-semibold mb-0.5">{t("run.dashboard.failedTitle")}</div>
          <div className="font-mono">{error ?? t("run.dashboard.unknownError")}</div>
        </div>
      )}

      {status === "cancelled" && (
        <div className="md-panel p-3 border md-border-warning md-text-warning">
          {t("run.dashboard.cancelled")}
        </div>
      )}

      {status === "succeeded" && (
        <div className="md-text-muted italic">{t("run.dashboard.completed")}</div>
      )}

      {isRunning && activeStage && (
        <div className="md-panel p-3 space-y-1" aria-live="polite">
          <div className="flex justify-between text-xs">
            <span className="md-text-accent">{activeStage}</span>
            <span className="md-text-muted">
              {(pctClamped * 100).toFixed(0)}%
            </span>
          </div>
          <div className="h-1.5 rounded bg-[var(--md-bg-hover)] overflow-hidden">
            <div
              role="progressbar"
              aria-valuenow={pctClamped * 100}
              aria-valuemin={0}
              aria-valuemax={100}
              className="h-full bg-[var(--md-accent-blue)] transition-all duration-300"
              style={{ width: `${pctClamped * 100}%` }}
            />
          </div>
          {throughput && throughput.perSec > 0 && (
            <ThroughputRow throughput={throughput} />
          )}
          {activeStageMsg && (
            <div className="text-xs md-text-muted truncate">
              {activeStageMsg}
            </div>
          )}
        </div>
      )}

      <FunnelChart />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <StageTimingTable />
        <LiveOracleLog />
      </div>

      <RunDiagnostics />

      <HitsList />
    </div>
  );
}
