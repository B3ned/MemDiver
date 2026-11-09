/**
 * Animated funnel chart for the Pipeline run dashboard.
 *
 * Renders one horizontal bar per reduction stage (raw → variance →
 * aligned → high_entropy → candidates → verified). Bars are log-scaled
 * against the ``raw`` byte count so a 192 MB → 2 byte reduction is still
 * visually legible. CSS-only transitions — no framer-motion.
 */

import type { JSX } from "react";
import { useTranslation } from "react-i18next";

import { SEQUENTIAL_RAMP } from "@/components/charts/tokens";
import { usePipelineStore } from "@/stores/pipeline-store";
import type { FunnelCounts } from "@/stores/pipeline-store";

import { ScudoFunnel } from "./ScudoFunnel";

interface FunnelRow {
  key: keyof FunnelCounts;
  labelKey: string;
}

// Stage order doubles as the ramp index: "raw" (the funnel's widest, earliest
// stage) takes the lightest step, "verified" (narrowest, most-refined) the
// darkest — see SEQUENTIAL_RAMP in components/charts/tokens.ts.
const ROWS: FunnelRow[] = [
  { key: "raw", labelKey: "run.funnel.rows.raw" },
  { key: "variance", labelKey: "run.funnel.rows.variance" },
  { key: "aligned", labelKey: "run.funnel.rows.aligned" },
  { key: "high_entropy", labelKey: "run.funnel.rows.highEntropy" },
  { key: "candidates", labelKey: "run.funnel.rows.candidates" },
  { key: "verified", labelKey: "run.funnel.rows.verified" },
];

function logFraction(count: number, raw: number): number {
  if (raw <= 0 || count <= 0) return 0;
  if (count >= raw) return 1;
  const num = Math.log10(Math.max(1, count));
  const den = Math.log10(Math.max(1, raw));
  if (den <= 0) return 0;
  return Math.max(0, Math.min(1, num / den));
}

export function FunnelChart(): JSX.Element {
  const { t } = useTranslation("pipeline");
  const funnel = usePipelineStore((s) => s.funnel);
  const scudoSummary = usePipelineStore((s) => s.scudoSummary);
  const raw = funnel.raw;

  if (scudoSummary) {
    return <ScudoFunnel summary={scudoSummary} verified={funnel.verified} />;
  }

  return (
    <div
      className="md-panel p-3 space-y-2 text-xs md-text-secondary"
      data-tour-id="pipeline-funnel"
    >
      <div className="md-text-accent font-semibold">{t("run.funnel.title")}</div>
      {raw === 0 ? (
        <div className="md-text-muted italic py-2">
          {t("run.funnel.awaiting")}
        </div>
      ) : (
        <div className="space-y-1.5" aria-live="polite">
          {ROWS.map((row, index) => {
            const count = funnel[row.key];
            const fraction = logFraction(count, raw);
            return (
              <div key={row.key} className="flex items-center gap-2">
                <div className="w-[100px] shrink-0 capitalize md-text-muted">
                  {t(row.labelKey)}
                </div>
                <div className="flex-1 h-3 rounded bg-[var(--md-bg-hover)] overflow-hidden">
                  <div
                    className="h-full transition-[width] duration-500 ease-out"
                    style={{
                      width: `${fraction * 100}%`,
                      backgroundColor: SEQUENTIAL_RAMP[index],
                    }}
                  />
                </div>
                <div className="w-[110px] shrink-0 text-right font-mono md-text-secondary">
                  {count.toLocaleString()}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
