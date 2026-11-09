/**
 * Wall-clock stage timings for the Pipeline run dashboard.
 *
 * Displays consensus / reduce / brute_force wall times from the
 * pipeline store's ``timings`` field plus a total row. Values ≥ 1000 ms
 * are shown in seconds; smaller values stay in milliseconds.
 */

import type { JSX } from "react";
import { useTranslation } from "react-i18next";

import { usePipelineStore } from "@/stores/pipeline-store";
import type { StageTimings } from "@/stores/pipeline-store";

interface TimingRow {
  key: keyof StageTimings;
  labelKey: string;
}

const ROWS: TimingRow[] = [
  { key: "consensus_ms", labelKey: "run.timings.consensus" },
  { key: "reduce_ms", labelKey: "run.timings.searchReduce" },
  { key: "brute_force_ms", labelKey: "run.timings.bruteForce" },
];

function formatMs(ms: number): string {
  if (ms >= 1000) {
    return `${(ms / 1000).toFixed(2)} s`;
  }
  return `${ms.toFixed(0)} ms`;
}

export function StageTimingTable(): JSX.Element {
  const { t } = useTranslation("pipeline");
  const timings = usePipelineStore((s) => s.timings);
  // A Scudo run builds its chunk consensus inside search-reduce, so a separate
  // row would only ever read "0 ms".
  const scudoRun = usePipelineStore((s) => s.form.scudo !== null);
  const rows = scudoRun ? ROWS.filter((row) => row.key !== "consensus_ms") : ROWS;
  const total =
    timings.consensus_ms + timings.reduce_ms + timings.brute_force_ms;

  return (
    <div className="md-panel p-3 space-y-2 text-xs md-text-secondary">
      <div className="md-text-accent font-semibold">{t("run.timings.title")}</div>
      <table className="w-full border-collapse">
        <tbody>
          {rows.map((row) => (
            <tr key={row.key} className="border-b border-[var(--md-border)]">
              <td className="py-1 md-text-muted">{t(row.labelKey)}</td>
              <td className="py-1 text-right font-mono">
                {formatMs(timings[row.key])}
              </td>
            </tr>
          ))}
          <tr>
            <td className="pt-1.5 md-text-accent font-semibold">{t("run.timings.total")}</td>
            <td className="pt-1.5 text-right font-mono md-text-accent font-semibold">
              {formatMs(total)}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}
