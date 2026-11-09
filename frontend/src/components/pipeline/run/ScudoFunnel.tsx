/**
 * Verdict table for an Android Scudo run, shown in place of the funnel bars.
 *
 * The positional funnel narrows bytes step by step. The Scudo reduction instead
 * gives every chunk of the reference exactly one verdict, so its numbers are a
 * partition, and "not judged" must stay distinct from "ruled out": a chunk whose
 * signature is absent from another run was never compared.
 */

import type { JSX } from "react";
import { useTranslation } from "react-i18next";

import type { ScudoReduceSummary } from "@/api/progress-events";
import { SCUDO_KEPT_VERDICTS, SCUDO_NOT_JUDGED_VERDICTS } from "@/components/pipeline/constants";
import { formatBytes } from "@/utils/format-bytes";

type Outcome = "kept" | "dropped" | "notJudged";

const OUTCOME_CLASS: Record<Outcome, string> = {
  kept: "md-text-success",
  dropped: "md-text-muted",
  notJudged: "md-text-warning",
};

function outcomeOf(verdict: string): Outcome {
  if (SCUDO_KEPT_VERDICTS.has(verdict)) return "kept";
  return SCUDO_NOT_JUDGED_VERDICTS.has(verdict) ? "notJudged" : "dropped";
}

interface Props {
  summary: ScudoReduceSummary;
  verified: number;
}

export function ScudoFunnel({ summary, verified }: Props): JSX.Element {
  const { t } = useTranslation("pipeline");
  const { funnel, totals, num_dumps: numDumps } = summary;

  return (
    <div
      className="md-panel p-3 space-y-2 text-xs md-text-secondary"
      data-tour-id="pipeline-funnel"
      data-testid="pipeline-scudo-funnel"
    >
      <div className="md-text-accent font-semibold">{t("run.scudoFunnel.title")}</div>
      <div className="md-text-muted">{t("run.scudoFunnel.scope", { count: numDumps })}</div>
      <table className="w-full border-collapse">
        <thead>
          <tr className="md-text-muted border-b border-[var(--md-border)]">
            <th className="text-left py-1 font-normal">{t("run.scudoFunnel.colVerdict")}</th>
            <th className="text-left py-1 font-normal">{t("run.scudoFunnel.colOutcome")}</th>
            <th className="text-right py-1 font-normal">{t("run.scudoFunnel.colChunks")}</th>
            <th className="text-right py-1 font-normal">{t("run.scudoFunnel.colBytes")}</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(funnel).map(([verdict, bucket]) => {
            const outcome = outcomeOf(verdict);
            return (
              <tr
                key={verdict}
                className="border-b border-[var(--md-border)]"
                data-testid="pipeline-scudo-verdict"
                data-verdict={verdict}
                data-outcome={outcome}
              >
                <td className="py-1">
                  {t(`run.scudoFunnel.verdicts.${verdict}`, { defaultValue: verdict })}
                </td>
                <td className={`py-1 ${OUTCOME_CLASS[outcome]}`}>
                  {t(`run.scudoFunnel.outcomes.${outcome}`)}
                </td>
                <td className="py-1 text-right font-mono">{bucket.chunks.toLocaleString("en-US")}</td>
                <td className="py-1 text-right font-mono">{formatBytes(bucket.bytes)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div className="md-text-accent" data-testid="pipeline-scudo-totals">
        {t("run.scudoFunnel.totals", {
          regions: totals.regions.toLocaleString("en-US"),
          bytes: formatBytes(totals.bytes),
          windows: totals.windows.toLocaleString("en-US"),
          verified: verified.toLocaleString("en-US"),
        })}
      </div>
    </div>
  );
}
