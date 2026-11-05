import { useTranslation } from "react-i18next";

import type { Usage } from "@/stores/agent-reducer";

export function UsageMeter({ usage }: { usage: Usage | null }) {
  const { t } = useTranslation("agent");
  if (!usage) return null;
  return (
    <div role="status" aria-label={t("usage.aria")} data-testid="usage-meter"
      className="flex gap-3 text-[11px] md-text-secondary">
      <span>{t("usage.turns", { turns: usage.turns, max: usage.max_turns })}</span>
      {usage.cost_known === false ? <span>{t("usage.costUnknown")}</span> : (
        <>
          <span>{t("usage.cost", { cost: usage.cost_estimate_usd.toFixed(2), max: usage.max_budget_usd.toFixed(2) })}</span>
          <span className="md-text-muted">({t("usage.estimated")})</span>
        </>
      )}
    </div>
  );
}
