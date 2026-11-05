import { useTranslation } from "react-i18next";

import type { AgentStatus } from "@/api/agent";

export function AgentStatusBanner({ status, error }: { status: AgentStatus | null; error: string | null }) {
  const { t } = useTranslation("agent");
  const note = "text-xs p-2 rounded border";
  if (error) return <p role="alert" className={note} style={{ borderColor: "var(--md-accent-red)" }}>{t("status.unreachable", { error })}</p>;
  if (!status) return <p role="status" className="text-xs md-text-muted">{t("status.loading")}</p>;
  const provider = status.providers?.find((p) => p.id === status.provider);
  const claudeProvider = !provider || provider.kind === "claude-sdk";
  return (
    <div className="space-y-1">
      {status.backend !== "sdk" && (
        <span data-testid="scripted-badge" className="inline-block text-[11px] px-1.5 rounded border"
          style={{ color: "var(--md-accent-orange)", borderColor: "var(--md-accent-orange)" }}>
          {t("status.scriptedBadge")}
        </span>
      )}
      {!status.available && (
        <div role="alert" className={note} style={{ borderColor: "var(--md-accent-red)" }}>
          {status.provider && <p data-testid="agent-provider">{t("status.provider", { provider: status.provider })}</p>}
          <p>{status.reason || (claudeProvider ? t("status.sdkMissing") : t("status.unavailable"))}</p>
          {(claudeProvider || status.install_hint) && (
            <p>{t("status.installHint")} <code className="font-mono">{status.install_hint || 'pip install "memdiver[agent]"'}</code></p>
          )}
        </div>
      )}
      {status.available && !status.credentials && status.backend === "sdk" && claudeProvider && (
        <p role="alert" className={note} style={{ borderColor: "var(--md-accent-orange)" }}>{t("status.noCredentials")}</p>
      )}
    </div>
  );
}
