import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { artifactDownloadUrl } from "@/api/pipeline";
import type { ArtifactSpec } from "@/api/pipeline";
import { ARTIFACT_NAMES, PRIMARY_ARTIFACT_NAMES } from "@/components/pipeline/constants";
import { usePipelineStore } from "@/stores/pipeline-store";

import { PluginPreview } from "./PluginPreview";
import { ReportHtmlFrame } from "./ReportHtmlFrame";

type TabKey = "plugin" | "report" | "raw";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

function shortSha(sha: string | null): string {
  if (!sha) return "—";
  return sha.slice(0, 12);
}

interface RawListProps {
  taskId: string;
  artifacts: ArtifactSpec[];
}

function RawArtifactList({ taskId, artifacts }: RawListProps) {
  const { t } = useTranslation("pipeline");
  const secondary = artifacts.filter((a) => !PRIMARY_ARTIFACT_NAMES.has(a.name));
  if (secondary.length === 0) {
    return (
      <div className="md-panel p-3 text-xs md-text-muted">
        {t("results.artifacts.noSecondary")}
      </div>
    );
  }
  return (
    <details open className="md-panel">
      <summary className="px-3 py-1.5 text-xs md-text-accent font-semibold cursor-pointer border-b border-[var(--md-border)]">
        {t("results.artifacts.rawOutputs", { count: secondary.length })}
      </summary>
      <table className="w-full text-[11px]">
        <thead>
          <tr className="md-text-muted border-b border-[var(--md-border)]">
            <th className="text-left px-3 py-1 font-normal">{t("results.artifacts.colName")}</th>
            <th className="text-left px-3 py-1 font-normal">{t("results.artifacts.colSize")}</th>
            <th className="text-left px-3 py-1 font-normal">{t("results.artifacts.colSha")}</th>
            <th className="text-right px-3 py-1 font-normal">{t("results.artifacts.colAction")}</th>
          </tr>
        </thead>
        <tbody>
          {secondary.map((a) => (
            <tr
              key={a.name}
              className="border-b border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
            >
              <td className="px-3 py-1 font-mono md-text-secondary">{a.name}</td>
              <td className="px-3 py-1 md-text-muted">{formatBytes(a.size)}</td>
              <td className="px-3 py-1 font-mono md-text-muted">{shortSha(a.sha256)}</td>
              <td className="px-3 py-1 text-right">
                <a
                  href={artifactDownloadUrl(taskId, a.name)}
                  download
                  className="text-[11px] px-2 py-0.5 rounded bg-[var(--md-accent-blue)] md-text-on-accent"
                >
                  {t("common:download")}
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}

/**
 * Tabbed artifact browser for a completed pipeline run. Shows the
 * emitted plugin, the interactive nsweep report, and a raw download
 * list for everything else the ArtifactStore registered.
 */
export function ArtifactsTabs() {
  const { t } = useTranslation("pipeline");
  const taskId = usePipelineStore((s) => s.taskId);
  const artifacts = usePipelineStore((s) => s.artifacts);
  const scudoRun = usePipelineStore((s) => s.form.scudo !== null);
  const [tab, setTab] = useState<TabKey>("plugin");

  const hasPlugin = useMemo(
    () => artifacts.some((a) => a.name === ARTIFACT_NAMES.VOL3_PLUGIN),
    [artifacts],
  );
  const hasReport = useMemo(
    () => artifacts.some((a) => a.name === ARTIFACT_NAMES.NSWEEP_HTML),
    [artifacts],
  );

  if (!taskId) {
    return (
      <div className="md-panel p-4 text-xs md-text-muted">
        {t("results.artifacts.noRunLoaded")}
      </div>
    );
  }

  const tabs: { key: TabKey; label: string }[] = [
    { key: "plugin", label: t("results.artifacts.tabPlugin") },
    { key: "report", label: t("results.artifacts.tabReport") },
    { key: "raw", label: t("results.artifacts.tabRaw") },
  ];

  return (
    <div className="flex flex-col gap-2" data-tour-id="pipeline-artifacts">
      <div
        role="tablist"
        className="flex gap-4 px-3 py-1.5 border-b border-[var(--md-border)]"
      >
        {tabs.map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={tab === t.key}
            onClick={() => setTab(t.key)}
            className={`text-xs px-2 py-0.5 capitalize transition-colors ${
              tab === t.key
                ? "font-semibold border-b-2 border-[var(--md-accent-blue)] bg-[var(--md-bg-hover)] rounded-t"
                : "md-text-secondary hover:bg-[var(--md-bg-hover)] rounded"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div role="tabpanel" className="flex-1">
        {tab === "plugin" &&
          (hasPlugin ? (
            <PluginPreview taskId={taskId} />
          ) : (
            <div
              className="md-panel p-4 text-xs md-text-muted"
              data-testid="pipeline-no-plugin"
            >
              {scudoRun ? t("scudo.pluginUnsupported") : t("results.artifacts.noPlugin")}
            </div>
          ))}
        {tab === "report" &&
          (hasReport ? (
            <ReportHtmlFrame taskId={taskId} />
          ) : (
            <div className="md-panel p-4 text-xs md-text-muted">
              {t("results.artifacts.noReport")}
            </div>
          ))}
        {tab === "raw" && <RawArtifactList taskId={taskId} artifacts={artifacts} />}
      </div>
    </div>
  );
}
