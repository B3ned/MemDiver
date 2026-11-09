/**
 * Refine panel — lets the user fold additional dumps into the
 * consensus to tighten the neighborhood variance, tracking
 * convergence (static byte count) across successive refinements.
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";

import { refinePipeline } from "@/api/pipeline";
import { usePipelineStore } from "@/stores/pipeline-store";
import { useHexStore } from "@/stores/hex-store";
import { notifyError } from "@/utils/errorNotifier";

export function RefinePanel() {
  const { t } = useTranslation("pipeline");
  const taskId = usePipelineStore((s) => s.taskId);
  const hits = usePipelineStore((s) => s.hits);
  const history = usePipelineStore((s) => s.convergenceHistory);
  const loading = usePipelineStore((s) => s.refineLoading);
  const addPoint = usePipelineStore((s) => s.addConvergencePoint);
  const setLoading = usePipelineStore((s) => s.setRefineLoading);
  const scudoRun = usePipelineStore((s) => s.form.scudo !== null);
  const [paths, setPaths] = useState("");

  // Refine folds more dumps into a positional consensus, which a Scudo run
  // does not have.
  if (!taskId || hits.length === 0 || scudoRun) return null;

  const handleRefine = async () => {
    const pathList = paths
      .split("\n")
      .map((p) => p.trim())
      .filter(Boolean);
    if (pathList.length === 0) return;
    setLoading(true);
    try {
      const resp = await refinePipeline(taskId, pathList);
      addPoint({
        n: resp.num_dumps,
        staticCount: resp.static_count,
        dynamicCount: resp.dynamic_count,
      });
      // Update the hex store neighborhood overlay with fresh variance.
      // ``fields`` now arrives on the refine response (server-inferred);
      // no client-side recompute.
      if (resp.hit_neighborhoods.length > 0) {
        const nh = resp.hit_neighborhoods[0];
        const hit = hits[0];
        useHexStore.getState().setActiveNeighborhoodOverlay({
          hitOffset: hit.offset,
          hitSize: hit.size,
          neighborhoodStart: nh.neighborhood_start,
          variance: nh.neighborhood_variance,
          fields: nh.fields,
        });
      }
    } catch (err) {
      notifyError(
        t("results.refine.refineFailed", {
          error: err instanceof Error ? err.message : String(err),
        }),
        "pipeline-refine",
      );
    } finally {
      setLoading(false);
      setPaths("");
    }
  };

  const lastPoint = history[history.length - 1];
  const prevPoint = history.length >= 2 ? history[history.length - 2] : null;
  const converged =
    prevPoint != null &&
    lastPoint != null &&
    lastPoint.staticCount === prevPoint.staticCount;

  return (
    <div className="border border-[var(--md-border)] rounded-lg p-4 space-y-3">
      <h3 className="text-sm font-semibold text-[var(--md-text-primary)]">
        {t("results.refine.title")}
      </h3>

      {/* Convergence tracker */}
      {history.length > 0 && (
        <div className="flex flex-wrap gap-2 items-center text-xs">
          {history.map((pt, i) => (
            <span key={i} className="inline-flex items-center gap-1">
              {i > 0 && <span className="md-text-muted">&rarr;</span>}
              <span className="bg-[var(--md-bg-tertiary)] px-2 py-0.5 rounded font-mono">
                N={pt.n}:{" "}
                <span className="md-text-success">{pt.staticCount}</span>/
                <span className="md-text-secondary">
                  {pt.staticCount + pt.dynamicCount}
                </span>{" "}
                {t("results.refine.static")}
              </span>
            </span>
          ))}
        </div>
      )}

      {/* Convergence guidance */}
      {converged && (
        <p className="text-xs md-text-warning">
          {t("results.refine.converged")}
        </p>
      )}
      {!converged && history.length >= 2 && (
        <p className="text-xs md-text-success">
          {t("results.refine.stillDecreasing")}
        </p>
      )}

      {/* Add dumps */}
      <div className="space-y-2">
        <textarea
          className="w-full bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded px-2 py-1.5 text-xs font-mono text-[var(--md-text-primary)] placeholder-[var(--md-text-muted)]"
          rows={3}
          placeholder={t("results.refine.pathsPlaceholder")}
          value={paths}
          onChange={(e) => setPaths(e.target.value)}
          disabled={loading}
        />
        <button
          className="px-3 py-1.5 text-xs font-medium bg-[var(--md-accent-blue)] hover:opacity-90 disabled:bg-[var(--md-bg-hover)] disabled:text-[var(--md-text-muted)] rounded md-text-on-accent"
          onClick={handleRefine}
          disabled={loading || !paths.trim()}
        >
          {loading ? t("results.refine.folding") : t("results.refine.refineButton")}
        </button>
      </div>
    </div>
  );
}
