/**
 * Pipeline bottom-tab — wizard shell.
 *
 * Owns the whole state machine for the Phase 25 Web UI: the four
 * wizard stages (recipe → dumps → oracle → thresholds), a live
 * run dashboard while the task is executing, and a results view
 * once it reaches a terminal state.
 *
 * The wizard's source of truth is `usePipelineStore`. The user's
 * form values, current stage, active task id, and last-seen seq
 * are all persisted to localStorage via the `persist` middleware,
 * so switching to another bottom tab mid-run and coming back
 * restores the exact view — including re-subscribing to the live
 * WebSocket from whatever seq was last observed.
 */

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { cancelPipelineRun, getPipelineRun } from "@/api/pipeline";
import { useFtueStore } from "@/ftue/store";
import { useTaskProgress } from "@/hooks/useTaskProgress";
import { FunnelChart } from "@/components/pipeline/run/FunnelChart";
import { HitsList, PipelineRunDashboard, RunDiagnostics } from "@/components/pipeline/run/PipelineRunDashboard";
import { ArtifactsTabs } from "@/components/pipeline/results/ArtifactsTabs";
import { RefinePanel } from "@/components/pipeline/results/RefinePanel";
import { SurvivorCurve } from "@/components/pipeline/results/SurvivorCurve";
import { StageRecipe } from "@/components/pipeline/stages/StageRecipe";
import { StageDumps } from "@/components/pipeline/stages/StageDumps";
import { StageOracle } from "@/components/pipeline/stages/StageOracle";
import { StageThresholds } from "@/components/pipeline/stages/StageThresholds";
import type { TaskProgressEvent } from "@/api/websocket";
import type { WizardStage } from "@/stores/pipeline-store";
import { usePipelineStore } from "@/stores/pipeline-store";

// Wizard-stage order used by the stepper. Labels are resolved at
// render time via t("panel.steps.<id>").
const WIZARD_STEPS: Array<{ id: WizardStage }> = [
  { id: "recipe" },
  { id: "dumps" },
  { id: "oracle" },
  { id: "thresholds" },
  { id: "running" },
  { id: "results" },
];

const STATUS_BADGE_BG: Record<string, string> = {
  idle: "var(--md-text-muted)",
  pending: "var(--md-accent-blue)",
  running: "var(--md-accent-blue)",
  succeeded: "var(--md-accent-green)",
  failed: "var(--md-accent-red)",
  cancelled: "var(--md-accent-orange)",
};

function Stepper({
  stage,
  onJump,
}: {
  stage: WizardStage;
  onJump: (next: WizardStage) => void;
}) {
  const { t } = useTranslation("pipeline");
  const activeIdx = WIZARD_STEPS.findIndex((s) => s.id === stage);
  return (
    <div className="flex items-center gap-1 px-3 py-2 border-b border-[var(--md-border)]">
      {WIZARD_STEPS.map((step, idx) => {
        const isActive = idx === activeIdx;
        const isDone = idx < activeIdx;
        // Only allow jumping BACK to completed steps. Forward jumps
        // would skip required form fields and are handled by each
        // stage's own Next button.
        const canJump = idx < activeIdx;
        return (
          <div key={step.id} className="flex items-center gap-1">
            <button
              type="button"
              disabled={!canJump}
              onClick={() => (canJump ? onJump(step.id) : undefined)}
              className={`flex items-center gap-1.5 px-2 py-0.5 rounded transition-colors text-xs ${
                isActive
                  ? "bg-[var(--md-accent-blue)] md-text-on-accent font-semibold"
                  : isDone
                    ? "md-text-secondary hover:bg-[var(--md-bg-hover)] cursor-pointer"
                    : "md-text-muted"
              }`}
            >
              <span
                className={`inline-flex items-center justify-center w-4 h-4 rounded-full text-[10px] ${
                  isActive
                    ? "bg-white text-[var(--md-accent-blue)]"
                    : isDone
                      ? "bg-[var(--md-bg-hover)] md-text-secondary"
                      : "bg-[var(--md-bg-hover)] md-text-muted"
                }`}
              >
                {idx + 1}
              </span>
              {t(`panel.steps.${step.id}`)}
            </button>
            {idx < WIZARD_STEPS.length - 1 && (
              <span className="md-text-muted text-xs">›</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

function HeaderBar() {
  const { t } = useTranslation("pipeline");
  const status = usePipelineStore((s) => s.status);
  const taskId = usePipelineStore((s) => s.taskId);
  const stage = usePipelineStore((s) => s.stage);
  const resetRun = usePipelineStore((s) => s.resetRun);
  const [cancelling, setCancelling] = useState(false);

  const [prevTaskId, setPrevTaskId] = useState(taskId);

  // Reset the debounce whenever the run transitions to a fresh task
  // (adjusted during render rather than in an effect).
  if (prevTaskId !== taskId) {
    setPrevTaskId(taskId);
    setCancelling(false);
  }

  return (
    <div className="flex items-center gap-3 px-3 py-2 border-b border-[var(--md-border)] md-bg-secondary">
      <h2 className="text-sm font-semibold md-text-accent">{t("panel.title")}</h2>
      <span
        className="inline-block text-[10px] uppercase tracking-wide md-text-on-accent rounded px-2 py-0.5"
        style={{ background: STATUS_BADGE_BG[status] ?? "var(--md-text-muted)" }}
      >
        {status}
      </span>
      <span className="md-text-muted text-xs">{t("panel.stageLabel", { stage })}</span>
      {taskId && (
        <span className="md-text-muted text-[10px] font-mono truncate">
          {t("panel.taskLabel", { taskId: taskId.slice(0, 12) })}
        </span>
      )}
      <div className="flex-1" />
      {(status === "running" || status === "pending") && taskId && (
        <button
          type="button"
          data-testid="pipeline-cancel-btn"
          disabled={cancelling}
          onClick={() => {
            setCancelling(true);
            void cancelPipelineRun(taskId).catch(() => undefined);
          }}
          className="text-xs px-2 py-1 rounded bg-[var(--md-accent-orange)] text-[var(--md-text-bright)] hover:opacity-90 disabled:opacity-50"
          title={t("panel.cancelTitle")}
        >
          {cancelling ? t("panel.cancelling") : t("panel.cancelRun")}
        </button>
      )}
      {(status === "succeeded" || status === "failed" || status === "cancelled") && (
        <button
          type="button"
          onClick={resetRun}
          className="text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
          title={t("panel.newRunTitle")}
        >
          {t("panel.newRun")}
        </button>
      )}
    </div>
  );
}

function ResumingBanner() {
  const { t } = useTranslation("pipeline");
  const taskId = usePipelineStore((s) => s.taskId);
  const status = usePipelineStore((s) => s.status);
  const stage = usePipelineStore((s) => s.stage);
  if (!taskId) return null;
  if (status !== "pending" && status !== "running") return null;
  return (
    <div
      className="mx-3 mt-3 p-2 text-xs rounded border border-[var(--md-accent-blue)] bg-[var(--md-bg-hover)] md-text-accent"
      data-testid="pipeline-resuming-banner"
    >
      {t("panel.resuming")}{" "}
      <span className="font-mono">{taskId.slice(0, 12)}…</span>{" "}
      {t("panel.resumingTail", { stage })}
    </div>
  );
}

function ResultsView() {
  const scudoRan = usePipelineStore((s) => s.scudoSummary !== null);
  return (
    <div className="p-4 space-y-4">
      {/*
       * The verdicts say why a Scudo run searched what it searched. They would
       * otherwise leave the screen with the run dashboard, which is exactly
       * when a zero-hit run needs them.
       */}
      {scudoRan && <FunnelChart />}
      {/*
       * The verified hits are the run's headline result -- a key proven against
       * a real capture shows here as "Verified via pcap capture". `HitsList`
       * is also mounted by the run dashboard while `stage === "running"`; the
       * two stages are mutually exclusive, so the list never renders twice.
       * It self-hides when there are no hits.
       */}
      <HitsList />
      {/*
       * ...and the diagnostics say what that hit list is worth. `HitsList`
       * renders nothing on a zero-hit run, which used to leave this screen
       * completely silent: a secret at a non-stride-aligned offset was never
       * tested, yet the run still reported "succeeded". `RunDiagnostics`
       * shows the search coverage (on every run, hit or not) and any backend
       * warning such as `brute_force.partial_coverage`.
       */}
      <RunDiagnostics />
      <SurvivorCurve />
      <RefinePanel />
      <ArtifactsTabs />
    </div>
  );
}

export default function PipelinePanel() {
  const stage = usePipelineStore((s) => s.stage);
  const status = usePipelineStore((s) => s.status);
  const taskId = usePipelineStore((s) => s.taskId);
  const lastSeq = usePipelineStore((s) => s.lastSeq);
  const setStage = usePipelineStore((s) => s.setStage);
  const ingestEvent = usePipelineStore((s) => s.ingestEvent);

  // Subscribe to the task progress stream whenever there's an active
  // taskId. The hook is a no-op when taskId is null.
  useTaskProgress(taskId, {
    onEvent: (event: TaskProgressEvent) => {
      ingestEvent(event);
      if (event.type === "error") void usePipelineStore.getState().offerForcedRerun(event);
    },
    since: lastSeq,
  });

  // TourProvider only re-evaluates triggers on appView change, so
  // clicking into this tab from inside "workspace" wouldn't otherwise
  // fire pipeline-101. Kick the check manually on first mount.
  useEffect(() => {
    const ftue = useFtueStore.getState();
    if (ftue.activeTourId !== null) return;
    if (!ftue.seenTours.some((t) => t.id === "pipeline-101")) {
      ftue.startTour("pipeline-101");
    }
  }, []);

  // When the pipeline finishes, advance the wizard to results. When
  // the pipeline is actively running but we haven't entered the run
  // stage yet (e.g. because a re-mount landed on the old stage after
  // a tab switch), push the user forward.
  useEffect(() => {
    if (status === "succeeded" || status === "failed" || status === "cancelled") {
      if (stage !== "results") setStage("results");
      return;
    }
    if ((status === "running" || status === "pending") && stage !== "running") {
      setStage("running");
    }
  }, [status, stage, setStage]);

  // When a persisted taskId rehydrates from localStorage but the user
  // has since gone and deleted the backend task (or restarted the
  // server), fetch the canonical record once to sync our local status.
  //
  // The record is folded in unconditionally, terminal or not. A reload
  // DURING a long run used to restore nothing at all — the old early-out
  // below skipped every non-terminal record, leaving status, artifacts and
  // the stage history blank while the run ground on. The WebSocket ring
  // cannot fill that in either (it holds 512 events; a stride-1 brute-force
  // run emits thousands), so this record is the only mechanism there is.
  //
  // When the task is already terminal on load (e.g. the user was away,
  // came back after completion), the WebSocket backfill won't fire — so
  // we manually replay the saved `record.stages` as synthetic
  // stage_start / stage_end events. Without this, the stepper jumps
  // straight to the terminal badge with an empty funnel; with it, the
  // full stage history repaints as if we'd watched it live.
  useEffect(() => {
    if (!taskId) return;
    let cancelled = false;
    void getPipelineRun(taskId)
      .then((record) => {
        if (cancelled) return;
        // Repaint from the canonical record first. Safe for a live run
        // because it never touches `lastSeq` — see hydrateFromRecord's note.
        usePipelineStore.getState().hydrateFromRecord(record);
        const isTerminal =
          record.status === "succeeded" ||
          record.status === "failed" ||
          record.status === "cancelled";
        if (!isTerminal) return;
        // A run that failed on the memory guard before the socket attached.
        if (record.status === "failed") void usePipelineStore.getState().offerForcedRerun(record);

        // Replay stage history. Use a local seq cursor advanced past
        // the *current* lastSeq (read at run time, not from the stale
        // closure value) so the reducer's "already seen" check never
        // drops a synthetic event and the base isn't numbered off a
        // pre-rehydration snapshot.
        let seq = usePipelineStore.getState().lastSeq;
        for (const stage of record.stages ?? []) {
          const startTs = stage.started_at ?? record.started_at ?? record.created_at;
          ingestEvent({
            task_id: taskId,
            type: "stage_start",
            stage: stage.name,
            seq: ++seq,
            ts: startTs ?? Date.now() / 1000,
            msg: stage.msg ?? null,
          });
          // If the stage itself finished, emit stage_end too. Stages
          // that were mid-flight when the task aborted stay at their
          // last-known pct/msg.
          if (
            stage.status === "succeeded" ||
            stage.status === "failed" ||
            stage.status === "cancelled"
          ) {
            const endTs = stage.ended_at ?? startTs;
            ingestEvent({
              task_id: taskId,
              type: "stage_end",
              stage: stage.name,
              seq: ++seq,
              ts: endTs ?? Date.now() / 1000,
              pct: 1,
              msg: stage.msg ?? null,
            });
          }
        }

        // Finally, emit the terminal event so `status` flips.
        ingestEvent({
          task_id: taskId,
          type: record.status === "succeeded" ? "done" : "error",
          seq: ++seq,
          ts: Date.now() / 1000,
          error: record.error ?? undefined,
        });
      })
      .catch(() => {
        // Backend forgot about this task; reset the store so the
        // stepper returns to the recipe stage.
        if (cancelled) return;
        usePipelineStore.getState().resetRun();
      });
    return () => {
      cancelled = true;
    };
    // Intentionally only re-runs on taskId change — re-running on
    // every lastSeq bump would hammer the endpoint.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [taskId]);

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <HeaderBar />
      <Stepper stage={stage} onJump={setStage} />
      <ResumingBanner />
      <div className="flex-1 overflow-auto">
        {stage === "recipe" && <StageRecipe onAdvance={setStage} />}
        {stage === "dumps" && <StageDumps onAdvance={setStage} />}
        {stage === "oracle" && <StageOracle onAdvance={setStage} />}
        {stage === "thresholds" && <StageThresholds onAdvance={setStage} />}
        {stage === "running" && <PipelineRunDashboard />}
        {stage === "results" && <ResultsView />}
      </div>
    </div>
  );
}
