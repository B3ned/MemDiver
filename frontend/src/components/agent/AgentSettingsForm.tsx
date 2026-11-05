import { useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import type { AgentSettings, AgentSettingsBundle, NumericSettingName } from "@/api/agent";

import { ProviderModelFields } from "./ProviderModelFields";
import { numericProblem, PRICE_FIELDS, priceProblem, toChanges, toDraft, type Draft } from "./settings-draft";

const NUMERIC: { name: NumericSettingName; label: string }[] = [
  { name: "max_turns", label: "settings.maxTurns" },
  { name: "max_budget_usd", label: "settings.maxBudget" },
  { name: "result_budget_bytes", label: "settings.resultBudget" },
];

/** Any reason the draft cannot be saved yet (numeric limits, a price, an empty model). */
function hasProblems(draft: Draft, limits: AgentSettingsBundle["limits"]): boolean {
  return NUMERIC.some((n) => numericProblem(draft[n.name], n.name, limits[n.name]))
    || PRICE_FIELDS.some((name) => priceProblem(draft[name])) || draft.model.trim() === "";
}

export function AgentSettingsForm({ bundle, onSave }: {
  bundle: AgentSettingsBundle; onSave: (changes: Partial<AgentSettings>) => Promise<void>;
}) {
  const { t } = useTranslation("agent");
  const [draft, setDraft] = useState<Draft>(() => toDraft(bundle.settings));
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [syncedFrom, setSyncedFrom] = useState(bundle.settings);
  if (syncedFrom !== bundle.settings) { setSyncedFrom(bundle.settings); setDraft(toDraft(bundle.settings)); }

  const blocked = hasProblems(draft, bundle.limits);
  const patch = (changes: Partial<Draft>) => { setDraft((d) => ({ ...d, ...changes })); setMessage(null); };

  const submit = async (changes: Partial<AgentSettings>) => {
    try { await onSave(changes); setMessage({ ok: true, text: t("settings.saved") }); }
    catch (e) { setMessage({ ok: false, text: t("settings.saveFailed", { error: readableFailure(e) }) }); }
  };
  const input = "w-full px-1 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)]";

  return (
    <form data-testid="agent-settings" className="space-y-2 text-xs"
      onSubmit={(e) => { e.preventDefault(); if (!blocked) void submit(toChanges(draft)); }}>
      <h3 className="font-semibold">{t("settings.title")}</h3>
      {bundle.warning && <p role="note" style={{ color: "var(--md-accent-orange)" }}>{t("settings.warning")}</p>}
      <ProviderModelFields bundle={bundle} draft={draft} onChange={patch} />
      {NUMERIC.map(({ name, label }) => {
        const [lo, hi] = bundle.limits[name];
        const bad = numericProblem(draft[name], name, [lo, hi]);
        const id = `agent-setting-${name}`;
        return (
          <div key={name}>
            <label htmlFor={id}>{t(label)}</label>
            <input id={id} className={input} inputMode="decimal" value={draft[name]}
              aria-invalid={bad} aria-describedby={`${id}-hint`} onChange={(e) => patch({ [name]: e.target.value })} />
            <span id={`${id}-hint`} className={bad ? "" : "md-text-muted"}
              style={bad ? { color: "var(--md-accent-red)" } : undefined} role={bad ? "alert" : undefined}>
              {bad ? t("settings.invalid", { low: lo, high: hi }) : t("settings.range", { low: lo, high: hi, default: bundle.defaults[name] })}
            </span>
          </div>
        );
      })}
      <div className="flex gap-2">
        <button type="submit" disabled={blocked}
          className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50">
          {t("settings.save")}
        </button>
        <button type="button" onClick={() => void submit({ ...bundle.defaults })}
          className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
          {t("settings.reset")}
        </button>
      </div>
      {message && (
        <p role="status" style={{ color: message.ok ? "var(--md-accent-green)" : "var(--md-accent-red)" }}>{message.text}</p>
      )}
    </form>
  );
}
