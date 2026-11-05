import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { listProviderModels, type AgentSettingsBundle, type ProviderInfo } from "@/api/agent";
import { readableFailure } from "@/api/client";

import { MAX_PRICE, PRICE_FIELDS, priceProblem, type Draft } from "./settings-draft";

const INPUT = "w-full px-1 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)]";
const BUTTON = "px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50";
const ERROR = { color: "var(--md-accent-red)" };

/** A labelled control with a hint line outside the label (so the label stays the name). */
function Field({ id, label, children, hint }: { id: string; label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <div>
      <label htmlFor={id} className="block">{label}</label>
      {children}
      {hint}
    </div>
  );
}

interface Props {
  bundle: AgentSettingsBundle;
  draft: Draft;
  onChange: (patch: Partial<Draft>) => void;
}

/** Provider, model, effort and (for OpenAI-compatible providers) tool set and prices. */
export function ProviderModelFields({ bundle, draft, onChange }: Props) {
  const { t } = useTranslation("agent");
  const providers = bundle.choices.providers;
  const info = providers.find((p) => p.id === draft.provider);
  const pickProvider = (id: string) => onChange({
    provider: id, model: providers.find((p) => p.id === id)?.default_model ?? "",
    tool_set: "", price_input_per_mtok: "", price_output_per_mtok: "",
  });
  return (
    <>
      <Field id="agent-setting-provider" label={t("settings.provider")}
        hint={info && !info.available && <span role="alert" style={ERROR}>{info.reason}</span>}>
        <select id="agent-setting-provider" className={INPUT} value={draft.provider} onChange={(e) => pickProvider(e.target.value)}>
          {providers.map((p) => (
            <option key={p.id} value={p.id} disabled={!p.available}>
              {p.available ? p.id : t("settings.providerUnavailable", { id: p.id, reason: p.reason ?? "" })}
            </option>
          ))}
        </select>
      </Field>
      {info?.kind === "openai-compat"
        ? <CompatModelField key={info.id} info={info} value={draft.model} onChange={(model) => onChange({ model })} />
        : <ClaudeModelField bundle={bundle} value={draft.model} onChange={(model) => onChange({ model })} />}
      <EffortField bundle={bundle} value={draft.effort} supported={info?.supports_effort ?? true}
        onChange={(effort) => onChange({ effort })} />
      {info?.kind === "openai-compat" && <CompatExtras bundle={bundle} info={info} draft={draft} onChange={onChange} />}
    </>
  );
}

function ClaudeModelField({ bundle, value, onChange }: {
  bundle: AgentSettingsBundle; value: string; onChange: (v: string) => void;
}) {
  const { t } = useTranslation("agent");
  return (
    <Field id="agent-setting-model" label={t("settings.model")}
      hint={<span className="md-text-muted">{t("settings.choiceDefault", { value: bundle.defaults.model })}</span>}>
      <select id="agent-setting-model" className={INPUT} value={value} onChange={(e) => onChange(e.target.value)}>
        {bundle.choices.model.map((c) => <option key={c} value={c}>{c}</option>)}
      </select>
    </Field>
  );
}

function CompatModelField({ info, value, onChange }: {
  info: ProviderInfo; value: string; onChange: (v: string) => void;
}) {
  const { t } = useTranslation("agent");
  const [loaded, setLoaded] = useState<string[]>([]);
  const [state, setState] = useState<{ loading: boolean; error: string | null }>({ loading: false, error: null });
  const load = async () => {
    setState({ loading: true, error: null });
    try { setLoaded((await listProviderModels(info.id)).models); setState({ loading: false, error: null }); }
    catch (e) { setState({ loading: false, error: readableFailure(e) }); }
  };
  const options = [...new Set([...info.model_suggestions, ...loaded])];
  const listId = `agent-models-${info.id}`;
  const missing = value.trim() === "";
  return (
    <div>
      <label htmlFor="agent-setting-model">{t("settings.model")}</label>
      <div className="flex gap-1">
        <input id="agent-setting-model" className={INPUT} list={listId} value={value} aria-invalid={missing}
          placeholder={info.default_model} onChange={(e) => onChange(e.target.value)} />
        <button type="button" className={BUTTON} disabled={state.loading} onClick={() => void load()}>
          {state.loading ? t("settings.loadingModels") : t("settings.loadModels")}
        </button>
      </div>
      <datalist id={listId}>{options.map((m) => <option key={m} value={m} />)}</datalist>
      {missing && <span role="alert" style={ERROR}>{t("settings.modelRequired")}</span>}
      {!missing && <span className="md-text-muted">{t("settings.choiceDefault", { value: info.default_model || "-" })}</span>}
      {state.error && <p role="alert" style={ERROR}>{t("settings.loadModelsFailed", { error: state.error })}</p>}
      {!state.error && !state.loading && loaded.length > 0 && (
        <p role="status" className="md-text-muted">{t("settings.modelsLoaded", { count: loaded.length })}</p>
      )}
    </div>
  );
}

function EffortField({ bundle, value, supported, onChange }: {
  bundle: AgentSettingsBundle; value: string; supported: boolean; onChange: (v: string) => void;
}) {
  const { t } = useTranslation("agent");
  return (
    <Field id="agent-setting-effort" label={t("settings.effort")} hint={<span className="md-text-muted">
      {supported ? t("settings.choiceDefault", { value: bundle.defaults.effort }) : t("settings.effortUnsupported")}
    </span>}>
      <select id="agent-setting-effort" className={INPUT} value={value} disabled={!supported}
        onChange={(e) => onChange(e.target.value)}>
        {bundle.choices.effort.map((c) => <option key={c} value={c}>{c}</option>)}
      </select>
    </Field>
  );
}

function CompatExtras({ bundle, info, draft, onChange }: Props & { info: ProviderInfo }) {
  const { t } = useTranslation("agent");
  return (
    <>
      <Field id="agent-setting-tool_set" label={t("settings.toolSet")}
        hint={<span className="md-text-muted">{t("settings.toolSetHint")}</span>}>
        <select id="agent-setting-tool_set" className={INPUT} value={draft.tool_set}
          onChange={(e) => onChange({ tool_set: e.target.value })}>
          <option value="">{t("settings.toolSetDefault", { value: info.default_tool_set })}</option>
          {bundle.choices.tool_set.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </Field>
      {PRICE_FIELDS.map((name, i) => {
        const id = `agent-setting-${name}`;
        const bad = priceProblem(draft[name]);
        const preset = info.default_prices[i];
        return (
          <div key={name}>
            <label htmlFor={id}>{t(i === 0 ? "settings.priceInput" : "settings.priceOutput")}</label>
            <input id={id} className={INPUT} inputMode="decimal" value={draft[name]} placeholder={String(preset)}
              aria-invalid={bad} aria-describedby={`${id}-hint`} onChange={(e) => onChange({ [name]: e.target.value })} />
            <span id={`${id}-hint`} className={bad ? "" : "md-text-muted"} style={bad ? ERROR : undefined}
              role={bad ? "alert" : undefined}>
              {bad ? t("settings.priceInvalid", { high: MAX_PRICE }) : t("settings.priceDefault", { value: preset })}
            </span>
          </div>
        );
      })}
    </>
  );
}
