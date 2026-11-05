import type { AgentSettings, NumericSettingName } from "@/api/agent";

/** The form's editable copy: every field as text; "" means `null` for the nullable ones. */
export type Draft = Record<keyof AgentSettings, string>;
export type PriceSettingName = "price_input_per_mtok" | "price_output_per_mtok";

export const PRICE_FIELDS: PriceSettingName[] = ["price_input_per_mtok", "price_output_per_mtok"];
/** Server bound on a per-1M-token price (USD). */
export const MAX_PRICE = 1000;

const text = (v: number | string | null) => (v === null ? "" : String(v));

export const toDraft = (s: AgentSettings): Draft => ({
  model: s.model, effort: s.effort, max_turns: String(s.max_turns),
  max_budget_usd: String(s.max_budget_usd), result_budget_bytes: String(s.result_budget_bytes),
  provider: s.provider, tool_set: text(s.tool_set),
  price_input_per_mtok: text(s.price_input_per_mtok), price_output_per_mtok: text(s.price_output_per_mtok),
});

export function numericProblem(raw: string, name: NumericSettingName, [lo, hi]: [number, number]): boolean {
  const v = Number(raw);
  if (raw.trim() === "" || !Number.isFinite(v) || v < lo || v > hi) return true;
  return name !== "max_budget_usd" && !Number.isInteger(v);
}

/** An empty price is fine (the preset default); otherwise a finite number in [0, MAX_PRICE]. */
export function priceProblem(raw: string): boolean {
  if (raw.trim() === "") return false;
  const v = Number(raw);
  return !Number.isFinite(v) || v < 0 || v > MAX_PRICE;
}

const orNull = (raw: string) => (raw.trim() === "" ? null : raw.trim());

/** The PUT body for a draft that passed validation. */
export const toChanges = (d: Draft): AgentSettings => ({
  provider: d.provider, model: d.model.trim(), effort: d.effort,
  max_turns: Number(d.max_turns), max_budget_usd: Number(d.max_budget_usd),
  result_budget_bytes: Number(d.result_budget_bytes), tool_set: orNull(d.tool_set),
  price_input_per_mtok: d.price_input_per_mtok.trim() === "" ? null : Number(d.price_input_per_mtok),
  price_output_per_mtok: d.price_output_per_mtok.trim() === "" ? null : Number(d.price_output_per_mtok),
});
