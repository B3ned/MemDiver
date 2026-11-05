import type { AgentSettingsBundle, ProviderInfo } from "@/api/agent";

export const provider = (over: Partial<ProviderInfo>): ProviderInfo => ({
  id: "anthropic", kind: "claude-sdk", default_model: "m1", model_suggestions: ["m1", "m2"],
  supports_effort: true, default_prices: [5, 25], default_tool_set: "full", local: false,
  available: true, reason: null, ...over,
});

export const PROVIDERS: ProviderInfo[] = [
  provider({}),
  provider({ id: "ollama", kind: "openai-compat", default_model: "llama3.3", model_suggestions: ["llama3.3"],
    supports_effort: false, default_prices: [0, 0], default_tool_set: "minimal", local: true }),
  provider({ id: "openai", kind: "openai-compat", default_model: "gpt-x", model_suggestions: ["gpt-x"],
    available: false, reason: "set OPENAI_API_KEY" }),
];

const base = {
  effort: "low", max_turns: 8, max_budget_usd: 0.5, result_budget_bytes: 20000,
  provider: "anthropic", tool_set: null, price_input_per_mtok: null, price_output_per_mtok: null,
};

export const bundle: AgentSettingsBundle = {
  settings: { ...base, model: "m1", max_turns: 12, max_budget_usd: 1 },
  defaults: { ...base, model: "m1" },
  limits: { max_turns: [1, 200], max_budget_usd: [0.05, 50], result_budget_bytes: [2000, 500000] },
  choices: { model: ["m1", "m2"], effort: ["low", "high"], provider: PROVIDERS.map((p) => p.id),
    providers: PROVIDERS, tool_set: ["full", "compact", "minimal"] },
  warning: false,
};
