import { request } from "./client";

export type ProviderKind = "claude-sdk" | "openai-compat";

/** What the server reveals about a provider preset (never its base URL or key). */
export interface ProviderInfo {
  id: string;
  kind: ProviderKind;
  default_model: string;
  model_suggestions: string[];
  supports_effort: boolean;
  /** USD per 1M tokens: `[input, output]`. */
  default_prices: [number, number];
  default_tool_set: string;
  local: boolean;
  available: boolean;
  reason: string | null;
}

export interface AgentStatus {
  available: boolean;
  backend: "sdk" | "scripted" | "scripted-compat";
  credentials: boolean;
  /** The selected provider id; absent only from servers older than the provider presets. */
  provider?: string;
  providers?: ProviderInfo[];
  reason?: string;
  install_hint?: string;
}

export interface AgentSettings {
  model: string;
  effort: string;
  max_turns: number;
  max_budget_usd: number;
  result_budget_bytes: number;
  provider: string;
  /** `null` means the provider preset's default tool set. */
  tool_set: string | null;
  /** USD per 1M tokens; `null` means the provider preset's default price. */
  price_input_per_mtok: number | null;
  price_output_per_mtok: number | null;
}

export type NumericSettingName = "max_turns" | "max_budget_usd" | "result_budget_bytes";

export interface AgentSettingsBundle {
  settings: AgentSettings;
  defaults: AgentSettings;
  limits: Record<NumericSettingName, [number, number]>;
  choices: { model: string[]; effort: string[]; provider: string[]; providers: ProviderInfo[]; tool_set: string[] };
  warning: boolean;
}

export interface Playbook {
  name: string;
  summary: string;
  params: string[];
}

export interface AgentChatTicket {
  chat_id: string;
  ws_path: string;
  read_tools: string[];
  write_tools: string[];
  /** Non-fatal notes (e.g. the case is read-only for the chat); the UI may ignore them. */
  warnings?: string[];
}

export interface StartChatBody {
  case_dir?: string;
  dump_paths?: string[];
}

export const getAgentStatus = () => request<AgentStatus>("/api/agent/status");

export const getAgentSettings = () => request<AgentSettingsBundle>("/api/agent/settings");

export const putAgentSettings = (changes: Partial<AgentSettings>) =>
  request<AgentSettingsBundle>("/api/agent/settings", { method: "PUT", body: JSON.stringify(changes) });

/** Model ids an OpenAI-compatible provider serves (a POST: the server makes a key-bearing call). */
export const listProviderModels = (providerId: string) =>
  request<{ models: string[] }>(`/api/agent/providers/${encodeURIComponent(providerId)}/models`, { method: "POST" });

export const listPlaybooks = () => request<Playbook[]>("/api/agent/playbooks");

export const renderPlaybook = (name: string, args: Record<string, string>) =>
  request<{ text: string }>(`/api/agent/playbooks/${encodeURIComponent(name)}/render`, {
    method: "POST",
    body: JSON.stringify({ args }),
  });

export const startAgentChat = (body: StartChatBody) =>
  request<AgentChatTicket>("/api/agent/chats", { method: "POST", body: JSON.stringify(body) });

export const deleteAgentChat = (chatId: string) =>
  request<void>(`/api/agent/chats/${encodeURIComponent(chatId)}`, { method: "DELETE" });

/** Absolute ws:// URL for a ticket's `ws_path`; carries the page's `?token=` when it has one. */
export function agentSocketUrl(wsPath: string): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  let token: string | null = null;
  try { token = new URLSearchParams(location.search).get("token"); } catch { token = null; }
  const sep = wsPath.includes("?") ? "&" : "?";
  const suffix = token && !wsPath.includes("token=") ? `${sep}token=${encodeURIComponent(token)}` : "";
  return `${proto}//${location.host}${wsPath}${suffix}`;
}
