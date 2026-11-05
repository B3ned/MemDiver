/** Pure transcript reducer for the agent chat WebSocket protocol (unknown events are ignored). */

export interface ChatLocation { dump_path: string; va?: number; offset?: number; view?: string }

export interface ToolResult {
  ok: boolean; summary: string; bytes: number; truncated: boolean; locations: ChatLocation[];
}

export type TranscriptItem =
  | { kind: "user"; text: string }
  | { kind: "assistant"; text: string; streaming: boolean }
  | { kind: "tool"; id: string; name: string; input: unknown; access: string; result: ToolResult | null }
  | {
      kind: "approval"; id: string; tool: string; input: unknown; access: string; scopes: string[];
      resolved: { allowed: boolean; message: string } | null;
    }
  | { kind: "error"; code: string; message: string };

export interface Usage {
  turns: number; max_turns: number; cost_estimate_usd: number; max_budget_usd: number;
  /** `false` when the provider has no price (e.g. a local model); absent means known. */
  cost_known?: boolean;
}
export type ChatState = "idle" | "starting" | "ready" | "running" | "closed";

export interface ChatView {
  items: TranscriptItem[];
  state: ChatState;
  usage: Usage | null;
  result: { stop_reason: string; is_error: boolean } | null;
}

export const EMPTY_CHAT: ChatView = { items: [], state: "idle", usage: null, result: null };

const asRecord = (v: unknown): Record<string, unknown> =>
  v !== null && typeof v === "object" ? (v as Record<string, unknown>) : {};
const str = (v: unknown, d = ""): string => (typeof v === "string" ? v : d);
const num = (v: unknown, d = 0): number => (typeof v === "number" && Number.isFinite(v) ? v : d);

function finishStreaming(items: TranscriptItem[]): TranscriptItem[] {
  const last = items[items.length - 1];
  if (last?.kind === "assistant" && last.streaming) return [...items.slice(0, -1), { ...last, streaming: false }];
  return items;
}

function parseLocations(raw: unknown): ChatLocation[] {
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((entry) => {
    const e = asRecord(entry);
    if (typeof e.dump_path !== "string") return [];
    const loc: ChatLocation = { dump_path: e.dump_path };
    if (typeof e.va === "number") loc.va = e.va;
    if (typeof e.offset === "number") loc.offset = e.offset;
    if (typeof e.view === "string") loc.view = e.view;
    return [loc];
  });
}

const mapItem = (items: TranscriptItem[], match: (i: TranscriptItem) => boolean,
  change: (i: TranscriptItem) => TranscriptItem): TranscriptItem[] =>
  items.map((i) => (match(i) ? change(i) : i));

export function reduceChatEvent(view: ChatView, raw: unknown): ChatView {
  const ev = asRecord(raw);
  const items = view.items;
  switch (ev.type) {
    case "status": {
      const state = str(ev.state) as ChatState;
      return ["starting", "ready", "running", "closed"].includes(state) ? { ...view, state } : view;
    }
    case "text_delta": {
      const last = items[items.length - 1];
      if (last?.kind === "assistant" && last.streaming) {
        return { ...view, items: [...items.slice(0, -1), { ...last, text: last.text + str(ev.text) }] };
      }
      return { ...view, items: [...items, { kind: "assistant", text: str(ev.text), streaming: true }] };
    }
    case "assistant_message": {
      const last = items[items.length - 1];
      const done: TranscriptItem = { kind: "assistant", text: str(ev.text), streaming: false };
      if (last?.kind === "assistant" && last.streaming) return { ...view, items: [...items.slice(0, -1), done] };
      return { ...view, items: [...items, done] };
    }
    case "tool_call":
      return { ...view, items: [...finishStreaming(items), {
        kind: "tool", id: str(ev.id), name: str(ev.name), input: ev.input ?? {}, access: str(ev.access, "read"),
        result: null,
      }] };
    case "tool_result": {
      const result: ToolResult = {
        ok: ev.ok === true, summary: str(ev.summary), bytes: num(ev.bytes),
        truncated: ev.truncated === true, locations: parseLocations(ev.locations),
      };
      return { ...view, items: mapItem(items, (i) => i.kind === "tool" && i.id === ev.id,
        (i) => ({ ...(i as Extract<TranscriptItem, { kind: "tool" }>), result })) };
    }
    case "approval_request":
      return { ...view, items: [...finishStreaming(items), {
        kind: "approval", id: str(ev.id), tool: str(ev.tool), input: ev.input ?? {}, access: str(ev.access, "write"),
        scopes: Array.isArray(ev.scopes) ? ev.scopes.filter((s): s is string => typeof s === "string") : ["once"],
        resolved: null,
      }] };
    case "approval_resolved": {
      const resolved = { allowed: ev.allowed === true, message: str(ev.message) };
      return { ...view, items: mapItem(items, (i) => i.kind === "approval" && i.id === ev.id,
        (i) => ({ ...(i as Extract<TranscriptItem, { kind: "approval" }>), resolved })) };
    }
    case "usage":
      return { ...view, usage: {
        turns: num(ev.turns), max_turns: num(ev.max_turns), cost_estimate_usd: num(ev.cost_estimate_usd),
        max_budget_usd: num(ev.max_budget_usd),
        ...(typeof ev.cost_known === "boolean" ? { cost_known: ev.cost_known } : {}),
      } };
    case "result":
      return { ...view, items: finishStreaming(items),
        result: { stop_reason: str(ev.stop_reason), is_error: ev.is_error === true } };
    case "error":
      return { ...view, items: [...finishStreaming(items), { kind: "error", code: str(ev.code), message: str(ev.message) }] };
    default:
      return view;
  }
}
