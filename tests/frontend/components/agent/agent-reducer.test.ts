import { describe, expect, it } from "vitest";

import { EMPTY_CHAT, reduceChatEvent, type ChatView } from "@/stores/agent-reducer";

const run = (events: unknown[], start: ChatView = EMPTY_CHAT) => events.reduce<ChatView>(reduceChatEvent, start);

describe("agent chat reducer", () => {
  it("accumulates text deltas into one streaming bubble, then finalizes on assistant_message", () => {
    const mid = run([{ type: "text_delta", text: "Hel" }, { type: "text_delta", text: "lo" }]);
    expect(mid.items).toEqual([{ kind: "assistant", text: "Hello", streaming: true }]);
    const done = run([{ type: "assistant_message", text: "Hello!" }], mid);
    expect(done.items).toEqual([{ kind: "assistant", text: "Hello!", streaming: false }]);
  });

  it("pairs tool_result with its tool_call by id and keeps locations", () => {
    const v = run([
      { type: "tool_call", id: "a", name: "scan", input: { x: 1 }, access: "read" },
      { type: "tool_call", id: "b", name: "other", input: {}, access: "write" },
      { type: "tool_result", id: "a", ok: true, summary: "2 hits", bytes: 10, truncated: true,
        locations: [{ dump_path: "/d", offset: 5 }, { nope: 1 }] },
    ]);
    const [a, b] = v.items as Array<{ result: unknown }>;
    expect(a.result).toEqual({ ok: true, summary: "2 hits", bytes: 10, truncated: true, locations: [{ dump_path: "/d", offset: 5 }] });
    expect(b.result).toBeNull();
  });

  it("walks the approval lifecycle", () => {
    const pending = run([{ type: "approval_request", id: "p", tool: "export", input: {}, access: "write", scopes: ["once", "chat"] }]);
    expect(pending.items[0]).toMatchObject({ kind: "approval", resolved: null, scopes: ["once", "chat"] });
    const done = run([{ type: "approval_resolved", id: "p", allowed: false, message: "no" }], pending);
    expect(done.items[0]).toMatchObject({ resolved: { allowed: false, message: "no" } });
  });

  it("tracks status, usage, result and errors; ignores unknown types", () => {
    const v = run([
      { type: "status", state: "running" },
      { type: "usage", turns: 2, max_turns: 8, cost_estimate_usd: 0.1, max_budget_usd: 0.5 },
      { type: "mystery", x: 1 },
      { type: "result", session_id: "s", num_turns: 2, cost_estimate_usd: 0.1, stop_reason: "end_turn", is_error: false },
      { type: "error", code: "boom", message: "bad" },
    ]);
    expect(v.state).toBe("running");
    expect(v.usage).toEqual({ turns: 2, max_turns: 8, cost_estimate_usd: 0.1, max_budget_usd: 0.5 });
    expect(v.result).toEqual({ stop_reason: "end_turn", is_error: false });
    expect(v.items).toEqual([{ kind: "error", code: "boom", message: "bad" }]);
  });

  it("passes cost_known through only when the event carries a boolean", () => {
    const ev = { type: "usage", turns: 1, max_turns: 8, cost_estimate_usd: 0, max_budget_usd: 0.5 };
    expect(run([{ ...ev, cost_known: false }]).usage?.cost_known).toBe(false);
    expect(run([{ ...ev, cost_known: true }]).usage?.cost_known).toBe(true);
    expect(run([{ ...ev, cost_known: "no" }]).usage).not.toHaveProperty("cost_known");
  });
});
