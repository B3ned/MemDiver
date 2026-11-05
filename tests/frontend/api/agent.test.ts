import { afterEach, describe, expect, it, vi } from "vitest";

import { agentSocketUrl, listProviderModels, putAgentSettings, renderPlaybook, startAgentChat } from "@/api/agent";

afterEach(() => vi.unstubAllGlobals());

function mockFetch(body: unknown = {}) {
  const fn = vi.fn(async () => new Response(JSON.stringify(body)));
  vi.stubGlobal("fetch", fn);
  return fn;
}
const call = (fn: ReturnType<typeof mockFetch>) => fn.mock.calls.at(-1) as unknown as [string, RequestInit];

describe("agent client", () => {
  it("PUTs partial settings", async () => {
    const fn = mockFetch();
    await putAgentSettings({ max_turns: 5 });
    expect(call(fn)[0]).toBe("/api/agent/settings");
    expect(call(fn)[1].method).toBe("PUT");
    expect(JSON.parse(call(fn)[1].body as string)).toEqual({ max_turns: 5 });
  });

  it("renders a playbook and starts a chat", async () => {
    const fn = mockFetch({ text: "t" });
    await renderPlaybook("a b", { x: "1" });
    expect(call(fn)[0]).toBe("/api/agent/playbooks/a%20b/render");
    await startAgentChat({ case_dir: "/c" });
    expect(call(fn)[0]).toBe("/api/agent/chats");
    expect(JSON.parse(call(fn)[1].body as string)).toEqual({ case_dir: "/c" });
  });

  it("POSTs a provider's model listing", async () => {
    const fn = mockFetch({ models: ["a"] });
    expect(await listProviderModels("my llm")).toEqual({ models: ["a"] });
    expect(call(fn)[0]).toBe("/api/agent/providers/my%20llm/models");
    expect(call(fn)[1].method).toBe("POST");
  });

  it("builds a ws url from the ticket path", () => {
    expect(agentSocketUrl("/ws/agent/c1")).toMatch(/^wss?:\/\/.+\/ws\/agent\/c1$/);
  });
});
