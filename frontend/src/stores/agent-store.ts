import { create } from "zustand";

import {
  agentSocketUrl, deleteAgentChat, getAgentSettings, getAgentStatus, putAgentSettings, startAgentChat,
  type AgentSettings, type AgentSettingsBundle, type AgentStatus, type StartChatBody,
} from "@/api/agent";
import { readableFailure } from "@/api/client";
import { EMPTY_CHAT, reduceChatEvent, type ChatView } from "./agent-reducer";

/**
 * Agent chat state. Deliberately NOT persisted: the transcript can hold forensic
 * content and nothing here is a secret (credentials live on the server only).
 * Since nothing is persisted there is no zustand `version`/`migrate` to maintain.
 */
interface AgentState extends ChatView {
  status: AgentStatus | null;
  statusError: string | null;
  bundle: AgentSettingsBundle | null;
  chatId: string | null;
  connectionError: string | null;
  loadStatus: () => Promise<void>;
  loadSettings: () => Promise<void>;
  saveSettings: (changes: Partial<AgentSettings>) => Promise<void>;
  startChat: (body: StartChatBody) => Promise<void>;
  endChat: () => Promise<void>;
  sendMessage: (text: string) => boolean;
  sendApproval: (id: string, allow: boolean, scope: "once" | "chat", message?: string) => boolean;
  interrupt: () => boolean;
  ingest: (event: unknown) => void;
  reset: () => void;
}

let socket: WebSocket | null = null;

function post(message: Record<string, unknown>): boolean {
  if (!socket || socket.readyState !== WebSocket.OPEN) return false;
  socket.send(JSON.stringify(message));
  return true;
}

function closeSocket() {
  const s = socket;
  socket = null;
  if (s) { s.onmessage = null; s.onclose = null; s.onerror = null; s.close(); }
}

const IDLE_STATE = { ...EMPTY_CHAT, chatId: null, connectionError: null };

export const useAgentStore = create<AgentState>((set, get) => ({
  ...IDLE_STATE,
  status: null,
  statusError: null,
  bundle: null,
  loadStatus: async () => {
    try { set({ status: await getAgentStatus(), statusError: null }); }
    catch (e) { set({ statusError: readableFailure(e) }); }
  },
  loadSettings: async () => { set({ bundle: await getAgentSettings() }); },
  // Status is provider-aware: refetch it after a save so the banner and Start chat follow
  // the saved provider. loadStatus never throws, so a status failure cannot fail the save.
  saveSettings: async (changes) => {
    set({ bundle: await putAgentSettings(changes) });
    await get().loadStatus();
  },
  startChat: async (body) => {
    await get().endChat();
    set({ ...EMPTY_CHAT, state: "starting", connectionError: null });
    try {
      const ticket = await startAgentChat(body);
      const ws = new WebSocket(agentSocketUrl(ticket.ws_path));
      socket = ws;
      ws.onmessage = (evt) => {
        try { get().ingest(JSON.parse(String(evt.data))); } catch { /* malformed frame: ignore */ }
      };
      ws.onerror = () => set({ connectionError: "connection" });
      ws.onclose = () => { if (socket === ws) { socket = null; set({ state: "closed" }); } };
      set({ chatId: ticket.chat_id });
    } catch (e) {
      set({ state: "idle", connectionError: readableFailure(e) });
    }
  },
  endChat: async () => {
    const id = get().chatId;
    // Closing an attached socket already closes the chat server-side (disconnect = end);
    // DELETE is only needed when the socket never attached, and would 404 (a console
    // error) for a chat the server has already closed.
    const attached = socket !== null;
    closeSocket();
    set({ ...IDLE_STATE });
    if (id && !attached) { try { await deleteAgentChat(id); } catch { /* already gone */ } }
  },
  sendMessage: (text) => {
    const trimmed = text.trim();
    if (!trimmed || !post({ type: "user_message", text: trimmed })) return false;
    set((s) => ({ items: [...s.items, { kind: "user", text: trimmed }], state: "running" }));
    return true;
  },
  sendApproval: (id, allow, scope, message) =>
    post({ type: "approval", id, allow, scope, ...(message ? { message } : {}) }),
  interrupt: () => post({ type: "interrupt" }),
  ingest: (event) => set((s) => reduceChatEvent(s, event)),
  reset: () => { closeSocket(); set({ ...IDLE_STATE }); },
}));
