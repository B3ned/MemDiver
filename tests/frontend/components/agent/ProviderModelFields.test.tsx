import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import "@/i18n";

vi.mock("@/api/agent", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/agent")>()), listProviderModels: vi.fn(),
}));

import { listProviderModels } from "@/api/agent";
import { ProviderModelFields } from "@/components/agent/ProviderModelFields";
import { toDraft, type Draft } from "@/components/agent/settings-draft";

import { bundle } from "./fixtures";

const draftFor = (over: Partial<Draft> = {}): Draft => ({ ...toDraft(bundle.settings), ...over });
const ollama = (over: Partial<Draft> = {}) => draftFor({ provider: "ollama", model: "llama3.3", ...over });
const renderFields = (draft: Draft) => {
  const onChange = vi.fn();
  render(<ProviderModelFields bundle={bundle} draft={draft} onChange={onChange} />);
  return onChange;
};

// Braces matter: a function returned from beforeEach runs as a teardown (it would call the mock).
beforeEach(() => { vi.mocked(listProviderModels).mockReset(); });

describe("ProviderModelFields", () => {
  it("offers the Claude models as a select with effort enabled", () => {
    renderFields(draftFor());
    const model = screen.getByLabelText("Model");
    expect(model.tagName).toBe("SELECT");
    expect(screen.getByLabelText("Effort")).toBeEnabled();
    expect(screen.queryByText("Load models")).toBeNull();
    expect(screen.queryByLabelText("Tool set")).toBeNull();
  });

  it("gives a compat provider a free-text model with suggestions, tool set and prices", () => {
    const { container } = render(<ProviderModelFields bundle={bundle} draft={ollama()} onChange={vi.fn()} />);
    const model = screen.getByLabelText("Model");
    expect(model.tagName).toBe("INPUT");
    const list = container.querySelector(`datalist#${model.getAttribute("list")}`);
    expect(list?.querySelector('option[value="llama3.3"]')).not.toBeNull();
    expect(screen.getByLabelText("Effort")).toBeDisabled();
    expect(screen.getByText("This provider does not support an effort setting.")).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "default (minimal)" })).toHaveValue("");
    expect(screen.getByLabelText("Input price (USD per 1M tokens)")).toHaveAttribute("placeholder", "0");
  });

  it("disables an unavailable provider and names the reason", () => {
    renderFields(draftFor());
    const option = screen.getByRole("option", { name: "openai (unavailable: set OPENAI_API_KEY)" });
    expect(option).toBeDisabled();
  });

  it("resets the model, tool set and prices on a provider change", () => {
    const onChange = renderFields(ollama({ tool_set: "full", price_input_per_mtok: "3" }));
    fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "anthropic" } });
    expect(onChange).toHaveBeenCalledWith({
      provider: "anthropic", model: "m1", tool_set: "", price_input_per_mtok: "", price_output_per_mtok: "",
    });
  });

  it("loads the provider's models into the suggestions", async () => {
    vi.mocked(listProviderModels).mockResolvedValue({ models: ["qwen3", "llama3.3"] });
    const { container } = render(<ProviderModelFields bundle={bundle} draft={ollama()} onChange={vi.fn()} />);
    fireEvent.click(screen.getByText("Load models"));
    expect(await screen.findByText(/2 model\(s\) loaded/)).toBeInTheDocument();
    expect(listProviderModels).toHaveBeenCalledWith("ollama");
    expect(container.querySelectorAll("datalist option")).toHaveLength(2);
    expect(container.querySelector('datalist option[value="qwen3"]')).not.toBeNull();
  });

  it("shows a readable error when the listing fails", async () => {
    vi.mocked(listProviderModels).mockRejectedValue(
      new Error('{"detail":{"code":"provider_unreachable","message":"the provider did not answer"}}'));
    renderFields(ollama());
    fireEvent.click(screen.getByText("Load models"));
    expect(await screen.findByText("Could not load models: the provider did not answer")).toBeInTheDocument();
  });
});
