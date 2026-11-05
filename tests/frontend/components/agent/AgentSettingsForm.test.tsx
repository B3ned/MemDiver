import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@/i18n";

import { AgentSettingsForm } from "@/components/agent/AgentSettingsForm";
import { bundle } from "./fixtures";

describe("AgentSettingsForm", () => {
  it("shows limits and defaults and blocks saving an out-of-range value", () => {
    const onSave = vi.fn(async () => {});
    render(<AgentSettingsForm bundle={bundle} onSave={onSave} />);
    expect(screen.getByText("Allowed 1 to 200, default 8")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Max turns"), { target: { value: "500" } });
    expect(screen.getByText("Enter a number between 1 and 200.")).toBeInTheDocument();
    expect(screen.getByLabelText("Max turns")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText("Save settings")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Max turns"), { target: { value: "2.5" } });
    expect(screen.getByText("Save settings")).toBeDisabled();
  });

  it("saves valid values and resets to the defaults", async () => {
    const onSave = vi.fn(async () => {});
    render(<AgentSettingsForm bundle={bundle} onSave={onSave} />);
    fireEvent.change(screen.getByLabelText("Max turns"), { target: { value: "20" } });
    fireEvent.click(screen.getByText("Save settings"));
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ max_turns: 20, model: "m1" })));
    fireEvent.click(screen.getByText("Reset to defaults"));
    await waitFor(() => expect(onSave).toHaveBeenLastCalledWith(bundle.defaults));
  });

  it("surfaces a server rejection", async () => {
    const onSave = vi.fn(async () => { throw new Error('{"detail":"max_turns must be between 1 and 200"}'); });
    render(<AgentSettingsForm bundle={bundle} onSave={onSave} />);
    fireEvent.click(screen.getByText("Save settings"));
    expect(await screen.findByText(/max_turns must be between 1 and 200/)).toBeInTheDocument();
  });

  it("sends the provider fields, with empty prices as null", async () => {
    const onSave = vi.fn(async () => {});
    render(<AgentSettingsForm bundle={bundle} onSave={onSave} />);
    fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "ollama" } });
    fireEvent.change(screen.getByLabelText("Input price (USD per 1M tokens)"), { target: { value: "0.5" } });
    fireEvent.click(screen.getByText("Save settings"));
    await waitFor(() => expect(onSave).toHaveBeenCalledWith({
      provider: "ollama", model: "llama3.3", effort: "low", max_turns: 12, max_budget_usd: 1,
      result_budget_bytes: 20000, tool_set: null, price_input_per_mtok: 0.5, price_output_per_mtok: null,
    }));
  });

  it("blocks saving a negative price or an empty model", () => {
    render(<AgentSettingsForm bundle={bundle} onSave={vi.fn(async () => {})} />);
    fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "ollama" } });
    fireEvent.change(screen.getByLabelText("Output price (USD per 1M tokens)"), { target: { value: "-1" } });
    expect(screen.getByText("Save settings")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Output price (USD per 1M tokens)"), { target: { value: "" } });
    expect(screen.getByText("Save settings")).toBeEnabled();
    fireEvent.change(screen.getByLabelText("Model"), { target: { value: " " } });
    expect(screen.getByText("Enter a model name.")).toBeInTheDocument();
    expect(screen.getByText("Save settings")).toBeDisabled();
  });
});
