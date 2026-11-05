import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import "@/i18n";

import { AgentStatusBanner } from "@/components/agent/AgentStatusBanner";

import { PROVIDERS } from "./fixtures";

describe("AgentStatusBanner", () => {
  it("names the selected provider and its reason when unavailable", () => {
    render(<AgentStatusBanner error={null} status={{ available: false, backend: "sdk", credentials: false,
      provider: "openai", providers: PROVIDERS, reason: "set OPENAI_API_KEY" }} />);
    expect(screen.getByText("Provider: openai")).toBeInTheDocument();
    expect(screen.getByText("set OPENAI_API_KEY")).toBeInTheDocument();
    expect(screen.queryByText(/ANTHROPIC_API_KEY/)).toBeNull();
  });

  it("badges the scripted-compat backend as a demo", () => {
    render(<AgentStatusBanner error={null} status={{ available: true, backend: "scripted-compat", credentials: true }} />);
    expect(screen.getByTestId("scripted-badge")).toBeInTheDocument();
  });
});
