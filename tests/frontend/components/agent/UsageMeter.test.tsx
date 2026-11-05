import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import "@/i18n";

import { UsageMeter } from "@/components/agent/UsageMeter";

const usage = { turns: 2, max_turns: 8, cost_estimate_usd: 0.1, max_budget_usd: 0.5 };

describe("UsageMeter", () => {
  it("shows the estimated cost when it is known", () => {
    render(<UsageMeter usage={usage} />);
    expect(screen.getByText("Est. cost $0.10 / $0.50")).toBeInTheDocument();
  });

  it("says the cost is unknown for a local model", () => {
    render(<UsageMeter usage={{ ...usage, cost_known: false }} />);
    expect(screen.getByText("cost n/a (local model)")).toBeInTheDocument();
    expect(screen.queryByText(/Est\. cost/)).toBeNull();
  });
});
