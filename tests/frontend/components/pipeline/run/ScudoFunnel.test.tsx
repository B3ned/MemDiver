import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
// Real i18n bundle on purpose: these tests assert the rendered ENGLISH strings.
import "@/i18n";

import type { ScudoReduceSummary } from "@/api/progress-events";
import { ScudoFunnel } from "@/components/pipeline/run/ScudoFunnel";

const SUMMARY: ScudoReduceSummary = {
  source: "search-reduce:scudo",
  num_regions: 2,
  num_dumps: 3,
  reference_dump: "/dumps/a.msl",
  funnel: {
    signature_unique: { chunks: 2, bytes: 2048 },
    dynamic_residue: { chunks: 0, bytes: 0 },
    content_shared: { chunks: 1200, bytes: 1048576 },
    missing: { chunks: 3, bytes: 96 },
  },
  totals: { regions: 2, bytes: 2048, key_sizes: [32], stride: 1, windows: 1985 },
  not_judged: { chunks: 3, bytes: 96 },
  diagnostics: [],
};

function rowFor(verdict: string): HTMLElement {
  const row = screen
    .getAllByTestId("pipeline-scudo-verdict")
    .find((el) => el.getAttribute("data-verdict") === verdict);
  if (!row) throw new Error(`no row for ${verdict}`);
  return row;
}

describe("ScudoFunnel", () => {
  it("lists every verdict in the backend's order, zeros included", () => {
    render(<ScudoFunnel summary={SUMMARY} verified={1} />);
    expect(
      screen.getAllByTestId("pipeline-scudo-verdict").map((el) => el.getAttribute("data-verdict")),
    ).toEqual(["signature_unique", "dynamic_residue", "content_shared", "missing"]);
    expect(rowFor("dynamic_residue")).toHaveTextContent("0 B");
  });

  it("tells kept, dropped and not judged apart", () => {
    render(<ScudoFunnel summary={SUMMARY} verified={1} />);
    expect(rowFor("signature_unique")).toHaveAttribute("data-outcome", "kept");
    expect(within(rowFor("signature_unique")).getByText("kept")).toBeInTheDocument();
    expect(rowFor("content_shared")).toHaveAttribute("data-outcome", "dropped");
    expect(rowFor("missing")).toHaveAttribute("data-outcome", "notJudged");
    expect(within(rowFor("missing")).getByText("not judged")).toBeInTheDocument();
  });

  it("prints readable counts and sizes", () => {
    render(<ScudoFunnel summary={SUMMARY} verified={1} />);
    expect(rowFor("content_shared")).toHaveTextContent("1,200");
    expect(rowFor("content_shared")).toHaveTextContent("1.0 MiB");
    expect(screen.getByText("Unique signature, varies")).toBeInTheDocument();
  });

  it("names how many dumps were compared", () => {
    render(<ScudoFunnel summary={SUMMARY} verified={0} />);
    expect(screen.getByText(/compared across 3 dumps/)).toBeInTheDocument();
  });

  it("sums up the search space and the verified keys", () => {
    render(<ScudoFunnel summary={SUMMARY} verified={1} />);
    expect(screen.getByTestId("pipeline-scudo-totals")).toHaveTextContent(
      "2 regions, 2.0 KiB, 1,985 candidate windows, 1 verified",
    );
  });

  it("shows a verdict this build does not know instead of hiding it", () => {
    const summary = { ...SUMMARY, funnel: { future_verdict: { chunks: 4, bytes: 8 } } };
    render(<ScudoFunnel summary={summary} verified={0} />);
    expect(rowFor("future_verdict")).toHaveTextContent("future_verdict");
    expect(rowFor("future_verdict")).toHaveAttribute("data-outcome", "dropped");
  });
});
