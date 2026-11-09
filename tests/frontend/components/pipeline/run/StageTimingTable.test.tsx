import { afterEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { StageTimingTable } from "@/components/pipeline/run/StageTimingTable";
import { usePipelineStore } from "@/stores/pipeline-store";

describe("StageTimingTable", () => {
  const PRISTINE = usePipelineStore.getState();

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
  });

  it("has a consensus row on a positional run", () => {
    render(<StageTimingTable />);
    expect(screen.getByText("Consensus")).toBeInTheDocument();
  });

  it("drops the consensus row on a Scudo run, which has no such stage", () => {
    usePipelineStore.setState({
      form: { ...PRISTINE.form, scudo: { allocator: "auto" } },
    });
    render(<StageTimingTable />);
    expect(screen.queryByText("Consensus")).toBeNull();
    expect(screen.getByText("Search-reduce")).toBeInTheDocument();
    expect(screen.getByText("Brute-force")).toBeInTheDocument();
  });
});
