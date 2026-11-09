import { afterEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { RefinePanel } from "@/components/pipeline/results/RefinePanel";
import { usePipelineStore, type HitRecord } from "@/stores/pipeline-store";

const HIT: HitRecord = {
  offset: 16,
  size: 32,
  region_index: 0,
  key_hex: "00",
  neighborhood_start: 16,
  neighborhood_variance: [],
};

describe("RefinePanel", () => {
  const PRISTINE = usePipelineStore.getState();

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
  });

  it("offers a refine on a positional run with hits", () => {
    usePipelineStore.setState({ taskId: "task-1", hits: [HIT] });
    render(<RefinePanel />);
    expect(screen.getByRole("textbox")).toBeInTheDocument();
  });

  it("is absent on a Scudo run, which has no consensus to fold into", () => {
    usePipelineStore.setState({
      taskId: "task-1",
      hits: [HIT],
      form: { ...PRISTINE.form, scudo: { allocator: "auto" } },
    });
    const { container } = render(<RefinePanel />);
    expect(container).toBeEmptyDOMElement();
  });
});
