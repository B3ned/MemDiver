import { afterEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
// Real i18n bundle on purpose: these tests assert the rendered ENGLISH strings.
import "@/i18n";

import { ArtifactsTabs } from "@/components/pipeline/results/ArtifactsTabs";
import { usePipelineStore } from "@/stores/pipeline-store";

/** The Plugin tab is the default, so it is the first thing a finished run shows. */
describe("ArtifactsTabs Plugin tab without a plugin", () => {
  const PRISTINE = usePipelineStore.getState();

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
  });

  it("says a Scudo run cannot produce one, and why", () => {
    usePipelineStore.setState({
      taskId: "task-1",
      form: { ...PRISTINE.form, scudo: { allocator: "auto" } },
    });
    render(<ArtifactsTabs />);
    const note = screen.getByTestId("pipeline-no-plugin");
    expect(note).toHaveTextContent("Volatility 3 plugin generation is not supported yet");
    expect(note).toHaveTextContent("per-byte variance");
  });

  it("keeps the plain message on a positional run", () => {
    usePipelineStore.setState({ taskId: "task-1" });
    render(<ArtifactsTabs />);
    expect(screen.getByTestId("pipeline-no-plugin")).toHaveTextContent(
      "No vol3_plugin artifact in this run.",
    );
  });
});
