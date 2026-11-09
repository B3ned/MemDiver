import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
// Real i18n bundle on purpose: these tests assert the rendered ENGLISH strings,
// which is the only guard in this repo against a missing or typo'd key.
import "@/i18n";

import { usePipelineStore } from "@/stores/pipeline-store";

/**
 * Recipe stage -> pre-populated form.
 *
 * The gocryptfs card claims to reproduce the published IMF numbers in one
 * click. It used to write only `reduce` + `bruteForce`, leaving `nsweep`
 * at its `null` default -- so the "replication" ran no sweep at all, and
 * even when a user turned the sweep on by hand it measured a different
 * candidate grid, because `NSweepParams` carries its OWN key_sizes /
 * stride / exhaustive and inherits none of them from the brute-force
 * stage. The assertions below pin the whole triple.
 */

async function renderStage(onAdvance = vi.fn()): Promise<void> {
  const { StageRecipe } = await import(
    "@/components/pipeline/stages/StageRecipe"
  );
  render(<StageRecipe onAdvance={onAdvance} />);
}

function clickGocryptfs(): void {
  fireEvent.click(
    screen.getByRole("button", { name: /Replicate gocryptfs IMF result/ }),
  );
}

describe("StageRecipe gocryptfs preset", () => {
  const PRISTINE = usePipelineStore.getState();

  beforeEach(() => {
    usePipelineStore.setState({ ...PRISTINE, stage: "recipe" });
  });

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
  });

  it("writes the published N-sweep grid, not just the thresholds", async () => {
    await renderStage();
    clickGocryptfs();

    // The exact grid behind tests/e2e/fixtures/pipeline/summary.json: the CLI
    // run that produced it passed --first-hit (exhaustive=false) at stride 8.
    expect(usePipelineStore.getState().form.nsweep).toEqual({
      n_values: [1, 3, 5, 10, 15, 20],
      key_sizes: [32],
      stride: 8,
      exhaustive: false,
    });
  });

  it("still writes the section 4.2 reduce thresholds", async () => {
    await renderStage();
    clickGocryptfs();

    expect(usePipelineStore.getState().form.reduce).toEqual({
      alignment: 8,
      block_size: 32,
      density_threshold: 0.5,
      min_variance: 1500.0,
      entropy_window: 32,
      entropy_threshold: 4.5,
      min_region: 16,
    });
  });

  it("still writes the brute-force settings", async () => {
    await renderStage();
    clickGocryptfs();

    expect(usePipelineStore.getState().form.bruteForce).toEqual({
      key_sizes: [32],
      stride: 8,
      jobs: 1,
      exhaustive: true,
      top_k: 10,
    });
  });

  it("advances to the dumps stage", async () => {
    const onAdvance = vi.fn();
    await renderStage(onAdvance);
    clickGocryptfs();

    expect(onAdvance).toHaveBeenCalledWith("dumps");
  });

  it("leaves the form untouched when the blank card is picked", async () => {
    const onAdvance = vi.fn();
    await renderStage(onAdvance);
    fireEvent.click(screen.getByRole("button", { name: /Start blank/ }));

    expect(usePipelineStore.getState().form.nsweep).toBeNull();
    expect(onAdvance).toHaveBeenCalledWith("dumps");
  });

  it("tells the reader the recipe covers the sweep as well", async () => {
    await renderStage();

    expect(
      screen.getByText(/N = 1,3,5,10,15,20, stride 8/),
    ).toBeInTheDocument();
  });

  // The card says "first verified key" while the thresholds screen shows
  // Exhaustive CHECKED, and both are correct -- they belong to different
  // stages that share no settings. The copy has to say which is which, or the
  // preset reads as a bug.
  it("attributes first-hit to the sweep and exhaustive to the brute-force pass", async () => {
    await renderStage();

    const card = screen.getByText(/single-N brute-force pass/);
    expect(card).toHaveTextContent(/stays exhaustive/);
    expect(card).toHaveTextContent(/stops at the first verified key/);
  });
});

describe("StageRecipe Android Scudo preset", () => {
  const PRISTINE = usePipelineStore.getState();

  beforeEach(() => {
    usePipelineStore.setState({ ...PRISTINE, stage: "recipe" });
  });

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
  });

  it("selects the method and clears what the method refuses", async () => {
    const onAdvance = vi.fn();
    usePipelineStore.getState().updateForm({ emit: { name: "p" }, nsweep: { n_values: [2] } });
    await renderStage(onAdvance);

    fireEvent.click(screen.getByTestId("pipeline-recipe-scudo"));

    const { form } = usePipelineStore.getState();
    expect(form.scudo).toEqual({ allocator: "auto" });
    expect(form.emit).toBeNull();
    expect(form.nsweep).toBeNull();
    expect(onAdvance).toHaveBeenCalledWith("dumps");
  });

  it("restores full coverage after the gocryptfs recipe set stride 8", async () => {
    await renderStage();
    clickGocryptfs();
    fireEvent.click(screen.getByTestId("pipeline-recipe-scudo"));

    const { bruteForce } = usePipelineStore.getState().form;
    expect(bruteForce.stride).toBe(1);
    expect(bruteForce.exhaustive).toBe(true);
  });

  it("is left again by the gocryptfs recipe", async () => {
    await renderStage();
    fireEvent.click(screen.getByTestId("pipeline-recipe-scudo"));
    clickGocryptfs();
    expect(usePipelineStore.getState().form.scudo).toBeNull();
  });

  it("is left again by the blank recipe", async () => {
    usePipelineStore.getState().updateForm({ scudo: { allocator: "auto" } });
    await renderStage();
    fireEvent.click(screen.getByRole("button", { name: /Start blank/ }));
    expect(usePipelineStore.getState().form.scudo).toBeNull();
  });

  it("takes a Scudo key size with it when left through the blank recipe", async () => {
    usePipelineStore.getState().updateForm({
      scudo: { allocator: "auto" },
      bruteForce: { ...PRISTINE.form.bruteForce, key_sizes: [48] },
    });
    await renderStage();
    fireEvent.click(screen.getByRole("button", { name: /Start blank/ }));
    expect(usePipelineStore.getState().form.bruteForce.key_sizes).toEqual([32]);
  });
});
