import { afterEach, describe, it, expect, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useHexStore } from "@/stores/hex-store";
import { usePipelineStore, type HitRecord } from "@/stores/pipeline-store";

import { HitsList, PipelineRunDashboard, RunDiagnostics } from "@/components/pipeline/run/PipelineRunDashboard";

/**
 * Unit-level mirror of the Playwright assertion in
 * `tests/e2e/specs/pcap-upload-run.spec.ts`: a key confirmed against a real
 * capture must say so in the DOM. Catches a broken wire-up without a backend.
 */

const PCAP_HIT: HitRecord = {
  offset: 585148,
  size: 32,
  region_index: 0,
  key_hex: "34733aa526c1213555d78f7ca9da1b9c0e03b7d7ef203441ea5913a51521a43e",
  neighborhood_start: 585100,
  neighborhood_variance: [],
  verified: true,
  confirmedBy: "pcap",
};

function seedHits(hits: HitRecord[]): void {
  usePipelineStore.setState({ hits, form: { ...usePipelineStore.getState().form } });
}

describe("HitsList", () => {
  beforeEach(() => {
    seedHits([]);
  });

  it("renders nothing when the run produced no hits", () => {
    const { container } = render(<HitsList />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the pcap provenance on a capture-confirmed hit", () => {
    seedHits([PCAP_HIT]);
    render(<HitsList />);

    const row = screen.getByTestId("pipeline-hit-row");
    expect(row).toHaveAttribute("data-hit-offset", String(PCAP_HIT.offset));
    expect(row).toHaveTextContent("0x0008edbc");

    const badge = screen.getByTestId("verification-badge");
    expect(badge).toHaveAttribute("data-confirmed-by", "pcap");
    expect(badge).toHaveTextContent("Verified via pcap capture");
  });

  it("shows the oracle provenance on a script-confirmed hit", () => {
    seedHits([{ ...PCAP_HIT, confirmedBy: "oracle" }]);
    render(<HitsList />);

    const badge = screen.getByTestId("verification-badge");
    expect(badge).toHaveAttribute("data-confirmed-by", "oracle");
    expect(badge).toHaveTextContent("Verified via oracle script");
  });

  it("falls back to the neutral badge when the hit carries no provenance", () => {
    seedHits([{ ...PCAP_HIT, verified: undefined, confirmedBy: null }]);
    render(<HitsList />);

    const badge = screen.getByTestId("verification-badge");
    expect(badge).toHaveAttribute("data-confirmed-by", "");
    expect(badge).not.toHaveTextContent("Verified via");
  });

  it("renders one row per hit", () => {
    seedHits([PCAP_HIT, { ...PCAP_HIT, offset: 663776 }]);
    render(<HitsList />);
    expect(screen.getAllByTestId("pipeline-hit-row")).toHaveLength(2);
  });
});

/**
 * The zero-hit silence bug: the brute-force stage tests offsets on an
 * absolute stride grid, so at stride=8 a secret at offset 585148 (585148 % 8
 * === 4) is never tested. `HitsList` renders nothing on that run, so without
 * `RunDiagnostics` the results screen says absolutely nothing and a missed
 * key is indistinguishable from an absent one.
 */

const PARTIAL_COVERAGE_MESSAGE =
  "No candidate was confirmed. The search tested 110,326 of 701,084 possible " +
  "32-byte windows (15.7%): stride=8 only tests offsets that are multiples of " +
  "8, so a secret that is not 8-aligned cannot be found at this setting. " +
  "Re-run with a smaller stride (e.g. --stride 4 or 1) to widen coverage.";

const PARTIAL_COVERAGE = {
  tested: 110326,
  possible: 701084,
  stride: 8,
  fraction: 0.1573,
};

describe("RunDiagnostics", () => {
  beforeEach(() => {
    usePipelineStore.setState({ hits: [], coverage: null, warnings: [] });
  });

  it("renders nothing before the brute-force stage reports coverage", () => {
    const { container } = render(<RunDiagnostics />);
    expect(container).toBeEmptyDOMElement();
  });

  it("breaks the silence on a zero-hit run", () => {
    usePipelineStore.setState({
      hits: [],
      coverage: PARTIAL_COVERAGE,
      warnings: [
        {
          code: "brute_force.partial_coverage",
          message: PARTIAL_COVERAGE_MESSAGE,
          severity: "warning",
          details: { stride: 8 },
        },
      ],
    });
    render(<RunDiagnostics />);

    const coverage = screen.getByTestId("pipeline-coverage");
    expect(coverage).toHaveAttribute(
      "data-coverage-fraction",
      String(PARTIAL_COVERAGE.fraction),
    );
    expect(coverage).toHaveTextContent("110,326");
    expect(coverage).toHaveTextContent("701,084");
    expect(coverage).toHaveTextContent("15.7%");
    expect(coverage).toHaveTextContent("stride 8");

    const warning = screen.getByTestId("pipeline-warning");
    expect(warning).toHaveAttribute(
      "data-warning-code",
      "brute_force.partial_coverage",
    );
    // The backend sentence is rendered verbatim, remediation hint included.
    expect(warning).toHaveTextContent(PARTIAL_COVERAGE_MESSAGE);
    expect(warning).toHaveAttribute("role", "status");
  });

  it("still reports coverage when the run DID find a key", () => {
    // "1 hit" out of a 16%-covered space is a lower bound, not a total.
    usePipelineStore.setState({
      hits: [PCAP_HIT],
      coverage: PARTIAL_COVERAGE,
      warnings: [],
    });
    render(<RunDiagnostics />);

    expect(screen.getByTestId("pipeline-coverage")).toHaveTextContent("15.7%");
    expect(screen.queryByTestId("pipeline-warning")).toBeNull();
  });

  it("calls out an exhaustive search", () => {
    usePipelineStore.setState({
      hits: [],
      coverage: { tested: 701084, possible: 701084, stride: 1, fraction: 1 },
      warnings: [],
    });
    render(<RunDiagnostics />);
    expect(screen.getByTestId("pipeline-coverage")).toHaveTextContent(
      "The search was exhaustive",
    );
  });

  it("renders one block per warning", () => {
    usePipelineStore.setState({
      coverage: PARTIAL_COVERAGE,
      warnings: [
        { code: "brute_force.partial_coverage", message: "a" },
        { code: "brute_force.other", message: "b" },
      ],
    });
    render(<RunDiagnostics />);
    expect(screen.getAllByTestId("pipeline-warning")).toHaveLength(2);
  });
});

/**
 * The stride default moved 8 -> 1, so a typical run went from ~110k to ~701k
 * candidates. A bare percentage bar can't tell the user whether "12%" means
 * one more minute or one more hour, so the dashboard shows the live rate and
 * an ETA derived from the counters the engine already emits.
 */
describe("PipelineRunDashboard throughput row", () => {
  beforeEach(() => {
    usePipelineStore.setState({
      status: "running",
      activeStage: "brute_force",
      activeStagePct: 0.12,
      activeStageMsg: "tried=84000/701084 hits=0",
      hits: [],
      coverage: null,
      warnings: [],
      throughput: null,
    });
  });

  it("renders the rate and the ETA once a rate exists", () => {
    usePipelineStore.setState({
      throughput: {
        perSec: 256,
        etaSeconds: 2736.6,
        lastTs: 101,
        lastTried: 512,
      },
    });
    render(<PipelineRunDashboard />);

    const row = screen.getByTestId("pipeline-throughput");
    expect(row).toHaveTextContent("256 candidates/sec");
    expect(row).toHaveTextContent("45m 36s remaining");
  });

  it("says it is still estimating while the ETA is unknown", () => {
    usePipelineStore.setState({
      throughput: { perSec: 40, etaSeconds: null, lastTs: 101, lastTried: 512 },
    });
    render(<PipelineRunDashboard />);
    expect(screen.getByTestId("pipeline-throughput")).toHaveTextContent(
      "estimating time remaining",
    );
  });

  it("renders nothing before the first rate is known", () => {
    render(<PipelineRunDashboard />);
    expect(screen.queryByTestId("pipeline-throughput")).toBeNull();
  });

  it("stays hidden on a seeded-but-rateless first sample", () => {
    usePipelineStore.setState({
      throughput: { perSec: 0, etaSeconds: null, lastTs: 100, lastTried: 256 },
    });
    render(<PipelineRunDashboard />);
    expect(screen.queryByTestId("pipeline-throughput")).toBeNull();
  });
});

describe("Android Scudo run", () => {
  const PRISTINE = usePipelineStore.getState();
  const HEX_PRISTINE = useHexStore.getState();
  const REFERENCE = "/dumps/run-1.msl";
  const HIT: HitRecord = { ...PCAP_HIT, offset: 4096, size: 40, neighborhood_variance: [] };

  function seedScudoRun(diagnostics: { code: string; message: string; severity: string }[]): void {
    usePipelineStore.setState({
      form: { ...PRISTINE.form, sourcePaths: [REFERENCE, "/dumps/run-2.msl"], scudo: { allocator: "auto" } },
      hits: [HIT],
      scudoSummary: {
        source: "search-reduce:scudo",
        num_regions: 1,
        num_dumps: 2,
        reference_dump: REFERENCE,
        funnel: { signature_unique: { chunks: 1, bytes: 40 } },
        totals: { regions: 1, bytes: 40, key_sizes: [40], stride: 1, windows: 1 },
        not_judged: { chunks: 0, bytes: 0 },
        diagnostics,
      },
    });
  }

  beforeEach(() => {
    usePipelineStore.setState(PRISTINE, true);
  });

  afterEach(() => {
    usePipelineStore.setState(PRISTINE, true);
    useHexStore.setState(HEX_PRISTINE, true);
  });

  it("shows the verdict table instead of the positional funnel", () => {
    seedScudoRun([]);
    render(<PipelineRunDashboard />);
    expect(screen.getByTestId("pipeline-scudo-funnel")).toBeInTheDocument();
    expect(screen.queryByText("Reduction funnel")).toBeNull();
  });

  it("keeps the positional funnel on a positional run", () => {
    render(<PipelineRunDashboard />);
    expect(screen.queryByTestId("pipeline-scudo-funnel")).toBeNull();
    expect(screen.getByText("Reduction funnel")).toBeInTheDocument();
  });

  it("separates warnings from notes and prints the backend sentence", () => {
    seedScudoRun([
      { code: "scudo.scope_fallback", message: "no VAS map named the heap", severity: "warning" },
      { code: "scudo.not_judged", message: "3 chunks were never compared", severity: "info" },
    ]);
    render(<RunDiagnostics />);

    const [warning, note] = screen.getAllByTestId("pipeline-scudo-diagnostic");
    expect(warning).toHaveAttribute("data-severity", "warning");
    expect(warning).toHaveTextContent("Scudo scan warning");
    expect(warning).toHaveTextContent("no VAS map named the heap");
    expect(note).toHaveAttribute("data-severity", "info");
    expect(note).toHaveTextContent("Scudo scan note");
    expect(note).toHaveTextContent("3 chunks were never compared");
  });

  it("opens a hit in the reference dump's flat view", async () => {
    seedScudoRun([]);
    render(<HitsList />);

    fireEvent.click(screen.getByRole("button", { name: "Open in hex" }));

    await waitFor(() => expect(useHexStore.getState().dumpPath).toBe(REFERENCE));
    expect(useHexStore.getState().format).toBe("msl");
    expect(useHexStore.getState().requestedView).toBe("vas");
  });

  it("replaces another open dump, where the offset would mean nothing", async () => {
    useHexStore.getState().setDumpPath("/dumps/other.msl", 0, "msl");
    seedScudoRun([]);
    render(<HitsList />);

    fireEvent.click(screen.getByRole("button", { name: "Open in hex" }));

    await waitFor(() => expect(useHexStore.getState().dumpPath).toBe(REFERENCE));
  });

  it("leaves a positional run's open dump alone", async () => {
    useHexStore.getState().setDumpPath("/dumps/other.msl", 0, "msl");
    usePipelineStore.setState({
      form: { ...PRISTINE.form, sourcePaths: [REFERENCE] },
      hits: [HIT],
    });
    render(<HitsList />);

    fireEvent.click(screen.getByRole("button", { name: "Open in hex" }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Open in hex" })).toBeEnabled(),
    );
    expect(useHexStore.getState().dumpPath).toBe("/dumps/other.msl");
    expect(useHexStore.getState().requestedView).toBeNull();
  });
});
