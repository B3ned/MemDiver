import { readFileSync } from "node:fs";
import AxeBuilder from "@axe-core/playwright";
import { test, expect, type Page } from "@playwright/test";
import { tab } from "../fixtures/selectors";
import { scudoExpectedPath, scudoMslAvailable, scudoMslPaths } from "../fixtures/dataset";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";

/**
 * The Android Scudo method, through the real wizard and a real worker.
 *
 * The committed runs hold a secret that Scudo moved every run, so a hit proves
 * the chunk consensus ran: the positional consensus cannot pair those bytes.
 * The oracle stage is the only part not clicked through, because its upload and
 * dry-run flow has its own specs and is the same for either reduction method.
 */

const BACKEND = `http://127.0.0.1:${process.env.BACKEND_PORT ?? "8091"}`;
const PLUGIN_NOTE = /Volatility 3 plugin generation is not supported yet/;

const expected = scudoMslAvailable
  ? (JSON.parse(readFileSync(scudoExpectedPath, "utf8")) as {
      key_size: number;
      secret_hex: string;
    })
  : { key_size: 0, secret_hex: "" };

async function armOracle(page: Page): Promise<string> {
  // Uploads answer 503 until oracle storage is on. 409 means an operator pinned
  // the directory through the environment, which is just as usable here.
  const enabled = await page.request.post(`${BACKEND}/api/oracles/enable`);
  expect([200, 409]).toContain(enabled.status());

  const source =
    `TARGET = bytes.fromhex("${expected.secret_hex}")\n` +
    "def verify(candidate):\n" +
    "    return candidate == TARGET\n";
  const uploaded = await page.request.post(`${BACKEND}/api/oracles/upload`, {
    multipart: {
      file: { name: "scudo_oracle.py", mimeType: "text/x-python", buffer: Buffer.from(source) },
    },
  });
  expect(uploaded.ok()).toBe(true);
  const { id, sha256 } = (await uploaded.json()) as { id: string; sha256: string };
  const armed = await page.request.post(`${BACKEND}/api/oracles/${id}/arm`, { data: { sha256 } });
  expect(armed.ok()).toBe(true);
  return id;
}

async function openScudoThresholds(page: Page): Promise<void> {
  const oracleId = await armOracle(page);
  await enterWorkspaceWithMsl(page, scudoMslPaths[0], { autoAnalyze: false });
  await page.locator(tab("pipeline")).first().click();
  await page.getByTestId("pipeline-recipe-scudo").click();

  await page.locator('textarea[placeholder*="gdb_raw.bin"]').fill(scudoMslPaths.join("\n"));
  await page.getByRole("button", { name: "Add paths" }).click();
  await expect(page.getByText(/3 dumps selected/i)).toBeVisible();

  await page.evaluate(async (id) => {
    const { usePipelineStore } = await import("/src/stores/pipeline-store.ts" as string);
    usePipelineStore.getState().updateForm({ oracleId: id });
    usePipelineStore.getState().setStage("thresholds");
  }, oracleId);
  await expect(page.getByTestId("pipeline-method")).toBeVisible();
}

test.describe("Pipeline: Android Scudo method", () => {
  test.skip(!scudoMslAvailable, "scudo_msl fixture missing");

  test("the recipe selects the method and the form explains what it cannot do", async ({ page }) => {
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await openScudoThresholds(page);

    await expect(page.getByTestId("pipeline-method-scudo")).toBeChecked();
    await expect(page.getByTestId("pipeline-heap-policy-select")).toHaveCount(0);
    await expect(page.getByTestId("emit-enable")).toBeDisabled();
    await expect(page.getByTestId("emit-hint")).toHaveText(PLUGIN_NOTE);
    await expect(page.getByTestId("nsweep-enable")).toBeDisabled();

    const results = await new AxeBuilder({ page })
      .include('[data-testid="pipeline-method"]')
      .withTags(["wcag2a", "wcag2aa"])
      .analyze();
    const blocking = results.violations.filter((v) =>
      ["critical", "serious"].includes(v.impact ?? ""),
    );
    expect(blocking.map((v) => v.id)).toEqual([]);

    guards.assertClean();
  });

  test("a run finds the reference run's secret and reports its verdicts", async ({ page }) => {
    test.setTimeout(120_000);
    const guards = installErrorGuards(page);
    await openScudoThresholds(page);

    // The minimal fixture heap is not detected as Scudo, so the run forces it.
    await page.getByTestId("pipeline-scudo-force").check();
    await page.getByTestId("pipeline-scudo-key-sizes").fill(String(expected.key_size));
    // A real session usually carries the Regions step's choice, and the server
    // refuses a filter on this method.
    await page.evaluate(async () => {
      const { useRegionSelectionStore } = await import(
        "/src/stores/region-selection-store.ts" as string
      );
      useRegionSelectionStore.getState().setRegionFilter("heap,stack");
    });
    await page.getByRole("button", { name: /Run pipeline/i }).click();

    await expect(page.getByRole("button", { name: /New run/i })).toBeVisible({ timeout: 90_000 });
    await expect(page.getByText("succeeded", { exact: true })).toBeVisible();
    await expect(page.getByTestId("pipeline-hit-row")).toHaveCount(1);

    const funnel = page.getByTestId("pipeline-scudo-funnel");
    await expect(funnel).toBeVisible();
    await expect(
      funnel.locator('[data-verdict="signature_unique"]'),
    ).toHaveAttribute("data-outcome", "kept");
    await expect(page.getByTestId("pipeline-scudo-totals")).toContainText("1 verified");

    await expect(page.getByTestId("pipeline-no-plugin")).toHaveText(PLUGIN_NOTE);

    guards.assertClean();
  });

  test("a hit opens in the reference dump's flat view", async ({ page }) => {
    test.setTimeout(120_000);
    await openScudoThresholds(page);
    await page.getByTestId("pipeline-scudo-force").check();
    await page.getByTestId("pipeline-scudo-key-sizes").fill(String(expected.key_size));
    await page.getByRole("button", { name: /Run pipeline/i }).click();
    await expect(page.getByTestId("pipeline-hit-row")).toHaveCount(1, { timeout: 90_000 });

    await page.getByRole("button", { name: "Open in hex" }).click();

    await expect
      .poll(() =>
        page.evaluate(async () => {
          const { useHexStore } = await import("/src/stores/hex-store.ts" as string);
          const { dumpPath, viewMode } = useHexStore.getState();
          return { dumpPath, viewMode };
        }),
      )
      .toEqual({ dumpPath: scudoMslPaths[0], viewMode: "vas" });
  });
});
