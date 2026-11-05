/**
 * In-UI agent chat, end to end against BOTH scripted backends (no model, no API key):
 * `scripted` (the Claude Agent SDK client over a scripted CLI transport) and
 * `scripted-compat` (the OpenAI-compatible loop over a scripted chat model). The same
 * script and the same UI assertions run against each, on its own port.
 *
 * The shared Playwright webServer cannot take per-spec env, and this flow needs
 * MEMDIVER_AGENT_BACKEND=scripted plus a script naming this run's temp case, so the spec
 * starts its OWN backend per variant serving the BUILT `frontend/dist` (run
 * `npm run build --workspace frontend` first; the spec skips, loudly, when dist is
 * missing). The real-case demo script lives in fixtures/agent_chat/.
 */
import { test, expect, type Page } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { syntheticMslAvailable, syntheticMslPath } from "../fixtures/dataset";
import { enterWorkspaceWithMsl, installErrorGuards } from "../fixtures/workspace";

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const DIST_INDEX = path.join(REPO_ROOT, "frontend", "dist", "index.html");
const PYTHON = process.env.MEMDIVER_PYTHON ?? "python";
const CAPTURE_ID = "agent-ui-capture";

/**
 * One backend variant. `turnsAfterFirstMessage` differs by design: the SDK transport
 * counts every scripted step as a turn, the compat loop counts MODEL turns (a run of
 * text steps plus the tool step after it is one model turn; see scripted_model.py).
 */
interface Variant { backend: "scripted" | "scripted-compat"; port: number; turnsAfterFirstMessage: number }

const VARIANTS: Variant[] = [
  { backend: "scripted", port: Number(process.env.AGENT_E2E_PORT ?? "8794"), turnsAfterFirstMessage: 5 },
  { backend: "scripted-compat", port: Number(process.env.AGENT_COMPAT_E2E_PORT ?? "8795"), turnsAfterFirstMessage: 4 },
];

test.skip(!syntheticMslAvailable, "synthetic MSL fixture missing");
test.skip(!fs.existsSync(DIST_INDEX), "frontend/dist not built (npm run build --workspace frontend)");

for (const variant of VARIANTS) {
  test.describe(`agent chat [${variant.backend}]`, () => {
    const AGENT_PORT = variant.port;
    test.use({ baseURL: `http://127.0.0.1:${AGENT_PORT}` });

    let server: ChildProcess | null = null;
    let home = "";
    let caseDir = "";

    function script(): object {
      const note = (label: string, value: number) => ({
        tool: "annotations_add",
        input: { case_dir: caseDir, capture_id: CAPTURE_ID, kind: "annotation", author: "agent", label,
          locations: [{ space: "physical", value }] },
      });
      return {
        turns: [
          [
            { text: "Recon first: manifest, then two offsets of the dump." },
            { tool: "case_manifest", input: { case_dir: caseDir } },
            { tool: "anchor_consensus", input: { anchors: [
              { dump_path: syntheticMslPath, offset: 64 }, { dump_path: syntheticMslPath, offset: 128 }],
              delta_start: 0, length: 16 } },
            note("agent-ui first", 4096),
            { text: "Two offsets read [seen]. They look like plain data [inferred]. Intent unknown [unknown]." },
          ],
          [note("agent-ui second", 8192), { text: "Second note recorded [seen]." }],
        ],
      };
    }

    const annotationLines = (): number => {
      const file = path.join(caseDir, "annotations", `${CAPTURE_ID}.jsonl`);
      return fs.existsSync(file) ? fs.readFileSync(file, "utf8").split("\n").filter(Boolean).length : 0;
    };

    async function waitForStatus(): Promise<void> {
      for (let i = 0; i < 120; i++) {
        try {
          const r = await fetch(`http://127.0.0.1:${AGENT_PORT}/api/agent/status`);
          if (r.ok) return;
        } catch { /* not up yet */ }
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
      throw new Error("agent e2e backend did not start");
    }

    test.beforeAll(async () => {
      home = fs.mkdtempSync(path.join(os.tmpdir(), "memdiver-agent-e2e-"));
      caseDir = path.join(home, "memdiver", "cases", "agent_ui_case");
      fs.mkdirSync(path.join(caseDir, "annotations"), { recursive: true });
      fs.writeFileSync(path.join(caseDir, "case.json"),
        JSON.stringify({ v: 1, name: "agent_ui_case", created: "2026-01-01T00:00:00+00:00" }));
      const scriptPath = path.join(home, "script.json");
      fs.writeFileSync(scriptPath, JSON.stringify(script()));
      server = spawn(PYTHON, ["-m", "memdiver.cli", "web", "--port", String(AGENT_PORT)], {
        cwd: REPO_ROOT,
        env: { ...process.env, PYTHONUNBUFFERED: "1", XDG_DATA_HOME: home,
          MEMDIVER_AGENT_BACKEND: variant.backend, MEMDIVER_AGENT_SCRIPT: scriptPath },
        stdio: "ignore",
      });
      await waitForStatus();
    });

    test.afterAll(async () => {
      if (server && server.exitCode === null) {
        server.kill("SIGTERM");
        await new Promise((resolve) => setTimeout(resolve, 2000));
        if (server.exitCode === null) server.kill("SIGKILL");
      }
      if (home) fs.rmSync(home, { recursive: true, force: true });
    });

    async function openAgentTab(page: Page) {
      await enterWorkspaceWithMsl(page, syntheticMslPath);
      await page.getByTestId("tab-agent").click();
      return page.locator("section[aria-label='Agent chat']");
    }

    async function startChatAndSend(page: Page, panel: ReturnType<Page["locator"]>, text: string) {
      await panel.getByRole("button", { name: "Start chat" }).click();
      const composer = page.locator("#agent-composer");
      await expect(composer).toBeEnabled({ timeout: 20_000 });
      await composer.fill(text);
      await panel.getByRole("button", { name: "Send" }).click();
    }

    test("settings, playbook, streaming, approval once-per-chat, evidence badges, open in hex", async ({ page }) => {
      const guards = installErrorGuards(page);
      const panel = await openAgentTab(page);

      // Status banner: the demo backend is labelled, and (being scripted) is NOT told it lacks credentials.
      await expect(page.getByTestId("scripted-badge")).toContainText("no model");
      await expect(panel.getByText(/No model credentials/)).toHaveCount(0);

      // Settings: defaults, limits, persistence through a reload, reset.
      await panel.locator("summary").click();
      const turns = page.locator("#agent-setting-max_turns");
      await expect(turns).toHaveValue("8");
      await expect(page.locator("#agent-setting-max_budget_usd")).toHaveValue("0.5");
      await expect(page.locator("#agent-setting-result_budget_bytes")).toHaveValue("20000");
      await expect(page.getByTestId("agent-settings")).toContainText("Allowed 1 to 200, default 8");
      await turns.fill("12");
      await page.getByRole("button", { name: "Save settings" }).click();
      await expect(page.getByText("Settings saved.")).toBeVisible();
      await page.reload();
      const panel2 = await (async () => { await enterWorkspaceWithMsl(page, syntheticMslPath); await page.getByTestId("tab-agent").click(); return page.locator("section[aria-label='Agent chat']"); })();
      await panel2.locator("summary").click();
      await expect(page.locator("#agent-setting-max_turns")).toHaveValue("12");
      await page.getByRole("button", { name: "Reset to defaults" }).click();
      await expect(page.locator("#agent-setting-max_turns")).toHaveValue("8");
      await panel2.locator("summary").click();

      // Playbook -> composer.
      await panel2.getByLabel(/Start from playbook/).selectOption("memdiver_start");
      await panel2.getByRole("button", { name: "Fill composer" }).click();
      await expect(page.locator("#agent-composer")).toHaveValue(/MemDiver/, { timeout: 10_000 });

      // Turn 1: read tools run on their own, the write waits for the analyst.
      await startChatAndSend(page, panel2, "Start the recon.");
      const approval = page.getByTestId("approval-card");
      await expect(approval).toBeVisible({ timeout: 60_000 });
      await expect(page.getByTestId("tool-card").filter({ hasText: "case_manifest" })).toContainText("READ", { ignoreCase: true });
      await expect(approval).toContainText("annotations_add");
      expect(annotationLines()).toBe(0); // nothing written before the click
      await approval.getByRole("button", { name: "Allow for this chat" }).click();
      await expect(page.getByTestId("evidence-seen").first()).toBeVisible({ timeout: 30_000 });
      await expect(page.getByTestId("evidence-inferred")).toBeVisible();
      await expect(page.getByTestId("evidence-unknown")).toBeVisible();
      expect(annotationLines()).toBe(1);
      await expect(page.getByTestId("usage-meter")).toContainText(`Turns ${variant.turnsAfterFirstMessage}/8`);

      // "Open in hex": the offset travels with its view, so the right view opens.
      const openButtons = page.getByRole("button", { name: /Open in hex/ });
      await expect(openButtons.first()).toBeEnabled();
      await openButtons.first().click();
      await expect(page.getByRole("tab", { name: "VA", exact: true })).toHaveAttribute("aria-selected", "true");

      // Turn 2: same tool, approved for this chat -> no second card, the note is written.
      await page.locator("#agent-composer").fill("One more note.");
      await panel2.getByRole("button", { name: "Send" }).click();
      await expect(page.getByText("Second note recorded")).toBeVisible({ timeout: 30_000 });
      await expect(page.getByTestId("approval-card")).toHaveCount(1);
      expect(annotationLines()).toBe(2);
      guards.assertClean();
    });

    test("deny writes nothing; interrupt withdraws the pending approval", async ({ page }) => {
      const guards = installErrorGuards(page);
      const panel = await openAgentTab(page);
      const before = annotationLines();

      await startChatAndSend(page, panel, "Recon.");
      await panel.getByRole("button", { name: "Deny" }).click({ timeout: 60_000 });
      await expect(page.getByTestId("approval-resolved")).toContainText("Denied");
      await expect(page.getByTestId("tool-card").filter({ hasText: "annotations_add" })).toContainText("FAILED", { ignoreCase: true });
      await expect(page.getByTestId("evidence-unknown")).toBeVisible({ timeout: 30_000 });
      expect(annotationLines()).toBe(before);

      // Fresh chat, interrupt while the approval is pending.
      await panel.getByRole("button", { name: "End chat" }).click();
      await startChatAndSend(page, panel, "Recon again.");
      await expect(page.getByTestId("approval-card")).toBeVisible({ timeout: 60_000 });
      await panel.getByRole("button", { name: "Interrupt" }).click();
      await expect(page.getByTestId("approval-resolved")).toContainText("Denied", { timeout: 15_000 });
      await expect(panel.getByRole("button", { name: "Deny" })).toHaveCount(0);
      expect(annotationLines()).toBe(before);
      guards.assertClean();
    });
  });
}
