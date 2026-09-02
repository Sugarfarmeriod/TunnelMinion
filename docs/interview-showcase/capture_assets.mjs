import { chromium } from "../../frontend/node_modules/@playwright/test/index.mjs";
import { mkdir, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const output = path.join(root, "docs/interview-showcase/assets");
const baseURL =
  process.env.TUNNELMINION_SHOWCASE_URL ?? "http://127.0.0.1:4175";
const operationId = `operation_${"1".repeat(32)}`;

await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  recordVideo: { dir: output, size: { width: 1280, height: 720 } },
});
const page = await context.newPage();
const video = page.video();

async function labelFixture() {
  await page.evaluate(() => {
    const banner = document.createElement("div");
    banner.textContent =
      "离线 fixture · 未执行真实 A/B · feature/interview-showcase@6d9e98a";
    banner.setAttribute("role", "note");
    Object.assign(banner.style, {
      position: "fixed",
      inset: "0 0 auto 0",
      zIndex: "2147483647",
      padding: "10px 16px",
      color: "#fff",
      background: "#9f2d20",
      font: "600 16px/1.4 system-ui, sans-serif",
      textAlign: "center",
    });
    document.body.append(banner);
  });
}

await page.goto(`${baseURL}/app/overview`);
await page.getByRole("heading", { name: "总览" }).waitFor();
await labelFixture();
await page.screenshot({
  path: path.join(output, "overview-readonly-fixture.png"),
  fullPage: true,
});
await page.waitForTimeout(1200);

await page.goto(`${baseURL}/app/operations/${operationId}`);
await page
  .getByRole("heading", { name: "package-acceptance-dashboard" })
  .waitFor();
await labelFixture();
await page.screenshot({
  path: path.join(output, "operation-awaiting-approval-fixture.png"),
  fullPage: true,
});
await page.waitForTimeout(1200);
await page.getByRole("button", { name: "批准一次" }).click();
await page.getByRole("dialog", { name: "确认批准一次" }).waitFor();
await page.waitForTimeout(1500);
await page.keyboard.press("Escape");
await page.waitForTimeout(500);

await page.close();
await context.close();
if (video === null) throw new Error("Playwright 没有创建录屏");
const temporaryVideo = await video.path();
await video.saveAs(path.join(output, "degraded-fixture-flow.webm"));
await rm(temporaryVideo, { force: true });
await browser.close();
