import { defineConfig, devices } from "@playwright/test";

const browser = process.env.TUNNELMINION_PACKAGE_BROWSER;
if (browser !== "chromium" && browser !== "webkit") {
  throw new Error("TUNNELMINION_PACKAGE_BROWSER 必须是 chromium 或 webkit");
}

export default defineConfig({
  testDir: "./e2e",
  testMatch: "package-product.spec.ts",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://127.0.0.1:4175",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: browser,
      use:
        browser === "chromium"
          ? { ...devices["Desktop Chrome"] }
          : { ...devices["Desktop Safari"] },
    },
  ],
  webServer: {
    command:
      "uv run --offline --project .. python ../scripts/run_runtime_package_browser_server.py --port 4175",
    url: "http://127.0.0.1:4175/app/overview",
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
