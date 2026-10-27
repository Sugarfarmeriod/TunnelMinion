import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testIgnore: "package-product.spec.ts",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://127.0.0.1:4174",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: [
    {
      command:
        "uv run --project .. python ../scripts/run_frontend_e2e_server.py --host 127.0.0.1 --port 4174",
      url: "http://127.0.0.1:4174/app/overview",
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
    {
      command:
        "uv run --project .. python ../scripts/run_frontend_e2e_server.py --host 127.0.0.1 --port 4176 --read-only-preview",
      url: "http://127.0.0.1:4176/app/overview",
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
  ],
});
