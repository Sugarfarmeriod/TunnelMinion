import { expect, test } from "@playwright/test";

const baseURL = "http://127.0.0.1:4174";
const localBrowserHeaders = {
  Origin: baseURL,
  "Sec-Fetch-Site": "same-origin",
};

test("默认入口进入 React 总览", async ({ page }) => {
  const response = await page.goto("/");
  expect(response?.status()).toBe(200);
  expect(page.url()).toBe(`${baseURL}/app/overview`);
  await expect(page.getByRole("heading", { name: "总览" })).toBeVisible();
});

test("FastAPI 交付深链、严格缓存和同源 CSP", async ({ page, request }) => {
  const response = await page.goto("/app/operations/not-a-real-operation");
  expect(response?.status()).toBe(200);
  expect(response?.headers()["cache-control"]).toBe("no-store");
  expect(response?.headers()["x-content-type-options"]).toBe("nosniff");

  const csp = response?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("script-src 'self'");
  expect(csp).toContain("style-src 'self'");
  expect(csp).toContain("connect-src 'self'");
  expect(csp).not.toContain("'unsafe-inline'");
  expect(csp).not.toMatch(/https?:\/\/(?!127\.0\.0\.1)/);

  await page.reload();
  await expect(page.getByRole("heading", { name: "操作详情" })).toBeVisible();

  const assetPaths = await page
    .locator("script[src], link[rel=stylesheet][href]")
    .evaluateAll((elements) =>
      elements.map((element) =>
        element instanceof HTMLScriptElement
          ? element.src
          : (element as HTMLLinkElement).href,
      ),
    );
  expect(assetPaths.length).toBeGreaterThan(0);
  for (const assetPath of assetPaths) {
    expect(new URL(assetPath).pathname).toMatch(
      /^\/app-assets\/assets\/.+-[\w-]+\.(?:js|css)$/,
    );
    const asset = await request.get(assetPath);
    expect(asset.status()).toBe(200);
    expect(asset.headers()["cache-control"]).toBe(
      "public, max-age=31536000, immutable",
    );
    expect(asset.headers()["x-content-type-options"]).toBe("nosniff");
  }
});

test("不存在的 API 和 SSE 保持 JSON 404", async ({ request }) => {
  for (const path of [
    "/api/does-not-exist",
    "/api/runs/00000000-0000-0000-0000-000000000000/events",
  ]) {
    const response = await request.get(path);
    expect(response.status()).toBe(404);
    expect(response.headers()["content-type"]).toContain("application/json");
    expect(await response.text()).not.toContain("<!doctype html>");
  }
});

test("真实服务按固定优先级守住本机写请求", async ({ request }) => {
  const cases: Array<{ headers: Record<string, string>; code: string }> = [
    {
      headers: { Host: "example.test:4174" },
      code: "invalid_host",
    },
    {
      headers: {
        ...localBrowserHeaders,
        Origin: "http://evil.example",
        "Sec-Fetch-Site": "cross-site",
      },
      code: "cross_site_request",
    },
    {
      headers: {
        ...localBrowserHeaders,
        Origin: "http://evil.example",
      },
      code: "invalid_origin",
    },
    {
      headers: localBrowserHeaders,
      code: "request_header_required",
    },
    {
      headers: {
        ...localBrowserHeaders,
        "X-TunnelMinion-Request": "wrong",
      },
      code: "invalid_request_header",
    },
  ];

  for (const item of cases) {
    const response = await request.post("/api/threads", {
      headers: item.headers,
    });
    expect(response.status()).toBe(403);
    expect((await response.json()).detail.code).toBe(item.code);
  }

  const cliCompatible = await request.post("/api/threads");
  expect(cliCompatible.status()).toBe(200);
});

test("React 写请求穿过真实守卫且浏览器不留下持久数据", async ({ page }) => {
  await page.goto("/app/chat");
  const responsePromise = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/threads") &&
      response.request().method() === "POST",
  );
  await page.getByRole("button", { name: "新建线程" }).click();
  const response = await responsePromise;
  expect(response.status()).toBe(200);
  expect(response.request().headers()["x-tunnelminion-request"]).toBe(
    "same-origin",
  );

  const storage = await page.evaluate(async () => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
    databases:
      typeof indexedDB.databases === "function"
        ? (await indexedDB.databases()).map(({ name }) => name ?? "")
        : [],
  }));
  expect(storage).toEqual({ local: [], session: [], databases: [] });
});
