import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { requestJson, requestNoContent } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("同源 API client", () => {
  it("只给 unsafe 浏览器请求加入约定请求头", async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const schema = z.object({ ok: z.boolean() });

    await requestJson("/api/read", schema);
    await requestJson("/api/write", schema, { method: "POST" });

    const read = fetchMock.mock.calls[0]?.[1] as RequestInit;
    const write = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(new Headers(read.headers).has("X-TunnelMinion-Request")).toBe(false);
    expect(new Headers(write.headers).get("X-TunnelMinion-Request")).toBe(
      "same-origin",
    );
    expect(write.credentials).toBe("same-origin");
  });

  it("把稳定服务端错误转换为 ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            detail: { code: "invalid_origin", message: "拒绝跨站请求" },
          }),
          { status: 403, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );

    await expect(
      requestJson("/api/write", z.object({}), { method: "DELETE" }),
    ).rejects.toMatchObject({
      status: 403,
      code: "invalid_origin",
      message: "拒绝跨站请求",
    });
  });

  it("拒绝不符合强类型契约的成功响应", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ ok: "not-a-boolean" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(
      requestJson("/api/read", z.object({ ok: z.boolean() })),
    ).rejects.toThrow();
  });

  it("明确接受 204 且不尝试解析空响应正文", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(null, { status: 204 })),
    );

    await expect(
      requestNoContent("/api/item", { method: "DELETE" }),
    ).resolves.toBeUndefined();
  });

  it("无正文请求拒绝其他成功状态，避免误判删除结果", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(
      requestNoContent("/api/item", { method: "DELETE" }),
    ).rejects.toMatchObject({ code: "unexpected_response" });
  });
});
