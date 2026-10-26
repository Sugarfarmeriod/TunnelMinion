import { afterEach, describe, expect, it, vi } from "vitest";

import { getThread, startRun, allowedToolNames } from "./api";
import { makeRun } from "./testFixtures";

const threadId = `thread_${"a".repeat(32)}`;
const detail = {
  thread: {
    thread_id: threadId,
    created_at: "2026-10-15T08:00:00Z",
    updated_at: "2026-10-15T08:00:00Z",
    message_count: 0,
  },
  messages: [],
};

afterEach(() => vi.unstubAllGlobals());

it("从保存的上下文继续提问时只发送对象身份，不把显示名称带入 about", async () => {
  const fetch = vi.fn().mockResolvedValue(Response.json(makeRun()));
  vi.stubGlobal("fetch", fetch);
  const context = {
    node_id: `node_${"b".repeat(32)}`,
    service_key: "python:app.py",
    service_name: "相册",
  };
  await startRun(
    threadId,
    "接着问",
    allowedToolNames,
    undefined,
    undefined,
    context,
  );
  expect(JSON.parse(fetch.mock.calls[0]![1].body)).toEqual({
    question: "接着问",
    tool_names: [...allowedToolNames],
    about: { node_id: context.node_id, service_key: context.service_key },
  });
});

describe("读取对话的程序关联", () => {
  it.each([`service_${"b".repeat(32)}`, null])(
    "读取私有页面记录，保留明确关联或空关联（%s）",
    async (serviceId) => {
      const fetch = vi
        .fn()
        .mockResolvedValue(Response.json({ ...detail, service_id: serviceId }));
      vi.stubGlobal("fetch", fetch);
      const controller = new AbortController();
      expect(await getThread(threadId, controller.signal)).toEqual({
        ...detail,
        service_id: serviceId,
      });
      expect(fetch).toHaveBeenCalledOnce();
      expect(fetch).toHaveBeenCalledWith(
        `/api/ui/threads/${threadId}`,
        expect.objectContaining({ signal: controller.signal }),
      );
    },
  );

  it("仅在旧程序缺少私有接口时回退公开读取，沿用取消信号", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({}, { status: 404 }))
      .mockResolvedValueOnce(Response.json(detail));
    vi.stubGlobal("fetch", fetch);
    const controller = new AbortController();
    expect(await getThread(threadId, controller.signal)).toEqual(detail);
    expect(fetch.mock.calls.map(([path]) => path)).toEqual([
      `/api/ui/threads/${threadId}`,
      `/api/threads/${threadId}`,
    ]);
    for (const [, init] of fetch.mock.calls) {
      expect(init.signal).toBe(controller.signal);
      expect(init.method ?? "GET").toBe("GET");
    }
  });

  it.each([
    { status: 503, payload: {} },
    { status: 200, payload: { ...detail, service_id: "错误身份" } },
    { status: 200, payload: { ...detail, service_id: null, unexpected: true } },
  ])(
    "读取失败或契约错误时不绕过校验（$status）",
    async ({ status, payload }) => {
      const fetch = vi
        .fn()
        .mockResolvedValue(Response.json(payload, { status }));
      vi.stubGlobal("fetch", fetch);
      await expect(getThread(threadId)).rejects.toBeInstanceOf(Error);
      expect(fetch).toHaveBeenCalledOnce();
    },
  );
});
