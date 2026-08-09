import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PropsWithChildren } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { longTermMemorySchema, nodeIdSchema, type LongTermMemory } from "./api";
import { MemoriesPage } from "./MemoriesPage";

const nodeA = "node_6fcf3484754b46c6bc3ef4571e76495e";
const nodeB = "node_3b95993ebb664991887d195ae40b9b34";

function makeMemory(overrides: Partial<LongTermMemory> = {}): LongTermMemory {
  return {
    memory_id: "memory_0fd2446ca09e4db7ae5da8d985fc79d3",
    namespace: {
      user: "local-user",
      network: "home",
      node_id: nodeA,
      task_type: "local-conversation",
      security_scope: "read-only-agent",
    },
    kind: "preference",
    content: "优先使用本机工具",
    source: "用户确认",
    user_confirmed: true,
    updated_at: "2026-08-08T09:00:00+08:00",
    valid_until: null,
    revision_of: null,
    superseded_by: null,
    deleted_at: null,
    ...overrides,
  };
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderMemories() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: Number.POSITIVE_INFINITY },
    },
  });
  function Wrapper({ children }: PropsWithChildren) {
    return (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
  }
  return render(<MemoriesPage />, { wrapper: Wrapper });
}

async function chooseScope(
  user: ReturnType<typeof userEvent.setup>,
  nodeId = nodeA,
) {
  const nodeInput = screen.getByLabelText("节点 ID");
  await user.clear(nodeInput);
  await user.type(nodeInput, nodeId);
  await user.click(screen.getByRole("button", { name: "查看这个作用域" }));
}

describe("MemoriesPage", () => {
  let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

  beforeEach(() => {
    fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("先显示精确作用域提示，再覆盖 loading 与 empty", async () => {
    let resolveRequest: ((response: Response) => void) | undefined;
    fetchMock.mockReturnValueOnce(
      new Promise<Response>((resolve) => {
        resolveRequest = resolve;
      }),
    );
    const user = userEvent.setup();

    renderMemories();
    expect(
      screen.getByText(/不会把一个作用域的缓存显示到另一个作用域/),
    ).toBeVisible();

    await chooseScope(user);
    expect(
      screen.getByText("正在读取这个精确作用域的长期记忆……"),
    ).toBeVisible();
    resolveRequest?.(jsonResponse([]));

    expect(
      await screen.findByText("这个精确作用域还没有长期记忆。"),
    ).toBeVisible();
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining(`node_id=${encodeURIComponent(nodeA)}`),
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("在请求前拒绝错误 node_id，并拒绝错误 memory_id 与默认作用域格式", async () => {
    const user = userEvent.setup();
    renderMemories();

    await chooseScope(user, "6fcf3484-754b-46c6-bc3e-f4571e76495e");
    expect(
      screen.getByText("节点 ID 必须是 node_ 加 32 位小写十六进制字符。"),
    ).toBeVisible();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(nodeIdSchema.safeParse(nodeA).success).toBe(true);
    expect(
      longTermMemorySchema.safeParse({
        ...makeMemory(),
        memory_id: "0fd2446c-a09e-4db7-ae5d-a8d985fc79d3",
      }).success,
    ).toBe(false);
    expect(
      longTermMemorySchema.safeParse({
        ...makeMemory(),
        namespace: {
          ...makeMemory().namespace,
          task_type: "unexpected-task",
        },
      }).success,
    ).toBe(false);
    expect(
      longTermMemorySchema.safeParse({
        ...makeMemory(),
        namespace: {
          ...makeMemory().namespace,
          security_scope: "unexpected-security-scope",
        },
      }).success,
    ).toBe(false);
  });

  it.each([
    ["user", { user: "other-user" }],
    ["network", { network: "other-network" }],
    ["node_id", { node_id: nodeB }],
  ] as const)(
    "服务返回其他 %s 作用域时 fail closed",
    async (_field, namespaceOverride) => {
      const outOfScope = makeMemory({
        namespace: {
          ...makeMemory().namespace,
          ...namespaceOverride,
        },
      });
      fetchMock.mockResolvedValueOnce(jsonResponse([outOfScope]));
      const user = userEvent.setup();

      renderMemories();
      await chooseScope(user);

      expect(
        await screen.findByRole("heading", { name: "现在读不到长期记忆" }),
      ).toBeVisible();
      expect(screen.getByText(/不会猜测或跨作用域展示/)).toBeVisible();
      expect(screen.queryByText(outOfScope.content)).not.toBeInTheDocument();
    },
  );

  it("读取失败时给出恢复入口，恢复后显示空状态", async () => {
    fetchMock
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValueOnce(jsonResponse([]));
    const user = userEvent.setup();

    renderMemories();
    await chooseScope(user);

    const errorHeading = await screen.findByRole("heading", {
      name: "现在读不到长期记忆",
    });
    expect(errorHeading).toBeVisible();
    const errorRegion = errorHeading.closest<HTMLElement>("[role='alert']");
    expect(errorRegion).not.toBeNull();
    await user.click(
      within(errorRegion as HTMLElement).getByRole("button", {
        name: "重新读取",
      }),
    );
    expect(
      await screen.findByText("这个精确作用域还没有长期记忆。"),
    ).toBeVisible();
  });

  it("把恶意内容当作文本，并在切换节点时隔离缓存", async () => {
    const maliciousContent = '<img src=x onerror="alert(1)">';
    const maliciousSource = "<script>alert('source')</script>";
    fetchMock.mockImplementation((input) => {
      const path = String(input);
      return Promise.resolve(
        jsonResponse(
          path.includes(encodeURIComponent(nodeA))
            ? [
                makeMemory({
                  content: maliciousContent,
                  source: maliciousSource,
                }),
              ]
            : [],
        ),
      );
    });
    const user = userEvent.setup();

    const { container } = renderMemories();
    await chooseScope(user);

    expect(await screen.findByText(maliciousContent)).toBeVisible();
    expect(screen.getByText(maliciousSource)).toBeVisible();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();

    await chooseScope(user, nodeB);
    expect(
      await screen.findByText("这个精确作用域还没有长期记忆。"),
    ).toBeVisible();
    expect(screen.queryByText(maliciousContent)).not.toBeInTheDocument();
  });

  it("在原作用域内确认一次修正，并维持键盘与焦点", async () => {
    let values = [makeMemory()];
    let capturedBody: Record<string, unknown> | undefined;
    fetchMock.mockImplementation(async (input, init) => {
      const path = String(input);
      const method = init?.method ?? "GET";
      if (method === "PUT") {
        capturedBody = JSON.parse(String(init?.body)) as Record<
          string,
          unknown
        >;
        values = [
          makeMemory({
            memory_id: "memory_2cc7e0c118484f1ca05523d66fac88f2",
            content: String(capturedBody.content),
            source: String(capturedBody.source),
            revision_of: values[0]?.memory_id ?? null,
            updated_at: "2026-08-08T09:05:00+08:00",
          }),
        ];
        return jsonResponse(values[0]);
      }
      expect(path).toContain("/api/memories?");
      return jsonResponse(values);
    });
    const user = userEvent.setup();

    renderMemories();
    await chooseScope(user);
    await screen.findByText("优先使用本机工具");
    await user.click(screen.getByRole("button", { name: "修正这条记忆" }));

    const content = screen.getByLabelText("记忆内容");
    await waitFor(() => expect(content).toHaveFocus());
    await user.clear(content);
    await user.type(content, "只使用经过确认的本机工具");
    const source = screen.getByLabelText("来源说明");
    await user.clear(source);
    await user.type(source, "用户再次确认");
    await user.click(screen.getByRole("button", { name: "检查并确认修正" }));

    const cancel = screen.getByRole("button", { name: "取消" });
    await waitFor(() => expect(cancel).toHaveFocus());
    await user.tab();
    const confirm = screen.getByRole("button", { name: "确认修正一次" });
    expect(confirm).toHaveFocus();
    await user.keyboard("{Enter}");

    expect(
      await screen.findByText("服务端已确认修正，并返回了新的更新时间。"),
    ).toBeVisible();
    expect(await screen.findByText("只使用经过确认的本机工具")).toBeVisible();
    expect(capturedBody).toEqual({
      content: "只使用经过确认的本机工具",
      source: "用户再次确认",
    });
    expect(capturedBody).not.toHaveProperty("namespace");
    expect(
      screen.getByText(
        /用户“local-user”.*网络“home”.*任务“local-conversation”.*安全域“read-only-agent”/,
      ),
    ).toBeVisible();
    expect(screen.getByText("用户再次确认")).toBeVisible();
    const putCalls = fetchMock.mock.calls.filter(
      ([, init]) => init?.method === "PUT",
    );
    expect(putCalls).toHaveLength(1);
    expect(
      new Headers(putCalls[0]?.[1]?.headers).get("X-TunnelMinion-Request"),
    ).toBe("same-origin");
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "重新读取" })).toHaveFocus(),
    );
  });

  it("删除结果未知时只重新读取，不自动重放写请求", async () => {
    const value = makeMemory();
    fetchMock.mockImplementation((input, init) => {
      if (init?.method === "DELETE") {
        return Promise.reject(new TypeError("response lost"));
      }
      return Promise.resolve(jsonResponse([value]));
    });
    const user = userEvent.setup();

    renderMemories();
    await chooseScope(user);
    await screen.findByText(value.content);
    await user.click(screen.getByRole("button", { name: "删除这条记忆" }));
    expect(screen.getByRole("button", { name: "取消" })).toHaveFocus();
    await user.click(screen.getByRole("button", { name: "确认删除一次" }));

    expect(
      await screen.findByText(/删除请求的结果未知.*没有自动重放删除/),
    ).toBeVisible();
    expect(screen.getByText(value.content)).toBeVisible();
    const deleteCalls = fetchMock.mock.calls.filter(
      ([, init]) => init?.method === "DELETE",
    );
    expect(deleteCalls).toHaveLength(1);
    expect(
      new Headers(deleteCalls[0]?.[1]?.headers).get("X-TunnelMinion-Request"),
    ).toBe("same-origin");
    expect(
      screen.getByText(/删除请求的结果未知.*没有自动重放删除/),
    ).toHaveAttribute("role", "alert");
  });

  it("删除遇到服务端竞态时只重读最新作用域，不重放 DELETE", async () => {
    const value = makeMemory();
    let values = [value];
    fetchMock.mockImplementation((_input, init) => {
      if (init?.method === "DELETE") {
        values = [];
        return Promise.resolve(
          jsonResponse(
            {
              detail: {
                code: "memory_conflict",
                message: "这条记忆已被另一个请求删除",
              },
            },
            409,
          ),
        );
      }
      return Promise.resolve(jsonResponse(values));
    });
    const user = userEvent.setup();

    renderMemories();
    await chooseScope(user);
    await screen.findByText(value.content);
    await user.click(screen.getByRole("button", { name: "删除这条记忆" }));
    await user.click(screen.getByRole("button", { name: "确认删除一次" }));

    const notice = await screen.findByText(
      /这条记忆已被另一个请求删除.*只重新读取了一次.*没有自动重放删除/,
    );
    expect(notice).toHaveAttribute("role", "alert");
    expect(screen.getByText("这个精确作用域还没有长期记忆。")).toBeVisible();
    expect(screen.queryByText(value.content)).not.toBeInTheDocument();
    expect(
      fetchMock.mock.calls.filter(([, init]) => init?.method === "DELETE"),
    ).toHaveLength(1);
    expect(
      fetchMock.mock.calls.filter(([, init]) => init?.method === undefined),
    ).toHaveLength(2);
  });

  it("只清空确认框中展示的精确作用域，并以重读结果确认 204", async () => {
    let values = [makeMemory()];
    fetchMock.mockImplementation((input, init) => {
      if (init?.method === "DELETE") {
        expect(String(input)).toContain("/api/memories/scope?");
        expect(String(input)).toContain(`node_id=${encodeURIComponent(nodeA)}`);
        values = [];
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      return Promise.resolve(jsonResponse(values));
    });
    const user = userEvent.setup();

    renderMemories();
    await chooseScope(user);
    await screen.findByText("优先使用本机工具");
    await user.click(
      screen.getByRole("button", { name: "清空这个精确作用域" }),
    );
    const dialog = screen.getByRole("dialog", {
      name: "确认清空精确作用域",
    });
    expect(
      within(dialog).getByText(/^将清空：用户“local-user”.*节点/),
    ).toBeVisible();
    await user.click(screen.getByRole("button", { name: "确认清空一次" }));

    expect(
      await screen.findByText(
        "服务端已用 204 明确确认：这个精确作用域已经清空。",
      ),
    ).toBeVisible();
    expect(screen.getByText("这个精确作用域还没有长期记忆。")).toBeVisible();
    expect(
      fetchMock.mock.calls.filter(([, init]) => init?.method === "DELETE"),
    ).toHaveLength(1);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "重新读取" })).toHaveFocus(),
    );
  });
});
