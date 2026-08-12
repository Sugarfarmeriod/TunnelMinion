import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PropsWithChildren } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { OperationSummary } from "./schemas";
import { makeOperationSummary } from "./testFixtures";
import { OperationsListPage } from "./OperationsListPage";

function jsonResponse(payload: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

function renderList() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: Number.POSITIVE_INFINITY },
    },
  });
  function Wrapper({ children }: PropsWithChildren) {
    return (
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/app/operations"]}>
          {children}
        </MemoryRouter>
      </QueryClientProvider>
    );
  }
  return render(<OperationsListPage />, { wrapper: Wrapper });
}

describe("OperationsListPage", () => {
  let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

  beforeEach(() => {
    fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("先显示 loading，再显示明确空状态", async () => {
    fetchMock.mockReturnValueOnce(jsonResponse([]));

    renderList();

    expect(screen.getByRole("status")).toHaveTextContent("正在读取操作记录");
    expect(
      await screen.findByRole("heading", { name: "当前没有操作记录" }),
    ).toBeVisible();
    expect(screen.getByText(/已有操作/)).toBeVisible();
  });

  it("显示状态摘要但详情链接只携带 operation ID", async () => {
    const summary = makeOperationSummary();
    fetchMock.mockReturnValueOnce(jsonResponse([summary]));

    renderList();

    expect(await screen.findByText("等待本机批准")).toBeVisible();
    expect(screen.getByText(summary.request_node_id)).toBeVisible();
    expect(screen.getByText(summary.target_node_id)).toBeVisible();
    expect(
      screen.getByRole("link", { name: "查看服务端最新详情" }),
    ).toHaveAttribute("href", `/app/operations/${summary.operation_id}`);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/operations",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("刷新失败时保留并明确标记陈旧列表", async () => {
    const staleSummary: OperationSummary = makeOperationSummary({
      tool_name: "旧列表里的工具",
    });
    fetchMock
      .mockReturnValueOnce(jsonResponse([staleSummary]))
      .mockRejectedValueOnce(new TypeError("offline"));
    const user = userEvent.setup();

    renderList();
    await screen.findByText("旧列表里的工具");
    await user.click(screen.getByRole("button", { name: "刷新列表" }));

    expect(
      await screen.findByText("刷新失败，下面是上一次成功读取的陈旧列表。"),
    ).toBeVisible();
    expect(screen.getByText("旧列表里的工具")).toBeVisible();
    expect(screen.getByText(/按 operation ID 单独读取/)).toBeVisible();
  });

  it("初次错误提供第一个可键盘触发的恢复按钮", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("offline"));
    const user = userEvent.setup();

    renderList();

    expect(
      await screen.findByRole("heading", { name: "现在读不到操作记录" }),
    ).toBeVisible();
    const retry = screen.getByRole("button", { name: "重新读取" });
    await user.tab();
    expect(retry).toHaveFocus();
  });
});
