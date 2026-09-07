import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PropsWithChildren } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { OperationListItem } from "./schemas";
import {
  makeOperationDetail,
  makeOperationListItem,
  targetNodeId,
} from "./testFixtures";
import {
  OperationsListPage,
  parseIncidentOperationPrefill,
} from "./OperationsListPage";

function jsonResponse(payload: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

function mockOperationsAndPeers(
  fetchMock: ReturnType<typeof vi.fn<typeof fetch>>,
  operations: OperationListItem[],
) {
  fetchMock.mockImplementation((input) =>
    jsonResponse(input === "/api/operations" ? operations : []),
  );
}

function renderList(initialEntry = "/app/operations") {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: Number.POSITIVE_INFINITY },
    },
  });
  function Wrapper({ children }: PropsWithChildren) {
    return (
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[initialEntry]}>{children}</MemoryRouter>
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
    mockOperationsAndPeers(fetchMock, []);

    renderList();

    expect(screen.getByRole("status")).toHaveTextContent("正在读取操作记录");
    expect(
      await screen.findByRole("heading", { name: "当前没有操作记录" }),
    ).toBeVisible();
    expect(
      screen.getByText(
        "聊天、模型或 Coordinator 不可用时，这里仍会保留已有操作。",
      ),
    ).toBeVisible();
  });

  it("显示状态摘要但详情链接只携带 operation ID", async () => {
    const summary = makeOperationListItem();
    mockOperationsAndPeers(fetchMock, [summary]);

    renderList();

    expect(await screen.findByText("等待本机批准")).toBeVisible();
    expect(screen.getByText(summary.request_node_id)).toBeVisible();
    expect(screen.getByText(summary.target_node_id)).toBeVisible();
    expect(
      screen.getByRole("link", { name: "查看操作最新详情" }),
    ).toHaveAttribute("href", `/app/operations/${summary.operation_id}`);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/operations",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("刷新失败时保留并明确标记陈旧列表", async () => {
    const staleSummary: OperationListItem = makeOperationListItem({
      tool_name: "旧列表里的工具",
    });
    let listCalls = 0;
    fetchMock.mockImplementation((input) => {
      if (input !== "/api/operations") {
        return jsonResponse([]);
      }
      listCalls += 1;
      return listCalls === 1
        ? jsonResponse([staleSummary])
        : Promise.reject(new TypeError("offline"));
    });
    const user = userEvent.setup();

    renderList();
    await screen.findByText(/旧列表里的工具/);
    await user.click(screen.getByRole("button", { name: "刷新列表" }));

    expect(
      await screen.findByText("刷新失败，下面是上一次成功读取的陈旧列表。"),
    ).toBeVisible();
    expect(screen.getByText(/旧列表里的工具/)).toBeVisible();
    expect(screen.getByText(/按 operation ID 单独读取/)).toBeVisible();
  });

  it("初次错误提供第一个可键盘触发的恢复按钮", async () => {
    fetchMock.mockImplementation((input) =>
      input === "/api/operations"
        ? Promise.reject(new TypeError("offline"))
        : jsonResponse([]),
    );
    const user = userEvent.setup();

    renderList();

    expect(
      await screen.findByRole("heading", { name: "现在读不到操作记录" }),
    ).toBeVisible();
    const retry = screen.getByRole("button", { name: "重新读取" });
    await user.tab();
    expect(retry).toHaveFocus();
  });

  it("只向合格对端提交一次有限字段并导航到同一操作", async () => {
    const detail = makeOperationDetail({ role: "requester" });
    fetchMock.mockImplementation((input, init) => {
      if (input === "/api/operations/eligible-peers") {
        return jsonResponse([
          {
            node_id: targetNodeId,
            host: "10.77.0.1",
            port: 8787,
            allowed_tools: ["get_node_summary"],
            allowed_operations: ["share_local_http_service"],
            credential_configured: true,
          },
        ]);
      }
      if ((init?.method ?? "GET").toUpperCase() === "POST") {
        return jsonResponse(detail);
      }
      return jsonResponse([]);
    });
    const user = userEvent.setup();

    renderList();
    await screen.findByRole("option", { name: new RegExp(targetNodeId) });
    await user.click(
      screen.getByRole("checkbox", { name: /目标节点批准后会创建/ }),
    );
    const submit = screen.getByRole("button", { name: "生成计划并请求批准" });
    fireEvent.click(submit);
    fireEvent.click(submit);

    await waitFor(() => {
      const writes = fetchMock.mock.calls.filter(
        ([path, init]) =>
          path === "/api/operations" &&
          (init?.method ?? "GET").toUpperCase() === "POST",
      );
      expect(writes).toHaveLength(1);
      expect(JSON.parse(String(writes[0]?.[1]?.body))).toEqual({
        target_node_id: targetNodeId,
        service_port: 8080,
        bind_port: 18881,
        duration_seconds: 300,
        confirmed: true,
      });
    });
  });

  it("校验 Incident 预填并在用户再次确认后只提交一次", async () => {
    const incidentId = `incident_${"8".repeat(32)}`;
    const detail = makeOperationDetail({ role: "requester" });
    fetchMock.mockImplementation((input, init) => {
      if (input === "/api/operations/eligible-peers") {
        return jsonResponse([
          {
            node_id: targetNodeId,
            host: "10.77.0.1",
            port: 8787,
            allowed_tools: ["get_node_summary"],
            allowed_operations: ["share_local_http_service"],
            credential_configured: true,
          },
        ]);
      }
      if ((init?.method ?? "GET").toUpperCase() === "POST") {
        return jsonResponse(detail);
      }
      return jsonResponse([]);
    });
    const user = userEvent.setup();

    renderList(
      `/app/operations?incident_id=${incidentId}&target_node_id=${targetNodeId}&service_port=4312`,
    );

    expect(
      await screen.findByText(`来自 Incident ${incidentId}`),
    ).toBeVisible();
    expect(screen.getByLabelText("目标节点")).toHaveValue(targetNodeId);
    expect(screen.getByLabelText("目标服务端口")).toHaveValue(4312);
    expect(
      fetchMock.mock.calls.filter(
        ([, init]) => (init?.method ?? "GET").toUpperCase() === "POST",
      ),
    ).toHaveLength(0);

    await user.click(
      screen.getByRole("checkbox", { name: /目标节点批准后会创建/ }),
    );
    await user.click(
      screen.getByRole("button", { name: "生成计划并请求批准" }),
    );

    await waitFor(() => {
      const writes = fetchMock.mock.calls.filter(
        ([path, init]) =>
          path === "/api/operations" &&
          (init?.method ?? "GET").toUpperCase() === "POST",
      );
      expect(writes).toHaveLength(1);
      expect(JSON.parse(String(writes[0]?.[1]?.body))).toEqual({
        target_node_id: targetNodeId,
        service_port: 4312,
        bind_port: 18881,
        duration_seconds: 300,
        confirmed: true,
      });
    });
  });

  it("Incident 目标不再合格时不静默改选或提交", async () => {
    const incidentId = `incident_${"8".repeat(32)}`;
    const unavailableTarget = `node_${"9".repeat(32)}`;
    fetchMock.mockImplementation((input) =>
      jsonResponse(
        input === "/api/operations/eligible-peers"
          ? [
              {
                node_id: targetNodeId,
                host: "10.77.0.1",
                port: 8787,
                allowed_tools: ["get_node_summary"],
                allowed_operations: ["share_local_http_service"],
                credential_configured: true,
              },
            ]
          : [],
      ),
    );

    renderList(
      `/app/operations?incident_id=${incidentId}&target_node_id=${unavailableTarget}&service_port=4312`,
    );

    expect(
      await screen.findByText(/该目标当前不在服务端返回的合格对端中/),
    ).toBeVisible();
    expect(screen.getByLabelText("目标节点")).toHaveValue(unavailableTarget);
    expect(
      screen.getByRole("button", { name: "生成计划并请求批准" }),
    ).toBeDisabled();
    expect(
      fetchMock.mock.calls.some(([, init]) => init?.method === "POST"),
    ).toBe(false);
  });

  it("拒绝缺字段、重复字段和越界端口的 Incident 预填", () => {
    expect(parseIncidentOperationPrefill(new URLSearchParams())).toEqual({
      kind: "none",
    });
    expect(
      parseIncidentOperationPrefill(
        new URLSearchParams(
          "incident_id=bad&target_node_id=bad&service_port=0",
        ),
      ),
    ).toEqual({ kind: "invalid" });
    expect(
      parseIncidentOperationPrefill(
        new URLSearchParams(
          `incident_id=incident_${"8".repeat(32)}&target_node_id=${targetNodeId}&target_node_id=${targetNodeId}&service_port=8080`,
        ),
      ),
    ).toEqual({ kind: "invalid" });
  });

  it("没有合格对端时禁用新建但保留已有操作", async () => {
    mockOperationsAndPeers(fetchMock, [makeOperationListItem()]);

    renderList();

    expect(await screen.findByText(/当前没有已配置凭据/)).toBeVisible();
    expect(
      screen.getByRole("button", { name: "生成计划并请求批准" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("link", { name: "查看操作最新详情" }),
    ).toBeVisible();
  });
});
