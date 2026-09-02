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
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { OperationDetailPage } from "./OperationDetailPage";
import type { OperationDetail } from "./schemas";
import {
  makeOperationDetail,
  makeOperationSummary,
  operationId,
  recordedAt,
  requestNodeId,
  resourceId,
} from "./testFixtures";

function jsonResponse(payload: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(payload), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

function renderDetail() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: Number.POSITIVE_INFINITY },
      mutations: { retry: false },
    },
  });
  function Wrapper({ children }: PropsWithChildren) {
    return (
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[`/app/operations/${operationId}`]}>
          <Routes>
            <Route path="/app/operations/:operationId" element={children} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    );
  }
  return render(<OperationDetailPage />, { wrapper: Wrapper });
}

function postCalls(fetchMock: ReturnType<typeof vi.fn<typeof fetch>>) {
  return fetchMock.mock.calls.filter(
    ([, init]) => (init?.method ?? "GET").toUpperCase() === "POST",
  );
}

describe("OperationDetailPage", () => {
  let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

  beforeEach(() => {
    fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("按 ID 加载并可访问地展示恶意文本、验证、自有资源、清理和人工动作", async () => {
    const maliciousService = '<script>alert("service")</script>';
    const maliciousText = '<img src=x onerror="alert(1)">';
    const detail = makeOperationDetail({
      state: "cleanup_failed",
      allowed_actions: [],
      service_id: maliciousService,
      expected_change: maliciousText,
      summary: makeOperationSummary({
        status: "cleanup_failed",
        authorization_kind: "one_time",
        authorization_basis: "目标节点本地用户逐次批准",
        resource_ids: [resourceId],
        verification_results: ["requester_offline"],
        cleanup_result: "ownership_mismatch",
        error: {
          code: "cleanup_failed",
          message: maliciousText,
          retryable: false,
          correlation_id: "operation-cleanup-1",
        },
      }),
      owned_resources: [
        {
          resource_id: resourceId,
          kind: maliciousText,
          bind_host: "10.77.0.1",
          bind_port: 18_881,
          created_at: recordedAt,
        },
      ],
      verification_summaries: [
        {
          verifier_node_id: requestNodeId,
          result: "requester_offline",
          status_code: null,
          evidence_summary: maliciousText,
          verified_at: recordedAt,
        },
      ],
      cleanup_record: {
        result: "ownership_mismatch",
        reason: maliciousText,
        completed_at: recordedAt,
      },
      manual_action: "关闭残留入口并核对资源所有权",
      transitions: [
        {
          from_status: "none",
          to_status: "cleanup_failed",
          reason: maliciousText,
          occurred_at: recordedAt,
        },
      ],
    });
    fetchMock.mockReturnValueOnce(jsonResponse(detail));

    const { container } = renderDetail();

    expect(screen.getByRole("status")).toHaveTextContent("按 operation ID");
    expect(
      await screen.findByRole("heading", { name: maliciousService }),
    ).toBeVisible();
    expect(screen.getByText("清理失败，需要人工处理")).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "验证、资源与清理" }),
    ).toBeVisible();
    expect(screen.getByText("requester_offline")).toBeVisible();
    expect(screen.getAllByText(maliciousText).length).toBeGreaterThan(2);
    expect(screen.getByText("关闭残留入口并核对资源所有权")).toBeVisible();
    expect(screen.getByRole("alert", { name: "" })).toBeInTheDocument();
    expect(screen.getByText("当前没有可提交动作。")).toBeVisible();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(fetchMock.mock.calls[0]?.[0]).toBe(`/api/operations/${operationId}`);
  });

  it("初次错误可键盘恢复，刷新错误则标记陈旧详情并禁用动作", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("offline"));
    const user = userEvent.setup();

    const firstRender = renderDetail();
    expect(
      await screen.findByRole("heading", { name: "现在读不到这条操作" }),
    ).toBeVisible();
    await user.tab();
    await user.tab();
    expect(screen.getByRole("button", { name: "重新读取详情" })).toHaveFocus();
    firstRender.unmount();

    fetchMock
      .mockReturnValueOnce(jsonResponse(makeOperationDetail()))
      .mockRejectedValueOnce(new TypeError("offline"));
    renderDetail();
    const refresh = await screen.findByRole("button", { name: "刷新详情" });
    await user.click(refresh);
    expect(
      await screen.findByText("刷新失败，下面是上一次成功读取的陈旧详情。"),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "批准一次" })).toBeDisabled();
  });

  it("打开确认框前复读详情，键盘焦点可取消并回到原动作", async () => {
    const detail = makeOperationDetail();
    fetchMock
      .mockReturnValueOnce(jsonResponse(detail))
      .mockReturnValueOnce(jsonResponse(detail));
    const user = userEvent.setup();

    renderDetail();
    const approve = await screen.findByRole("button", { name: "批准一次" });
    approve.focus();
    await user.keyboard("{Enter}");

    const dialog = await screen.findByRole("dialog", { name: "确认批准一次" });
    expect(dialog).toHaveTextContent(operationId);
    expect(screen.getByRole("button", { name: "返回检查详情" })).toHaveFocus();
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await user.keyboard("{Escape}");
    await waitFor(() => expect(approve).toHaveFocus());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(postCalls(fetchMock)).toHaveLength(0);
  });

  it("批准只提交一次并在响应后重新读取详情", async () => {
    const awaiting = makeOperationDetail();
    const authorizedSummary = makeOperationSummary({
      status: "authorized",
      authorization_kind: "one_time",
      authorization_basis: "目标节点本地用户逐次批准",
      absolute_expires_at: "2026-08-08T10:00:00+08:00",
    });
    const authorized = makeOperationDetail({
      state: "authorized",
      summary: authorizedSummary,
      allowed_actions: ["cancel"],
      transitions: [
        {
          from_status: "none",
          to_status: "authorized",
          reason: "目标节点本地用户逐次批准",
          occurred_at: recordedAt,
        },
      ],
    });
    fetchMock
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(jsonResponse(authorizedSummary))
      .mockReturnValueOnce(jsonResponse(authorized));
    const user = userEvent.setup();

    renderDetail();
    await user.click(await screen.findByRole("button", { name: "批准一次" }));
    const confirm = await screen.findByRole("button", { name: "确认批准一次" });
    fireEvent.click(confirm);
    fireEvent.click(confirm);

    expect(await screen.findByText(/服务器已回应批准一次请求/)).toBeVisible();
    expect(screen.getByText("已授权，等待执行")).toBeVisible();
    expect(screen.getByRole("button", { name: "取消操作" })).toBeVisible();
    const writes = postCalls(fetchMock);
    expect(writes).toHaveLength(1);
    const [path, init] = writes[0];
    expect(path).toBe(`/api/operations/${operationId}/approve`);
    const headers = new Headers(init?.headers);
    expect(headers.get("X-TunnelMinion-Request")).toBe("same-origin");
    expect(JSON.parse(String(init?.body))).toEqual(
      expect.objectContaining({ operator: "target-local-user" }),
    );
  });

  it("复读发现批准已经过期时不打开确认框也不写入", async () => {
    const awaiting = makeOperationDetail();
    const expired = makeOperationDetail({
      state: "authorization_expired",
      summary: makeOperationSummary({ status: "authorization_expired" }),
      allowed_actions: [],
      transitions: [
        {
          from_status: "none",
          to_status: "authorization_expired",
          reason: "批准有效期已过",
          occurred_at: recordedAt,
        },
      ],
    });
    fetchMock
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(jsonResponse(expired));
    const user = userEvent.setup();

    renderDetail();
    await user.click(await screen.findByRole("button", { name: "批准一次" }));

    expect(
      await screen.findByText(/现在不允许批准一次。本次未提交/),
    ).toBeVisible();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(postCalls(fetchMock)).toHaveLength(0);
  });

  it("权限拒绝后只查询最新详情且不重放写请求", async () => {
    const detail = makeOperationDetail();
    fetchMock
      .mockReturnValueOnce(jsonResponse(detail))
      .mockReturnValueOnce(jsonResponse(detail))
      .mockReturnValueOnce(
        jsonResponse(
          { detail: { code: "invalid_origin", message: "请求来源不受信任" } },
          403,
        ),
      )
      .mockReturnValueOnce(jsonResponse(detail));
    const user = userEvent.setup();

    renderDetail();
    await user.click(await screen.findByRole("button", { name: "拒绝" }));
    await user.type(
      screen.getByRole("textbox", { name: "拒绝原因" }),
      "不同意开放端口",
    );
    await user.click(screen.getByRole("button", { name: "确认拒绝" }));

    expect(
      await screen.findByText(/invalid_origin：请求来源不受信任/),
    ).toBeVisible();
    expect(postCalls(fetchMock)).toHaveLength(1);
  });

  it("传输错误后 state 与 allowed action 未变化时持续未知且只查询", async () => {
    const awaiting = makeOperationDetail();
    fetchMock
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockRejectedValueOnce(new TypeError("network timeout"))
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(jsonResponse(awaiting));
    const user = userEvent.setup();

    renderDetail();
    await user.click(await screen.findByRole("button", { name: "批准一次" }));
    await user.click(
      await screen.findByRole("button", { name: "确认批准一次" }),
    );

    expect(
      await screen.findByText("批准一次请求的写入结果未知。"),
    ).toBeVisible();
    expect(screen.getByText(/页面没有重放该请求/)).toBeVisible();
    expect(
      screen.getByText(/state 仍是.*等待本机批准.*且仍允许批准一次/),
    ).toBeVisible();
    expect(screen.getByText(/写入结果未知期间只允许查询/)).toBeVisible();
    expect(postCalls(fetchMock)).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: "只查询最新状态" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(5));
    expect(postCalls(fetchMock)).toHaveLength(1);
    expect(screen.queryByText("批准一次请求的写入结果未知。")).toBeVisible();
    expect(screen.getByText(/写入结果继续未知/)).toBeVisible();
    expect(
      screen.queryByRole("button", { name: /再次批准/ }),
    ).not.toBeInTheDocument();
  });

  it("未知写响应后的只读详情能证明裁决时清除 unknown 但不声称成功", async () => {
    const awaiting = makeOperationDetail();
    const authorized = makeOperationDetail({
      state: "authorized",
      summary: makeOperationSummary({ status: "authorized" }),
      allowed_actions: ["cancel"],
      transitions: [
        {
          from_status: "none",
          to_status: "authorized",
          reason: "随后查询到的状态",
          occurred_at: recordedAt,
        },
      ],
    });
    fetchMock
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockRejectedValueOnce(new TypeError("network timeout"))
      .mockReturnValueOnce(jsonResponse(authorized));
    const user = userEvent.setup();

    renderDetail();
    await user.click(await screen.findByRole("button", { name: "批准一次" }));
    await user.click(
      await screen.findByRole("button", { name: "确认批准一次" }),
    );

    expect(
      await screen.findByText(/写请求响应曾经未知.*服务端已经裁决原动作/),
    ).toBeVisible();
    expect(screen.getByText(/不根据响应缺失猜测成功/)).toBeVisible();
    expect(
      screen.queryByText("批准一次请求的写入结果未知。"),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "取消操作" })).toBeVisible();
    expect(postCalls(fetchMock)).toHaveLength(1);
  });

  it("HTTP 5xx 后复读失败保持 unknown 且不提供写动作", async () => {
    const awaiting = makeOperationDetail();
    fetchMock
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(
        jsonResponse(
          { detail: { code: "lifecycle_unavailable", message: "暂时不可用" } },
          503,
        ),
      )
      .mockRejectedValueOnce(new TypeError("detail still offline"));
    const user = userEvent.setup();

    renderDetail();
    await user.click(await screen.findByRole("button", { name: "批准一次" }));
    await user.click(
      await screen.findByRole("button", { name: "确认批准一次" }),
    );

    expect(
      await screen.findByText("批准一次请求的写入结果未知。"),
    ).toBeVisible();
    expect(
      screen.getByText(/写入结果仍未知，最新详情也读取失败/),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "只查询最新状态" }),
    ).toBeVisible();
    expect(screen.getByText(/写入结果未知期间只允许查询/)).toBeVisible();
    expect(postCalls(fetchMock)).toHaveLength(1);
  });

  it("仅当详情明确允许时展示 Coordinator 离线也可执行的本机撤销", async () => {
    const succeeded = makeOperationDetail({
      state: "succeeded",
      summary: makeOperationSummary({ status: "succeeded" }),
      allowed_actions: ["revoke"],
      transitions: [
        {
          from_status: "none",
          to_status: "succeeded",
          reason: "请求节点验证通过",
          occurred_at: recordedAt,
        },
      ],
    });
    fetchMock.mockReturnValueOnce(jsonResponse(succeeded));

    renderDetail();

    expect(
      await screen.findByRole("button", { name: "主动撤销" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "批准一次" }),
    ).not.toBeInTheDocument();
  });
});
