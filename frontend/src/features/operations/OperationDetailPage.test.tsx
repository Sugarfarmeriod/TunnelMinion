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
    vi.stubGlobal("fetch", (path: string, init: RequestInit) =>
      path === "/api/ui/overview"
        ? jsonResponse(
            { detail: { code: "unavailable", message: "名称暂不可用" } },
            503,
          )
        : fetchMock(path, init),
    );
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

    expect(screen.getByRole("status")).toHaveTextContent("正在读取这条请求");
    expect(
      await screen.findByRole("heading", { name: "临时访问请求" }),
    ).toBeVisible();
    await userEvent.setup().click(screen.getByText("查看技术详情与记录"));
    expect(screen.getByText(maliciousService)).toBeVisible();
    expect(screen.getByText("入口关闭失败，需要处理")).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "验证、资源与清理" }),
    ).toBeVisible();
    expect(screen.getByText("requester_offline")).toBeVisible();
    expect(screen.getAllByText(maliciousText).length).toBeGreaterThan(2);
    expect(
      screen.getAllByText("关闭残留入口并核对资源所有权")[0],
    ).toBeVisible();
    expect(screen.getAllByRole("alert").length).toBeGreaterThan(0);
    expect(screen.getByText("当前没有可提交动作。")).toBeVisible();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(fetchMock.mock.calls[0]?.[0]).toBe(`/api/operations/${operationId}`);
  });

  it("展示并链接回持久化的来源 Incident", async () => {
    const incidentId = `incident_${"8".repeat(32)}`;
    fetchMock.mockReturnValueOnce(
      jsonResponse(makeOperationDetail({ source_incident_id: incidentId })),
    );

    renderDetail();

    expect(
      await screen.findByRole("link", { name: "返回调查结果" }),
    ).toBeVisible();
    expect(await screen.findByText(incidentId)).toHaveAttribute(
      "href",
      `/app/overview?incident_id=${incidentId}#overview-incidents`,
    );
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
    expect(screen.getByText("等待对方开始")).toBeVisible();
    expect(screen.getByRole("button", { name: "取消请求" })).toBeVisible();
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

    expect(await screen.findByText("这次请求的结果还不明确。")).toBeVisible();
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(screen.getByText("结果待确认", { exact: true })).toBeVisible();
    expect(screen.queryByText(/认识这个请求再批准/)).not.toBeInTheDocument();
    expect(
      screen.queryByText(/operation ID|state 仍是|allowed_actions/),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("region", { name: "处理请求" }),
    ).not.toBeInTheDocument();
    expect(postCalls(fetchMock)).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: "查询这条请求" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(5));
    expect(postCalls(fetchMock)).toHaveLength(1);
    expect(screen.getByText("这次请求的结果还不明确。")).toBeVisible();
    expect(screen.getByText(/查询后仍没有明确结果/)).toBeVisible();
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
      await screen.findByText(/已读到最新状态，请以下方结果为准/),
    ).toBeVisible();
    expect(screen.getByText(/刚才的请求没有再次发送/)).toBeVisible();
    expect(screen.queryByText(/批准成功|执行成功/)).not.toBeInTheDocument();
    expect(
      screen.queryByText("这次请求的结果还不明确。"),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "取消请求" })).toBeVisible();
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

    expect(await screen.findByText("这次请求的结果还不明确。")).toBeVisible();
    expect(screen.getByText(/暂时查不到最新结果/)).toBeVisible();
    expect(screen.getByRole("button", { name: "查询这条请求" })).toBeVisible();
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(
      screen.queryByRole("button", { name: "批准一次" }),
    ).not.toBeInTheDocument();
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
      await screen.findByRole("button", { name: "结束临时访问" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "批准一次" }),
    ).not.toBeInTheDocument();
  });

  it("请求端复读授权后只执行一次，并只暴露不含凭据的本机访问地址", async () => {
    const authorized = makeOperationDetail({
      role: "requester",
      state: "authorized",
      summary: makeOperationSummary({ status: "authorized" }),
      allowed_actions: ["refresh", "execute"],
      last_checked_at: recordedAt,
    });
    const succeeded = makeOperationDetail({
      role: "requester",
      state: "succeeded",
      summary: makeOperationSummary({ status: "succeeded" }),
      allowed_actions: ["refresh", "access"],
      last_checked_at: recordedAt,
      access_expires_at: "2026-08-08T09:05:00+08:00",
    });
    fetchMock
      .mockReturnValueOnce(jsonResponse(authorized))
      .mockReturnValueOnce(jsonResponse(authorized))
      .mockReturnValueOnce(jsonResponse(succeeded));
    const user = userEvent.setup();

    renderDetail();
    await user.click(
      await screen.findByRole("button", { name: "开始临时访问" }),
    );
    expect(
      await screen.findByRole("dialog", { name: "确认开始临时访问" }),
    ).toHaveTextContent("结果不明确时，请先刷新，不要重复开始");
    const confirm = screen.getByRole("button", { name: "确认开始临时访问" });
    fireEvent.click(confirm);
    fireEvent.click(confirm);

    const access = await screen.findByRole("link", { name: "打开临时访问" });
    expect(access).toHaveAttribute(
      "href",
      `/api/operations/${operationId}/access/`,
    );
    expect(access.getAttribute("href")).not.toMatch(/token|secret|credential/i);
    const executeWrites = postCalls(fetchMock).filter(
      ([path]) => path === `/api/operations/${operationId}/execute`,
    );
    expect(executeWrites).toHaveLength(1);
    expect(JSON.parse(String(executeWrites[0]?.[1]?.body))).toEqual({
      confirmed: true,
    });
    expect(
      new Headers(executeWrites[0]?.[1]?.headers).get("X-TunnelMinion-Request"),
    ).toBe("same-origin");
  });

  it("请求端结果未知时只允许刷新同一 operation，不自动重放执行", async () => {
    const unknown = makeOperationDetail({
      role: "requester",
      state: "authorized",
      summary: makeOperationSummary({ status: "authorized" }),
      allowed_actions: ["refresh"],
      execution_result_unknown: true,
      error_code: "execution_result_unknown",
      last_checked_at: recordedAt,
    });
    fetchMock
      .mockReturnValueOnce(jsonResponse(unknown))
      .mockReturnValueOnce(jsonResponse(unknown));
    const user = userEvent.setup();

    renderDetail();
    expect(await screen.findByText("这次请求的结果还不明确。")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "开始临时访问" }),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "查询这条请求" }));

    await waitFor(() => expect(postCalls(fetchMock)).toHaveLength(1));
    expect(postCalls(fetchMock)[0]?.[0]).toBe(
      `/api/operations/${operationId}/refresh`,
    );
    expect(
      fetchMock.mock.calls.filter(
        ([path]) => path === `/api/operations/${operationId}/execute`,
      ),
    ).toHaveLength(0);
  });

  it.each([
    {
      role: "target",
      state: "awaiting_authorization",
      flag: "submission_result_unknown",
      action: "批准一次",
    },
    {
      role: "target",
      state: "awaiting_authorization",
      flag: "execution_result_unknown",
      action: "批准一次",
    },
    {
      role: "requester",
      state: "authorized",
      flag: "execution_result_unknown",
      action: "开始临时访问",
    },
  ] as const)(
    "准备 $action 时最新详情变成 $flag，不再打开确认框",
    async ({ role, state, flag, action }) => {
      const detail = makeOperationDetail({
        role,
        state,
        allowed_actions:
          role === "target" ? ["approve"] : ["execute", "refresh"],
      });
      fetchMock
        .mockReturnValueOnce(jsonResponse(detail))
        .mockReturnValueOnce(jsonResponse({ ...detail, [flag]: true }));
      const user = userEvent.setup();
      renderDetail();
      await user.click(await screen.findByRole("button", { name: action }));
      expect(await screen.findByText("这次请求的结果还不明确。")).toBeVisible();
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: "查询这条请求" }),
      ).toBeVisible();
      expect(postCalls(fetchMock)).toHaveLength(0);
    },
  );

  it("入口关闭失败与待确认并存时，不掩盖需要人工处理的提醒", async () => {
    fetchMock.mockReturnValueOnce(
      jsonResponse(
        makeOperationDetail({
          state: "cleanup_failed",
          execution_result_unknown: true,
          manual_action: "请检查尚未关闭的入口",
          allowed_actions: [],
        }),
      ),
    );
    renderDetail();
    expect(await screen.findByText("入口关闭失败，需要处理")).toBeVisible();
    expect(screen.getByText("需要你处理：临时入口没有安全关闭")).toBeVisible();
    expect(screen.getByText("请检查尚未关闭的入口")).toBeVisible();
    expect(screen.getByText("这次请求的结果还不明确。")).toBeVisible();
  });

  it("结果待确认时只保留一个查询入口，读取失败也不重新展示批准建议", async () => {
    const detail = makeOperationDetail({
      submission_result_unknown: true,
      error_code: "submission_result_unknown",
    });
    fetchMock
      .mockReturnValueOnce(jsonResponse(detail))
      .mockRejectedValueOnce(new TypeError("offline"));
    const user = userEvent.setup();
    const { container } = renderDetail();

    await screen.findByText("这次请求的结果还不明确。");
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(
      screen.getAllByRole("button", { name: "查询这条请求" }),
    ).toHaveLength(1);
    expect(container.querySelector(".operation-request-intent")).toBeNull();
    expect(container.querySelector(".operation-actions")).toBeNull();
    expect(screen.getByText(/请向发起人确认身份/)).toBeVisible();
    expect(screen.getByText(/使用者可能查看或修改内容/)).toBeVisible();
    expect(
      screen.getByText("awaiting_authorization", { exact: true }),
    ).not.toBeVisible();
    await user.click(screen.getByText("查看技术详情与记录"));
    expect(
      screen.getByText("awaiting_authorization", { exact: true }),
    ).toBeVisible();
    expect(screen.getByText("approve、reject、cancel")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "查询这条请求" }));
    expect(await screen.findByText(/暂时查不到最新结果/)).toBeVisible();
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(screen.getByText("结果待确认", { exact: true })).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "批准一次" }),
    ).not.toBeInTheDocument();
    expect(postCalls(fetchMock)).toHaveLength(0);
  });

  it("已收到提交响应但详情读取失败时，先查询同一请求再恢复允许动作", async () => {
    const awaiting = makeOperationDetail();
    const authorized = makeOperationDetail({
      state: "authorized",
      allowed_actions: ["cancel"],
    });
    fetchMock
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(jsonResponse(authorized.summary))
      .mockRejectedValueOnce(new TypeError("detail offline"))
      .mockReturnValueOnce(jsonResponse(authorized));
    const user = userEvent.setup();
    renderDetail();
    await user.click(await screen.findByRole("button", { name: "批准一次" }));
    await user.click(
      await screen.findByRole("button", { name: "确认批准一次" }),
    );
    expect(
      await screen.findByText(/请求已收到，但暂时读不到处理结果/),
    ).toBeVisible();
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(
      screen.queryByRole("button", { name: "批准一次" }),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "查询这条请求" }));
    expect(await screen.findByText("等待对方开始")).toBeVisible();
    expect(
      screen.queryByText("这次请求的结果还不明确。"),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "取消请求" })).toBeVisible();
    expect(postCalls(fetchMock)).toHaveLength(1);
    expect(
      fetchMock.mock.calls.filter(
        ([path]) => path === `/api/operations/${operationId}`,
      ),
    ).toHaveLength(4);
  });

  it("查询进行中禁用唯一按钮，重复点击不会再次提交或查询", async () => {
    const awaiting = makeOperationDetail();
    let finishQuery!: (response: Response) => void;
    const response = new Promise<Response>((resolve) => {
      finishQuery = resolve;
    });
    fetchMock
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockRejectedValueOnce(new TypeError("response lost"))
      .mockReturnValueOnce(jsonResponse(awaiting))
      .mockReturnValueOnce(response);
    const user = userEvent.setup();
    renderDetail();
    await user.click(await screen.findByRole("button", { name: "批准一次" }));
    await user.click(
      await screen.findByRole("button", { name: "确认批准一次" }),
    );
    await user.click(
      await screen.findByRole("button", { name: "查询这条请求" }),
    );
    const querying = screen.getByRole("button", { name: "正在查询……" });
    expect(querying).toBeDisabled();
    fireEvent.click(querying);
    expect(fetchMock).toHaveBeenCalledTimes(5);
    finishQuery(new Response(JSON.stringify(awaiting), { status: 200 }));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "查询这条请求" }),
      ).toBeEnabled(),
    );
    expect(postCalls(fetchMock)).toHaveLength(1);
  });
});
