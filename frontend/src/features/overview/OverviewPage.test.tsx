import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PropsWithChildren } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ResourceOverview } from "../../api/schemas/overview";
import { makeOperationListItem } from "../operations/testFixtures";

import { OverviewPage } from "./OverviewPage";

const generatedAt = "2026-08-08T09:00:00+08:00";
const evidenceAt = "2026-08-08T08:59:00+08:00";
const nodeA = `node_${"1".repeat(32)}`;
const nodeB = `node_${"2".repeat(32)}`;
const serviceA = `service_${"3".repeat(32)}`;

function makeOverview(): ResourceOverview {
  return {
    schema_version: "resource-overview/v1",
    generated_at: generatedAt,
    local: {
      source: "local_runtime",
      evidence_at: evidenceAt,
      freshness: "live",
      error: null,
      runtime: "running",
      platform: "windows",
      version: "0.1.0",
      package: {
        name: "tunnelminion",
        kind: "source",
        version: "0.1.0",
        manifest_schema: null,
      },
      readiness: "ready",
    },
    model: {
      source: "model_configuration",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      configured: true,
      status: "available",
    },
    coordinator: {
      source: "coordinator_sync",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      configured: true,
      state: "ready",
      revision: 12,
      last_success_at: evidenceAt,
    },
    network_path: {
      source: "network_path_evidence",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      configured: true,
      state: "direct",
      provider: "windows",
      revision: 4,
      handshake: { status: "passed", observed_at: evidenceAt },
      route: { status: "passed", observed_at: evidenceAt },
      probe: { status: "passed", observed_at: evidenceAt },
    },
    nodes: {
      source: "coordinator_directory",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      items: [],
    },
    services: {
      source: "coordinator_directory",
      evidence_at: evidenceAt,
      freshness: "fresh",
      error: null,
      items: [],
    },
    incidents: {
      source: "local_observation",
      evidence_at: null,
      freshness: "not_applicable",
      error: null,
      items: [],
    },
  };
}

function jsonResponse(payload: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

function renderOverview(entry = "/app/overview") {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: Number.POSITIVE_INFINITY },
    },
  });
  function Wrapper({ children }: PropsWithChildren) {
    return (
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[entry]}>{children}</MemoryRouter>
      </QueryClientProvider>
    );
  }
  return render(<OverviewPage />, { wrapper: Wrapper });
}

describe("OverviewPage", () => {
  let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

  beforeEach(() => {
    fetchMock = vi.fn<typeof fetch>();
    fetchMock.mockImplementation((input) =>
      input === "/api/operations"
        ? jsonResponse([])
        : Promise.reject(new TypeError(`unexpected request: ${String(input)}`)),
    );
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("首页没有空栏目，技术状态从更多信息打开", async () => {
    fetchMock.mockReturnValueOnce(jsonResponse(makeOverview()));
    const user = userEvent.setup();

    renderOverview();

    expect(screen.getByRole("status")).toHaveTextContent("正在读取本机");
    expect(await screen.findByText("还没有发现设备或服务。")).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "需要你处理" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("list", { name: "需要你处理的请求" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("还没有发现设备或服务。")).toBeVisible();
    expect(screen.getByText("本机程序正在运行")).not.toBeVisible();
    expect(screen.getByText("没有检测到重要变化")).not.toBeVisible();
    await user.click(screen.getByText("更多信息"));
    expect(screen.getByRole("heading", { name: "本机运行" })).toBeVisible();
    expect(screen.getByText("本机接口已准备好")).toBeVisible();
    expect(screen.getByText("模型现在可以使用")).toBeVisible();
    expect(screen.getByText("Coordinator 目录已同步")).toBeVisible();
    expect(screen.getByText("当前选择了直连路径")).toBeVisible();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/resources/overview",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("明确展示无模型、无 Coordinator、peer 离线、可选诊断错误与未知/陈旧记录", async () => {
    const payload = makeOverview();
    payload.model = {
      ...payload.model,
      configured: false,
      status: "unconfigured",
      freshness: "not_applicable",
      evidence_at: null,
    };
    payload.coordinator = {
      ...payload.coordinator,
      configured: false,
      state: "unconfigured",
      freshness: "not_applicable",
      evidence_at: null,
      revision: null,
      last_success_at: null,
    };
    payload.network_path = {
      ...payload.network_path,
      state: "offline",
      error: { code: "firewall_log_unavailable", retryable: false },
      handshake: { status: "passed", observed_at: evidenceAt },
      route: { status: "missing", observed_at: null },
      probe: { status: "failed", observed_at: evidenceAt },
    };
    payload.nodes = {
      ...payload.nodes,
      freshness: "stale",
      error: { code: "directory_cache_stale", retryable: true },
      items: [
        {
          node_id: nodeA,
          display_name: "离线的 Mac",
          platform: "macos",
          state: "offline",
          source: "coordinator_directory",
          evidence_at: evidenceAt,
          freshness: "stale",
          service_count: 0,
        },
        {
          node_id: nodeB,
          display_name: "状态待确认的电脑",
          platform: null,
          state: "unknown",
          source: "unknown",
          evidence_at: null,
          freshness: "unknown",
          service_count: 0,
        },
      ],
    };
    payload.services = {
      ...payload.services,
      freshness: "unavailable",
      error: { code: "service_inventory_unavailable", retryable: true },
    };
    fetchMock.mockReturnValueOnce(jsonResponse(payload));
    const user = userEvent.setup();

    renderOverview();

    await user.click(await screen.findByText("更多信息"));
    expect(screen.getByText("还没有配置模型")).toBeVisible();
    expect(
      screen.getByText("未配置 Coordinator，当前按仅本机模式工作"),
    ).toBeVisible();
    expect(screen.getByText("peer 路径当前不可达")).toBeVisible();
    for (const disclosure of screen.getAllByText("查看证据")) {
      await user.click(disclosure);
    }
    expect(screen.getByText("firewall_log_unavailable")).toBeVisible();
    expect(screen.getByText("service_inventory_unavailable")).toBeVisible();
    expect(screen.getByText("2 台设备")).toBeVisible();
    expect(
      screen.getByText("设备清单还不能确认最新状态，请刷新后再判断。"),
    ).toBeVisible();
    expect(
      screen.getByText("服务清单还不能确认最新状态，请刷新后再判断。"),
    ).toBeVisible();
    expect(screen.getByText("当前离线（记录已过时）")).toBeVisible();
    expect(screen.getByText("状态未知")).toBeVisible();
    expect(screen.getByText(/先看真实探测是否通过/)).toBeVisible();
    expect(screen.queryByText(/^健康$/)).not.toBeInTheDocument();
  });

  it("把恶意节点名和服务名只当作文本呈现", async () => {
    const payload = makeOverview();
    const maliciousNode = '<img src=x onerror="alert(1)">';
    const maliciousService = "<script>alert('service')</script>";
    payload.nodes.items = [
      {
        node_id: nodeA,
        display_name: maliciousNode,
        platform: "macos",
        state: "online",
        source: "coordinator_directory",
        evidence_at: evidenceAt,
        freshness: "fresh",
        service_count: 1,
      },
    ];
    payload.services.items = [
      {
        service_id: serviceA,
        node_id: nodeA,
        display_name: maliciousService,
        protocol: "https",
        port: 443,
        access_address: "https://service.example:443",
        accessibility: "network",
        lifecycle: "active",
        state: "available",
        source: "coordinator_directory",
        evidence_at: evidenceAt,
        freshness: "fresh",
      },
    ];
    fetchMock.mockReturnValueOnce(jsonResponse(payload));
    const user = userEvent.setup();

    const { container } = renderOverview();

    await user.click(await screen.findByText(maliciousNode));
    expect(screen.getAllByText(maliciousService)[0]).toBeVisible();
    expect(
      screen.getAllByText(/https:\/\/service\.example:443/)[0],
    ).not.toBeVisible();
    await user.click(screen.getByText("查看全部 1 个检测项目（技术清单）"));
    expect(
      screen.getAllByText(/https:\/\/service\.example:443/)[0],
    ).toBeVisible();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
  });

  it("按设备汇总全部监听项，不再用分页隐藏总数", async () => {
    const payload = makeOverview();
    payload.nodes.items = [
      {
        node_id: nodeA,
        display_name: "工作室 Mac",
        platform: "macos",
        state: "online",
        source: "coordinator_directory",
        evidence_at: evidenceAt,
        freshness: "fresh",
        service_count: 7,
      },
      {
        node_id: nodeB,
        display_name: "客厅电脑",
        platform: "windows",
        state: "online",
        source: "coordinator_directory",
        evidence_at: evidenceAt,
        freshness: "fresh",
        service_count: 6,
      },
    ];
    payload.services.items = Array.from({ length: 13 }, (_, index) => ({
      service_id: `service_${index.toString(16).padStart(32, "0")}`,
      node_id: index < 7 ? nodeA : nodeB,
      display_name: null,
      protocol: "tcp" as const,
      port: 9000 + index,
      access_address: `tcp://10.77.0.${index < 7 ? 1 : 2}:${9000 + index}`,
      accessibility: "network" as const,
      lifecycle: "active" as const,
      state: "available" as const,
      source: "coordinator_directory" as const,
      evidence_at: evidenceAt,
      freshness: "fresh" as const,
    }));
    fetchMock.mockReturnValueOnce(jsonResponse(payload));
    const user = userEvent.setup();

    renderOverview();

    expect(await screen.findByText("2 台设备")).toBeVisible();
    expect(screen.queryByText("第 1 / 3 页")).not.toBeInTheDocument();
    expect(
      screen
        .getAllByText("用途未识别的后台项目")
        .filter((item) => item.closest("details")?.open),
    ).toHaveLength(0);
    await user.click(screen.getByText("工作室 Mac"));
    expect(screen.getByText("查看全部 7 个检测项目（技术清单）")).toBeVisible();
    expect(screen.getByText("tcp://10.77.0.1:9006")).not.toBeVisible();
    await user.click(screen.getByText("查看全部 7 个检测项目（技术清单）"));
    expect(
      screen
        .getAllByText("用途未识别的后台项目")
        .filter((item) => item.closest("details")?.open),
    ).toHaveLength(7);
    expect(screen.getByText("tcp://10.77.0.1:9006")).toBeVisible();
    expect(screen.queryByText(nodeA.slice(0, 8))).not.toBeInTheDocument();
  });

  it("展示 incident 详情、未知项和建议追问，并把不可信轨迹只当文本", async () => {
    Object.defineProperty(window, "innerWidth", {
      configurable: true,
      value: 320,
    });
    const payload = makeOverview();
    const incidentId = `incident_${"4".repeat(32)}`;
    const snapshotA = `snapshot_${"5".repeat(32)}`;
    const snapshotB = `snapshot_${"6".repeat(32)}`;
    const runId = `run_${"7".repeat(32)}`;
    const threadId = `thread_${"8".repeat(32)}`;
    const malicious = "<script>alert('incident')</script>";
    payload.incidents = {
      source: "local_observation",
      evidence_at: evidenceAt,
      freshness: "live",
      error: null,
      items: [
        {
          incident_id: incidentId,
          event_type: "local_only",
          object_kind: "service",
          object_id: serviceA,
          severity: "warning",
          status: "insufficient_evidence",
          first_observed_at: evidenceAt,
          last_observed_at: generatedAt,
          conclusion: null,
        },
      ],
    };
    const detail = {
      incident: {
        schema_version: "incident/v1",
        investigation: {
          schema_version: "investigation-state/v1",
          skill_id: "service.local-only",
          skill_version: "1",
          phase: "collecting",
          model_rounds: 2,
          tool_calls: 3,
          steps: [
            {
              step_id: "inspect-target-listener",
              requirement_ids: ["target-listener"],
              tool_name: "get_process_summary",
              execution: "target",
              status: "succeeded",
              attempts: 1,
              evidence: {
                snapshot_id: snapshotB,
                tool_run_id: `toolrun_${"9".repeat(32)}`,
                observed_at: evidenceAt,
                summary: "目标节点确认服务只监听环回地址",
              },
              observations: { private_note: "不应展示" },
              failure_code: null,
            },
            {
              step_id: "probe-requester",
              requirement_ids: ["requester-reachability"],
              tool_name: "probe_service",
              execution: "requester",
              status: "failed",
              attempts: 2,
              evidence: null,
              observations: {},
              failure_code: "connection_refused",
            },
            {
              step_id: "inspect-private-network",
              requirement_ids: ["private-network"],
              tool_name: "get_node_summary",
              execution: "target",
              status: "attempted",
              attempts: 1,
              evidence: null,
              observations: {},
              failure_code: null,
            },
            {
              step_id: "confirm-owner",
              requirement_ids: ["target-process"],
              tool_name: "get_process_owner",
              execution: "target",
              status: "pending",
              attempts: 0,
              evidence: null,
              observations: {},
              failure_code: null,
            },
          ],
          facts: ["服务只监听环回地址"],
          unknowns: ["还不知道监听进程"],
          stop_reason: null,
          updated_at: generatedAt,
        },
        incident_id: incidentId,
        dedup_key: `sha256:${"a".repeat(64)}`,
        event: {
          event_type: "local_only",
          object_kind: "service",
          object_id: serviceA,
          target_node_id: nodeA,
          baseline_snapshot_id: snapshotA,
          current_snapshot_id: snapshotB,
          baseline_revision: 1,
          current_revision: 2,
          observed_at: evidenceAt,
          source: "local_observation",
          before_state: "network",
          after_state: "loopback",
          dedup_key: `sha256:${"a".repeat(64)}`,
        },
        status: "insufficient_evidence",
        created_at: evidenceAt,
        last_observed_at: generatedAt,
        run_id: null,
        hypotheses: [],
        trace: [
          {
            occurred_at: generatedAt,
            kind: "report",
            summary: malicious,
            tool_name: null,
            evidence: [],
          },
        ],
        report: {
          facts: [],
          candidate_explanations: [],
          unknowns: ["还不知道监听进程"],
          conclusion: null,
          stop_reason: "insufficient_evidence",
          evidence: [],
        },
      },
      suggested_questions: ["哪个进程持有这个监听端口？"],
      thread_id: null,
    };
    fetchMock.mockImplementation((input, init) => {
      if (input === "/api/resources/overview") {
        return jsonResponse(payload);
      }
      if (input === "/api/operations") {
        return jsonResponse([]);
      }
      if (input === `/api/incidents/${incidentId}`) {
        return jsonResponse(detail);
      }
      if (
        input === `/api/incidents/${incidentId}/follow-up` &&
        init?.method === "POST"
      ) {
        return jsonResponse({
          run_id: runId,
          thread_id: threadId,
          status: "running",
          created_at: generatedAt,
          finished_at: null,
          result: null,
          error_code: null,
          error_message: null,
          failure: null,
        });
      }
      return Promise.reject(
        new TypeError(`unexpected request: ${String(input)}`),
      );
    });
    const user = userEvent.setup();
    const { container } = renderOverview();

    await user.click(await screen.findByText("更多信息"));
    await user.click(
      await screen.findByRole("button", { name: "查看调查详情" }),
    );
    expect(
      await screen.findByRole("heading", { name: "调查结果" }),
    ).toBeVisible();
    expect(screen.getByText("service.local-only@1")).not.toBeVisible();
    await user.click(screen.getByText("查看技术过程与证据"));
    expect(screen.getByText(malicious)).toBeVisible();
    expect(screen.getByText("还不知道监听进程")).toBeVisible();
    expect(screen.getByText("service.local-only@1")).toBeVisible();
    expect(screen.getByText("正在收集证据")).toBeVisible();
    expect(screen.getByText("工具执行成功")).toBeVisible();
    expect(screen.getByText("工具执行失败")).toBeVisible();
    expect(screen.getByText("已尝试，结果待确认")).toBeVisible();
    expect(screen.getByText("等待执行")).toBeVisible();
    expect(screen.getByText("调查进行中")).toBeVisible();
    expect(screen.queryByText("不应展示")).not.toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();

    await user.click(screen.getByText("查看公开证据引用"));
    expect(screen.getByText(snapshotB)).toBeVisible();
    expect(screen.getByText("目标节点确认服务只监听环回地址")).toBeVisible();

    await user.click(screen.getByText("继续问一下（会使用模型额度）"));
    const composer = screen.getByLabelText("针对这个事件追问");
    const suggestion = screen.getByRole("button", {
      name: "哪个进程持有这个监听端口？",
    });
    await user.click(composer);
    expect(composer).toHaveFocus();
    await user.tab();
    expect(suggestion).toHaveFocus();
    await user.click(suggestion);
    expect(composer).toHaveValue("哪个进程持有这个监听端口？");
    await user.click(screen.getByRole("button", { name: "开始只读追问" }));
    expect(
      await screen.findByRole("link", { name: "打开对应聊天线程" }),
    ).toHaveAttribute("href", `/app/chat?thread=${threadId}`);
    expect(fetchMock).toHaveBeenLastCalledWith(
      `/api/incidents/${incidentId}/follow-up`,
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
      }),
    );
  });

  it("从已确认的远端 local-only incident 只导航到预填候选计划", async () => {
    const payload = makeOverview();
    const incidentId = `incident_${"4".repeat(32)}`;
    const snapshotA = `snapshot_${"5".repeat(32)}`;
    const snapshotB = `snapshot_${"6".repeat(32)}`;
    payload.nodes.items = [
      {
        node_id: nodeA,
        display_name: "本机",
        platform: "windows",
        state: "local",
        source: "local_observation",
        evidence_at: evidenceAt,
        freshness: "live",
        service_count: 0,
      },
      {
        node_id: nodeB,
        display_name: "远端 Mac",
        platform: "macos",
        state: "online",
        source: "coordinator_directory",
        evidence_at: evidenceAt,
        freshness: "fresh",
        service_count: 1,
      },
    ];
    payload.services.items = [
      {
        service_id: serviceA,
        node_id: nodeB,
        display_name: "远端面板",
        protocol: "tcp",
        port: 4312,
        access_address: "tcp://127.0.0.1:4312",
        accessibility: "loopback",
        lifecycle: "active",
        state: "available",
        source: "coordinator_directory",
        evidence_at: evidenceAt,
        freshness: "fresh",
      },
    ];
    payload.incidents.items = [
      {
        incident_id: incidentId,
        event_type: "local_only",
        object_kind: "service",
        object_id: serviceA,
        severity: "warning",
        status: "confirmed",
        first_observed_at: evidenceAt,
        last_observed_at: generatedAt,
        conclusion: "远端服务只监听环回地址",
      },
    ];
    const detail = {
      incident: {
        schema_version: "incident/v1",
        incident_id: incidentId,
        dedup_key: `sha256:${"a".repeat(64)}`,
        event: {
          event_type: "local_only",
          object_kind: "service",
          object_id: serviceA,
          target_node_id: nodeB,
          baseline_snapshot_id: snapshotA,
          current_snapshot_id: snapshotB,
          baseline_revision: 1,
          current_revision: 2,
          observed_at: evidenceAt,
          source: "coordinator_directory",
          before_state: "network",
          after_state: "loopback",
          dedup_key: `sha256:${"a".repeat(64)}`,
        },
        status: "confirmed",
        created_at: evidenceAt,
        last_observed_at: generatedAt,
        run_id: `run_${"7".repeat(32)}`,
        hypotheses: [],
        trace: [],
        report: {
          facts: ["服务只监听环回地址"],
          candidate_explanations: [],
          unknowns: [],
          conclusion: "远端服务只监听环回地址",
          stop_reason: "evidence_sufficient",
          evidence: [
            {
              snapshot_id: snapshotB,
              tool_run_id: null,
              observed_at: evidenceAt,
              summary: "当前快照确认环回监听",
            },
          ],
        },
      },
      suggested_questions: [],
      thread_id: null,
    };
    fetchMock.mockImplementation((input) => {
      if (input === "/api/resources/overview") {
        return jsonResponse(payload);
      }
      if (input === "/api/operations") {
        return jsonResponse([]);
      }
      if (input === `/api/incidents/${incidentId}`) {
        return jsonResponse(detail);
      }
      return Promise.reject(
        new TypeError(`unexpected request: ${String(input)}`),
      );
    });
    const user = userEvent.setup();

    renderOverview(
      `/app/overview?incident_id=${incidentId}#overview-incidents`,
    );
    const handoff = await screen.findByRole("link", {
      name: "查看临时访问方案",
    });

    expect(screen.getByText(/暂未记录结构化调查过程/)).not.toBeVisible();
    expect(handoff).toHaveAttribute(
      "href",
      `/app/operations?incident_id=${incidentId}&target_node_id=${nodeB}&service_port=4312`,
    );
    expect(
      screen.getByText(/只有你发出请求、对方批准并确认执行后/),
    ).toBeVisible();
    await user.click(screen.getByText("查看技术过程与证据"));
    expect(screen.getByText(/暂未记录结构化调查过程/)).toBeVisible();
    await user.click(handoff);
    expect(
      fetchMock.mock.calls.filter(
        ([, init]) => (init?.method ?? "GET").toUpperCase() === "POST",
      ),
    ).toHaveLength(0);
  });

  it("只突出需要本机介入的操作，操作读取失败也不破坏 incident 总览", async () => {
    const payload = makeOverview();
    const operations = [
      makeOperationListItem({ operation_id: `operation_${"1".repeat(32)}` }),
      makeOperationListItem({
        operation_id: `operation_${"2".repeat(32)}`,
        role: "requester",
        status: "authorized",
      }),
      makeOperationListItem({
        operation_id: `operation_${"3".repeat(32)}`,
        role: "requester",
        status: "awaiting_authorization",
      }),
      makeOperationListItem({
        operation_id: `operation_${"4".repeat(32)}`,
        status: "succeeded",
      }),
      makeOperationListItem({
        operation_id: `operation_${"5".repeat(32)}`,
        execution_result_unknown: true,
      }),
      makeOperationListItem({
        operation_id: `operation_${"6".repeat(32)}`,
        status: "cleanup_failed",
      }),
    ];
    fetchMock.mockImplementation((input) =>
      input === "/api/resources/overview"
        ? jsonResponse(payload)
        : input === "/api/operations"
          ? jsonResponse(operations)
          : Promise.reject(
              new TypeError(`unexpected request: ${String(input)}`),
            ),
    );

    renderOverview();

    expect(await screen.findByText("待本机批准")).toBeVisible();
    expect(screen.getByText("待确认执行")).toBeVisible();
    expect(screen.getByText("写入结果待确认")).toBeVisible();
    expect(screen.getByText("清理失败，需人工处理")).toBeVisible();
    expect(screen.getAllByRole("link", { name: "查看并处理" })).toHaveLength(4);

    cleanup();
    fetchMock.mockImplementation((input) =>
      input === "/api/resources/overview"
        ? jsonResponse(payload)
        : Promise.reject(new TypeError("operations offline")),
    );
    renderOverview();

    expect(await screen.findByText("更多信息")).toBeVisible();
    expect(
      await screen.findByText("暂时读不到待处理请求；设备和服务仍可查看。"),
    ).toBeVisible();
  });

  it("刷新失败时把旧结果标为缓存，并允许再次刷新后恢复", async () => {
    const first = makeOverview();
    first.nodes.items = [
      {
        node_id: nodeA,
        display_name: "旧的节点记录",
        platform: "macos",
        state: "online",
        source: "coordinator_directory",
        evidence_at: evidenceAt,
        freshness: "fresh",
        service_count: 0,
      },
    ];
    const recovered = makeOverview();
    recovered.nodes.items = [
      {
        ...first.nodes.items[0],
        display_name: "刷新后恢复的节点",
        evidence_at: generatedAt,
      },
    ];
    let overviewCalls = 0;
    fetchMock.mockImplementation((input) => {
      if (input === "/api/operations") {
        return jsonResponse([]);
      }
      if (input === "/api/resources/overview") {
        overviewCalls += 1;
        if (overviewCalls === 1) {
          return jsonResponse(first);
        }
        if (overviewCalls === 2) {
          return Promise.reject(new TypeError("network unavailable"));
        }
        return jsonResponse(recovered);
      }
      return Promise.reject(
        new TypeError(`unexpected request: ${String(input)}`),
      );
    });
    const user = userEvent.setup();

    renderOverview();
    await screen.findByText("旧的节点记录");
    await user.click(screen.getByRole("button", { name: "刷新" }));

    expect(
      await screen.findByText("刷新失败，下面是上一次成功读取的缓存。"),
    ).toBeVisible();
    expect(
      screen.getByText("这些状态现在都不能视为最新，请稍后再次刷新。"),
    ).toBeVisible();

    await user.click(screen.getByRole("button", { name: "刷新" }));

    expect(await screen.findByText("刷新后恢复的节点")).toBeVisible();
    await waitFor(() => {
      expect(
        screen.queryByText("刷新失败，下面是上一次成功读取的缓存。"),
      ).not.toBeInTheDocument();
    });
  });

  it("初次读取失败时给出可键盘触发的恢复动作", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("offline"));
    const user = userEvent.setup();

    renderOverview();

    expect(
      await screen.findByRole("heading", { name: "现在读不到总览" }),
    ).toBeVisible();
    const retry = screen.getByRole("button", { name: "重新读取" });
    await user.tab();
    expect(retry).toHaveFocus();
  });

  it("在 320px 语义视图中保持原生键盘控件顺序", async () => {
    Object.defineProperty(window, "innerWidth", {
      configurable: true,
      value: 320,
    });
    const payload = makeOverview();
    payload.model = {
      ...payload.model,
      configured: false,
      status: "unconfigured",
      freshness: "not_applicable",
    };
    fetchMock.mockReturnValueOnce(jsonResponse(payload));
    const user = userEvent.setup();

    renderOverview();

    const refresh = await screen.findByRole("button", { name: "刷新" });
    await user.tab();
    expect(refresh).toHaveFocus();
    await user.click(screen.getByText("更多信息"));
    expect(
      screen.getByRole("link", {
        name: /需要聊天时再去设置中配置模型/,
      }),
    ).toBeVisible();
    expect(screen.getByRole("heading", { name: "总览" })).toBeVisible();
  });
});
