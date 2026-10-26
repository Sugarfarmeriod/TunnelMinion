import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IncidentsPage } from "./IncidentsPage";
import { makeOverview } from "./testFixtures";
const generatedAt = "2026-08-08T09:00:00+08:00";
const evidenceAt = "2026-08-08T08:59:00+08:00";
const nodeA = `node_${"1".repeat(32)}`;
const nodeB = `node_${"2".repeat(32)}`;
const serviceA = `service_${"3".repeat(32)}`;
function jsonResponse(value: unknown) {
  return Promise.resolve(
    new Response(JSON.stringify(value), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
}
function renderOverview(entry = "/app/incidents") {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <IncidentsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
describe("最近事件", () => {
  let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
  beforeEach(() => {
    fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
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
      if (input === "/api/ui/overview") {
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
    ).toHaveAttribute("href", `/app/map?thread=${threadId}`);
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
      if (input === "/api/ui/overview") {
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
      `/app/incidents?incident_id=${incidentId}#overview-incidents`,
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
});
