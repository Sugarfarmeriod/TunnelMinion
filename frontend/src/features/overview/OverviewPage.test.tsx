import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PropsWithChildren } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ResourceOverview } from "../../api/schemas/overview";

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
  };
}

function jsonResponse(payload: ResourceOverview): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

function renderOverview() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: Number.POSITIVE_INFINITY },
    },
  });
  function Wrapper({ children }: PropsWithChildren) {
    return (
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/app/overview"]}>
          {children}
        </MemoryRouter>
      </QueryClientProvider>
    );
  }
  return render(<OverviewPage />, { wrapper: Wrapper });
}

describe("OverviewPage", () => {
  let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

  beforeEach(() => {
    fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("先显示 loading，再按独立领域展示服务端强类型状态", async () => {
    fetchMock.mockReturnValueOnce(jsonResponse(makeOverview()));

    renderOverview();

    expect(screen.getByRole("status")).toHaveTextContent("正在读取本机");
    expect(
      await screen.findByRole("heading", { name: "本机运行" }),
    ).toBeVisible();
    expect(screen.getByText("本机接口已准备好")).toBeVisible();
    expect(screen.getByText("模型现在可以使用")).toBeVisible();
    expect(screen.getByText("Coordinator 目录已同步")).toBeVisible();
    expect(screen.getByText("当前选择了直连路径")).toBeVisible();
    expect(screen.getByText("还没有已知节点")).toBeVisible();
    expect(screen.getByText("还没有已知服务")).toBeVisible();
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

    renderOverview();

    expect(await screen.findByText("还没有配置模型")).toBeVisible();
    expect(
      screen.getByText("未配置 Coordinator，当前按仅本机模式工作"),
    ).toBeVisible();
    expect(screen.getByText("peer 路径当前不可达")).toBeVisible();
    expect(screen.getByText("firewall_log_unavailable")).toBeVisible();
    expect(screen.getByText("directory_cache_stale")).toBeVisible();
    expect(screen.getByText("service_inventory_unavailable")).toBeVisible();
    expect(screen.getByText("当前没有服务端确认的服务记录。")).toBeVisible();
    expect(screen.getByText("当前离线（证据陈旧）")).toBeVisible();
    expect(screen.getByText("状态未知")).toBeVisible();
    expect(
      screen.getByText(/防火墙日志只是可选诊断，不是运行条件/),
    ).toBeVisible();
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
        accessibility: "network",
        lifecycle: "active",
        state: "available",
        source: "coordinator_directory",
        evidence_at: evidenceAt,
        freshness: "fresh",
      },
    ];
    fetchMock.mockReturnValueOnce(jsonResponse(payload));

    const { container } = renderOverview();

    expect(await screen.findByText(maliciousNode)).toBeVisible();
    expect(screen.getByText(maliciousService)).toBeVisible();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
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
    fetchMock
      .mockReturnValueOnce(jsonResponse(first))
      .mockRejectedValueOnce(new TypeError("network unavailable"))
      .mockReturnValueOnce(jsonResponse(recovered));
    const user = userEvent.setup();

    renderOverview();
    await screen.findByText("旧的节点记录");
    await user.click(screen.getByRole("button", { name: "刷新证据" }));

    expect(
      await screen.findByText("刷新失败，下面是上一次成功读取的缓存。"),
    ).toBeVisible();
    expect(
      screen.getByText("这些状态现在都不能视为最新，请稍后再次刷新。"),
    ).toBeVisible();

    await user.click(screen.getByRole("button", { name: "刷新证据" }));

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

    const refresh = await screen.findByRole("button", { name: "刷新证据" });
    const settingsLink = screen.getByRole("link", {
      name: /需要聊天时再去设置中配置模型/,
    });
    await user.tab();
    expect(refresh).toHaveFocus();
    await user.tab();
    expect(settingsLink).toHaveFocus();
    expect(screen.getByRole("heading", { name: "已知节点" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "已知服务" })).toBeVisible();
  });
});
