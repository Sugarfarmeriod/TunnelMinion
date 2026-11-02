import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PropsWithChildren } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { UpdatePanel } from "./UpdatePanel";
import type { UpdateView } from "./updateApi";

function makeView(overrides: Partial<UpdateView> = {}): UpdateView {
  return {
    supported: true,
    unsupported_reason: null,
    current: {
      package_id: "pkg-old",
      source_revision: "1111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      release_tag: null,
    },
    latest: {
      tag: "build-12",
      source_revision: "2222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      published_at: "2026-11-02T08:00:00Z",
      size: 1000,
    },
    availability: "update_available",
    checked_at: "2026-11-02T08:01:00Z",
    check_error: null,
    job: {
      phase: "idle",
      release_tag: null,
      downloaded_bytes: 0,
      total_bytes: 0,
      error_code: null,
    },
    last_result: null,
    ...overrides,
  };
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderPanel() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  function Wrapper({ children }: PropsWithChildren) {
    return (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
  }
  return render(<UpdatePanel />, { wrapper: Wrapper });
}

describe("UpdatePanel", () => {
  let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

  beforeEach(() => {
    fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("显示当前和最新版本，确认后带上版本号提交更新", async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(jsonResponse(makeView()));
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        makeView({
          job: {
            phase: "restarting",
            release_tag: "build-12",
            downloaded_bytes: 1000,
            total_bytes: 1000,
            error_code: null,
          },
        }),
        202,
      ),
    );
    renderPanel();
    expect(await screen.findByText("提交 1111111")).toBeInTheDocument();
    expect(screen.getByText("build-12（提交 2222222）")).toBeInTheDocument();
    expect(screen.getByText("有新版本")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "更新到 build-12" }));
    const dialog = screen.getByRole("dialog", { name: "确认更新" });
    expect(dialog).toHaveTextContent("从 提交 1111111 换到 build-12");
    await user.click(screen.getByRole("button", { name: "确认更新" }));

    expect(
      await screen.findByText(/正在停止旧版、启动新版/),
    ).toBeInTheDocument();
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe("/api/update/apply");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ release_tag: "build-12" });
    expect(new Headers(init?.headers).get("X-TunnelMinion-Request")).toBe(
      "same-origin",
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("取消确认框不会发起更新", async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(jsonResponse(makeView()));
    renderPanel();
    await user.click(
      await screen.findByRole("button", { name: "更新到 build-12" }),
    );
    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("第一次打开且还没检查过时自动检查一次", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        makeView({ checked_at: null, latest: null, availability: null }),
      ),
    );
    fetchMock.mockResolvedValueOnce(
      jsonResponse(makeView({ availability: "up_to_date" })),
    );
    renderPanel();
    expect(await screen.findByText("已是最新")).toBeInTheDocument();
    expect(fetchMock.mock.calls[1][0]).toBe("/api/update/check");
    expect(
      screen.queryByRole("button", { name: /更新到/ }),
    ).not.toBeInTheDocument();
  });

  it("不支持更新时说明原因且不显示按钮", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        makeView({
          supported: false,
          unsupported_reason: "source_run",
          latest: null,
          availability: null,
          checked_at: null,
        }),
      ),
    );
    renderPanel();
    expect(
      await screen.findByText("从源码运行，不支持一键更新，请用 git pull。"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("显示下载进度、校验失败和上一次结果", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        makeView({
          job: {
            phase: "downloading",
            release_tag: "build-12",
            downloaded_bytes: 250,
            total_bytes: 1000,
            error_code: null,
          },
        }),
      ),
    );
    fetchMock.mockResolvedValue(
      jsonResponse(
        makeView({
          job: {
            phase: "failed",
            release_tag: "build-12",
            downloaded_bytes: 1000,
            total_bytes: 1000,
            error_code: "checksum_mismatch",
          },
          last_result: {
            outcome: "rolled_back",
            from_package_id: "pkg-old",
            to_package_id: "pkg-new",
            release_tag: "build-11",
            error_code: "new_version_unhealthy",
            finished_at: "2026-11-01T08:00:00Z",
          },
        }),
      ),
    );
    renderPanel();
    expect(await screen.findByText(/正在下载 25%/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "检查更新" })).toBeDisabled();
    expect(
      await screen.findByText(
        "下载的文件和发布清单对不上，已删掉，没有换包。",
        {},
        { timeout: 4000 },
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("上次更新：新版本没能启动，已自动退回原来的版本。"),
    ).toBeInTheDocument();
  });

  it("新版本起来后显示结果并提供刷新", async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(jsonResponse(makeView()));
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        makeView({
          job: {
            phase: "restarting",
            release_tag: "build-12",
            downloaded_bytes: 1000,
            total_bytes: 1000,
            error_code: null,
          },
        }),
        202,
      ),
    );
    fetchMock.mockRejectedValueOnce(new TypeError("connection refused"));
    fetchMock.mockResolvedValue(
      jsonResponse(
        makeView({
          current: {
            package_id: "pkg-new",
            source_revision: "2222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            release_tag: "build-12",
          },
          availability: "up_to_date",
          last_result: {
            outcome: "updated",
            from_package_id: "pkg-old",
            to_package_id: "pkg-new",
            release_tag: "build-12",
            error_code: null,
            finished_at: "2026-11-02T08:05:00Z",
          },
        }),
      ),
    );
    renderPanel();
    await user.click(
      await screen.findByRole("button", { name: "更新到 build-12" }),
    );
    await user.click(screen.getByRole("button", { name: "确认更新" }));
    expect(
      await screen.findByText(
        /上次更新：已更新到 build-12。/,
        {},
        { timeout: 6000 },
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "刷新页面" }),
    ).toBeInTheDocument();
  }, 10000);

  it("检查失败和请求被拒时给出可读说明", async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(
      jsonResponse(makeView({ check_error: "github_rate_limited" })),
    );
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          detail: {
            code: "release_changed",
            message: "最新版本刚刚变了，请重新检查后再确认",
          },
        },
        409,
      ),
    );
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        { detail: { code: "x", message: "现在不能更新，请稍后重试" } },
        409,
      ),
    );
    renderPanel();
    expect(
      await screen.findByText("GitHub 暂时限制了查询次数，过一会儿再试。"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "更新到 build-12" }));
    await user.click(screen.getByRole("button", { name: "确认更新" }));
    expect(
      await screen.findByText("最新版本刚刚变了，请重新检查后再确认"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "取消" }));
    await user.click(screen.getByRole("button", { name: "检查更新" }));
    await waitFor(() =>
      expect(screen.getByText("现在不能更新，请稍后重试")).toBeInTheDocument(),
    );
  });

  it("读不到版本信息时提示", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("down"));
    renderPanel();
    expect(
      await screen.findByText(
        "读不到版本信息，请确认本机 TunnelMinion 仍在运行。",
      ),
    ).toBeInTheDocument();
  });
});
