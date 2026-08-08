import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PropsWithChildren } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ModelConfiguration } from "./api";
import { SettingsPage } from "./SettingsPage";

function makeConfiguration(
  overrides: Partial<ModelConfiguration> = {},
): ModelConfiguration {
  return {
    endpoint: "http://127.0.0.1:8080/v1",
    model: "qwen-local",
    timeout_seconds: 30,
    api_key_configured: false,
    status: "available",
    error_code: null,
    error_message: null,
    ...overrides,
  };
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderSettings() {
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
  return render(<SettingsPage />, { wrapper: Wrapper });
}

describe("SettingsPage", () => {
  let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

  beforeEach(() => {
    fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("覆盖 loading 与未配置状态，秘密输入永远从空值开始", async () => {
    let resolveRequest: ((response: Response) => void) | undefined;
    fetchMock.mockReturnValueOnce(
      new Promise<Response>((resolve) => {
        resolveRequest = resolve;
      }),
    );

    renderSettings();
    expect(screen.getByText("正在读取脱敏模型配置……")).toBeVisible();
    resolveRequest?.(
      jsonResponse(
        makeConfiguration({
          endpoint: null,
          model: null,
          timeout_seconds: null,
          status: "unconfigured",
        }),
      ),
    );

    expect(await screen.findByText("尚未配置")).toBeVisible();
    expect(screen.getByText(/聊天的新 AI run 暂不可用/)).toBeVisible();
    expect(screen.getByLabelText("新 API 密钥（可选）")).toHaveValue("");
  });

  it("拒绝包含秘密字段的成功响应，且不把秘密写入页面", async () => {
    const leakedSecret = "server-must-not-return-this-secret";
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ ...makeConfiguration(), api_key: leakedSecret }),
    );

    renderSettings();

    expect(
      await screen.findByRole("heading", { name: "现在读不到模型配置" }),
    ).toBeVisible();
    expect(screen.getByText(/不符合脱敏契约/)).toBeVisible();
    expect(screen.queryByText(leakedSecret)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(leakedSecret);
  });

  it("把恶意 endpoint、模型名和错误说明都按文本呈现", async () => {
    const maliciousEndpoint = '<img src=x onerror="alert(1)">';
    const maliciousModel = "<script>alert('model')</script>";
    const maliciousError = '<a href="https://evil.test">点我</a>';
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        makeConfiguration({
          endpoint: maliciousEndpoint,
          model: maliciousModel,
          status: "unavailable",
          error_code: "invalid_response",
          error_message: maliciousError,
        }),
      ),
    );

    const { container } = renderSettings();

    expect(await screen.findByText(maliciousEndpoint)).toBeVisible();
    expect(screen.getByText(maliciousModel)).toBeVisible();
    expect(screen.getByText(maliciousError)).toBeVisible();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("a[href='https://evil.test']")).toBeNull();
  });

  it("确认后只保存一次，使用共享同源头且不在确认或响应中回显密钥", async () => {
    let current = makeConfiguration();
    let capturedBody: Record<string, unknown> | undefined;
    let capturedHeaders: Headers | undefined;
    fetchMock.mockImplementation(async (_input, init) => {
      if (init?.method === "PUT") {
        capturedBody = JSON.parse(String(init.body)) as Record<string, unknown>;
        capturedHeaders = new Headers(init.headers);
        current = makeConfiguration({
          endpoint: String(capturedBody.endpoint),
          model: String(capturedBody.model),
          timeout_seconds: Number(capturedBody.timeout_seconds),
          api_key_configured: true,
        });
        return jsonResponse(current);
      }
      return jsonResponse(current);
    });
    const user = userEvent.setup();
    const secret = "typed-only-once-secret";

    renderSettings();
    await screen.findByText("模型可用");
    const endpoint = screen.getByLabelText("OpenAI-compatible endpoint");
    await user.clear(endpoint);
    await user.type(endpoint, "http://127.0.0.1:9090/v1");
    const model = screen.getByLabelText("模型名称");
    await user.clear(model);
    await user.type(model, "new-local-model");
    await user.type(screen.getByLabelText("新 API 密钥（可选）"), secret);
    await user.click(screen.getByRole("button", { name: "检查并确认保存" }));

    const cancel = screen.getByRole("button", { name: "取消" });
    await waitFor(() => expect(cancel).toHaveFocus());
    expect(screen.queryByText(secret)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(secret);
    await user.tab();
    expect(screen.getByRole("button", { name: "确认保存一次" })).toHaveFocus();
    await user.keyboard("{Enter}");

    expect(
      await screen.findByText("服务端已验证、保存并重新返回脱敏模型配置。"),
    ).toBeVisible();
    expect(screen.getByText("已安全保存")).toBeVisible();
    expect(screen.getByLabelText("新 API 密钥（可选）")).toHaveValue("");
    expect(capturedBody).toEqual({
      endpoint: "http://127.0.0.1:9090/v1",
      model: "new-local-model",
      timeout_seconds: 30,
      api_key: secret,
    });
    expect(capturedHeaders?.get("X-TunnelMinion-Request")).toBe("same-origin");
    expect(
      fetchMock.mock.calls.filter(([, init]) => init?.method === "PUT"),
    ).toHaveLength(1);
    expect(document.body.textContent).not.toContain(secret);
  });

  it("保存结果未知时只重新读取，不自动重放并立即清空秘密输入", async () => {
    const current = makeConfiguration();
    fetchMock.mockImplementation((_input, init) => {
      if (init?.method === "PUT") {
        return Promise.reject(new TypeError("response lost"));
      }
      return Promise.resolve(jsonResponse(current));
    });
    const user = userEvent.setup();

    renderSettings();
    await screen.findByText("模型可用");
    await user.type(
      screen.getByLabelText("新 API 密钥（可选）"),
      "short-lived-secret",
    );
    await user.click(screen.getByRole("button", { name: "检查并确认保存" }));
    await user.click(screen.getByRole("button", { name: "确认保存一次" }));

    expect(
      await screen.findByText(/保存请求的结果无法确认.*没有自动重放写请求/),
    ).toBeVisible();
    expect(screen.getByLabelText("新 API 密钥（可选）")).toHaveValue("");
    expect(
      fetchMock.mock.calls.filter(([, init]) => init?.method === "PUT"),
    ).toHaveLength(1);
  });

  it("清除只在收到确定 204 后报告成功，并把焦点移到可用刷新入口", async () => {
    let current = makeConfiguration({ api_key_configured: true });
    fetchMock.mockImplementation((_input, init) => {
      if (init?.method === "DELETE") {
        current = makeConfiguration({
          endpoint: null,
          model: null,
          timeout_seconds: null,
          api_key_configured: false,
          status: "unconfigured",
        });
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      return Promise.resolve(jsonResponse(current));
    });
    const user = userEvent.setup();

    renderSettings();
    await screen.findByText("已安全保存");
    await user.click(
      screen.getByRole("button", { name: "清除模型配置与密钥" }),
    );
    expect(screen.getByRole("button", { name: "取消" })).toHaveFocus();
    await user.click(screen.getByRole("button", { name: "确认清除一次" }));

    expect(
      await screen.findByText(
        "服务端已用 204 明确确认：模型配置和已保存密钥均已清除。",
      ),
    ).toBeVisible();
    expect(screen.getByText("尚未配置")).toBeVisible();
    expect(
      fetchMock.mock.calls.filter(([, init]) => init?.method === "DELETE"),
    ).toHaveLength(1);
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "重新读取状态" }),
      ).toHaveFocus(),
    );
  });

  it("keyring 部分失败后即使重读未配置也不宣称密钥已清除", async () => {
    let current = makeConfiguration({ api_key_configured: true });
    fetchMock.mockImplementation((_input, init) => {
      if (init?.method === "DELETE") {
        current = makeConfiguration({
          endpoint: null,
          model: null,
          timeout_seconds: null,
          api_key_configured: false,
          status: "unconfigured",
        });
        return Promise.resolve(
          jsonResponse(
            {
              detail: {
                code: "secret_store_failure",
                message: "操作系统秘密存储删除失败",
              },
            },
            500,
          ),
        );
      }
      return Promise.resolve(jsonResponse(current));
    });
    const user = userEvent.setup();

    renderSettings();
    await screen.findByText("已安全保存");
    await user.click(
      screen.getByRole("button", { name: "清除模型配置与密钥" }),
    );
    await user.click(screen.getByRole("button", { name: "确认清除一次" }));

    expect(
      await screen.findByText(/无法确认操作系统秘密存储中的密钥是否已清除/),
    ).toBeVisible();
    expect(screen.getByText("尚未配置")).toBeVisible();
    expect(
      screen.queryByText(/204 明确确认.*均已清除/),
    ).not.toBeInTheDocument();
    const retry = screen.getByRole("button", {
      name: "重试清除配置与密钥",
    });
    expect(retry).toBeEnabled();
    expect(retry).toHaveFocus();
    expect(
      screen.getByRole("button", { name: "检查并确认保存" }),
    ).toBeDisabled();
    expect(
      fetchMock.mock.calls.filter(([, init]) => init?.method === "DELETE"),
    ).toHaveLength(1);
  });
});
