import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { identitySchema, shortFingerprint, type Identity } from "./api";
import { PeoplePage } from "./PeoplePage";
import { WelcomeGate } from "./WelcomeGate";

const LOCAL = `node_${"9".repeat(32)}`;
const OTHER = `node_${"2".repeat(32)}`;
const LEGACY = `node_${"8".repeat(32)}`;
const FRIEND = "sha256:abcdef0123456789";
const RECOVERY = "ABCD-EFGH-JKLM-NPQR";

function makeIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    initialized: false,
    local_display_name: "Windows 电脑",
    owner_fingerprint: null,
    has_owner_key: false,
    removed: false,
    roster_version: null,
    trust_list_version: null,
    bind: null,
    address_candidates: ["10.20.0.9"],
    devices: [],
    friends: [],
    legacy_peers: [],
    ...overrides,
  };
}

function owner(overrides: Partial<Identity> = {}): Identity {
  return makeIdentity({
    initialized: true,
    owner_fingerprint: "sha256:1234567890abcdef",
    has_owner_key: true,
    roster_version: 2,
    trust_list_version: 2,
    bind: { host: "10.20.0.9", port: 8787 },
    devices: [
      {
        node_id: LOCAL,
        display_name: "书房电脑",
        platform: "windows",
        host: "10.20.0.9",
        port: 8787,
        is_local: true,
        permissions: {
          allow_delegation: true,
          allow_model_borrowing: true,
          allow_proxy_repair_approval: true,
        },
      },
      {
        node_id: OTHER,
        display_name: "Mac mini",
        platform: "macos",
        host: "10.20.0.2",
        port: 8787,
        is_local: false,
        permissions: {
          allow_delegation: true,
          allow_model_borrowing: false,
          allow_proxy_repair_approval: true,
        },
      },
    ],
    friends: [
      {
        owner_fingerprint: FRIEND,
        display_name: "阿强",
        allow_model_borrowing: false,
        devices: [
          { node_id: OTHER, display_name: "阿强的电脑", platform: null },
        ],
        conflicting_devices: [`node_${"3".repeat(32)}`],
      },
    ],
    legacy_peers: [
      {
        node_id: LEGACY,
        display_name: "旧电脑",
        platform: null,
        host: "10.20.0.8",
        port: 8787,
        allow_proxy_repair_approval: false,
      },
    ],
    ...overrides,
  });
}

function inspection(kind: "owner" | "friend", extra: object = {}) {
  return {
    kind,
    owner_fingerprint: "sha256:feedfacecafebeef",
    inviter_host: "10.20.0.1",
    inviter_port: 8787,
    expires_at: "2026-10-30T08:00:00+00:00",
    expired: false,
    suggested_host: "10.20.0.7",
    suggested_port: 8787,
    bind_locked: false,
    ...extra,
  };
}

const server = setupServer();
const requests: { method: string; path: string; body: unknown }[] = [];

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  requests.length = 0;
  server.events.on("request:start", ({ request }) => {
    void request
      .clone()
      .text()
      .then((text) => {
        requests.push({
          method: request.method,
          path: new URL(request.url).pathname,
          body: text === "" ? null : (JSON.parse(text) as unknown),
        });
      });
  });
});
afterEach(() => {
  cleanup();
  server.resetHandlers();
  server.events.removeAllListeners();
});
afterAll(() => server.close());

function renderWith(element: React.ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{element}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("api", () => {
  it("拒绝多出的字段，指纹只显示前 8 位", () => {
    expect(() =>
      identitySchema.parse({ ...makeIdentity(), token: "tmn_x" }),
    ).toThrow();
    expect(shortFingerprint("sha256:1234567890")).toBe("12345678");
    expect(shortFingerprint(null)).toBe("");
  });
});

describe("WelcomeGate", () => {
  it("第一台电脑：显示恢复码、隐藏后输错可重输、输对后完成", async () => {
    let identity = makeIdentity();
    server.use(
      http.get("/api/identity", () => HttpResponse.json(identity)),
      http.post("/api/identity/setup", () =>
        HttpResponse.json({
          setup_id: "setup-1",
          recovery_code: RECOVERY,
          expires_at: "2026-10-29T08:10:00+00:00",
        }),
      ),
      http.post("/api/identity/setup/:id", async ({ request }) => {
        const body = (await request.json()) as { recovery_code: string };
        if (body.recovery_code.toUpperCase() !== RECOVERY) {
          return HttpResponse.json(
            {
              detail: {
                code: "recovery_code_mismatch",
                message: "输入的恢复码和刚才显示的不一致，请再核对一遍",
              },
            },
            { status: 400 },
          );
        }
        identity = owner();
        return HttpResponse.json(identity);
      }),
    );
    const user = userEvent.setup();
    renderWith(<WelcomeGate />);
    const welcome = await screen.findByRole("complementary", {
      name: "这台电脑还没有加入任何人的电脑",
    });
    await user.click(
      within(welcome).getByRole("button", { name: "这是我的第一台电脑" }),
    );
    const name = screen.getByLabelText("这台电脑叫什么");
    await user.clear(name);
    await user.type(name, "书房电脑");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(await screen.findByLabelText("恢复码")).toHaveTextContent(RECOVERY);
    expect(
      requests.find((item) => item.path === "/api/identity/setup")?.body,
    ).toEqual({ host: "10.20.0.9", port: 8787, display_name: "书房电脑" });
    const createUrl = vi.fn((_blob: Blob) => "blob:recovery");
    const revokeUrl = vi.fn();
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => undefined);
    Object.assign(URL, {
      createObjectURL: createUrl,
      revokeObjectURL: revokeUrl,
    });
    await user.click(screen.getByRole("button", { name: "存成文件" }));
    expect(await createUrl.mock.calls[0]?.[0].text()).toContain(RECOVERY);
    expect(click).toHaveBeenCalledOnce();
    expect(revokeUrl).toHaveBeenCalledWith("blob:recovery");
    click.mockRestore();
    // 勾选"已存好"之前不能完成；完成时直接用页面上的恢复码，不用再输一遍。
    const finish = screen.getByRole("button", { name: "完成" });
    expect(finish).toBeDisabled();
    await user.click(
      screen.getByRole("checkbox", { name: "我已经把恢复码存好了" }),
    );
    await user.click(finish);
    expect(await screen.findByText("已建立你的机主身份。")).toBeInTheDocument();
    expect(
      requests.find((item) => item.path.endsWith(":confirm"))?.body,
    ).toEqual({ recovery_code: RECOVERY });
    expect(document.body.textContent).not.toContain(RECOVERY);
    await user.click(screen.getByRole("button", { name: "好的" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByRole("complementary")).not.toBeInTheDocument();
    expect(window.localStorage.length).toBe(0);
  });

  it("加入我的电脑：核对码种类、过期，再用建议的地址加入", async () => {
    let kind: "owner" | "friend" = "friend";
    let expired = true;
    server.use(
      http.get("/api/identity", () => HttpResponse.json(makeIdentity())),
      http.post("/api/identity/codes:inspect", () =>
        HttpResponse.json(inspection(kind, { expired })),
      ),
      http.post("/api/identity/owner:join", () =>
        HttpResponse.json(owner({ has_owner_key: false })),
      ),
    );
    const user = userEvent.setup();
    renderWith(<WelcomeGate />);
    await user.click(
      await screen.findByRole("button", { name: "加入我的电脑" }),
    );
    const code = screen.getByLabelText("加入码（tmo1_ 开头）");
    await user.type(code, "tmo1_code");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("朋友的配对码");
    kind = "owner";
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("过期");
    expired = false;
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(await screen.findByText(/10.20.0.1:8787/)).toBeInTheDocument();
    expect(screen.getByLabelText("本机组网地址")).toHaveValue("10.20.0.7");
    await user.click(screen.getByRole("button", { name: "加入" }));
    expect(await screen.findByText("已加入我的电脑。")).toBeInTheDocument();
    expect(
      requests.find((item) => item.path === "/api/identity/owner:join")?.body,
    ).toEqual({ code: "tmo1_code", host: "10.20.0.7", port: 8787 });
  });

  it("我是朋友：先建身份再配对；配对失败时保留身份并说明", async () => {
    let pairing = 400;
    server.use(
      http.get("/api/identity", () => HttpResponse.json(makeIdentity())),
      http.post("/api/identity/codes:inspect", () =>
        HttpResponse.json(inspection("friend")),
      ),
      http.post("/api/identity/setup", () =>
        HttpResponse.json({
          setup_id: "s",
          recovery_code: RECOVERY,
          expires_at: "2026-10-29T08:10:00+00:00",
        }),
      ),
      http.post("/api/identity/setup/:id", () => HttpResponse.json(owner())),
      http.post("/api/identity/friends:join", () =>
        pairing === 200
          ? HttpResponse.json(owner())
          : HttpResponse.json(
              {
                detail: {
                  code: "identity_error",
                  message: "连不上邀请方的电脑",
                },
              },
              { status: 400 },
            ),
      ),
    );
    const user = userEvent.setup();
    renderWith(<WelcomeGate />);
    await user.click(
      await screen.findByRole("button", { name: "我是朋友，粘贴配对码" }),
    );
    await user.type(screen.getByLabelText("配对码（tmf1_ 开头）"), "tmf1_x");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(
      await screen.findByLabelText("你的名字（朋友那边看到的，可不填）"),
      "小林",
    );
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(
      await screen.findByRole("checkbox", { name: "我已经把恢复码存好了" }),
    );
    await user.click(screen.getByRole("button", { name: "完成" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "身份已经建好，但这次没配上对：连不上邀请方的电脑",
    );
    expect(
      requests.find((item) => item.path === "/api/identity/friends:join")?.body,
    ).toEqual({ code: "tmf1_x", display_name: "小林" });
    pairing = 200;
  });

  it("关掉恢复码弹窗会作废这次设置", async () => {
    const cancelled = vi.fn(() => new HttpResponse(null, { status: 204 }));
    server.use(
      http.get("/api/identity", () =>
        HttpResponse.json(
          makeIdentity({ bind: { host: "10.20.0.5", port: 8790 } }),
        ),
      ),
      http.post("/api/identity/setup", () =>
        HttpResponse.json({
          setup_id: "s1",
          recovery_code: RECOVERY,
          expires_at: "2026-10-29T08:10:00+00:00",
        }),
      ),
      http.delete("/api/identity/setup/:id", cancelled),
    );
    const user = userEvent.setup();
    renderWith(<WelcomeGate />);
    await user.click(
      await screen.findByRole("button", { name: /这是我的第一台电脑/ }),
    );
    expect(
      screen.getByText(/已按本机现有网关配置：10.20.0.5:8790/),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await screen.findByLabelText("恢复码");
    expect(
      requests.find((item) => item.path === "/api/identity/setup")?.body,
    ).toEqual({ display_name: "Windows 电脑" });
    await user.keyboard("{Escape}");
    await waitFor(() => expect(cancelled).toHaveBeenCalledOnce());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("PeoplePage", () => {
  it("列出我的电脑、朋友、旧式配对；生成加入码和配对码", async () => {
    server.use(
      http.get("/api/identity", () => HttpResponse.json(owner())),
      http.post("/api/identity/owner:invite", () =>
        HttpResponse.json({
          code: "tmo1_invite",
          expires_at: "2026-10-30T08:00:00+00:00",
        }),
      ),
      http.post("/api/identity/friends:invite", () =>
        HttpResponse.json({
          code: "tmf1_invite",
          expires_at: "2026-10-30T08:00:00+00:00",
        }),
      ),
    );
    const user = userEvent.setup();
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    renderWith(<PeoplePage />);
    expect(await screen.findByText("书房电脑")).toBeInTheDocument();
    expect(screen.getByText("这台电脑")).toBeInTheDocument();
    expect(screen.getByText("12345678")).toBeInTheDocument();
    expect(screen.getByText("阿强")).toBeInTheDocument();
    expect(screen.getByText(/编号冲突，暂不认/)).toBeInTheDocument();
    expect(screen.getByText("旧电脑")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "加一台我的电脑" }));
    expect(
      screen.getByLabelText("加入码", { selector: "p" }),
    ).toHaveTextContent("tmo1_invite");
    await user.click(screen.getByRole("button", { name: "复制" }));
    expect(writeText).toHaveBeenCalledWith("tmo1_invite");
    expect(
      await screen.findByRole("button", { name: "已复制" }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "关闭" }));
    await user.type(
      screen.getByLabelText("朋友那边看到的我的名字（可不填）"),
      "老张",
    );
    await user.click(screen.getByRole("button", { name: "邀请朋友" }));
    expect(
      screen.getByLabelText("配对码", { selector: "p" }),
    ).toHaveTextContent("tmf1_invite");
    expect(
      requests.find((item) => item.path === "/api/identity/friends:invite")
        ?.body,
    ).toEqual({ display_name: "老张" });
  });

  it("关开关、移除、改名先确认，并报告没推到的电脑", async () => {
    let identity = owner();
    server.use(
      http.get("/api/identity", () => HttpResponse.json(identity)),
      http.put("/api/identity/devices/:id/permissions", () => {
        identity = owner();
        identity.devices[1]!.permissions.allow_proxy_repair_approval = false;
        return HttpResponse.json(identity);
      }),
      http.delete("/api/identity/devices/:id", () =>
        HttpResponse.json({ unreached: ["Mac mini"] }),
      ),
      http.patch("/api/identity/friends/:id", () =>
        HttpResponse.json({ unreached: [] }),
      ),
      http.put("/api/identity/friends/:id/permissions", () =>
        HttpResponse.json({ unreached: [] }),
      ),
      http.delete("/api/identity/friends/:id", () =>
        HttpResponse.json(
          { detail: { code: "identity_error", message: "朋友不存在" } },
          { status: 400 },
        ),
      ),
      http.put("/api/identity/legacy-peers/:id/proxy-approval", () =>
        HttpResponse.json(owner()),
      ),
    );
    const user = userEvent.setup();
    renderWith(<PeoplePage />);
    const proxy = await screen.findByRole("checkbox", {
      name: "允许替我批准修复",
      checked: true,
    });
    expect(
      screen.getAllByRole("checkbox", { name: "允许借模型" })[0],
    ).toBeDisabled();
    await user.click(proxy);
    const confirm = screen.getByRole("dialog");
    expect(confirm).toHaveTextContent("不能再打开");
    await user.click(within(confirm).getByRole("button", { name: "关掉" }));
    expect(await screen.findByRole("status")).toHaveTextContent("已完成。");
    expect(
      requests.find(
        (item) => item.method === "PUT" && item.path.includes("/devices/"),
      )?.body,
    ).toEqual({ allow_proxy_repair_approval: false });

    await user.click(screen.getAllByRole("button", { name: "移除" })[0]!);
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "移除" }),
    );
    expect(await screen.findByRole("status")).toHaveTextContent(
      "这次没推到 Mac mini",
    );

    await user.click(screen.getByRole("button", { name: "改名" }));
    const name = screen.getByLabelText("新名字");
    await user.clear(name);
    await user.type(name, "强哥");
    await user.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() =>
      expect(requests.find((item) => item.method === "PATCH")?.body).toEqual({
        display_name: "强哥",
      }),
    );

    await user.click(screen.getByRole("checkbox", { name: "允许借我的模型" }));
    await waitFor(() =>
      expect(
        requests.find(
          (item) => item.method === "PUT" && item.path.includes("/friends/"),
        )?.body,
      ).toEqual({ allow_model_borrowing: true }),
    );

    await user.click(screen.getAllByRole("button", { name: "移除" })[1]!);
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "移除" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("朋友不存在");

    await user.click(
      within(screen.getByRole("article", { name: "旧式配对" })).getByRole(
        "checkbox",
        { name: "允许替我批准修复" },
      ),
    );
    expect(await screen.findByRole("status")).toHaveTextContent(
      "重启 TunnelMinion 后生效",
    );
  });

  it("改名单时先说明正在通知其他电脑，等对方超时期间不只是按钮变灰", async () => {
    const answered: Array<() => void> = [];
    server.use(
      http.get("/api/identity", () => HttpResponse.json(owner())),
      http.delete(
        "/api/identity/devices/:id",
        () =>
          new Promise<Response>((resolve) =>
            answered.push(() =>
              resolve(HttpResponse.json({ unreached: ["Mac mini"] })),
            ),
          ),
      ),
      http.patch(
        "/api/identity/friends/:id",
        () =>
          new Promise<Response>((resolve) =>
            answered.push(() => resolve(HttpResponse.json({ unreached: [] }))),
          ),
      ),
    );
    const user = userEvent.setup();
    renderWith(<PeoplePage />);
    await user.click(
      (await screen.findAllByRole("button", { name: "移除" }))[0]!,
    );
    const dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "移除" }));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "正在保存并通知其他电脑",
    );
    expect(
      within(dialog).getByRole("button", { name: "正在通知其他电脑……" }),
    ).toBeDisabled();
    await waitFor(() => expect(answered).toHaveLength(1));
    answered[0]!();
    expect(await screen.findByRole("status")).toHaveTextContent(
      "这次没推到 Mac mini，下次接触时会同步",
    );

    await user.click(screen.getByRole("button", { name: "改名" }));
    await user.type(screen.getByLabelText("新名字"), "2");
    await user.click(screen.getByRole("button", { name: "保存" }));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "正在保存并通知其他电脑",
    );
    await waitFor(() => expect(answered).toHaveLength(2));
    answered[1]!();
    expect(await screen.findByRole("status")).toHaveTextContent("已改名。");
  });

  it("没有机主密钥时邀请按钮不可用，并说明去哪台电脑操作；被移出时提示", async () => {
    server.use(
      http.get("/api/identity", () =>
        HttpResponse.json(
          owner({ has_owner_key: false, removed: true, legacy_peers: [] }),
        ),
      ),
    );
    renderWith(<PeoplePage />);
    expect(
      await screen.findByRole("button", { name: "加一台我的电脑" }),
    ).toBeDisabled();
    expect(
      screen.getByText("去持有机主密钥的那台电脑上操作。"),
    ).toBeInTheDocument();
    expect(screen.getByText(/已经被移出/)).toBeInTheDocument();
    expect(screen.queryByText("旧式配对")).not.toBeInTheDocument();
  });

  it("没有身份时提供开始设置；已有身份时可以粘贴朋友的配对码", async () => {
    server.use(
      http.get("/api/identity", () => HttpResponse.json(makeIdentity())),
    );
    const user = userEvent.setup();
    renderWith(<PeoplePage />);
    await user.click(await screen.findByRole("button", { name: "开始设置" }));
    expect(
      screen.getByRole("button", { name: /我是朋友/ }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "以后再说" }));
    cleanup();

    server.use(
      http.get("/api/identity", () => HttpResponse.json(owner())),
      http.post("/api/identity/codes:inspect", () =>
        HttpResponse.json(inspection("friend")),
      ),
      http.post("/api/identity/friends:join", () => HttpResponse.json(owner())),
    );
    renderWith(<PeoplePage />);
    await user.click(
      await screen.findByRole("button", { name: "粘贴朋友的配对码" }),
    );
    await user.type(screen.getByLabelText("配对码（tmf1_ 开头）"), "tmf1_y");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(await screen.findByRole("button", { name: "配对" }));
    expect(await screen.findByText("已经和朋友配好对了。")).toBeInTheDocument();
  });

  it("读不到时显示原因并可以重试", async () => {
    server.use(
      http.get("/api/identity", () =>
        HttpResponse.json(
          {
            detail: {
              code: "secret_store_unavailable",
              message: "系统钥匙串暂时不可用",
            },
          },
          { status: 500 },
        ),
      ),
    );
    renderWith(<PeoplePage />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "系统钥匙串暂时不可用",
    );
    expect(
      screen.getByRole("button", { name: "重新读取" }),
    ).toBeInTheDocument();
  });
});

// "以后再说"在整个页面期间有效，所以放在最后。
describe("WelcomeGate 以后再说", () => {
  it("已有身份时不显示；以后再说后这次打开期间不再显示，也不写浏览器存储", async () => {
    server.use(http.get("/api/identity", () => HttpResponse.json(owner())));
    renderWith(<WelcomeGate />);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(screen.queryByRole("complementary")).not.toBeInTheDocument();
    cleanup();
    server.use(
      http.get("/api/identity", () => HttpResponse.json(makeIdentity())),
    );
    const user = userEvent.setup();
    renderWith(<WelcomeGate />);
    await user.click(await screen.findByRole("button", { name: "以后再说" }));
    expect(screen.queryByRole("complementary")).not.toBeInTheDocument();
    cleanup();
    renderWith(<WelcomeGate />);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(screen.queryByRole("complementary")).not.toBeInTheDocument();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });
});
