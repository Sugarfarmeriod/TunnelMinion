import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it } from "vitest";
import { RuntimeOverview } from "./OverviewCards";
import { makeOverview } from "./testFixtures";

afterEach(cleanup);

it("运行基础保留四张状态卡，数据来源和完整连接信息按需展开", async () => {
  const data = makeOverview();
  data.nodes.items = [
    {
      node_id: `node_${"1".repeat(32)}`,
      display_name: "这台电脑",
      platform: "windows",
      state: "local",
      source: "local_observation",
      evidence_at: data.generated_at,
      freshness: "fresh",
      service_count: 1,
    },
  ];
  data.services.items = [
    {
      service_id: `service_${"2".repeat(32)}`,
      node_id: data.nodes.items[0]!.node_id,
      display_name: "相册",
      protocol: "tcp",
      port: 8787,
      access_address: "tcp://127.0.0.1:8787",
      accessibility: "loopback",
      lifecycle: "active",
      state: "available",
      source: "local_observation",
      evidence_at: data.generated_at,
      freshness: "fresh",
    },
  ];
  render(
    <MemoryRouter>
      <RuntimeOverview data={data} />
    </MemoryRouter>,
  );
  for (const name of ["本机运行", "模型", "Coordinator", "跨节点网络路径"])
    expect(screen.getByRole("heading", { name })).toBeVisible();
  expect(screen.getByText(/tcp:\/\/127.0.0.1:8787/)).not.toBeVisible();
  await userEvent.click(screen.getByText("数据来源与高级连接信息"));
  expect(screen.getByText(/tcp:\/\/127.0.0.1:8787/)).toBeVisible();
  expect(screen.getByRole("list", { name: "设备记录来源" })).toHaveTextContent(
    "这台电脑",
  );
});
