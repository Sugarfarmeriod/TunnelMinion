import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";

import { router } from "./router";

afterEach(cleanup);

describe("产品外壳", () => {
  it("暴露大白话导航与本机隐私提示", async () => {
    const memoryRouter = createMemoryRouter(router.routes, {
      initialEntries: ["/app/chat"],
    });
    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={memoryRouter} />
      </QueryClientProvider>,
    );

    expect(
      await screen.findByRole("heading", { name: "TunnelMinion" }),
    ).toBeVisible();
    expect(screen.getByRole("navigation", { name: "主要导航" })).toBeVisible();
    expect(screen.getByText("只连接这台电脑上的 TunnelMinion")).toBeVisible();
    expect(screen.getByRole("heading", { name: "工作台" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "一起处理" })).toBeVisible();
    expect(
      screen
        .getByRole("navigation", { name: "主要导航" })
        .querySelectorAll("a"),
    ).toHaveLength(4);
    expect(screen.getByRole("link", { name: "服务地图" })).toHaveAttribute(
      "href",
      "/app/map",
    );
    expect(screen.getByRole("link", { name: "工作台" })).toHaveAttribute(
      "href",
      "/app/overview",
    );
  });

  it("/app 默认进入服务地图", async () => {
    const memoryRouter = createMemoryRouter(router.routes, {
      initialEntries: ["/app"],
    });
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={memoryRouter} />
      </QueryClientProvider>,
    );
    expect(
      await screen.findByRole("heading", { name: "服务地图" }),
    ).toBeVisible();
    expect(memoryRouter.state.location.pathname).toBe("/app/map");
    expect(
      screen.queryByRole("heading", { name: "工作台" }),
    ).not.toBeInTheDocument();
    queryClient.clear();
  });
});
