import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { router } from "./router";

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
    expect(screen.getByRole("heading", { name: "聊天" })).toBeVisible();
  });
});
