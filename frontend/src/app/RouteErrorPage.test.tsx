import { render, screen } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { RouteErrorPage } from "./RouteErrorPage";

function BrokenPage(): never {
  throw new Error("private backend detail must not render");
}

describe("RouteErrorPage", () => {
  it("隐藏异常正文并提供安全恢复入口", async () => {
    const router = createMemoryRouter(
      [
        {
          path: "/app/broken",
          element: <BrokenPage />,
          errorElement: <RouteErrorPage />,
        },
      ],
      { initialEntries: ["/app/broken"] },
    );

    render(<RouterProvider router={router} />);

    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(
      screen.queryByText(/private backend detail/i),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "返回总览" })).toHaveAttribute(
      "href",
      "/app/overview",
    );
  });
});
