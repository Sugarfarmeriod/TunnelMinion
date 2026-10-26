import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it } from "vitest";
import { MessageHistory } from "./MessageHistory";
import { makeMessage, makeThread } from "./testFixtures";

afterEach(cleanup);

it("回答保留推断标签，证据默认折叠，用户原文和上下文直接显示", async () => {
  const content = "模型的推断\n\n证据索引（程序生成）：\n检查编号 123";
  render(
    <MessageHistory
      compact
      contextLabel="这台电脑 · 相册（Docker）"
      detail={{
        thread: makeThread(),
        messages: [
          makeMessage("user", "相册怎么打不开？"),
          { ...makeMessage("assistant", content), answer_basis: "inferred" },
        ],
      }}
    />,
  );
  expect(screen.getByText("关于：这台电脑 · 相册（Docker）")).toBeVisible();
  expect(screen.getByText("推断 · 尚未逐条核对")).toBeVisible();
  expect(screen.getByText("模型的推断")).toBeVisible();
  expect(screen.getByText("检查编号 123")).not.toBeVisible();
  await userEvent.click(screen.getByText("查看证据编号"));
  expect(screen.getByText("检查编号 123")).toBeVisible();
});

it("旧的未核对回答按需查看，恶意 HTML 与用户的证据标记只作为原文", async () => {
  const unsafe = "<script>alert('x')</script>";
  const question = "问题\n\n证据索引（程序生成）：\n仍是问题";
  const { container } = render(
    <MessageHistory
      compact
      detail={{
        thread: makeThread(),
        messages: [
          makeMessage("user", question),
          { ...makeMessage("assistant", unsafe), answer_checked: false },
        ],
      }}
    />,
  );
  expect(screen.getByText(/仍是问题/)).toBeVisible();
  expect(container.querySelector("script")).toBeNull();
  expect(screen.getByText(unsafe)).not.toBeVisible();
  await userEvent.click(screen.getByText("查看原始说明（未核对）"));
  expect(screen.getByText(unsafe)).toBeVisible();
});
