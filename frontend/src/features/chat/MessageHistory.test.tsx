import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
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

it("回答带现成步骤时在正文下面显示，命令可以复制；旧消息没有步骤也照常显示", async () => {
  const writeText = vi.fn(() => Promise.resolve());
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText },
  });
  render(
    <MessageHistory
      compact
      detail={{
        thread: makeThread(),
        messages: [
          makeMessage("assistant", "旧回答"),
          {
            ...makeMessage("assistant", "这次修不了"),
            manual_steps: [
              { text: "打开终端，进到项目目录", command: null },
              { text: "重新运行", command: "python app.py" },
            ],
          },
        ],
      }}
    />,
  );
  expect(screen.getByText("旧回答")).toBeVisible();
  const steps = screen.getByRole("region", { name: "可以照着做" });
  expect(steps.closest("article")).toHaveTextContent("这次修不了");
  expect(screen.getAllByRole("region", { name: "可以照着做" })).toHaveLength(1);
  expect(screen.getByText("打开终端，进到项目目录")).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "复制" }));
  expect(writeText).toHaveBeenCalledWith("python app.py");
  expect(await screen.findByRole("button", { name: "已复制" })).toBeVisible();
});
