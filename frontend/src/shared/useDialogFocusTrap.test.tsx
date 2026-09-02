import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useRef, useState } from "react";
import { afterEach, describe, expect, it } from "vitest";

import { useDialogFocusTrap } from "./useDialogFocusTrap";

afterEach(() => cleanup());

function FocusTrapFixture({
  controls = true,
  extraControl = false,
  busy = false,
}: {
  controls?: boolean;
  extraControl?: boolean;
  busy?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const fallbackRef = useRef<HTMLHeadingElement>(null);

  return (
    <>
      <button ref={triggerRef} onClick={() => setOpen(true)} type="button">
        打开
      </button>
      <input aria-label="背景输入框" />
      <h1 ref={fallbackRef} tabIndex={-1}>
        页面标题
      </h1>
      {open ? (
        <TrapDialog
          busy={busy}
          controls={controls}
          extraControl={extraControl}
          fallbackFocus={fallbackRef.current}
          onClose={() => setOpen(false)}
          returnFocus={triggerRef.current}
        />
      ) : null}
    </>
  );
}

function TrapDialog({
  busy,
  controls,
  extraControl,
  fallbackFocus,
  onClose,
  returnFocus,
}: {
  busy: boolean;
  controls: boolean;
  extraControl: boolean;
  fallbackFocus: HTMLElement | null;
  onClose: () => void;
  returnFocus: HTMLElement | null;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const trap = useDialogFocusTrap<HTMLDivElement>({
    escapeDisabled: busy,
    initialFocusRef: cancelRef,
    onEscape: onClose,
    returnFocus: [returnFocus, fallbackFocus],
  });

  return (
    <div
      aria-label="确认"
      ref={trap.dialogRef}
      role="dialog"
      tabIndex={-1}
      onKeyDown={trap.handleKeyDown}
    >
      <p>确认对象</p>
      {controls ? (
        <>
          <button ref={cancelRef} disabled={busy} type="button">
            取消
          </button>
          {extraControl ? <input aria-label="嵌套编辑输入" /> : null}
          <button disabled={busy} type="button">
            确认
          </button>
        </>
      ) : null}
    </div>
  );
}

describe("useDialogFocusTrap", () => {
  it("初始聚焦安全取消控件，并独立于原生 Tab 偏好前进、反向和循环", async () => {
    const user = userEvent.setup();
    render(<FocusTrapFixture />);

    await user.click(screen.getByRole("button", { name: "打开" }));
    const cancel = screen.getByRole("button", { name: "取消" });
    const confirm = screen.getByRole("button", { name: "确认" });
    expect(cancel).toHaveFocus();

    await user.tab();
    expect(confirm).toHaveFocus();
    await user.tab();
    expect(cancel).toHaveFocus();
    await user.tab({ shift: true });
    expect(confirm).toHaveFocus();

    const prevented = screen.getByRole("dialog").dispatchEvent(
      new KeyboardEvent("keydown", {
        bubbles: true,
        cancelable: true,
        key: "Tab",
      }),
    );
    expect(prevented).toBe(false);
    expect(cancel).toHaveFocus();
  });

  it("按每次事件重新读取动态控件，并在焦点逃逸时拉回安全控件", async () => {
    const user = userEvent.setup();
    const view = render(<FocusTrapFixture />);

    await user.click(screen.getByRole("button", { name: "打开" }));
    view.rerender(<FocusTrapFixture extraControl />);
    const cancel = screen.getByRole("button", { name: "取消" });
    const editor = screen.getByRole("textbox", { name: "嵌套编辑输入" });
    const confirm = screen.getByRole("button", { name: "确认" });
    expect(cancel).toHaveFocus();
    await user.tab();
    expect(editor).toHaveFocus();
    await user.tab();
    expect(confirm).toHaveFocus();

    screen.getByRole("textbox", { name: "背景输入框" }).focus();
    await waitFor(() => expect(cancel).toHaveFocus());
    await user.click(screen.getByRole("textbox", { name: "背景输入框" }));
    expect(cancel).toHaveFocus();
  });

  it("忙碌时不关闭，所有控件禁用时仍把 Tab 留在对话框", async () => {
    const user = userEvent.setup();
    render(<FocusTrapFixture busy />);

    await user.click(screen.getByRole("button", { name: "打开" }));
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(dialog).toBeInTheDocument();
    await user.tab();
    expect(dialog).toHaveFocus();
  });

  it("没有控件时安全停留，并在关闭后恢复现有候选焦点", async () => {
    const user = userEvent.setup();
    render(<FocusTrapFixture controls={false} />);

    const trigger = screen.getByRole("button", { name: "打开" });
    await user.click(trigger);
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveFocus();
    await user.tab();
    expect(dialog).toHaveFocus();
    await user.keyboard("{Escape}");

    await waitFor(() => expect(trigger).toHaveFocus());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
