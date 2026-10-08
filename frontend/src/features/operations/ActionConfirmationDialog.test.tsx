import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ActionConfirmationDialog } from "./ActionConfirmationDialog";
import { makeOperationDetail } from "./testFixtures";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it.each([1, 120])(
  "访问 %s 秒不缩短默认批准窗口，也不因分钟截断提前过期",
  (duration) => {
    const now = Date.parse("2026-10-08T11:56:35Z");
    vi.spyOn(Date, "now").mockReturnValue(now);
    const confirm = vi.fn();
    const detail = makeOperationDetail({ duration_seconds: duration });
    render(
      <ActionConfirmationDialog
        action="approve"
        detail={detail}
        submitting={false}
        returnFocus={null}
        fallbackFocus={null}
        safeFallbackFocus={null}
        onCancel={vi.fn()}
        onConfirm={confirm}
      />,
    );
    const expiry = screen.getByLabelText(
      "批准有效期截止时间",
    ) as HTMLInputElement;
    expect(new Date(expiry.value).getTime()).toBe(now + 300_000);
    expect(expiry.step).toBe("1");
    fireEvent.submit(expiry.closest("form")!);
    expect(confirm).toHaveBeenCalledWith({
      action: "approve",
      operator: "target-local-user",
      expires_at: new Date(now + 300_000).toISOString(),
    });
    expect(detail.duration_seconds).toBe(duration);
  },
);
