import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { RequestExplanation } from "./RequestExplanation";
import { makeOperationDetail } from "./testFixtures";
import type { OperationStatus } from "./schemas";

afterEach(cleanup);

describe("RequestExplanation", () => {
  it.each<[OperationStatus, string]>([
    ["planned", "还没有开始使用"],
    ["awaiting_authorization", "正在等待对方同意"],
    ["authorized", "对方已同意"],
    ["executing", "正在准备临时入口"],
    ["verifying", "正在检查能否访问"],
    ["succeeded", "现在可以打开临时访问"],
    ["expiring", "正在关闭临时入口"],
    ["expired", "入口已关闭"],
    ["rolling_back", "正在撤回"],
    ["rolled_back", "临时入口已关闭"],
    ["cleanup_failed", "未能安全关闭"],
    ["rejected", "请求已被拒绝"],
    ["cancelled", "请求已取消"],
    ["authorization_expired", "不能再开始"],
  ])("请求端 %s 的提示与当前阶段一致", (state, text) => {
    const { container } = render(
      <RequestExplanation
        detail={makeOperationDetail({
          role: "requester",
          state,
          allowed_actions: ["access", "execute"],
        })}
      />,
    );
    expect(
      container.querySelector(".operation-request-intent"),
    ).toHaveTextContent(text);
    expect(screen.queryByText(/需要对方先同意/)).not.toBeInTheDocument();
  });

  it("目标端区分待批准、已批准和访问检查通过", () => {
    const { container, rerender } = render(
      <RequestExplanation detail={makeOperationDetail()} />,
    );
    expect(
      container.querySelector(".operation-request-intent"),
    ).toHaveTextContent("认识这个请求再批准");
    rerender(
      <RequestExplanation
        detail={makeOperationDetail({ state: "authorized" })}
      />,
    );
    expect(
      container.querySelector(".operation-request-intent"),
    ).toHaveTextContent("等待对方开始");
    rerender(
      <RequestExplanation
        detail={makeOperationDetail({
          state: "succeeded",
          allowed_actions: ["revoke"],
        })}
      />,
    );
    expect(
      container.querySelector(".operation-request-intent"),
    ).toHaveTextContent("提前结束");
  });

  it("访问会话不可用和写入未知时不承诺可打开", () => {
    const { container, rerender } = render(
      <RequestExplanation
        detail={makeOperationDetail({
          role: "requester",
          state: "succeeded",
          allowed_actions: ["refresh"],
          error_code: "access_session_unavailable",
        })}
      />,
    );
    expect(
      container.querySelector(".operation-request-intent"),
    ).toHaveTextContent("目前没有可用入口");
    rerender(
      <RequestExplanation
        detail={makeOperationDetail({
          state: "succeeded",
          execution_result_unknown: true,
        })}
      />,
    );
    expect(
      container.querySelector(".operation-request-intent"),
    ).toHaveTextContent("结果还不明确");
  });

  it("临时访问保留易懂风险，专业原文由调用方的技术详情承载", () => {
    render(
      <RequestExplanation
        detail={makeOperationDetail({
          risk_summary:
            "accessibility=local-only, confidence=low, requires target",
        })}
        compact
      />,
    );
    expect(screen.getByText(/能否修改内容或是否需要登录/)).toBeVisible();
    expect(screen.getByText(/不代表这些风险已确认安全/)).toBeVisible();
    expect(screen.queryByText(/accessibility=/)).not.toBeInTheDocument();
  });
});
