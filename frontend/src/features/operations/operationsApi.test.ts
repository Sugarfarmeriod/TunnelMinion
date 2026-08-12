import { describe, expect, it } from "vitest";

import { ApiError } from "../../api/client";

import {
  isUnknownOperationWriteError,
  operationActionWasAdjudicated,
} from "./operationsApi";
import { makeOperationDetail } from "./testFixtures";

describe("operation 写结果分类", () => {
  it.each([408, 429, 500, 503])("把 HTTP %s 保留为未知结果", (status) => {
    expect(
      isUnknownOperationWriteError(
        new ApiError(status, "request_failed", "响应不能证明写入结果"),
      ),
    ).toBe(true);
  });

  it("把传输/解析错误和不明确 4xx 保留为未知结果", () => {
    expect(isUnknownOperationWriteError(new TypeError("timeout"))).toBe(true);
    expect(
      isUnknownOperationWriteError(
        new ApiError(403, "request_failed", "不明确的拒绝"),
      ),
    ).toBe(true);
    expect(
      isUnknownOperationWriteError(
        new ApiError(400, "request_failed", "未约定的客户端错误"),
      ),
    ).toBe(true);
  });

  it("只把请求守卫或明确无副作用状态判定为直接失败", () => {
    expect(
      isUnknownOperationWriteError(
        new ApiError(403, "invalid_origin", "请求来源不受信任"),
      ),
    ).toBe(false);
    for (const status of [404, 409, 422]) {
      expect(
        isUnknownOperationWriteError(
          new ApiError(status, "request_failed", "业务请求未执行"),
        ),
      ).toBe(false);
    }
  });
});

describe("未知 operation 动作裁决证明", () => {
  const pending = {
    action: "approve" as const,
    initialState: "awaiting_authorization" as const,
  };

  it("原 state 与原 allowed action 都未变化时继续未知", () => {
    expect(operationActionWasAdjudicated(pending, makeOperationDetail())).toBe(
      false,
    );
  });

  it("state、allowed_actions 或终态能够证明服务端已经裁决", () => {
    expect(
      operationActionWasAdjudicated(
        pending,
        makeOperationDetail({
          state: "authorized",
          summary: {
            ...makeOperationDetail().summary,
            status: "authorized",
          },
          allowed_actions: ["cancel"],
        }),
      ),
    ).toBe(true);
    expect(
      operationActionWasAdjudicated(
        pending,
        makeOperationDetail({ allowed_actions: ["reject", "cancel"] }),
      ),
    ).toBe(true);
    expect(
      operationActionWasAdjudicated(
        pending,
        makeOperationDetail({
          state: "cancelled",
          summary: {
            ...makeOperationDetail().summary,
            status: "cancelled",
          },
          allowed_actions: [],
        }),
      ),
    ).toBe(true);
  });
});
