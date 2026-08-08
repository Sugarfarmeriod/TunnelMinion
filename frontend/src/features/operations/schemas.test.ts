import { describe, expect, it } from "vitest";

import { makeOperationDetail } from "./testFixtures";
import { operationDetailSchema } from "./schemas";

describe("operationDetailSchema", () => {
  it("接受服务端强类型详情并拒绝额外敏感字段", () => {
    const detail = makeOperationDetail();

    expect(operationDetailSchema.parse(detail)).toEqual(detail);
    expect(() =>
      operationDetailSchema.parse({
        ...detail,
        access_token: "tmn_share_must_not_enter_the_browser_contract",
      }),
    ).toThrow();
  });

  it("拒绝 state 与摘要不一致以及缺少人工动作的清理失败", () => {
    const detail = makeOperationDetail();

    expect(() =>
      operationDetailSchema.parse({ ...detail, state: "authorized" }),
    ).toThrow(/state 与 summary.status 不一致/);
    expect(() =>
      operationDetailSchema.parse({
        ...detail,
        state: "cleanup_failed",
        summary: { ...detail.summary, status: "cleanup_failed" },
        cleanup_record: {
          result: "failed",
          reason: "脱敏原因",
          completed_at: detail.created_at,
        },
        manual_action: null,
      }),
    ).toThrow(/清理失败时必须提供人工处理建议/);
  });

  it("按 Python 领域前缀拒绝 UUID、错误领域、长度与大写 hex", () => {
    const detail = makeOperationDetail();

    expect(() =>
      operationDetailSchema.parse({
        ...detail,
        summary: {
          ...detail.summary,
          operation_id: "11111111-1111-4111-8111-111111111111",
        },
      }),
    ).toThrow();
    expect(() =>
      operationDetailSchema.parse({
        ...detail,
        summary: {
          ...detail.summary,
          request_node_id: `resource_${"5".repeat(32)}`,
        },
      }),
    ).toThrow();
    expect(() =>
      operationDetailSchema.parse({
        ...detail,
        summary: {
          ...detail.summary,
          thread_id: `thread_${"a".repeat(31)}`,
        },
      }),
    ).toThrow();
    expect(() =>
      operationDetailSchema.parse({
        ...detail,
        summary: {
          ...detail.summary,
          resource_ids: [`resource_${"A".repeat(32)}`],
        },
      }),
    ).toThrow();
  });
});
