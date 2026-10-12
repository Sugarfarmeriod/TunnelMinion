import { describe, expect, it } from "vitest";

import { operationStatusLabel } from "./operationPresentation";
import type { OperationRole, OperationStatus } from "./schemas";

describe("operationStatusLabel", () => {
  it.each<[OperationStatus, OperationRole, string]>([
    ["awaiting_authorization", "target", "等待你决定"],
    ["awaiting_authorization", "requester", "等待对方同意"],
    ["authorized", "target", "等待对方开始"],
    ["authorized", "requester", "对方已同意"],
    ["succeeded", "target", "访问检查通过"],
    ["succeeded", "requester", "访问检查通过"],
    ["expiring", "requester", "正在关闭临时入口"],
    ["expired", "requester", "已到期，入口已关闭"],
    ["rolling_back", "target", "正在结束临时访问"],
    ["rolled_back", "target", "已结束，入口已关闭"],
    ["cleanup_failed", "target", "入口关闭失败，需要处理"],
    ["authorization_expired", "requester", "开始期限已过"],
  ])("%s 在 %s 一侧不混淆等待关系", (state, role, label) => {
    expect(operationStatusLabel(state, role)).toBe(label);
  });
});
