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
  ])("%s 在 %s 一侧不混淆等待关系", (state, role, label) => {
    expect(operationStatusLabel(state, role)).toBe(label);
  });
});
