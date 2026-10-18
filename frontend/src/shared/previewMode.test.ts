import { afterEach, expect, it } from "vitest";
import { isReadOnlyPreview } from "./previewMode";

afterEach(() =>
  document.head
    .querySelector('meta[name="tunnelminion-read-only-preview"]')
    ?.remove(),
);

it("没有启动标记时保持正常模式，只有明确的预览标记才限制操作", () => {
  expect(isReadOnlyPreview()).toBe(false);
  const meta = document.createElement("meta");
  meta.name = "tunnelminion-read-only-preview";
  document.head.append(meta);
  expect(isReadOnlyPreview()).toBe(false);
  meta.content = "true";
  expect(isReadOnlyPreview()).toBe(true);
});
