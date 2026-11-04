import { describe, expect, it } from "vitest";

import { makeService } from "./testFixtures";
import { webPageFailed, withoutWebPage } from "./webPage";

function withEndpoints(
  ...flags: { has_web_page: boolean | null; web_failed?: boolean }[]
) {
  return makeService({
    endpoints: flags.map((flag, index) => ({
      protocol: "tcp" as const,
      address: "127.0.0.1",
      port: 8000 + index,
      ...flag,
    })),
  });
}

describe("首页是不是网页", () => {
  it("没有网页和网页打不开分开", () => {
    const text = withEndpoints({ has_web_page: false });
    expect(withoutWebPage(text)).toBe(true);
    expect(webPageFailed(text)).toBe(false);

    const failed = withEndpoints({ has_web_page: false, web_failed: true });
    expect(withoutWebPage(failed)).toBe(false);
    expect(webPageFailed(failed)).toBe(true);
  });

  it("有一个入口是网页、或者还没探测过，都不算没有网页", () => {
    expect(
      withoutWebPage(
        withEndpoints({ has_web_page: false }, { has_web_page: true }),
      ),
    ).toBe(false);
    expect(withoutWebPage(withEndpoints({ has_web_page: null }))).toBe(false);
    expect(withoutWebPage(withEndpoints())).toBe(false);
  });
});
