import { describe, expect, it } from "vitest";

import { serviceUrl } from "./serviceUrl";
import { makeService } from "./testFixtures";

describe("服务打开地址", () => {
  it("远端使用对端主机，缺少地址时不给打开入口", () => {
    expect(serviceUrl(makeService(), "192.0.2.42")).toBe(
      "http://192.0.2.42:8787",
    );
    expect(serviceUrl(makeService(), "2001:db8::42")).toBe(
      "http://[2001:db8::42]:8787",
    );
    expect(serviceUrl(makeService(), "127.0.0.2")).toBe(
      "http://127.0.0.2:8787",
    );
    expect(serviceUrl(makeService(), null)).toBeNull();
  });
  it.each([
    "0.0.0.0",
    "::",
    "0:0:0:0:0:0:0:0",
    "127.0.0.1",
    "127.2.3.4",
    "::1",
    "0:0:0:0:0:0:0:1",
    "::ffff:127.0.0.1",
  ])("%s 使用 localhost", (address) => {
    const service = makeService();
    service.endpoints[0]!.address = address;
    expect(serviceUrl(service)).toBe("http://localhost:8787");
  });

  it.each([
    ["192.0.2.10", "http://192.0.2.10:8787"],
    ["2001:db8::1", "http://[2001:db8::1]:8787"],
    ["fe80::1234%4", "http://[fe80::1234%4]:8787"],
    ["0:0:0:0:0:0:0:2", "http://[0:0:0:0:0:0:0:2]:8787"],
  ])("保留其他地址 %s", (address, expected) => {
    const service = makeService();
    service.endpoints[0]!.address = address;
    expect(serviceUrl(service)).toBe(expected);
  });

  it("优先第一个已确认网页，否则选第一个未排除网页的 TCP 入口", () => {
    const service = makeService({
      endpoints: [
        { protocol: "udp", address: "127.0.0.1", port: 53, has_web_page: null },
        {
          protocol: "tcp",
          address: "127.0.0.1",
          port: 80,
          has_web_page: false,
        },
        {
          protocol: "tcp",
          address: "127.0.0.1",
          port: 3000,
          has_web_page: null,
        },
        {
          protocol: "tcp",
          address: "127.0.0.1",
          port: 8080,
          has_web_page: true,
        },
        {
          protocol: "tcp",
          address: "127.0.0.1",
          port: 8081,
          has_web_page: true,
        },
      ],
    });
    expect(serviceUrl(service)).toBe("http://localhost:8080");
    service.endpoints = service.endpoints.slice(0, 3);
    expect(serviceUrl(service)).toBe("http://localhost:3000");
    service.endpoints = service.endpoints.slice(0, 2);
    expect(serviceUrl(service)).toBeNull();
    service.endpoints = [];
    expect(serviceUrl(service)).toBeNull();
  });
});
