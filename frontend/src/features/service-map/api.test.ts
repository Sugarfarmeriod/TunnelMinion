import { describe, expect, it } from "vitest";

import {
  localServicesSchema,
  peersSchema,
  peerServicesSchema,
  peerServiceEntries,
} from "./api";
import {
  makeLocalServices,
  makeService,
  makePeer,
  makePeerServices,
} from "./testFixtures";

describe("服务地图严格契约", () => {
  it("接受对端清单与缓存状态，旧对端缺少 state 时默认为运行中", () => {
    expect(peersSchema.parse({ peers: [makePeer()] }).peers).toEqual([
      makePeer(),
    ]);
    const view = makePeerServices();
    const { state: _state, ...legacy } = view.services[0]!;
    const parsed = peerServicesSchema.parse({ ...view, services: [legacy] });
    expect(parsed.services[0]!.state).toBe("running");
    expect(peerServiceEntries(parsed)[0]!.endpoints[0]!.address).toBe(
      view.host,
    );
    expect(peerServiceEntries()).toEqual([]);
    expect(
      peerServicesSchema.safeParse({ ...view, token: "fake-private-field" })
        .success,
    ).toBe(false);
    expect(
      peerServicesSchema.safeParse({
        ...view,
        services: [{ ...legacy, state: "unknown" }],
      }).success,
    ).toBe(false);
  });
  it("接受完整清单以及所有可空字段", () => {
    expect(localServicesSchema.parse(makeLocalServices())).toEqual(
      makeLocalServices(),
    );
    const data = makeLocalServices([
      makeService({
        mark: "mine",
        web_title: null,
        endpoints: [
          { protocol: "udp", address: "::", port: 65535, has_web_page: null },
        ],
      }),
    ]);
    data.observed_at = null;
    expect(localServicesSchema.parse(data)).toEqual(data);
    expect(localServicesSchema.parse(makeLocalServices([])).services).toEqual(
      [],
    );
  });

  it.each(["清单", "服务", "入口"])(
    "拒绝%s中的多字段和每一个缺失字段",
    (level) => {
      const original = makeLocalServices();
      const select = (data: typeof original): Record<string, unknown> =>
        level === "清单"
          ? data
          : level === "服务"
            ? data.services[0]!
            : data.services[0]!.endpoints[0]!;
      const extra = structuredClone(original);
      select(extra).unexpected = true;
      expect(localServicesSchema.safeParse(extra).success).toBe(false);
      for (const key of Object.keys(select(original))) {
        const missing = structuredClone(original);
        delete select(missing)[key];
        expect(localServicesSchema.safeParse(missing).success, key).toBe(false);
      }
    },
  );

  it.each([
    { kind: "model" },
    { tier: "unknown" },
    { mark: "show" },
    { name: "" },
    { key: "" },
    {
      endpoints: [
        {
          protocol: "http",
          address: "localhost",
          port: 80,
          has_web_page: true,
        },
      ],
    },
    {
      endpoints: [
        { protocol: "tcp", address: "localhost", port: 0, has_web_page: true },
      ],
    },
    {
      endpoints: [
        {
          protocol: "tcp",
          address: "localhost",
          port: 65536,
          has_web_page: true,
        },
      ],
    },
    {
      endpoints: [
        {
          protocol: "tcp",
          address: "localhost",
          port: 80.5,
          has_web_page: true,
        },
      ],
    },
    {
      endpoints: [
        {
          protocol: "tcp",
          address: "localhost",
          port: 80,
          has_web_page: "true",
        },
      ],
    },
  ])("拒绝错误的服务取值 %j", (invalid) => {
    expect(
      localServicesSchema.safeParse({
        ...makeLocalServices(),
        services: [{ ...makeService(), ...invalid }],
      }).success,
    ).toBe(false);
  });

  it.each([{ node_id: "computer" }, { observed_at: "昨天" }])(
    "拒绝错误的清单取值 %j",
    (invalid) => {
      expect(
        localServicesSchema.safeParse({ ...makeLocalServices(), ...invalid })
          .success,
      ).toBe(false);
    },
  );
});
