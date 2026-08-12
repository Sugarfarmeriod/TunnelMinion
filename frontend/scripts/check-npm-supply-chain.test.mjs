import assert from "node:assert/strict";
import test from "node:test";

import {
  collectLicenseEvidence,
  parseAuditEvidence,
} from "./check-npm-supply-chain.mjs";

test("lockfile 许可证证据覆盖全部依赖并拒绝未知许可", () => {
  const lock = {
    lockfileVersion: 3,
    packages: {
      "": { name: "root" },
      "node_modules/example": { license: "MIT", version: "1.0.0" },
    },
  };
  assert.equal(collectLicenseEvidence(lock).packageCount, 1);
  assert.throws(
    () =>
      collectLicenseEvidence({
        ...lock,
        packages: {
          "node_modules/example": { license: "UNKNOWN", version: "1.0.0" },
        },
      }),
    /未审查许可证/,
  );
});

test("audit 必须有完整零漏洞证据", () => {
  const clean = JSON.stringify({
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
    },
  });
  assert.deepEqual(
    parseAuditEvidence(clean, 0).metadata.vulnerabilities.low,
    0,
  );
  assert.throws(() => parseAuditEvidence("not-json", 1), /有效 JSON/);
  assert.throws(
    () =>
      parseAuditEvidence(JSON.stringify({ error: { summary: "offline" } }), 1),
    /证据服务不可用/,
  );
  assert.throws(
    () =>
      parseAuditEvidence(
        JSON.stringify({ metadata: { vulnerabilities: { low: 1 } } }),
        1,
      ),
    /发现 1 个漏洞/,
  );
});
