import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  absoluteBudgetBytes,
  baselineSchema,
  evaluateBundleSize,
  measureAssets,
  parseBaseline,
} from "./check-bundle-size.mjs";

const baseline = {
  schema: baselineSchema,
  acceptedBytes: 1000,
  acceptedCommit: "ecfd0a4",
  reviewNote: "测试基线",
};

test("绝对预算和基线增长只允许落在边界内", () => {
  assert.equal(evaluateBundleSize(1100, baseline).relativeBudgetBytes, 1100);
  assert.throws(() => evaluateBundleSize(1101, baseline), /增长超过 10%/);
  const largeBaseline = { ...baseline, acceptedBytes: absoluteBudgetBytes };
  assert.equal(
    evaluateBundleSize(absoluteBudgetBytes, largeBaseline).totalBytes,
    307200,
  );
  assert.throws(
    () => evaluateBundleSize(absoluteBudgetBytes + 1, largeBaseline),
    /超过 300 KiB/,
  );
});

test("损坏基线会保守失败", () => {
  for (const value of [
    {},
    { ...baseline, acceptedBytes: 0 },
    { ...baseline, acceptedCommit: "not-a-commit" },
    { ...baseline, reviewNote: "" },
  ]) {
    assert.throws(() => parseBaseline(value), /基线格式无效/);
  }
});

test("空资源目录不能生成体积证据", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tunnelminion-bundle-"));
  try {
    await assert.rejects(measureAssets(directory), /没有可计量/);
  } finally {
    await rm(directory, { recursive: true });
  }
});
