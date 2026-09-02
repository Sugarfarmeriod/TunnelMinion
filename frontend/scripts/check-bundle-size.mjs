import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

export const absoluteBudgetBytes = 300 * 1024;
export const baselineSchema = "tunnelminion/frontend-bundle-baseline/v1";

const frontendRoot = fileURLToPath(new URL("../", import.meta.url));
const assetRoot = join(frontendRoot, "dist", "assets");
const baselinePath = join(frontendRoot, "bundle-size-baseline.json");
const evidencePath = fileURLToPath(
  new URL("../../build/supply-chain/frontend-bundle.json", import.meta.url),
);

export function parseBaseline(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    value.schema !== baselineSchema ||
    !Number.isInteger(value.acceptedBytes) ||
    value.acceptedBytes <= 0 ||
    typeof value.acceptedCommit !== "string" ||
    !/^[0-9a-f]{7,40}$/.test(value.acceptedCommit) ||
    typeof value.reviewNote !== "string" ||
    value.reviewNote.trim().length === 0
  ) {
    throw new Error("前端体积基线格式无效，必须记录有效字节数、提交和审查说明");
  }
  return value;
}

export function evaluateBundleSize(totalBytes, baseline) {
  if (!Number.isInteger(totalBytes) || totalBytes < 0) {
    throw new Error("前端 gzip 体积必须是非负整数");
  }
  const relativeBudgetBytes = Math.floor(baseline.acceptedBytes * 1.1);
  if (totalBytes > absoluteBudgetBytes) {
    throw new Error("初始 JS+CSS gzip 超过 300 KiB 门禁");
  }
  if (totalBytes > relativeBudgetBytes) {
    throw new Error(
      "初始 JS+CSS gzip 比已接受基线增长超过 10%，请审查并更新基线说明",
    );
  }
  return { relativeBudgetBytes, totalBytes };
}

export async function measureAssets(root) {
  const names = await readdir(root);
  const measured = names
    .filter((name) => [".js", ".css"].includes(extname(name)))
    .sort();
  if (measured.length === 0) {
    throw new Error("前端构建没有可计量的 JS/CSS 资源");
  }
  const assets = [];
  let totalBytes = 0;
  for (const name of measured) {
    const gzipBytes = gzipSync(await readFile(join(root, name))).byteLength;
    assets.push({ gzipBytes, name });
    totalBytes += gzipBytes;
  }
  return { assets, totalBytes };
}

async function main() {
  const baseline = parseBaseline(
    JSON.parse(await readFile(baselinePath, "utf8")),
  );
  const measured = await measureAssets(assetRoot);
  const limits = evaluateBundleSize(measured.totalBytes, baseline);
  const evidence = {
    schema: "tunnelminion/frontend-bundle-evidence/v1",
    baseline,
    limits: {
      absoluteBudgetBytes,
      relativeBudgetBytes: limits.relativeBudgetBytes,
    },
    ...measured,
  };
  await mkdir(dirname(evidencePath), { recursive: true });
  await writeFile(
    evidencePath,
    `${JSON.stringify(evidence, null, 2)}\n`,
    "utf8",
  );
  console.log(
    `initial JS+CSS gzip: ${(measured.totalBytes / 1024).toFixed(2)} KiB / ` +
      `${(absoluteBudgetBytes / 1024).toFixed(2)} KiB; baseline +10% ` +
      `${(limits.relativeBudgetBytes / 1024).toFixed(2)} KiB`,
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await main();
}
