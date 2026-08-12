import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const allowedLicenses = new Set([
  "(MIT OR CC0-1.0)",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "BlueOak-1.0.0",
  "CC0-1.0",
  "ISC",
  "MIT",
  "MIT-0",
  "MPL-2.0",
]);

const frontendRoot = fileURLToPath(new URL("../", import.meta.url));
const evidenceRoot = fileURLToPath(
  new URL("../../build/supply-chain/", import.meta.url),
);

export function collectLicenseEvidence(lock) {
  if (lock?.lockfileVersion !== 3 || typeof lock.packages !== "object") {
    throw new Error("package-lock.json 不是受支持的 lockfile v3");
  }
  const packages = Object.entries(lock.packages)
    .filter(([path]) => path !== "")
    .map(([path, metadata]) => {
      if (
        metadata === null ||
        typeof metadata !== "object" ||
        typeof metadata.version !== "string" ||
        typeof metadata.license !== "string"
      ) {
        throw new Error(`npm 依赖 ${path} 缺少版本或许可证证据`);
      }
      if (!allowedLicenses.has(metadata.license)) {
        throw new Error(
          `npm 依赖 ${path} 使用未审查许可证 ${metadata.license}`,
        );
      }
      return { license: metadata.license, path, version: metadata.version };
    })
    .sort((left, right) => left.path.localeCompare(right.path));
  if (packages.length === 0) {
    throw new Error("package-lock.json 没有依赖记录");
  }
  return {
    schema: "tunnelminion/npm-license-evidence/v1",
    packageCount: packages.length,
    packages,
  };
}

export function parseAuditEvidence(stdout, status, stderr = "") {
  let audit;
  try {
    audit = JSON.parse(stdout);
  } catch {
    throw new Error(`npm audit 没有生成有效 JSON 证据（exit ${status}）`);
  }
  if (audit.error) {
    throw new Error("npm audit 证据服务不可用，不能解释成零漏洞");
  }
  const vulnerabilities = audit.metadata?.vulnerabilities;
  if (vulnerabilities === null || typeof vulnerabilities !== "object") {
    throw new Error("npm audit JSON 缺少漏洞汇总");
  }
  const total = ["info", "low", "moderate", "high", "critical"].reduce(
    (sum, level) => sum + Number(vulnerabilities[level] ?? 0),
    0,
  );
  if (total > 0) {
    throw new Error(`npm audit 发现 ${total} 个漏洞`);
  }
  if (status !== 0) {
    throw new Error(
      `npm audit 执行失败（exit ${status}）：${stderr.trim() || "无错误详情"}`,
    );
  }
  return audit;
}

async function main() {
  await mkdir(evidenceRoot, { recursive: true });
  const lock = JSON.parse(
    await readFile(resolve(frontendRoot, "package-lock.json"), "utf8"),
  );
  const licenses = collectLicenseEvidence(lock);
  await writeFile(
    resolve(evidenceRoot, "npm-licenses.json"),
    `${JSON.stringify(licenses, null, 2)}\n`,
    "utf8",
  );

  const npmCli = process.env.npm_execpath;
  if (!npmCli) {
    throw new Error(
      "请通过 npm run supply-chain:check 启动固定版本的 npm audit",
    );
  }
  const completed = spawnSync(
    process.execPath,
    [npmCli, "audit", "--json", "--audit-level=low"],
    {
      cwd: frontendRoot,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  if (completed.error) {
    throw new Error(`无法启动 npm audit：${completed.error.message}`);
  }
  await writeFile(
    resolve(evidenceRoot, "npm-audit.json"),
    completed.stdout,
    "utf8",
  );
  parseAuditEvidence(completed.stdout, completed.status, completed.stderr);
  console.log(
    `npm supply chain: ${licenses.packageCount} packages, 0 vulnerabilities`,
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await main();
}
