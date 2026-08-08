import { readdir, readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const budgetBytes = 300 * 1024;
const assetRoot = fileURLToPath(new URL("../dist/assets/", import.meta.url));
const names = await readdir(assetRoot);
const measured = names.filter((name) =>
  [".js", ".css"].includes(extname(name)),
);
let totalBytes = 0;

for (const name of measured) {
  totalBytes += gzipSync(await readFile(join(assetRoot, name))).byteLength;
}

const kibibytes = (totalBytes / 1024).toFixed(2);
console.log(`initial JS+CSS gzip: ${kibibytes} KiB / 300.00 KiB`);
if (totalBytes > budgetBytes) {
  throw new Error("初始 JS+CSS gzip 超过 300 KiB 门禁");
}
