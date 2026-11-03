import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { collectSchemas, isStrictObject } from "./schemaShape";
import {
  responseSchemas,
  webApiContract,
  webResponses,
} from "./webApiContract";

// 改了网页的响应 schema 后，用 `npx vitest run src/api/contract -u` 更新快照，
// 再跑 `tests/web/test_frontend_contract.py` 和后端比对。
const webResponseSchemas = Object.fromEntries(
  Object.entries(webResponses).map(([operation, name]) => [
    operation,
    responseSchemas[name],
  ]),
);

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

// 不经 requestJson、由其他方式读取的接口。
const readOutsideRequestJson: Record<string, string> = {
  "GET /api/runs/{value}/events": "useRunEvents 用 EventSource 逐条解析",
};

interface CallSite {
  file: string;
  line: number;
  path: RegExp | null;
  methods: string[];
  schema: unknown;
  schemaName: string;
}

function sourceFiles(directory = sourceRoot): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      return entry.name === "test" || entry.name === "contract"
        ? []
        : sourceFiles(path);
    }
    return /\.tsx?$/.test(entry.name) &&
      !/\.test\.tsx?$/.test(entry.name) &&
      !entry.name.endsWith(".d.ts")
      ? [path]
      : [];
  });
}

function endOfString(source: string, start: number): number {
  const quote = source[start];
  for (let index = start + 1; index < source.length; index += 1) {
    if (source[index] === "\\") index += 1;
    else if (source[index] === quote) return index;
  }
  throw new Error("字符串没有结束");
}

/** 从调用的左括号开始，按顶层逗号切出各个参数的源码。 */
function readArguments(source: string, open: number): string[] {
  const args: string[] = [];
  const stack: string[] = [];
  let start = open + 1;
  for (let index = open + 1; index < source.length; index += 1) {
    const char = source[index];
    if (stack.at(-1) === "`") {
      if (char === "\\") index += 1;
      else if (char === "`") stack.pop();
      else if (char === "$" && source[index + 1] === "{") {
        stack.push("${");
        index += 1;
      }
      continue;
    }
    if (char === '"' || char === "'") {
      index = endOfString(source, index);
    } else if (char === "`" || char === "(" || char === "[" || char === "{") {
      stack.push(char);
    } else if (char === ")" || char === "]" || char === "}") {
      if (stack.length === 0) {
        args.push(source.slice(start, index).trim());
        return args.filter((value) => value !== "");
      }
      stack.pop();
    } else if (char === "," && stack.length === 0) {
      args.push(source.slice(start, index).trim());
      start = index + 1;
    }
  }
  throw new Error("调用没有结束");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** 把调用点的路径写法变成能匹配后端路由路径的正则；无法静态得知时返回 null。 */
function pathPattern(argument: string): RegExp | null {
  if (argument.startsWith('"')) {
    return new RegExp(`^${escapeRegExp(argument.slice(1, -1).split("?")[0])}$`);
  }
  if (!argument.startsWith("`")) return null;
  let pattern = "";
  let literal = "";
  let index = 1;
  while (index < argument.length - 1) {
    if (argument[index] === "$" && argument[index + 1] === "{") {
      let depth = 1;
      index += 2;
      while (depth > 0) {
        if (argument[index] === "{") depth += 1;
        if (argument[index] === "}") depth -= 1;
        index += 1;
      }
      pattern += escapeRegExp(literal) + "[^/]*/?";
      literal = "";
    } else {
      literal += argument[index];
      index += 1;
    }
  }
  pattern += escapeRegExp(literal);
  return new RegExp(`^${pattern.split("\\?")[0]}$`);
}

function requestMethods(argument: string | undefined): string[] {
  if (argument === undefined || !argument.includes("method")) {
    if (argument?.startsWith("send(")) {
      return [/^send\(\s*"([A-Z]+)"/.exec(argument)?.[1] ?? "?"];
    }
    return ["GET"];
  }
  const methods = [...argument.matchAll(/method:\s*"([A-Z]+)"/g)].map(
    (match) => match[1],
  );
  if (methods.length === 0) throw new Error(`读不出请求方法：${argument}`);
  return methods;
}

/** 找到调用点 schema 标识符实际导出的位置：跟随 import 和局部的 .superRefine() 派生。 */
function resolveExport(
  file: string,
  name: string,
): { file: string; name: string } {
  const source = readFileSync(file, "utf8");
  for (const match of source.matchAll(
    /import\s*\{([^}]*)\}\s*from\s*"([^"]+)"/g,
  )) {
    for (const specifier of match[1].split(",")) {
      const [imported, local = imported] = specifier
        .replace(/^\s*type\s+/, "")
        .split(/\s+as\s+/)
        .map((part) => part.trim());
      if (local === name && match[2].startsWith(".")) {
        return resolveExport(
          resolve(dirname(file), `${match[2]}.ts`),
          imported,
        );
      }
    }
  }
  if (new RegExp(`export const ${name}\\b`).test(source)) return { file, name };
  const derived = new RegExp(
    `const ${name} = (\\w+)\\s*\\.\\s*(?:superRefine|refine)\\(`,
  ).exec(source);
  if (derived) return resolveExport(file, derived[1]);
  throw new Error(
    `${relative(sourceRoot, file)}：请导出 ${name}，契约测试要按它比对`,
  );
}

async function callSites(): Promise<CallSite[]> {
  const sites: CallSite[] = [];
  for (const file of sourceFiles()) {
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(/\brequestJson\(/g)) {
      const open = match.index + match[0].length - 1;
      if (source.slice(0, match.index).trimEnd().endsWith("function")) continue;
      const [path, schema, init] = readArguments(source, open);
      if (!/^[A-Za-z_$][\w$]*$/.test(schema)) {
        throw new Error(
          `${relative(sourceRoot, file)}：requestJson 的 schema 请写成已导出的常量`,
        );
      }
      const target = resolveExport(file, schema);
      const module = (await import(
        /* @vite-ignore */ pathToFileURL(target.file).href
      )) as Record<string, unknown>;
      sites.push({
        file: relative(sourceRoot, file),
        line: source.slice(0, match.index).split("\n").length,
        path: pathPattern(path),
        methods: requestMethods(init),
        schema: module[target.name],
        schemaName: target.name,
      });
    }
  }
  return sites;
}

describe("网页与本机接口的数据格式契约", () => {
  it("生成后端契约测试读取的网页格式快照", async () => {
    await expect(
      `${JSON.stringify(webApiContract(), null, 2)}\n`,
    ).toMatchFileSnapshot("./web-api-contract.json");
  });

  it("每个 requestJson 调用点都登记了同一个响应 schema", async () => {
    const sites = await callSites();
    expect(sites.length).toBeGreaterThan(40);
    const used = new Set<string>();
    for (const site of sites) {
      const where = `${site.file}:${site.line}`;
      for (const method of site.methods) {
        const operations = Object.keys(webResponseSchemas).filter(
          (operation) => {
            const [registeredMethod, path] = operation.split(" ");
            return (
              registeredMethod === method && (site.path?.test(path) ?? true)
            );
          },
        );
        const matching = operations.filter(
          (operation) => webResponseSchemas[operation] === site.schema,
        );
        expect(
          matching,
          `${where} 用 ${site.schemaName} 解析 ${method} 请求，请在 webResponseSchemas 登记`,
        ).not.toHaveLength(0);
        matching.forEach((operation) => used.add(operation));
      }
    }
    const unused = Object.keys(webResponseSchemas).filter(
      (operation) =>
        !used.has(operation) && !(operation in readOutsideRequestJson),
    );
    expect(unused, "登记了却没有网页调用点的接口").toEqual([]);
  });

  it("每个导出的严格对象都在登记的响应 schema 里", async () => {
    const reachable = new Set<unknown>();
    for (const schema of Object.values(webResponseSchemas)) {
      collectSchemas(schema, reachable);
    }
    const missing: string[] = [];
    for (const file of sourceFiles()) {
      if (!readFileSync(file, "utf8").includes(".strict()")) continue;
      const module = (await import(
        /* @vite-ignore */ pathToFileURL(file).href
      )) as Record<string, unknown>;
      for (const [name, value] of Object.entries(module)) {
        if (isStrictObject(value) && !reachable.has(value)) {
          missing.push(`${relative(sourceRoot, file)}:${name}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });
});
