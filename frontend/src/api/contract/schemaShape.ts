import type { ZodType } from "zod";

/**
 * 网页解析某个响应时实际接受的数据形状，只保留会决定"整份收下还是整份拒收"的信息：
 * 字段名、哪些字段允许缺省、严格对象是否拒收多余字段、可选值、能否为 null 和基础类型。
 * 后端契约测试拿它和 OpenAPI 比对。
 */
export type SchemaShape =
  | "string"
  | "number"
  | "boolean"
  | "null"
  | "unknown"
  | {
      object: Record<string, SchemaShape>;
      strict: boolean;
      optional: string[];
    }
  | { array: SchemaShape }
  | { record: SchemaShape }
  | { union: SchemaShape[] }
  | { nullable: SchemaShape }
  | { enum: (string | number | boolean | null)[] }
  // `.catch()`：校验失败时回退默认值，不会让整份数据被拒收。
  | { catch: SchemaShape };

interface ZodDefinition {
  type: string;
  [key: string]: unknown;
}

export function zodDefinition(schema: unknown): ZodDefinition | null {
  if (typeof schema !== "object" || schema === null || !("_zod" in schema)) {
    return null;
  }
  return (schema as { _zod: { def: ZodDefinition } })._zod.def;
}

function definitionOf(schema: unknown): ZodDefinition {
  const definition = zodDefinition(schema);
  if (definition === null) throw new Error("不是 zod schema");
  return definition;
}

/** 严格对象：`.strict()` 把多余字段的校验设为 never，后端多一个字段就整份拒收。 */
export function isStrictObject(schema: unknown): boolean {
  const definition = zodDefinition(schema);
  return (
    definition?.type === "object" &&
    zodDefinition(definition.catchall)?.type === "never"
  );
}

/** 字段缺省时 zod 是否放行（`.optional()`、`.default()`、`.catch()`）。 */
function acceptsMissing(schema: unknown): boolean {
  const definition = definitionOf(schema);
  switch (definition.type) {
    case "optional":
    case "default":
    case "prefault":
    case "catch":
      return true;
    case "nullable":
    case "readonly":
      return acceptsMissing(definition.innerType);
    default:
      return false;
  }
}

export function describeSchema(schema: ZodType | unknown): SchemaShape {
  const definition = definitionOf(schema);
  switch (definition.type) {
    case "object": {
      const shape = definition.shape as Record<string, unknown>;
      const fields: Record<string, SchemaShape> = {};
      const names = Object.keys(shape).sort();
      for (const name of names) fields[name] = describeSchema(shape[name]);
      return {
        object: fields,
        strict: isStrictObject(schema),
        optional: names.filter((name) => acceptsMissing(shape[name])),
      };
    }
    case "array":
      return { array: describeSchema(definition.element) };
    case "record":
      return { record: describeSchema(definition.valueType) };
    case "union":
      return { union: (definition.options as unknown[]).map(describeSchema) };
    case "nullable":
      return { nullable: describeSchema(definition.innerType) };
    case "optional":
    case "default":
    case "prefault":
    case "readonly":
      return describeSchema(definition.innerType);
    case "catch":
      return { catch: describeSchema(definition.innerType) };
    case "pipe":
      return describeSchema(definition.in);
    case "enum":
      return {
        enum: Object.values(definition.entries as Record<string, string>),
      };
    case "literal":
      return { enum: definition.values as (string | number | boolean)[] };
    case "string":
    case "number":
    case "boolean":
    case "null":
    case "unknown":
      return definition.type;
    case "any":
      return "unknown";
    default:
      throw new Error(`契约描述还不认识 zod 类型 ${definition.type}`);
  }
}

/** 收集一个 schema 里嵌套的全部 zod schema 对象（含自身）。 */
export function collectSchemas(schema: unknown, found: Set<unknown>): void {
  const definition = zodDefinition(schema);
  if (definition === null || found.has(schema)) return;
  found.add(schema);
  for (const value of Object.values(definition)) {
    if (Array.isArray(value)) {
      for (const item of value) collectSchemas(item, found);
    } else if (zodDefinition(value) !== null) {
      collectSchemas(value, found);
    } else if (typeof value === "object" && value !== null) {
      for (const item of Object.values(value)) collectSchemas(item, found);
    }
  }
}
