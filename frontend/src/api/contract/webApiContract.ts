import type { ZodType } from "zod";

import {
  runEventSchema,
  runSchema,
  threadDetailSchema,
  threadListSchema,
  threadSchema,
} from "../../features/chat/contracts";
import {
  longTermMemoryListSchema,
  longTermMemorySchema,
} from "../../features/memories/api";
import {
  eligibleOperationPeersSchema,
  operationDetailSchema,
  operationListSchema,
  operationSummarySchema,
} from "../../features/operations/schemas";
import { patrolSchema } from "../../features/patrol/api";
import {
  identitySchema,
  inspectionSchema,
  issuedSchema,
  pushSchema,
  setupSchema,
} from "../../features/people/api";
import {
  peerRepairAccessSchema,
  repairDetailSchema,
  repairListSchema,
} from "../../features/repairs/api";
import {
  localServicesSchema,
  peerServicesSchema,
  peersSchema,
} from "../../features/service-map/api";
import { modelConfigurationSchema } from "../../features/settings/api";
import { updateViewSchema } from "../../features/settings/updateApi";
import {
  incidentDetailSchema,
  resourceOverviewSchema,
} from "../schemas/overview";
import { describeSchema, type SchemaShape } from "./schemaShape";

/** 网页用来解析本机接口响应的全部 schema，按导出名索引。 */
export const responseSchemas = {
  eligibleOperationPeersSchema,
  identitySchema,
  incidentDetailSchema,
  inspectionSchema,
  issuedSchema,
  localServicesSchema,
  longTermMemoryListSchema,
  longTermMemorySchema,
  modelConfigurationSchema,
  operationDetailSchema,
  operationListSchema,
  operationSummarySchema,
  patrolSchema,
  peerRepairAccessSchema,
  peerServicesSchema,
  peersSchema,
  pushSchema,
  repairDetailSchema,
  repairListSchema,
  resourceOverviewSchema,
  runEventSchema,
  runSchema,
  setupSchema,
  threadDetailSchema,
  threadListSchema,
  threadSchema,
  updateViewSchema,
} satisfies Record<string, ZodType>;

export type ResponseSchemaName = keyof typeof responseSchemas;

/**
 * 网页解析每个本机接口响应时使用的 schema。键是"方法 路径"，路径写法与后端路由一致
 * （含后端的路径参数名）。后端契约测试逐个和后端响应模型比对字段。
 */
export const webResponses: Record<string, ResponseSchemaName> = {
  "GET /api/model-config": "modelConfigurationSchema",
  "PUT /api/model-config": "modelConfigurationSchema",
  "POST /api/model-config/validate": "modelConfigurationSchema",
  "PUT /api/model/borrowed": "modelConfigurationSchema",
  "DELETE /api/model/borrowed": "modelConfigurationSchema",
  "GET /api/ui/overview": "resourceOverviewSchema",
  "GET /api/resources/overview": "resourceOverviewSchema",
  "GET /api/incidents/{value}": "incidentDetailSchema",
  "POST /api/incidents/{value}/follow-up": "runSchema",
  "GET /api/threads": "threadListSchema",
  "POST /api/threads": "threadSchema",
  "GET /api/threads/{value}": "threadDetailSchema",
  "GET /api/ui/threads/{value}": "threadDetailSchema",
  "POST /api/threads/{value}/runs": "runSchema",
  "POST /api/ui/threads/{value}/runs": "runSchema",
  "GET /api/runs/{value}": "runSchema",
  "POST /api/runs/{value}/cancel": "runSchema",
  // 事件流：每条 SSE 事件的 data 用 runEventSchema 单独解析。
  "GET /api/runs/{value}/events": "runEventSchema",
  "GET /api/memories": "longTermMemoryListSchema",
  "PUT /api/memories/{value}": "longTermMemorySchema",
  "GET /api/identity": "identitySchema",
  "POST /api/identity/codes:inspect": "inspectionSchema",
  "POST /api/identity/setup": "setupSchema",
  "POST /api/identity/setup/{setup_id}:confirm": "identitySchema",
  "POST /api/identity/owner:join": "identitySchema",
  "POST /api/identity/owner:invite": "issuedSchema",
  "DELETE /api/identity/devices/{device_id}": "pushSchema",
  "PUT /api/identity/devices/{value}/permissions": "identitySchema",
  "POST /api/identity/friends:invite": "issuedSchema",
  "POST /api/identity/friends:join": "identitySchema",
  "PATCH /api/identity/friends/{fingerprint}": "pushSchema",
  "DELETE /api/identity/friends/{fingerprint}": "pushSchema",
  "PUT /api/identity/friends/{fingerprint}/permissions": "pushSchema",
  "PUT /api/identity/legacy-peers/{value}/proxy-approval": "identitySchema",
  "GET /api/peers/{node_id}/repairs/{repair_id}": "peerRepairAccessSchema",
  "POST /api/peers/{node_id}/repairs/{repair_id}/approve":
    "peerRepairAccessSchema",
  "POST /api/peers/{node_id}/repairs/{repair_id}/reject":
    "peerRepairAccessSchema",
  "GET /api/peers": "peersSchema",
  "GET /api/peers/{value}/services": "peerServicesSchema",
  "GET /api/services/local": "localServicesSchema",
  "PUT /api/services/marks/{key}": "localServicesSchema",
  "DELETE /api/services/marks/{key}": "localServicesSchema",
  "GET /api/operations": "operationListSchema",
  "POST /api/operations": "operationDetailSchema",
  "GET /api/operations/eligible-peers": "eligibleOperationPeersSchema",
  "GET /api/operations/{value}": "operationDetailSchema",
  "POST /api/operations/{value}/approve": "operationSummarySchema",
  "POST /api/operations/{value}/reject": "operationSummarySchema",
  "POST /api/operations/{value}/cancel": "operationSummarySchema",
  "POST /api/operations/{value}/revoke": "operationSummarySchema",
  "POST /api/operations/{value}/refresh": "operationDetailSchema",
  "POST /api/operations/{value}/execute": "operationDetailSchema",
  "GET /api/repairs": "repairListSchema",
  "GET /api/repairs/{repair_id}": "repairDetailSchema",
  "POST /api/repairs/{repair_id}/approve": "repairDetailSchema",
  "POST /api/repairs/{repair_id}/reject": "repairDetailSchema",
  "GET /api/patrol": "patrolSchema",
  "PUT /api/patrol/services/{key}/auto-repair": "patrolSchema",
  "PUT /api/patrol/services/{key}/windows-service": "patrolSchema",
  "POST /api/patrol/services/{key}/acknowledge": "patrolSchema",
  "POST /api/patrol/services/{key}/forget": "patrolSchema",
  "GET /api/update": "updateViewSchema",
  "POST /api/update/check": "updateViewSchema",
  "POST /api/update/apply": "updateViewSchema",
};

/**
 * 网页不按严格格式解析响应体的本机接口及原因。后端新增接口时必须登记到
 * `webResponseSchemas` 或这里，否则后端契约测试失败。
 */
export const unparsedOperations: Record<string, string> = {
  "DELETE /api/model-config": "删除后只认 204，不读响应体",
  "DELETE /api/threads/{value}": "删除后不读响应体",
  "DELETE /api/memories/{value}": "删除后只认 204，不读响应体",
  "DELETE /api/memories/scope": "清空后只认 204，不读响应体",
  "DELETE /api/identity/setup/{setup_id}": "取消后只认 204，不读响应体",
  "POST /api/memories/confirm": "网页不调用",
  "POST /api/ai/runs/availability": "网页不调用",
  "POST /api/ui/runs/{value}/resume": "网页不调用",
  "GET /api/resources/health": "网页不调用",
  "GET /api/resources/wireguard": "网页不调用",
  "GET /api/resources/listeners": "网页不调用",
  "GET /api/resources/processes": "网页不调用",
  "GET /api/resources/docker": "网页不调用",
  "GET /api/resources/node-summary": "网页不调用",
  "GET /api/resources/managed-node": "网页不调用",
  "GET /api/resources/coordinator": "网页不调用",
  "GET /api/resources/network-path": "网页不调用",
  "POST /api/resources/probe": "网页不调用",
  "GET /api/diagnostics/export": "网页只把它作为下载链接，不解析",
  "GET /api/operations/{value}/access": "转发到被授权的远端网页，不是数据接口",
  "GET /api/operations/{value}/access/{path}":
    "转发到被授权的远端网页，不是数据接口",
  "GET /api/preauthorizations": "网页不调用",
  "POST /api/preauthorizations": "网页不调用",
  "POST /api/preauthorizations/{value}/revoke": "网页不调用",
};

export interface WebApiContract {
  schemas: Record<string, SchemaShape>;
  responses: Record<string, string>;
  unparsed: Record<string, string>;
}

function sortedRecord<T>(
  record: Record<string, T>,
  map: (value: T) => unknown = (value) => value,
): Record<string, never> {
  return Object.fromEntries(
    Object.keys(record)
      .sort()
      .map((key) => [key, map(record[key])]),
  ) as Record<string, never>;
}

/** 后端契约测试读取的快照内容。 */
export function webApiContract(): WebApiContract {
  return {
    schemas: sortedRecord<ZodType>(responseSchemas, describeSchema),
    responses: sortedRecord(webResponses),
    unparsed: sortedRecord(unparsedOperations),
  };
}
