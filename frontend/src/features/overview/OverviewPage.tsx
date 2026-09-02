import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { requestJson } from "../../api/client";
import {
  resourceOverviewSchema,
  type ResourceOverview,
} from "../../api/schemas/overview";

import "./overview.css";

type Tone = "positive" | "warning" | "danger" | "neutral";
type SectionMeta = Pick<
  ResourceOverview["local"],
  "source" | "evidence_at" | "freshness" | "error"
>;

const sourceLabels: Record<SectionMeta["source"], string> = {
  local_runtime: "本机运行时",
  model_configuration: "模型配置",
  coordinator_sync: "Coordinator 同步",
  coordinator_directory: "Coordinator 目录",
  network_path_evidence: "网络路径证据",
  local_observation: "本机观测",
  aggregated: "服务端聚合",
  unknown: "来源未知",
};

const freshnessLabels: Record<SectionMeta["freshness"], string> = {
  live: "实时证据",
  fresh: "新鲜证据",
  stale: "证据陈旧",
  expired: "证据已过期",
  unavailable: "暂时取不到证据",
  not_applicable: "不适用",
  unknown: "新鲜度未知",
};

const runtimeLabels: Record<ResourceOverview["local"]["runtime"], string> = {
  running: "本机程序正在运行",
  starting: "本机程序正在启动",
  stopping: "本机程序正在停止",
  stopped: "本机程序已停止",
  degraded: "本机程序能运行，但部分能力受限",
  unknown: "本机运行状态未知",
};

const readinessLabels: Record<ResourceOverview["local"]["readiness"], string> =
  {
    ready: "本机接口已准备好",
    degraded: "本机接口可用，但有降级",
    unavailable: "本机接口当前不可用",
    unknown: "本机接口是否可用还不确定",
  };

const modelLabels: Record<ResourceOverview["model"]["status"], string> = {
  unconfigured: "还没有配置模型",
  available: "模型现在可以使用",
  unavailable: "模型已配置，但现在不可用",
  unknown: "模型状态未知",
};

const coordinatorLabels: Record<
  ResourceOverview["coordinator"]["state"],
  string
> = {
  unconfigured: "未配置 Coordinator，当前按仅本机模式工作",
  config_invalid: "Coordinator 配置无法读取",
  credential_missing: "Coordinator 缺少凭据",
  sync_not_started: "Coordinator 尚未开始同步",
  connecting: "正在连接 Coordinator",
  ready: "Coordinator 目录已同步",
  stale: "Coordinator 目录已经陈旧",
  offline: "Coordinator 当前离线",
  incompatible: "Coordinator 版本不兼容",
  managed_auth_expired: "Coordinator 管理凭据已过期",
  unknown: "Coordinator 状态未知",
};

const pathLabels: Record<ResourceOverview["network_path"]["state"], string> = {
  unconfigured: "没有配置跨节点路径",
  pending: "网络路径正在等待证据",
  direct: "当前选择了直连路径",
  relayed: "当前选择了中继路径",
  static: "当前使用静态路径",
  offline: "peer 路径当前不可达",
  unknown: "网络路径状态未知",
};

const evidenceLabels: Record<
  ResourceOverview["network_path"]["handshake"]["status"],
  string
> = {
  passed: "已通过",
  failed: "未通过",
  missing: "没有证据",
  unknown: "状态未知",
};

const nodeStateLabels: Record<
  ResourceOverview["nodes"]["items"][number]["state"],
  string
> = {
  local: "本机节点",
  online: "有在线证据",
  stale: "只有陈旧证据",
  offline: "当前离线",
  revoked: "已撤销",
  incompatible: "版本不兼容",
  unknown: "状态未知",
};

const serviceStateLabels: Record<
  ResourceOverview["services"]["items"][number]["state"],
  string
> = {
  available: "有可用证据",
  degraded: "部分能力受限",
  unavailable: "当前不可用",
  stopped: "已停止",
  unknown: "状态未知",
};

const platformLabels: Record<
  NonNullable<ResourceOverview["local"]["platform"]>,
  string
> = {
  windows: "Windows",
  macos: "macOS",
  linux: "Linux",
};

function formatTimestamp(value: string | null): string {
  if (value === null) {
    return "没有证据时间";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

function freshnessTone(freshness: SectionMeta["freshness"]): Tone {
  switch (freshness) {
    case "live":
    case "fresh":
      return "positive";
    case "stale":
    case "expired":
      return "warning";
    case "unavailable":
      return "danger";
    case "not_applicable":
    case "unknown":
      return "neutral";
  }
}

function stateTone(state: string, freshness: SectionMeta["freshness"]): Tone {
  if (freshness === "stale" || freshness === "expired") {
    return "warning";
  }
  if (freshness === "unknown" || state === "unknown") {
    return "neutral";
  }
  if (
    state === "offline" ||
    state === "unavailable" ||
    state === "failed" ||
    state === "stopped" ||
    state === "revoked" ||
    state === "config_invalid" ||
    state === "credential_missing" ||
    state === "incompatible" ||
    state === "managed_auth_expired"
  ) {
    return "danger";
  }
  if (
    state === "pending" ||
    state === "connecting" ||
    state === "sync_not_started" ||
    state === "degraded" ||
    state === "missing" ||
    state === "stale" ||
    state === "starting" ||
    state === "stopping"
  ) {
    return "warning";
  }
  if (state === "unconfigured") {
    return "neutral";
  }
  return "positive";
}

function collectionTone(meta: SectionMeta, itemTones: readonly Tone[]): Tone {
  const metaTone = freshnessTone(meta.freshness);
  if (itemTones.length === 0) {
    return metaTone === "positive" ? "neutral" : metaTone;
  }
  const tones = [metaTone, ...itemTones];
  if (tones.includes("danger")) {
    return "danger";
  }
  if (tones.includes("warning")) {
    return "warning";
  }
  if (tones.includes("neutral")) {
    return "neutral";
  }
  return "positive";
}

function StatusBadge({ tone, children }: { tone: Tone; children: string }) {
  return (
    <span className={`overview-status overview-status--${tone}`}>
      {children}
    </span>
  );
}

function SectionMetadata({ meta }: { meta: SectionMeta }) {
  return (
    <dl className="overview-metadata">
      <div>
        <dt>来源</dt>
        <dd>{sourceLabels[meta.source]}</dd>
      </div>
      <div>
        <dt>证据时间</dt>
        <dd>{formatTimestamp(meta.evidence_at)}</dd>
      </div>
      <div>
        <dt>新鲜度</dt>
        <dd>
          <StatusBadge tone={freshnessTone(meta.freshness)}>
            {freshnessLabels[meta.freshness]}
          </StatusBadge>
        </dd>
      </div>
      <div>
        <dt>稳定错误</dt>
        <dd>
          {meta.error === null ? (
            "没有"
          ) : (
            <code className="overview-error-code">{meta.error.code}</code>
          )}
        </dd>
      </div>
    </dl>
  );
}

function SectionCard({
  id,
  title,
  summary,
  tone,
  meta,
  nextStep,
  children,
}: {
  id: string;
  title: string;
  summary: string;
  tone: Tone;
  meta: SectionMeta;
  nextStep: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <article aria-labelledby={id} className="overview-card">
      <div className="overview-card__heading">
        <h3 id={id}>{title}</h3>
        <StatusBadge tone={tone}>{summary}</StatusBadge>
      </div>
      {children}
      <SectionMetadata meta={meta} />
      <div className="overview-next-step">
        <strong>下一步：</strong>
        {nextStep}
      </div>
    </article>
  );
}

function LocalRuntimeCard({ data }: { data: ResourceOverview["local"] }) {
  const tone = stateTone(
    data.readiness === "ready" ? data.runtime : data.readiness,
    data.freshness,
  );
  const nextStep =
    data.readiness === "ready" && data.runtime === "running"
      ? "本机无需处理，可以继续查看其他能力。"
      : "先确认本机 TunnelMinion 进程仍在运行，再刷新证据。";

  return (
    <SectionCard
      id="overview-local"
      meta={data}
      nextStep={nextStep}
      summary={readinessLabels[data.readiness]}
      title="本机运行"
      tone={tone}
    >
      <dl className="overview-details">
        <div>
          <dt>程序</dt>
          <dd>{runtimeLabels[data.runtime]}</dd>
        </div>
        <div>
          <dt>平台</dt>
          <dd>
            {data.platform === null ? "未知" : platformLabels[data.platform]}
          </dd>
        </div>
        <div>
          <dt>版本</dt>
          <dd>{data.version ?? "未报告"}</dd>
        </div>
        <div>
          <dt>安装形态</dt>
          <dd>
            {data.package.kind} · {data.package.version ?? "版本未知"}
          </dd>
        </div>
      </dl>
    </SectionCard>
  );
}

function ModelCard({ data }: { data: ResourceOverview["model"] }) {
  const nextStep =
    data.status === "available" ? (
      <Link to="/app/chat">可以开始聊天。</Link>
    ) : data.status === "unconfigured" ? (
      <Link to="/app/settings">
        需要聊天时再去设置中配置模型；资源总览仍可使用。
      </Link>
    ) : (
      <Link to="/app/settings">
        到设置中检查脱敏的模型状态；资源与已有操作仍可使用。
      </Link>
    );

  return (
    <SectionCard
      id="overview-model"
      meta={data}
      nextStep={nextStep}
      summary={modelLabels[data.status]}
      title="模型"
      tone={stateTone(data.status, data.freshness)}
    >
      <p className="overview-explanation">
        {data.configured === true
          ? "已经保存模型配置。"
          : data.configured === false
            ? "没有保存模型配置。"
            : "暂时无法确认是否已配置模型。"}
      </p>
    </SectionCard>
  );
}

function CoordinatorCard({ data }: { data: ResourceOverview["coordinator"] }) {
  const nextStep =
    data.state === "ready"
      ? "目录无需处理；节点是否可达仍要看网络路径的独立证据。"
      : data.state === "unconfigured"
        ? "仅使用本机功能即可；需要多节点目录时再配置 Coordinator。"
        : "先刷新；仍异常时到设置中检查 Coordinator 的脱敏配置状态。";

  return (
    <SectionCard
      id="overview-coordinator"
      meta={data}
      nextStep={nextStep}
      summary={coordinatorLabels[data.state]}
      title="Coordinator"
      tone={stateTone(data.state, data.freshness)}
    >
      <dl className="overview-details">
        <div>
          <dt>目录版本</dt>
          <dd>{data.revision ?? "尚无"}</dd>
        </div>
        <div>
          <dt>上次同步成功</dt>
          <dd>{formatTimestamp(data.last_success_at)}</dd>
        </div>
      </dl>
    </SectionCard>
  );
}

function NetworkEvidence({
  label,
  evidence,
}: {
  label: string;
  evidence: ResourceOverview["network_path"]["handshake"];
}) {
  return (
    <li>
      <div className="overview-evidence__heading">
        <strong>{label}</strong>
        <StatusBadge tone={stateTone(evidence.status, "fresh")}>
          {evidenceLabels[evidence.status]}
        </StatusBadge>
      </div>
      <span>{formatTimestamp(evidence.observed_at)}</span>
    </li>
  );
}

function NetworkPathCard({ data }: { data: ResourceOverview["network_path"] }) {
  return (
    <SectionCard
      id="overview-network"
      meta={data}
      nextStep="先看真实 probe 是否通过；不可达时检查 peer 程序和网络。防火墙日志只是可选诊断，不是运行条件。"
      summary={pathLabels[data.state]}
      title="跨节点网络路径"
      tone={stateTone(data.state, data.freshness)}
    >
      <ul aria-label="网络路径证据" className="overview-evidence-list">
        <NetworkEvidence evidence={data.handshake} label="握手" />
        <NetworkEvidence evidence={data.route} label="路由" />
        <NetworkEvidence evidence={data.probe} label="真实探测" />
      </ul>
    </SectionCard>
  );
}

function NodeList({ data }: { data: ResourceOverview["nodes"] }) {
  return (
    <SectionCard
      id="overview-nodes"
      meta={data}
      nextStep="离线、未知或陈旧节点先刷新证据；不要把缓存记录当作当前在线。"
      summary={
        data.items.length === 0
          ? "还没有已知节点"
          : `已知 ${data.items.length} 个节点`
      }
      title="已知节点"
      tone={collectionTone(
        data,
        data.items.map((item) => stateTone(item.state, item.freshness)),
      )}
    >
      {data.items.length === 0 ? (
        <p className="overview-empty">
          当前没有服务端确认的节点记录。本机功能仍可使用。
        </p>
      ) : (
        <ul className="overview-resource-list">
          {data.items.map((node) => (
            <li key={node.node_id}>
              <div className="overview-resource-list__heading">
                <strong>{node.display_name}</strong>
                <StatusBadge tone={stateTone(node.state, node.freshness)}>
                  {node.freshness === "stale" || node.freshness === "expired"
                    ? `${nodeStateLabels[node.state]}（证据陈旧）`
                    : nodeStateLabels[node.state]}
                </StatusBadge>
              </div>
              <p>
                {node.platform === null
                  ? "平台未知"
                  : platformLabels[node.platform]}{" "}
                · 已报告 {node.service_count} 个服务
              </p>
              <p className="overview-resource-list__evidence">
                {sourceLabels[node.source]} ·{" "}
                {formatTimestamp(node.evidence_at)} ·{" "}
                {freshnessLabels[node.freshness]}
              </p>
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  );
}

function ServiceList({ data }: { data: ResourceOverview["services"] }) {
  return (
    <SectionCard
      id="overview-services"
      meta={data}
      nextStep="服务未知、陈旧或不可用时先刷新；需要连接时再检查所属节点和真实探测。"
      summary={
        data.items.length === 0
          ? "还没有已知服务"
          : `已知 ${data.items.length} 个服务`
      }
      title="已知服务"
      tone={collectionTone(
        data,
        data.items.map((item) => stateTone(item.state, item.freshness)),
      )}
    >
      {data.items.length === 0 ? (
        <p className="overview-empty">当前没有服务端确认的服务记录。</p>
      ) : (
        <ul className="overview-resource-list">
          {data.items.map((service) => (
            <li key={service.service_id}>
              <div className="overview-resource-list__heading">
                <strong>{service.display_name ?? "未命名服务"}</strong>
                <StatusBadge tone={stateTone(service.state, service.freshness)}>
                  {service.freshness === "stale" ||
                  service.freshness === "expired"
                    ? `${serviceStateLabels[service.state]}（证据陈旧）`
                    : serviceStateLabels[service.state]}
                </StatusBadge>
              </div>
              <p>
                {service.protocol === null
                  ? "协议未知"
                  : service.protocol.toUpperCase()}
                {service.port === null
                  ? " · 端口未知"
                  : ` · 端口 ${service.port}`}
                {` · 节点 ${service.node_id.slice(0, 8)}`}
              </p>
              <p className="overview-resource-list__evidence">
                访问地址：{service.access_address ?? "未知"}
              </p>
              <p className="overview-resource-list__evidence">
                {sourceLabels[service.source]} ·{" "}
                {formatTimestamp(service.evidence_at)} ·{" "}
                {freshnessLabels[service.freshness]}
              </p>
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  );
}

function readableRequestError(error: Error): string {
  return error.name === "ZodError"
    ? "服务返回的数据不符合总览契约，页面不会猜测状态。"
    : "无法读取本机总览，请确认 TunnelMinion 仍在运行。";
}

export function OverviewPage() {
  const query = useQuery({
    queryKey: ["resource-overview"],
    queryFn: () =>
      requestJson("/api/resources/overview", resourceOverviewSchema),
  });

  if (query.isPending) {
    return (
      <section
        aria-labelledby="overview-title"
        className="overview-page surface"
      >
        <h2 id="overview-title">总览</h2>
        <p aria-live="polite" role="status">
          正在读取本机、节点和服务状态……
        </p>
      </section>
    );
  }

  if (query.data === undefined) {
    return (
      <section
        aria-labelledby="overview-title"
        className="overview-page surface"
      >
        <h2 id="overview-title">总览</h2>
        <div className="overview-query-error" role="alert">
          <h3>现在读不到总览</h3>
          <p>{readableRequestError(query.error)}</p>
          <button type="button" onClick={() => void query.refetch()}>
            重新读取
          </button>
        </div>
      </section>
    );
  }

  const data = query.data;

  return (
    <section aria-labelledby="overview-title" className="overview-page surface">
      <header className="overview-page__header">
        <div>
          <p className="eyebrow">服务端确认的状态</p>
          <h2 id="overview-title">总览</h2>
          <p>本机运行、模型、Coordinator 和跨节点网络分别显示，互不冒充。</p>
        </div>
        <button
          disabled={query.isFetching}
          type="button"
          onClick={() => void query.refetch()}
        >
          {query.isFetching ? "正在刷新……" : "刷新证据"}
        </button>
      </header>

      {query.isRefetchError ? (
        <div className="overview-cache-warning" role="alert">
          <strong>刷新失败，下面是上一次成功读取的缓存。</strong>
          <span>这些状态现在都不能视为最新，请稍后再次刷新。</span>
        </div>
      ) : null}

      <p className="overview-generated-at">
        本页数据由服务端生成于 {formatTimestamp(data.generated_at)}。
      </p>

      <div className="overview-grid">
        <LocalRuntimeCard data={data.local} />
        <ModelCard data={data.model} />
        <CoordinatorCard data={data.coordinator} />
        <NetworkPathCard data={data.network_path} />
        <NodeList data={data.nodes} />
        <ServiceList data={data.services} />
      </div>
    </section>
  );
}
