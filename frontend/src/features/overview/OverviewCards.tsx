import { Link } from "react-router-dom";
import type { ResourceOverview } from "../../api/schemas/overview";
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
  static_peer_observation: "显式对端只读观察",
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

const platformLabels: Record<
  NonNullable<ResourceOverview["local"]["platform"]>,
  string
> = {
  windows: "Windows",
  macos: "macOS",
  linux: "Linux",
};

export function formatTimestamp(value: string | null): string {
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

export function stateTone(
  state: string,
  freshness: SectionMeta["freshness"],
): Tone {
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

export function collectionTone(
  meta: SectionMeta,
  itemTones: readonly Tone[],
): Tone {
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

export function StatusBadge({
  tone,
  children,
}: {
  tone: Tone;
  children: string;
}) {
  return (
    <span className={`overview-status overview-status--${tone}`}>
      {children}
    </span>
  );
}

function SectionMetadata({ meta }: { meta: SectionMeta }) {
  return (
    <details className="overview-metadata-disclosure">
      <summary>查看证据</summary>
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
        {meta.error === null ? null : (
          <div>
            <dt>稳定错误</dt>
            <dd>
              <code className="overview-error-code">{meta.error.code}</code>
            </dd>
          </div>
        )}
      </dl>
    </details>
  );
}

export function SectionCard({
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
  nextStep?: React.ReactNode;
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
      {nextStep === undefined ? null : (
        <div className="overview-next-step">
          <strong>建议：</strong>
          {nextStep}
        </div>
      )}
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
      ? undefined
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
    data.status === "available" ? undefined : data.status === "unconfigured" ? (
      <Link to="/app/settings">需要聊天时再去设置中配置模型。</Link>
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
      ? undefined
      : data.state === "unconfigured"
        ? undefined
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
  const nextStep =
    data.error?.code === "firewall_log_unavailable" &&
    data.probe.status === "passed"
      ? "真实探测已通过；防火墙日志不可用不影响当前路径判断。"
      : data.state === "unconfigured" ||
          data.state === "direct" ||
          data.state === "static" ||
          data.state === "relayed"
        ? undefined
        : "先看真实探测是否通过；不可达时检查 peer 程序和网络。";
  return (
    <SectionCard
      id="overview-network"
      meta={data}
      nextStep={nextStep}
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

export function RuntimeOverview({ data }: { data: ResourceOverview }) {
  return (
    <section aria-label="运行基础与数据来源">
      <h3>运行基础</h3>
      <div className="overview-grid overview-grid--system">
        <LocalRuntimeCard data={data.local} />
        <ModelCard data={data.model} />
        <CoordinatorCard data={data.coordinator} />
        <NetworkPathCard data={data.network_path} />
      </div>
      <details className="overview-source-details">
        <summary>数据来源与高级连接信息</summary>
        <h3>设备与服务的数据来源</h3>
        <ul aria-label="设备记录来源" className="overview-resource-list">
          {data.nodes.items.map((node) => (
            <li key={node.node_id}>
              <strong>{node.display_name}</strong>
              <p>
                {sourceLabels[node.source]} ·{" "}
                {formatTimestamp(node.evidence_at)} ·{" "}
                {freshnessLabels[node.freshness]}
              </p>
            </li>
          ))}
        </ul>
        <p>设备清单</p>
        <SectionMetadata meta={data.nodes} />
        <p>服务清单</p>
        <SectionMetadata meta={data.services} />
        <ul aria-label="连接明细" className="overview-resource-list">
          {data.services.items.map((service) => (
            <li key={service.service_id}>
              {service.application?.name ?? service.display_name ?? "程序"} ·{" "}
              {service.protocol?.toUpperCase() ?? "协议未知"}{" "}
              {service.port ?? "端口未知"} ·{" "}
              {service.access_address ?? "地址未知"}
            </li>
          ))}
        </ul>
      </details>
    </section>
  );
}
