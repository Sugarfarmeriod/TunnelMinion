import type { IncidentDetail } from "../../api/schemas/overview";

const stopReasonLabels = {
  evidence_sufficient: "证据充分",
  insufficient_evidence: "证据不足",
  budget_exhausted: "预算已用完",
  cancelled: "用户取消",
  failed: "调查失败",
  interrupted: "运行中断",
  model_unavailable: "模型不可用",
} as const;

const phaseLabels = {
  collecting: "正在收集证据",
  reporting: "正在整理报告",
  finished: "调查已停止",
} as const;

const stepStatusLabels = {
  pending: "等待执行",
  attempted: "已尝试，结果待确认",
  succeeded: "工具执行成功",
  failed: "工具执行失败",
} as const;

const executionLabels = {
  requester: "请求节点",
  target: "目标节点",
} as const;

type Incident = IncidentDetail["incident"];
type Evidence = NonNullable<
  Incident["investigation"]
>["steps"][number]["evidence"];

function EvidenceDetails({ evidence }: { evidence: NonNullable<Evidence> }) {
  return (
    <details className="investigation-evidence">
      <summary>查看公开证据引用</summary>
      <dl>
        {evidence.snapshot_id === null ? null : (
          <div>
            <dt>快照 ID</dt>
            <dd>{evidence.snapshot_id}</dd>
          </div>
        )}
        {evidence.tool_run_id === null ? null : (
          <div>
            <dt>工具运行 ID</dt>
            <dd>{evidence.tool_run_id}</dd>
          </div>
        )}
        <div>
          <dt>摘要</dt>
          <dd>{evidence.summary}</dd>
        </div>
        <div>
          <dt>观测时间</dt>
          <dd>{evidence.observed_at}</dd>
        </div>
      </dl>
    </details>
  );
}

function TextList({ empty, items }: { empty: string; items: string[] }) {
  return items.length === 0 ? (
    <p>{empty}</p>
  ) : (
    <ul>
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}

export function InvestigationDetails({ incident }: { incident: Incident }) {
  const investigation = incident.investigation;
  const facts = investigation?.facts ?? incident.report?.facts ?? [];
  const unknowns = investigation?.unknowns ?? incident.report?.unknowns ?? [];
  const stopReason =
    investigation === null || investigation === undefined
      ? incident.report?.stop_reason
      : investigation.stop_reason;
  const stopReasonLabel =
    stopReason === undefined || stopReason === null
      ? investigation?.phase === "collecting" ||
        investigation?.phase === "reporting"
        ? "调查进行中"
        : "未记录停止原因"
      : stopReasonLabels[stopReason];

  return (
    <>
      <h4>调查详情</h4>
      <p>
        <strong>结论：</strong>
        {incident.report?.conclusion ?? "尚未确认根因"}
      </p>

      {investigation === null || investigation === undefined ? (
        <p className="overview-empty">
          暂未记录结构化调查过程，下面保留已有的公开轨迹和报告。
        </p>
      ) : (
        <section aria-labelledby="investigation-state-title">
          <h5 id="investigation-state-title">结构化调查状态</h5>
          <p className="overview-explanation">
            调查会按 Skill 调用允许的只读工具，并记录可核验的公开证据。
          </p>
          <dl className="investigation-summary">
            <div>
              <dt>Skill</dt>
              <dd>
                {investigation.skill_id}@{investigation.skill_version}
              </dd>
            </div>
            <div>
              <dt>当前阶段</dt>
              <dd>{phaseLabels[investigation.phase]}</dd>
            </div>
            <div>
              <dt>已用模型轮次</dt>
              <dd>{investigation.model_rounds}</dd>
            </div>
            <div>
              <dt>已用工具调用</dt>
              <dd>{investigation.tool_calls}</dd>
            </div>
          </dl>

          <h5>调查步骤</h5>
          {investigation.steps.length === 0 ? (
            <p>尚未记录调查步骤。</p>
          ) : (
            <ol className="investigation-steps">
              {investigation.steps.map((step) => (
                <li key={step.step_id}>
                  <div className="investigation-step__heading">
                    <strong>{step.tool_name}</strong>
                    <span>{stepStatusLabels[step.status]}</span>
                  </div>
                  <p>
                    {executionLabels[step.execution]}执行 · 已尝试{" "}
                    {step.attempts} 次
                  </p>
                  <p className="investigation-step__id">步骤 {step.step_id}</p>
                  {step.failure_code === null ? null : (
                    <p>失败代码：{step.failure_code}</p>
                  )}
                  {step.evidence === null ? (
                    <p>尚无公开证据引用。</p>
                  ) : (
                    <EvidenceDetails evidence={step.evidence} />
                  )}
                </li>
              ))}
            </ol>
          )}
        </section>
      )}

      <h5>已知事实</h5>
      <TextList empty="尚无已确认事实。" items={facts} />
      <h5>仍未知</h5>
      <TextList empty="没有已记录的未知项。" items={unknowns} />
      <p>
        <strong>停止原因：</strong>
        {stopReasonLabel}
      </p>

      <h5>公开调查轨迹</h5>
      {incident.trace.length === 0 ? (
        <p>尚无工具或报告轨迹。</p>
      ) : (
        <ol>
          {incident.trace.map((item, index) => (
            <li key={`${item.occurred_at}-${index}`}>{item.summary}</li>
          ))}
        </ol>
      )}
    </>
  );
}
