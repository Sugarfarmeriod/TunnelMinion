# 常规 managed node 最终验收与证据边界（2026-07-31）

## 结论

Windows 与 macOS 常规本地应用的离线集成门禁通过。两端均按
`unconfigured → enrollment-required → ready → 重启后 ready` 收敛，稳定身份重复数为 0，三个
后台域都已进入常规应用组装，无模型配置时结果不变，资源状态未出现凭据、私钥、签名、指纹或
完整 endpoint。Gateway 配置没有被常规入口创建或修改。

项目所有者批准精确验收清单后，真实 Windows A 与 macOS B 已在隔离数据目录完成常规入口验收。
两端 enrollment 均为 `ready`，目录修订共同收敛到 8，服务数分别为 148 与 33，managed config
均完成首次成功且模型状态均为 `unconfigured`。停止隔离 Coordinator 后，两端目录和 managed
config 均进入 `backoff`，本地资源继续可用；本轮没有请求或执行 Provider/L3 写入。

## 指标

| 指标 | 结果 | 证据 |
|---|---:|---|
| 常规入口平台 | Windows、macOS | `managed-node-runtime-acceptance-2026-07-31.json` |
| 身份重复数 | 0 | 同上 |
| 非法参数数 | 0 | 同上与全量测试 |
| 安全拦截率 | 100% | 同上与 assurance 故障矩阵 |
| 重启恢复成功率 | 100% | 同上与 runtime/checkpoint 测试 |
| 模型开关不变量 | 100% | 两份离线报告 |
| 汇聚/路径选择正确率 | 100% | `managed-connectivity-assurance-2026-07-31.json` |
| 真实 A/B 常规入口 | 通过 | `../platform/managed-node-runtime-real-ab-2026-07-31.json` |
| 全量语句/分支覆盖 | 100% / 100% | `uv run python scripts/quality.py test` |

组装耗时和峰值内存记录在 JSON 报告中，它们是当前 Windows 开发机的一次隔离测量，只用于发现
数量级回归，不是跨机器 SLA。同步延迟、切换时间和资源成本继续由 assurance 报告记录；真实
网络延迟仍应在获批 A/B 验收中单独测量。

## 场景—证据映射

| 场景 | 当前证据 | 结果 |
|---|---|---|
| 首次启动、待 enrollment、注册后常规入口 | 隔离常规入口报告；应用/CLI 测试 | 通过 |
| Windows/macOS 稳定身份重启 | 隔离常规入口报告；managed application 测试 | 通过 |
| Coordinator 离线与有界退避 | coordinator、runtime、network sync 测试 | 通过 |
| 服务出现/消失、权限不足、Docker 降级 | service observation 与 managed coordinator 测试 | 通过 |
| desired config 待本机批准 | governance、managed network runtime 测试 | 通过 |
| Provider 部分失败、回滚、所有权冲突 | assurance 数据集与两平台 Provider 测试 | 通过 |
| 无模型与确定性结果一致 | assurance 报告、应用无模型测试 | 通过 |
| static peer、操作到期与恢复不受控制面影响 | gateway/operation/evaluation 回归 | 通过 |
| 真实 A/B 常规入口与生产资源前后不变 | 本轮脱敏真实 A/B 报告 | 通过 |

真实验收脚本为 `scripts/run_managed_node_runtime_ab_acceptance.py`。默认模式只打印精确授权清单；
只有显式 `--execute-approved` 才会连接 A/B。Murus GUI 不提供可复制的 SHA-256，验收不要求
操作者手工导出；脚本自动比较 PF 与 macOS Application Firewall 的可观察状态，并记录非交互权限
限制和零防火墙写入边界。`HomeMac` 基线不满足时会在创建远端临时状态前快速失败；生产
`8082`、`8787` 只保存并比较前后状态，不要求为了验收临时启动。

本轮报告的 `production_unchanged`、`production_baseline_valid`、`automated_passed` 和 `passed`
均为 `true`。`HomeMac` 服务/适配器、Windows `10.77` route 摘要、B WireGuard 状态摘要、
Application Firewall 摘要和生产端口状态前后相同；`8082`、`8787` 前后均为关闭。PF 规则读取
返回码前后均为 1，因此报告只证明可观察状态未变和零写入，不声称读取了 Murus GUI 或 PF 规则正文。

## 可重复命令

```shell
uv run python scripts/run_managed_node_runtime_acceptance.py \
  --output evaluations/reports/managed-node-runtime-acceptance-2026-07-31.json --check
uv run python scripts/run_managed_connectivity_assurance.py \
  --output evaluations/reports/managed-connectivity-assurance-2026-07-31.json --check
uv run python scripts/run_managed_node_runtime_ab_acceptance.py \
  --ssh-target 10.77.0.1 \
  --remote-python /Users/mac/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3.12 \
  --execute-approved \
  --output evaluations/platform/managed-node-runtime-real-ab-2026-07-31.json
uv run python scripts/security_scan.py --root .
uv run python scripts/quality.py all
openspec validate integrate-managed-node-runtime --strict
```

## 明确保留的边界

- 本轮只读取 `HomeMac`、B WireGuard 配置元数据、route/防火墙摘要和生产端口状态；没有读取
  配置正文，也没有修改这些资源、Murus、Gateway `8787` 或模型 `8082`。
- Gateway 继续由独立命令和私网监听器启动；常规本地应用只绑定环回。
- managed desired config 没有本机 L3 授权时只缓存并显示待批准，模型不能提供授权。
- enrollment Web 向导、节点/服务成品卡片、系统服务安装与 Gateway managed 授权投影仍属于后续
  独立 change。
