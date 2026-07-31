# 常规 managed node 最终验收与证据边界（2026-07-31）

## 结论

Windows 与 macOS 常规本地应用的离线集成门禁通过。两端均按
`unconfigured → enrollment-required → ready → 重启后 ready` 收敛，稳定身份重复数为 0，三个
后台域都已进入常规应用组装，无模型配置时结果不变，资源状态未出现凭据、私钥、签名、指纹或
完整 endpoint。Gateway 配置没有被常规入口创建或修改。

本轮没有重跑真实 A/B 网络写入。2026-07-29 的历史真机报告能证明 Provider、握手、`/32`
route、目标探测、失败恢复和用户资源不变性，但当时的逐项授权不能自动延伸到本 change。要把
“常规入口真实跑过”也判为通过，仍需项目所有者重新批准隔离接口、地址、端口、数据目录、
Provider plan hash 和清理范围。

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
| 真实 A/B 常规入口与生产资源前后不变 | 只有历史 Provider/Coordinator 基线，缺本次新授权 | 待核对 |

## 可重复命令

```shell
uv run python scripts/run_managed_node_runtime_acceptance.py \
  --output evaluations/reports/managed-node-runtime-acceptance-2026-07-31.json --check
uv run python scripts/run_managed_connectivity_assurance.py \
  --output evaluations/reports/managed-connectivity-assurance-2026-07-31.json --check
uv run python scripts/security_scan.py --root .
uv run python scripts/quality.py all
openspec validate integrate-managed-node-runtime --strict
```

## 明确保留的边界

- 本轮没有修改或读取 `HomeMac`、B 手写 WireGuard 配置、Murus/防火墙、用户 route、生产
  Gateway `8787` 或模型 `8082`。
- Gateway 继续由独立命令和私网监听器启动；常规本地应用只绑定环回。
- managed desired config 没有本机 L3 授权时只缓存并显示待批准，模型不能提供授权。
- enrollment Web 向导、节点/服务成品卡片、系统服务安装与 Gateway managed 授权投影仍属于后续
  独立 change。
