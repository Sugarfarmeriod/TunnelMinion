## 1. 当前机器路线决定与真实证据

- [x] 1.1 保存正式 macOS package/入口摘要、Application Firewall、Murus、WireGuard/稳定 route、生产配置/SecretStore、8082/8787、进程与零自启动基线，不读取秘密正文
- [x] 1.2 用户明确选择 `local-firewall-authorization` 作为个人 A/B 首发路线，并通过 macOS 系统 UI 允许清单中的精确 `cee836…` 正式 executable；未自动添加、删除或扩大防火墙规则
- [x] 1.3 从 Windows A 对获准正式 Gateway 发出无 Authorization header 的有界请求，记录首次等待许可后的 `401`、稳定 85–100 ms 结果和零响应正文证据
- [x] 1.4 对照执行后不变性：Murus、WireGuard、稳定 route、配置、SecretStore、8082 和零自启动保持不变，只有获明确授权的精确 Application Firewall 条目发生预期变化
- [x] 1.5 记录旧 Python 开发环境已不可复现，当前安全入口为正式候选 direct Gateway；后续回退目标必须是“切换前已验证入口”，不得假设旧 `.venv` 可用

## 2. 范围收敛与运维边界

- [x] 2.1 更新 proposal/design/specs：当前机器人工授权为唯一首发 trust mode；Developer ID、hardened runtime、公证 ticket、签名后分发清单延期到未来对外分发 change
- [x] 2.2 把 macOS 本机 hairpin、真实总 deadline、本地生命周期与 peer 状态机移交 `fix-macos-gateway-runtime-health`，本 change 只保留 artifact/人工许可/peer `401` 信任证据
- [ ] 2.3 更新首次许可、拒绝、精确撤销、新 package/path 重新核对、失败回退和故障诊断文档；不提供自动防火墙写入命令，不要求开机自启
- [ ] 2.4 在隔离 package/非生产端口验证拒绝、撤销、重试和第二个 package/path 的人工许可行为；不得停止生产模型、读取生产 SecretStore 或修改 Murus/WireGuard/route

## 3. 架构图、质量门禁与交付

- [ ] 3.1 核对并按需更新主 FigJam 的当前机器人工防火墙许可、Developer ID/公证未来标记、外部模型、Coordinator 延期和 health fix 分工，并更新最后核对日期/当前历史标记；当前 Figma Starter MCP 调用上限阻止画布读取，解除后补做
- [ ] 3.2 运行 OpenSpec strict、文档链接、证据 JSON、秘密扫描和不变性门禁，确认本 change 没有运行时代码、防火墙自动写入、自启动或网络治理修改
- [ ] 3.3 提交并推送最终阶段，创建 PR；合并后将当前机器信任前置同步到主规格，并让 `package-manual-node-runtime` 只等待 health fix 与隔离模型测试
