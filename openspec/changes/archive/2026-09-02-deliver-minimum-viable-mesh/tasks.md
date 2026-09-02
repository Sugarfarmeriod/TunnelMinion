## 1. 当前状态审计

- [x] 1.1 对照 proposal、design、四份 delta spec、主规格和当前代码，识别旧前提与重复范围
- [x] 1.2 对照已归档 `coordinate-agent-network` 和 `manage-wireguard-connectivity` 的任务与验收证据
- [x] 1.3 将旧规划内容分为已经实现、仍然缺失、已被替代和应拆成独立 change 四类

## 2. 规划收敛

- [x] 2.1 明确本 change 不再作为实现或主规格同步来源
- [x] 2.2 为四份历史 delta spec 标注当前规范归属和剩余缺口
- [x] 2.3 将默认运行时接线、packet relay、Linux Provider、产品体验和安装分发划为独立主题
- [x] 2.4 确认下一个最小交付建议为 `integrate-managed-node-runtime`

## 3. 后续边界

- [x] 3.1 保留 `build-isolated-packet-relay` 为独立安全敏感 change，不在本 change 实现
- [x] 3.2 保留 Linux Provider 为独立 change，不把第三平台加入默认运行时接线范围
- [x] 3.3 保留产品 UI 与安装分发为后续独立 change，不在本 change 实现
- [x] 3.4 记录需要用户确认的运行形态、enrollment 入口、服务来源、验收环境和 relay 基础设施问题

本任务表只跟踪本次规划审计。任何功能实现必须先建立与主题匹配的新 change；不得对本 change
执行 `/opsx:apply`。
