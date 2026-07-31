## Context

Coordinator 和受管网络 change 已交付可复用组件，但它们尚未进入常规节点组装：

- `AgentCoordinatorSynchronizer` 已能认证心跳、提交能力/服务完整快照、拉取目录修订并退避；
- `ManagedNetworkSynchronizer` 已能验签 desired config、保存 pending/last-known-good、确认阶段和降级；
- Windows/macOS 本地应用已具备只读工具、环回资源页、聊天、记忆和操作控制；
- `scripts/run_coordinator_managed_node.py` 证明这些组件可以在隔离 A/B 验收中组合，但脚本硬编码
  身份、服务和同步循环，不能作为日常产品入口。

本 change 的难点不是新协议，而是生命周期、秘密、跨平台服务观察和失败隔离。常规本地页面只
绑定环回地址；Tool/Operation Gateway 继续使用独立私网监听入口，不能为了简化接线而把两种
攻击面合并。

## Goals / Non-Goals

**Goals:**

- 为 Windows/macOS 提供同一份无秘密 managed node 配置和一次性 enrollment CLI。
- 由常规本地应用 lifespan 托管 Coordinator、服务快照和 managed config 后台任务。
- 复用现有确定性工具生成服务目录，不要求模型可用。
- 让后台任务可停止、可重启恢复、可观测，并与本地页面/static peer/操作恢复故障隔离。
- 用 fake、进程重启和隔离 A/B 证据证明常规入口闭环。

**Non-Goals:**

- 不把本地页面与私网 Gateway 合并到同一监听器；Gateway 继续独立启动。
- 不实现 Linux、packet relay、NAT 穿透、公共控制面或新前端框架。
- 不改变 Coordinator、Provider、L0～L4、目标节点批准或资源所有权语义。
- 不自动 apply 尚未获得本机 L3 授权的 desired config。
- 不迁移生产 A/B 数据面，不修改防火墙、Murus、DNS、用户路由或第三方 WireGuard 配置。

## Decisions

### 1. 配置与秘密分离

新增版本化 `ManagedNodeConfig`，保存在节点数据目录的普通配置中，只包含：启用状态、Coordinator
endpoint、network/node、Gateway endpoint、固定验证指纹、同步/退避预算、服务来源开关和协议
版本。refresh 凭据继续由 `AgentRefreshCredentialStore` 保存到 keyring 或显式选择的受限文件
秘密存储；enrollment token 只从标准输入读取并在成功或失败后清空引用。

配置使用 `extra="forbid"`、原子替换和安全导出允许列表。普通启动若只存在配置而没有 refresh，
进入 `enrollment-required`，不得反复消费 token 或静默创建新身份。

否决方案：把 token/refresh 写进 JSON 或环境变量。两者容易进入进程列表、日志、备份和支持包。

### 2. enrollment 是一次性 CLI，不是启动副作用

新增显式 `coordinator-enroll` 命令。管理员先写入无秘密配置并确认固定指纹，再通过标准输入提供
token；命令调用现有 `CoordinatorEnrollmentClient`，成功后只输出 node/network、指纹和稳定
状态摘要。普通 `tunnelminion` 启动从不尝试 enrollment，避免服务重启消费 token 或在错误
Coordinator 上注册。

首版不在 Web 页面输入 token。环回页面未来可以增加引导，但必须另行审查浏览器缓存、CSRF 和
屏幕暴露风险。

### 3. 本地应用 lifespan 托管一个 `ManagedNodeRuntime`

建立平台无关的运行时外壳，拥有：

- Coordinator 目录同步循环；
- 服务观察与快照生成器；
- managed config 拉取/验签循环；
- 可取消任务组、状态聚合和受控停止。

Windows/macOS 应用工厂在 managed config 启用时注入该运行时，并通过 FastAPI lifespan 启动。
停止顺序为：停止接收新同步轮次 → 设置取消信号 → 等待安全点 → 持久化 checkpoint/status →
关闭 HTTP 客户端。停止超时只记录稳定错误，不能强制执行或回滚未知 Provider 步骤。

Gateway 继续独立进程和私网监听。它消费现有 static 配置或未来由持久化授权投影提供的 managed
身份；本 change 不为简化生命周期而让环回应用监听 WireGuard 地址。

否决方案：在 CLI 外层使用无监督 `asyncio.create_task`。该方案在 Uvicorn 重载、测试和进程停止
时容易泄漏任务，无法证明 checkpoint 已保存。

### 4. 服务观察使用现有适配器并生成完整快照

每轮按固定顺序调用监听端口、进程和可选 Docker 只读工具，通过新的平台无关快照组装器关联
稳定 service ID、协议、规范地址/端口、可访问性、来源、置信度、观测时间和生命周期。权限不足
或 Docker 不可用只降级对应来源；完整快照仍提交可证明的数据。

默认启用监听与进程来源，Docker 为 best-effort 可配置来源；主动 HTTP/协议探测默认关闭。
快照生成受单并发、超时、记录数、字节和最小刷新间隔限制，不读取环境变量、完整命令行、响应
正文、文件、对话或记忆。

服务消失由下一份完整快照收敛；生成失败不得提交不完整快照冒充完整事实，而是保留上次服务器
修订并显示 `observation-degraded`。

### 5. managed config 只接到既有治理入口

运行时使用现有 `ManagedNetworkSynchronizer` 拉取并验签配置，将合法下一 revision 保存为
pending。没有本机 L3 授权时只显示 `awaiting-authorization`；授权存在时也必须经过现有
plan/apply/verify/rollback/recover 和 acknowledgement 边界。模型、对话、记忆和服务目录不能
构造 desired config、授权或 Provider 调用。

首次集成测试默认注入 fake Provider。真实 A/B 只复用已经批准的独立接口和地址；本 change 不
产生新的生产写授权。

### 6. 后台故障采用分域状态而不是全局离线

运行时分别维护 enrollment、directory sync、service observation、managed config 和 data-plane
状态。Coordinator 离线时目录/控制面显示 stale/backoff，但本地工具、页面、static peer、
last-known-good、操作到期与恢复继续运行。模型不可用只影响 AI 对话。

一个循环崩溃时，监督器记录脱敏稳定错误并按预算重启该循环；连续失败达到上限后保持 degraded，
不形成无界重启风暴。进程级未知异常使应用启动失败关闭，而不是以“全部正常”继续运行。

### 7. 资源 API 展示统一脱敏视图

扩展现有环回资源 API，返回 managed node 总览及分域状态：配置/注册、last success、revision、
快照计数、退避、pending/applied revision、授权、last-known-good、服务来源降级和稳定错误。
响应禁止 token、refresh、assertion、签名正文、私钥、完整 endpoint、配置正文和用户路由。

首版继续使用现有轻量 JSON 页面，不在本 change 重写产品 UI；页面必须能让用户区分“本地可用但
控制面离线”“尚未 enrollment”“配置待本机批准”和“服务观察降级”。

### 8. 验收顺序先 fake/重启，再隔离 A/B

先用内存 Coordinator/fake Provider 和临时数据目录覆盖 Windows/macOS 相同契约，再进行进程
停止/重启恢复测试。真实 A/B 只验证常规入口替代专用脚本后的 enrollment、目录/服务收敛、
无模型、Coordinator 离线和资源页状态；网络前后不变性沿用现有基线。

## Risks / Trade-offs

- [一个进程内多个后台循环互相拖累] → 独立超时/退避、单并发、任务监督和分域状态。
- [服务观察把敏感元数据同步出去] → 固定允许字段、完整快照预算、主动探测默认关闭和零秘密测试。
- [启动时误执行 L3 配置] → 普通启动只拉取/验签；写入仍必须通过现有本机授权和 Provider 治理。
- [Windows/macOS 停止语义不同] → lifespan 契约测试、取消安全点和平台适配层外的统一监督器。
- [Gateway 与本地应用仍是两个进程，部署稍复杂] → 保留清晰监听/攻击面边界；安装编排留给独立打包 change。
- [A/B 专用脚本与常规入口短期并存] → 验收完成后脚本只保留证据用途，文档以常规入口为准。

## Migration Plan

1. 增加配置、状态、运行时监督器和 fake 依赖，不启用真实网络写入。
2. 增加 enrollment CLI、秘密存储选择和安全导出/卸载覆盖。
3. 接入 Coordinator 目录同步与确定性服务快照，保持 managed config 只读/pending。
4. 接入既有 managed network 同步、治理和资源状态，使用 fake Provider 完成故障矩阵。
5. 分别接入 Windows/macOS 应用 lifespan，验证无配置时行为完全不变。
6. 在隔离 A/B 数据目录用常规入口替代专用 managed-node 脚本，保存前后不变性证据。
7. 回滚时停用 managed config 并停止后台任务；保留 refresh/checkpoint 供诊断或经显式卸载删除，
   不拆除 last-known-good 或用户网络资源。

## Open Questions

- 常规 Gateway 的 managed 授权缓存后续采用同进程同步还是持久化只读投影，本 change 只保证本地
  应用运行时与现有 Gateway 边界不冲突，不扩大 Gateway 监听范围。
- 成品化 enrollment 向导、节点/服务卡片和安装服务管理留给后续产品体验与打包 change。
