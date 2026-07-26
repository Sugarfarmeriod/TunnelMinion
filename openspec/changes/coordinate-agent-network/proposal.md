## Why

TunnelMinion 已能通过手工配置的 A/B peer 完成跨节点诊断和安全操作，但节点地址、Gateway
凭据、能力与服务仍散落在各节点本地配置中；新增、离线或撤销节点时无法自动收敛。现在需要
一个自托管、无模型依赖的 Coordinator 控制面，让 Agent 动态发现“有哪些已授权节点、当前
是否在线、能调用哪些能力、有哪些新鲜服务”，同时继续复用并保护现有 WireGuard 数据面。

## What Changes

- 新增自托管 Coordinator，管理单所有者私有网络内的节点注册、短期 enrollment token、
  长期 refresh 凭据、短期签名访问 assertion、撤销、协议版本与在线状态。
- 新增 Agent 控制面客户端，周期性发送有界心跳、工具能力摘要和脱敏服务快照，并以修订号
  拉取增量目录；断线后使用本机身份恢复，不创建重复节点。
- 新增带新鲜度的节点、能力和服务目录；节点离线、快照过期或服务消失时确定性收敛，不依赖
  大模型判断。
- 让跨节点诊断可以按稳定节点 ID 从目录解析当前 Gateway endpoint 和兼容工具版本，再继续
  使用节点间直连 Gateway；Coordinator 不代理工具正文或操作流量。
- 让 Agent 只从当前在线、已授权、版本兼容且适合任务阶段的能力中构造动态工具集合。
- 提供仅限本机管理员使用的 enrollment token 创建、节点查看和撤销 API；所有普通日志、
  目录与模型上下文排除完整 token、节点密钥、模型密钥、记忆和远端工具正文。
- 建立双 Coordinator 实例隔离、token 重放、节点撤销、心跳超时、乱序快照、目录过期、
  协议不兼容、Coordinator 离线和 A/B 真机迁移评估。
- 本 change 不创建或修改 WireGuard 接口、密钥、peer、路由或防火墙，不实现自动虚拟地址
  分配、中继、Linux Provider、公共 SaaS、多租户、企业 RBAC、L3 操作或新前端。

## Capabilities

### New Capabilities

- `coordinator-node-registry`: 自托管 Coordinator 的 enrollment token、节点身份、重连、
  撤销、协议版本与在线状态。
- `coordinator-client-sync`: Agent 与 Coordinator 之间有界、可取消、带修订号的心跳、
  能力与服务快照同步，以及离线降级。
- `coordinator-service-directory`: 按网络和节点隔离、带来源与新鲜度的节点、能力和服务目录，
  包括完整快照收敛和安全查询。

### Modified Capabilities

- `cross-node-diagnostics`: 从已验证目录按稳定节点 ID 解析当前直连 Gateway 与兼容能力，
  同时保留显式静态 peer 的安全迁移回退。
- `node-tool-runtime`: 动态远端工具集合增加节点在线、授权、平台、协议版本和任务阶段过滤，
  并记录目录修订与选择原因。

## Impact

- 新增 `coordinator` 应用边界、SQLite 控制面存储、签名密钥与验证公钥生命周期、版本化 HTTP
  协议模型、Agent 后台同步器和本机管理员 API。
- 扩展 Windows/macOS 应用组装、远端 peer 解析、动态工具加载、资源 API、审计和评估脚本；
  不改变现有模型 Provider、ContextBuilder、Tool/Operation Gateway 或临时服务共享执行协议。
- A/B 首次迁移继续使用现有 `10.77.0.1` WireGuard 地址和 Gateway `8787`，Coordinator 只
  分发应用层目录，不成为工具或服务数据面的中继。
- Coordinator 故障时，已配置的静态 peer、确定性本地工具、资源面板、已有操作状态和租约
  清理继续工作；目录明确标记陈旧，不把缓存状态伪装为实时事实。
