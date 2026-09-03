## ADDED Requirements

### Requirement: Windows 正式产品必须通过隔离 incident 体验验收

评估系统 MUST 在 Windows 临时数据目录和独立 IPv4 环回端口启动现有正式产品包，复用固定离线场景生成一条调查完成的 incident，并通过真实 HTTP API 与 Overview 页面验证 incident 卡片、调查轨迹、结论、未知项和建议问题。验收 MUST 使用拒绝秘密访问的存储实现，MUST NOT 调用真实模型或修改网络状态，并 SHALL 在结束后停止自有进程和清理临时数据。

#### Scenario: Windows 用户在 Overview 查看离线调查结果

- **WHEN** 隔离夹具运行现有环回监听故障场景并启动 Windows 正式产品包
- **THEN** Overview 显示唯一 incident 卡片，详情显示已确认结论、公开只读工具轨迹、停止原因、未知项状态和建议问题

#### Scenario: 普通刷新不触发模型

- **WHEN** 隔离夹具运行现有正常刷新场景且浏览器重复请求 Overview
- **THEN** 验收报告记录 incident 数与模型调用数均为零，页面刷新成功且没有真实模型请求

#### Scenario: 验收保持本机安全边界

- **WHEN** Windows 隔离体验验收完成或失败
- **THEN** 产品只监听指定环回端口，系统密钥存储没有被读取，现有产品实例和网络配置未改变，自有正式包进程停止且临时目录可删除
