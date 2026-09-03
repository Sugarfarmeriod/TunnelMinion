## 1. 隔离夹具

- [ ] 1.1 复用固定 `normal-refresh` 与 `loopback-listener` 场景，在 Windows 正式包夹具中生成零模型刷新证据和唯一已确认 incident
- [ ] 1.2 把 incident ID、离线 Provider 标识、正常刷新计数与安全边界写入无秘密夹具回执
- [ ] 1.3 扩展夹具定向测试，验证持久化 incident、零模型刷新和拒绝系统密钥访问

## 2. 正式产品体验

- [ ] 2.1 扩展现有正式包 Playwright 验收，验证 Overview incident 卡片及重复刷新
- [ ] 2.2 验证调查详情中的结论、停止原因、公开工具轨迹、未知项和建议问题

## 3. Windows 证据与清理

- [ ] 3.1 在 Windows 独立环回端口运行一次定向正式包验收并保存脱敏结果
- [ ] 3.2 核验自有进程停止、临时目录删除、现有实例和网络状态未改变
- [ ] 3.3 运行 OpenSpec strict、定向 Python/前端门禁并记录限制：未验证真实模型、真实自动发现、macOS 或双机 A/B
