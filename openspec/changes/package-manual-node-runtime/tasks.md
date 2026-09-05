## 1. 现场重定基线

- [x] 1.1 核对 `main` 已有 runtime profile、预检、进程所有权、公开生命周期、版本切换、双平台冻结构建和测试，不重复实现
- [x] 1.2 下载成功 CI 的 Windows 正式 artifact，在无源码目录复现“configure 成功、start 因缺少包内清单失败”，并验证补入原始清单后完整生命周期可用
- [x] 1.3 确认用户收益与完成标准，把生产 A/B、Provider、relay、自动组网、showcase、系统服务和模型管理排除在本阶段之外

## 2. 自包含归档与真实用户路径

- [ ] 2.1 暂存正式包时嵌入与外部证据逐字节一致的 `runtime-package-manifest.json`，保持文件集合闭合和篡改拒绝，并补最小回归测试
- [ ] 2.2 让干净环境门禁解包实际上传归档，只通过公开 CLI 验证 configure/start/重复 start/status/HTTP/stop 以及 Gateway 临时配置，不再用内部 `runtime-child` 冒充用户流程
- [ ] 2.3 通过公开 runtime-package 命令验证 stage/activate/status/remove，证明数据目录与 SecretStore 默认保留
- [ ] 2.4 修正顶层 `--help` 展开全部端口值，补齐无需 Python/uv/源码的下载包最短使用说明与故障提示

## 3. 双平台验收与独立裁决

- [ ] 3.1 运行格式、类型、定向 runtime/打包测试、全量测试和 OpenSpec strict validation
- [ ] 3.2 从同一提交构建并实际消费 Windows amd64、macOS arm64 正式归档，保存清单、公开生命周期、数据保留和零秘密证据
- [ ] 3.3 创建独立、干净的只读审计任务复核精确提交、范围、安全边界和证据；修复后复审至通过

## 4. 单 PR 合并与归档

- [ ] 4.1 推送范围清晰的阶段提交并创建一个 PR，等待全部 CI 成功
- [ ] 4.2 同步主规格、归档 `package-manual-node-runtime`，以 squash 合并到 `main` 并清理本阶段分支/worktree
