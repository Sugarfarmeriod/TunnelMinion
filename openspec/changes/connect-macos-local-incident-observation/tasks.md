## 1. macOS 本机观察接线

- [x] 1.1 在 macOS 默认应用复用现有服务缓存和确定性 observer，并把刷新接入 incident 快照前置回调
- [x] 1.2 managed coordinator 已配置时不得创建第二个本机 observer

## 2. 定向验证

- [x] 2.1 增加最小测试，覆盖默认本机服务展示、首轮零 incident、稳定新增 incident 和 managed 单观察路径
- [ ] 2.2 在 Mac 临时目录与环回监听执行非特权真机验收，确认零模型调用和自有资源清理
- [ ] 2.3 运行定向 Python 门禁、OpenSpec strict、diff 与脱敏复核

## 3. 收尾

- [ ] 3.1 同步主规格、归档 change、提交推送、PR、CI 与合并
