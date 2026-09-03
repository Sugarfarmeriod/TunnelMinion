## 1. Windows 本机观察接线

- [x] 1.1 让 incident 周期可在组装快照前刷新一个完整本机服务缓存，并验证首份结果只建立基线
- [x] 1.2 让 Overview 接受现有本机服务快照来源，保持未传入时的 managed 行为不变
- [x] 1.3 在 Windows 默认应用复用既有确定性服务观察器；managed 已配置时不得启动第二个采集路径

## 2. 定向验证

- [x] 2.1 增加最小定向测试，覆盖未配置 Coordinator 的本机服务展示、正常刷新零模型和稳定新增 incident
- [x] 2.2 在隔离数据目录与临时环回监听上验证真实后台自动发现，确认不触碰现有 8767
- [x] 2.3 运行定向 Python 门禁、OpenSpec strict、diff 与秘密复核并记录结果

验收记录：81 条受影响回归通过，ruff 与 pyright 通过，OpenSpec strict 通过；真实本机基线 186 个服务且启动 incident 为 0，新增临时 listener 形成 `service_added`/`investigation_unavailable`，刷新 HTTP 超时为 0，8767 前后监听数均为 1，临时目录已删除。
