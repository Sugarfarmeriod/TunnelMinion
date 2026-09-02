# 实施文件所有权

本表用于防止并行线程同时修改共享文件。跨 owner 变更必须交回 integration owner 串行整合。

| Workstream | 单一 owner | 允许写入 |
| --- | --- | --- |
| Integration / Foundation | integration owner | `frontend/package*.json`、工具链配置、`frontend/src/app/**`、`frontend/src/api/**`、design tokens、CI、Python 应用工厂、共享路由、OpenSpec tasks |
| Web request guard | security owner | `src/tunnelminion/web/request_guard.py`、`tests/web/test_request_guard.py` |
| Overview contracts | overview API owner | `src/tunnelminion/web/overview.py`、`tests/web/test_overview.py` |
| Overview adapters | application assembly owner | `src/tunnelminion/web/application_views.py`、`tests/web/test_application_views.py` |
| Operation detail | operation API owner | `src/tunnelminion/web/operations.py`、`tests/web/test_operation_control.py` |
| Overview UI | overview feature owner | `frontend/src/features/overview/**` |
| Chat UI | chat feature owner | `frontend/src/features/chat/**` |
| Operations UI | operations feature owner | `frontend/src/features/operations/**` |
| Memories / Settings UI | memories/settings feature owner | `frontend/src/features/memories/**`、`frontend/src/features/settings/**` |
| Package audit | read-only owner | 不写 builder、manifest 或 package 配置；只提交审计结论与隔离 harness 建议 |

共享 API client/schema、公共路由、Python 应用工厂、package manifest 生成器和本文件始终由 integration
owner 修改。功能切片进入集成分支的顺序固定为 Overview → Chat → Operations → Memories/Settings；每次
整合后重跑前端、Python 与浏览器门禁。
