# Mac 新版隔离页面：真实模型服务自动精选

- 状态：`已完成`（证据 PR 最终门禁通过并合并后生效）
- 主写分支：`docs/model-service-live-view`
- 基线：`c66d988394539050905a0d66e75e19e3c3309bb3`

## 用户影响与授权

用户明确允许经 SSH 在 Mac 的新目录和空闲端口启动新版隔离页面，看自动识别的实际效果。不动 Qwen 和旧页面，不复制模型凭据，不发推理请求、不开放新远端入口。

新页面地址是 Mac 本机 `http://127.0.0.1:18767/app/overview`，已通过 Mac 的 `open` 命令打开。该地址不代表 Windows 可访问；没有建立 SSH 转发或改绑定。页面留给用户查看，不宣称已得到用户的易用性认可或老人用户实测。

## 部署与真实证据

部署目录 `/Users/mac/Working-Env/tunnelminion-20261009-model-view` 启动前不存在，18767 无监听。使用 PR #114 [CI 8/8 通过的 macOS arm64 正式包](https://github.com/Sugarfarmeriod/TunnelMinion/actions/runs/37789091352)，实现 head `b0e716f169dd7958f4379e2b47f5b97690615988`，未手改包。

正式包源码输入摘要与当前主线代码一致：`459b5a877c13f9771459c95148a738c3b67f83a6366bce3ed15f892e192b50c2`。通过已有 `runtime configure/start` 创建独立 profile 和数据目录，只启用 local；原生启动前 package/profile/data-dir 校验通过。model 为 `unconfigured`、gateway 为 `disabled`、managed 为 `unconfigured`，这些是刻意的隔离条件，不复制旧凭据或接入配置。

北京时间 2026-10-09 00:54:22，新页面真实总览 GET HTTP 200，服务证据时间为 00:54:10，freshness 为 `fresh`。服务 `service_aae8cc91b632075cfab0d49e2172301c`：

- 名称：`模型服务 · llama.cpp · 8080`
- 状态：`available`，归属新鲜度 `fresh`
- 访问类别：`network`，不误称仅本机监听
- 本次共检测 33 项，10 项有可靠名称；后台项仍保留而非删除

这是正式新包实际运行的 API 证据，不是前端 fixture，不是只有源码规则测试。实际浏览器打开命令成功，但没有采集 Mac 屏幕截图或替用户点击展开设备，不冒充已经目视核验其浏览器画面。具体 Qwen 型号不写入自动名称；模型服务发现不等于推理、鉴权或远端访问已验收。

## 资源与交接

新本机页面 PID `31603` 监听 `127.0.0.1:18767`；Qwen PID `33870` 仍监听 8080，旧页面 PID `95881` 仍监听 18765。未创建 Gateway、共享租约、系统自启动或管理员规则，未改 WireGuard、防火墙、路由及 DNS。

新本机页面按用户查看目的保持运行；它不是已清理资源。只停止本次页面时，使用其独立 profile，避免按名称批量杀进程：

```sh
/Users/mac/Working-Env/tunnelminion-20261009-model-view/package/package/tunnelminion runtime stop --profile /Users/mac/Working-Env/tunnelminion-20261009-model-view/profile.json
```

不停止旧页面或模型，不删除旧目录。包和数据保留供用户查看；下次若要长期替换旧实例、远端接入或实际推理，须重新明确范围。

## 验收

- [x] CI 正式包及来源摘要匹配，原生闭合集合/平台/入口预检通过。
- [x] 新独立目录、仅本机端口、无模型/网关配置，原服务保留。
- [x] 真实模型服务自动出现在总览，名称、状态与访问类别有证据。
- [x] Mac 浏览器已打开，脱敏结果及停止方式可追溯。
- [x] 一个证据 PR，完成状态在最终门禁通过并合并后生效。
