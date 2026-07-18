# macOS B 节点只读不变性验收

- 日期：2026-07-18
- 节点：B（macOS，WireGuard `10.77.0.1`）
- Python：3.12
- 工具序列：WireGuard、监听端口、进程、Docker、TCP 可达性、节点摘要
- 结果：通过

## 执行命令

```shell
PYTHONPATH=src:.runtime python3.12 scripts/macos_invariance.py \
  --probe-host 10.77.0.2 --probe-port 8082
```

验收程序不读取 WireGuard 配置正文或私钥，只比较配置文件的路径、大小、修改时间与权限，
并比较 WireGuard 进程、接口、稳定接口字段和相关路由。流量计数等自然变化字段不参与比较。

## 前后不变证据

| 对象 | 调用前 | 调用后 | 结论 |
|---|---|---|---|
| `wg0.conf` 元数据 | 951 bytes，mode 644，mtime_ns `1783690793704873363` | 相同 | 未改变 |
| `wireguard-go` | PID 73924 | PID 73924 | 未重启或停止 |
| WireGuard 接口 | `utun4` | `utun4` | 未改变 |
| 稳定接口字段 SHA-256 | `4668a2c2…36a77` | `4668a2c2…36a77` | 未改变 |
| 相关路由集合 | 15 条 | 同一 15 条 | 未改变 |

## 工具结果

| 工具 | 状态 | `tool_run_id` |
|---|---|---|
| `get_wireguard_status` | success | `toolrun_6b5aadbdb25e4f69aaaf132fa073090f` |
| `list_network_listeners` | success | `toolrun_ea12f582f1c946b797e1678a74357639` |
| `get_process_summary` | success | `toolrun_39363b1ac53245119960c1bf1bcf1130` |
| `list_docker_services` | success | `toolrun_0d7d9943dcc142e59c18782ca6a7d430` |
| `probe_service_reachability` | success | `toolrun_248823b4f0064a9fb52800d04eef4727` |
| `get_node_summary` | success | `toolrun_022bf468e3de4a6489b29b6f2e0dde51` |

第一次真机运行发现 macOS 的 `psutil.net_connections` 会抛出 `psutil.AccessDenied`；平台边界
现已将其转换为结构化权限降级。修复后普通账户能够获得可用监听结果，且完整工具序列没有改变
现有手写 WireGuard 配置或终端启动的 `wireguard-go` 生命周期。
