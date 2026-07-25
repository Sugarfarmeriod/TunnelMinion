# Verified Playbook 候选数据结构

本 change 只定义将来可沉淀的经验边界，不实现检索、RAG、共享、自动执行或权限扩大。

```json
{
  "schema_version": 1,
  "playbook_id": "playbook_...",
  "title": "临时共享已确认的环回 HTTP 服务",
  "applicability": {
    "platform": "macos",
    "operation_name": "share_local_http_service",
    "operation_level": "L2",
    "required_service_state": "local-only",
    "maximum_duration_seconds": 3600
  },
  "required_evidence": [
    {
      "kind": "network_listener",
      "freshness_seconds": 30,
      "identity_fields": ["node_id", "address", "port", "process_pid", "process_name"]
    }
  ],
  "action_boundary": {
    "allowed_effect": "create_tunnelminion_owned_http_proxy",
    "forbidden_effects": [
      "modify_service",
      "restart_service",
      "control_docker",
      "modify_wireguard",
      "modify_firewall"
    ]
  },
  "verification": {
    "owner": "request_node",
    "path": "wireguard",
    "accepted_statuses": [200, 399]
  },
  "rollback": {
    "ownership_match_required": true,
    "on_verification_failure": "immediate",
    "on_expiry": "automatic"
  }
}
```

只有一次合规、正确、完整并通过独立验证的操作才有资格成为候选记录。记录不得包含临时凭据、
认证头、模型隐藏推理、用户私密正文或可以绕过治理的命令。未来即使加入检索，Playbook 也只能
帮助生成候选计划，不能自动创建预授权或提高操作等级。
