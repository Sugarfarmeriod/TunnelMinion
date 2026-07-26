# Coordinator Ed25519 assertion 安全 spike

日期：2026-07-26

## 结论

首版固定使用 `PyJWT 2.13.x` 与 `cryptography` 的标准 Ed25519/EdDSA JWT，不自定义签名格式。
项目直接声明 `pyjwt[crypto]>=2.13,<3`，避免密码学后端只是其他依赖的偶然传递依赖。

选择依据：

| 候选 | 结果 | 原因 |
| --- | --- | --- |
| PyJWT 2.13 | 采用并执行 spike | 官方文档明确支持 Ed25519 `EdDSA`，可固定 `algorithms=["EdDSA"]`，并验证 audience、issuer、exp 和 required claims；当前项目只需要紧凑 JWT |
| Authlib | 暂不采用 | 提供更广的 JOSE/OAuth 能力，但本阶段不需要 OAuth 客户端/服务端栈；引入面更大且没有增加当前协议所需约束 |
| python-jose | 暂不采用 | 当前项目未安装，且本 spike 没有获得比 PyJWT 更明确的 Ed25519、类型和维护收益，不为“多一个实现”扩大依赖面 |

参考：

- [PyJWT EdDSA 使用文档](https://pyjwt.readthedocs.io/en/stable/usage.html#encoding-decoding-tokens-with-eddsa-ed25519)
- [PyJWT API 与固定算法安全警告](https://pyjwt.readthedocs.io/en/stable/api.html)
- [cryptography Ed25519 文档](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)

## 固定协议

- JOSE header：`alg=EdDSA`、`typ=JWT`、管理员信任集合中的 `kid`。
- claims：`iss`、`sub`（node ID）、`net`（network ID）、`aud`、`iat`、`nbf`、`exp`、
  `jti` 和 `pv`（协议主版本）。
- TTL：固定 120 秒；Agent 只在内存持有。
- audience：仅 `coordinator-agent`、`tool-gateway`、`operation-gateway`，各接收方只接受自己的值。
- 公钥：只从管理员固定的本地信任集合按 `kid` 选择；不读取或信任 token 自带的公钥 URL。

## 失败关闭规则

验证器必须硬编码 `EdDSA`，先拒绝错误 `alg`/`typ` 和未知 `kid`，再进行标准签名、issuer、
audience、required claims 与时间验证。随后拒绝跨 network、协议主版本错误、畸形 node/jti
以及非 120 秒 TTL。签名篡改、过期、缺字段和解析失败都只返回稳定错误类型，不回显 token。

隔离实现位于 `spikes/coordinator_assertion_probe.py`；它不启动服务、不监听端口、不读取现有
Gateway/WireGuard 配置，也不保存生成的私钥或 token。
