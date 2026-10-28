"""新电脑只把自己的电脑密钥存入本机，机主密钥不经过网络。"""

from __future__ import annotations

import hashlib
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

from tunnelminion.agent.join import detect_local_host
from tunnelminion.domain.identifiers import NodeId
from tunnelminion.domain.tools import Platform
from tunnelminion.domain.trust import JoinCode, JoinCodeKind, JoinProof, SignaturePurpose
from tunnelminion.gateway.configuration import (
    FileGatewayConfigurationRepository,
    GatewayConfigurationService,
    GatewaySecretStoreKind,
    configure_gateway_secret_store,
    gateway_secret_store,
)
from tunnelminion.gateway.names import load_node_name
from tunnelminion.gateway.security import GatewayBindConfig
from tunnelminion.memory.sqlite import SQLiteStores, SQLiteTrustStore
from tunnelminion.model.secrets import KeyringSecretStore, RestrictedFileSecretStore
from tunnelminion.trust.contracts import (
    AlreadyInitializedError,
    IdentityError,
    OwnerJoinRequest,
    OwnerJoinResponse,
)
from tunnelminion.trust.devices import OwnDevicesService
from tunnelminion.trust.keys import PrivateKey
from tunnelminion.trust.service import ensure_no_identity_keys
from tunnelminion.trust.signatures import seal


async def join_owner(
    code: JoinCode,
    root: Path,
    *,
    host_override: str | None = None,
    secret_store_kind: GatewaySecretStoreKind | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """核对响应后落盘；失败时不留下电脑私钥。"""
    database = root / "runtime.sqlite3"
    if SQLiteTrustStore.is_initialized(database):
        raise AlreadyInitializedError("本机身份已经初始化，不能重复加入")
    secrets = (
        RestrictedFileSecretStore(root / "gateway-secrets")
        if secret_store_kind is GatewaySecretStoreKind.RESTRICTED_FILE
        else KeyringSecretStore()
        if secret_store_kind is GatewaySecretStoreKind.KEYRING
        else gateway_secret_store(root)
    )
    ensure_no_identity_keys(secrets)
    now = datetime.now(UTC)
    if (
        code.kind is not JoinCodeKind.OWNER
        or code.expires_at.tzinfo is None
        or code.expires_at <= now
    ):
        raise IdentityError("加入码无效或已过期，请重新生成")
    GatewayBindConfig(host=code.host, port=code.port)
    path = root / "node-id"
    node_id = NodeId(path.read_text(encoding="utf-8").strip()) if path.exists() else NodeId.new()
    if node_id == code.inviter_node_id:
        raise IdentityError("不能加入自己生成的加入码")
    repository = FileGatewayConfigurationRepository(root / "gateway.json")
    existing = repository.load()
    try:
        bind = GatewayBindConfig(
            host=host_override
            or (existing.bind.host if existing else detect_local_host(code.host, code.port)),
            port=existing.bind.port if existing else 8787,
        )
    except OSError:
        raise IdentityError("无法识别本机组网地址，请指定 --bind-host") from None
    platform = (
        Platform.WINDOWS
        if sys.platform == "win32"
        else Platform.MACOS
        if sys.platform == "darwin"
        else Platform.LINUX
    )
    key = PrivateKey.generate()
    request = OwnerJoinRequest(
        node_id=node_id,
        platform=platform,
        display_name=load_node_name(root, platform, persist_default=False),
        host=bind.host,
        port=bind.port,
        device_public_key=key.public_key,
        proof=seal(
            SignaturePurpose.JOIN_PROOF,
            JoinProof(
                token_digest=hashlib.sha256(code.token.encode()).hexdigest(),
                inviter_node_id=code.inviter_node_id,
                node_id=node_id,
                device_public_key=key.public_key,
                host=bind.host,
                port=bind.port,
                issued_at=now,
            ),
            key,
        ),
    )
    try:
        async with httpx.AsyncClient(
            base_url=httpx.URL(scheme="http", host=code.host, port=code.port),
            transport=transport or httpx.AsyncHTTPTransport(local_address=bind.host),
            timeout=15,
            trust_env=False,
        ) as client:
            response = await client.post(
                "/v1/owner:join",
                content=request.model_dump_json(),
                headers={
                    "Authorization": f"Bearer {code.token}",
                    "Content-Type": "application/json",
                },
            )
        if response.status_code == 429:
            raise IdentityError("请求太频繁，请一分钟后再试")
        if response.status_code != 200:
            raise IdentityError("邀请码无效、已过期或已被使用")
        if len(response.content) > 512_000:
            raise ValueError
        accepted = OwnerJoinResponse.model_validate_json(response.content)
    except httpx.HTTPError:
        raise IdentityError("连不上邀请方的电脑") from None
    except ValueError as exc:
        if isinstance(exc, IdentityError):
            raise
        raise IdentityError("加入响应格式无效") from None
    service = OwnDevicesService(node_id, SQLiteStores.open(database).trust, secrets)
    service.install_join(code, accepted, key)
    if secret_store_kind is not None:
        configure_gateway_secret_store(root, secret_store_kind)
    if not path.exists():
        temporary = path.with_suffix(".tmp")
        temporary.write_text(str(node_id), encoding="utf-8")
        temporary.replace(path)
    if existing is None:
        GatewayConfigurationService(repository, secrets).configure_local(bind)
    load_node_name(root, platform)
