"""macOS `wg-quick` 后端与 0600 受限配置材料。"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import secrets
from pathlib import Path
from typing import Protocol, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from tunnelminion.domain.identifiers import NetworkId, NodeId
from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    LocalNetworkKeyMaterial,
    NetworkErrorCode,
    NetworkPlan,
    NetworkPlanStep,
    PlanStepKind,
    canonical_sha256,
)
from tunnelminion.platforms.macos.managed_system import (
    FixedMacOSWireGuardCommands,
    MacOSProviderPreflight,
    MacOSTunnelSnapshot,
)
from tunnelminion.platforms.macos.network_provider import MacOSBackendError


class MacOSSecretStore(Protocol):
    """与 keyring/受限文件秘密后端兼容的最小协议。"""

    def get(self, name: str) -> str | None: ...  # pragma: no cover - Protocol

    def set(self, name: str, value: str) -> None: ...  # pragma: no cover - Protocol

    def delete(self, name: str) -> None: ...  # pragma: no cover - Protocol


class MacOSSnapshotObserver(Protocol):
    """官方后端依赖的只读快照边界。"""

    async def observe(
        self,
        interface_name: str,
    ) -> MacOSTunnelSnapshot: ...  # pragma: no cover - Protocol


class RestrictedMacOSConfigStore:
    """私钥只从秘密后端短暂装配到固定目录下的 0600 revision 文件。"""

    def __init__(self, root: Path, secrets_store: MacOSSecretStore) -> None:
        if not root.is_absolute():
            raise ValueError("macOS 配置根必须为绝对路径")
        self.root = root
        self._secrets = secrets_store

    def ensure_secret(self, desired: DesiredNetworkConfig) -> LocalNetworkKeyMaterial:
        return self.ensure_identity(desired.network_id, desired.target_node_id)

    def ensure_identity(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> LocalNetworkKeyMaterial:
        name = self._secret_name(network_id, node_id)
        private_text = self._secrets.get(name)
        if private_text is None:
            return self.create_identity(network_id, node_id)
        else:
            private = X25519PrivateKey.from_private_bytes(base64.b64decode(private_text))
        public = base64.b64encode(
            private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        ).decode()
        return LocalNetworkKeyMaterial(
            secret_reference=f"keyring:{name}",
            public_key=public,
            public_key_hash=canonical_sha256({"public_key": public}),
        )

    def create_identity(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> LocalNetworkKeyMaterial:
        """创建全新身份，不读取或复用秘密后端中的既有材料。"""
        name = self._secret_name(network_id, node_id)
        private = X25519PrivateKey.generate()
        self._secrets.set(
            name,
            base64.b64encode(
                private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ).decode(),
        )
        public = base64.b64encode(
            private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        ).decode()
        return LocalNetworkKeyMaterial(
            secret_reference=f"keyring:{name}",
            public_key=public,
            public_key_hash=canonical_sha256({"public_key": public}),
        )

    def write(
        self,
        desired: DesiredNetworkConfig,
        secret_reference: str,
        creation_nonce: str,
    ) -> str:
        private_text = self._load_secret(secret_reference)
        self._ensure_root()
        config = self.config_path(desired.interface_name, desired.revision)
        temporary = self.root / f".{config.name}.{secrets.token_hex(8)}.tmp"
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(self._render_config(desired, private_text))
            os.chmod(temporary, 0o600)
            os.replace(temporary, config)
            self._write_marker(
                desired.interface_name,
                creation_nonce=creation_nonce,
                revision=desired.revision,
                runtime_interface=None,
            )
        finally:
            if temporary.exists():
                temporary.unlink()
        return canonical_sha256(
            {"kind": "write_config", "path": config.name, "revision": desired.revision}
        )

    def record_runtime_interface(
        self,
        interface_name: str,
        *,
        creation_nonce: str,
        revision: int,
        runtime_interface: str,
    ) -> None:
        self._write_marker(
            interface_name,
            creation_nonce=creation_nonce,
            revision=revision,
            runtime_interface=runtime_interface,
        )

    def read_marker(self, interface_name: str) -> dict[str, object] | None:
        path = self.marker_path(interface_name)
        if not path.exists():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return None
        return cast(dict[str, object], value)

    def delete_config(self, interface_name: str, revision: int) -> str:
        path = self.config_path(interface_name, revision)
        if path.exists():
            path.unlink()
        return canonical_sha256({"kind": "delete_config", "path": path.name})

    def delete_secret(self, desired: DesiredNetworkConfig, secret_reference: str) -> str:
        self._secrets.delete(self._reference_name(secret_reference))
        marker = self.marker_path(desired.interface_name)
        if marker.exists():
            marker.unlink()
        return canonical_sha256(
            {
                "kind": "delete_secret_reference",
                "network_id": str(desired.network_id),
                "node_id": str(desired.target_node_id),
            }
        )

    def config_path(self, interface_name: str, revision: int) -> Path:
        if not interface_name.startswith("tmn-") or revision < 1:
            raise ValueError("macOS 配置名称或 revision 无效")
        return self.root / f"{interface_name}.r{revision}.conf"

    def marker_path(self, interface_name: str) -> Path:
        if not interface_name.startswith("tmn-"):
            raise ValueError("macOS marker 只属于受管接口")
        return self.root / f"{interface_name}.owner.json"

    def assert_restricted(self, path: Path) -> None:
        if path.stat().st_mode & 0o077:
            raise PermissionError("macOS 配置材料权限必须为 0600")

    def _write_marker(
        self,
        interface_name: str,
        *,
        creation_nonce: str,
        revision: int,
        runtime_interface: str | None,
    ) -> None:
        marker = self.marker_path(interface_name)
        temporary = self.root / f".{marker.name}.{secrets.token_hex(8)}.tmp"
        payload = {
            "creation_nonce": creation_nonce,
            "revision": revision,
            "runtime_interface": runtime_interface,
        }
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            os.chmod(temporary, 0o600)
            os.replace(temporary, marker)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _load_secret(self, reference: str) -> str:
        value = self._secrets.get(self._reference_name(reference))
        if value is None:
            raise MacOSBackendError(NetworkErrorCode.INVALID_CONFIG, "macOS 私钥引用不存在")
        return value

    @staticmethod
    def _reference_name(reference: str) -> str:
        if not reference.startswith("keyring:"):
            raise ValueError("macOS 私钥引用格式无效")
        return reference.removeprefix("keyring:")

    @staticmethod
    def _secret_name(network_id: NetworkId, node_id: NodeId) -> str:
        return f"wireguard/{network_id}/{node_id}"

    @staticmethod
    def _render_config(desired: DesiredNetworkConfig, private_text: str) -> str:
        lines = ["[Interface]", f"PrivateKey = {private_text}", f"Address = {desired.address}"]
        if desired.listen_port is not None:
            lines.append(f"ListenPort = {desired.listen_port}")
        for peer in desired.peers:
            lines.extend(("", "[Peer]", f"PublicKey = {peer.public_key}"))
            lines.append(f"AllowedIPs = {', '.join(peer.allowed_host_routes)}")
            if peer.candidates:
                candidate = peer.candidates[0]
                lines.append(f"Endpoint = {candidate.host}:{candidate.port}")
            if peer.persistent_keepalive_seconds is not None:
                lines.append(f"PersistentKeepalive = {peer.persistent_keepalive_seconds}")
        return "\n".join(lines) + "\n"


class OfficialMacOSManagedBackend:
    """把通用 Provider 步骤映射到固定 `wg-quick` argv。"""

    def __init__(
        self,
        commands: FixedMacOSWireGuardCommands,
        observer: MacOSSnapshotObserver,
        materials: RestrictedMacOSConfigStore,
    ) -> None:
        self._commands = commands
        self._observer = observer
        self._materials = materials

    def preflight(self) -> MacOSProviderPreflight:
        return self._commands.preflight()

    async def observe(self, interface_name: str) -> MacOSTunnelSnapshot:
        if not interface_name.startswith("tmn-"):
            return await self._observer.observe(interface_name)
        marker = self._materials.read_marker(interface_name)
        runtime = marker.get("runtime_interface") if marker is not None else None
        nonce = marker.get("creation_nonce") if marker is not None else None
        if not isinstance(runtime, str):
            return MacOSTunnelSnapshot(
                interface_name=interface_name,
                interface_present=False,
                interface_up=False,
                service_present=False,
                service_running=False,
                creation_nonce=nonce if isinstance(nonce, str) else None,
            )
        snapshot = await self._observer.observe(runtime)
        return snapshot.model_copy(
            update={
                "interface_name": interface_name,
                "creation_nonce": nonce if isinstance(nonce, str) else None,
            }
        )

    async def runtime_interfaces(self, interface_name: str) -> tuple[str, ...]:
        """返回 WireGuard 全部公开运行时接口，用于未决 mutation 恢复核对。"""
        del interface_name
        return await self._interfaces()

    def ensure_secret(self, desired: DesiredNetworkConfig) -> LocalNetworkKeyMaterial:
        return self._materials.ensure_secret(desired)

    def ensure_identity(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> LocalNetworkKeyMaterial:
        return self._materials.ensure_identity(network_id, node_id)

    def create_identity(
        self,
        network_id: NetworkId,
        node_id: NodeId,
    ) -> LocalNetworkKeyMaterial:
        return self._materials.create_identity(network_id, node_id)

    async def validate_no_conflicts(self, desired: DesiredNetworkConfig) -> None:
        result = await self._commands.route_table()
        if result.returncode != 0:
            raise MacOSBackendError(
                NetworkErrorCode.PROVIDER_UNAVAILABLE,
                "无法读取 macOS IPv4 路由冲突基线",
            )
        requested = {
            ipaddress.ip_interface(desired.address).ip,
            *(
                ipaddress.ip_network(route, strict=True).network_address
                for peer in desired.peers
                for route in peer.allowed_host_routes
            ),
        }
        conflicts = {
            (str(network), fingerprint)
            for network, fingerprint in _parse_macos_ipv4_route_records(result.stdout)
            if network.prefixlen != 0 and any(address in network for address in requested)
        }
        allowed = {
            (overlap.route, overlap.observation_fingerprint)
            for overlap in desired.allowed_route_overlaps
        }
        conflict = next(
            (
                item
                for item in conflicts
                if ipaddress.ip_network(item[0]).prefixlen == 32 or item not in allowed
            ),
            None,
        )
        if conflict is not None or allowed != {
            item for item in conflicts if ipaddress.ip_network(item[0]).prefixlen < 32
        }:
            raise MacOSBackendError(
                NetworkErrorCode.ROUTE_NOT_ALLOWED,
                "候选地址或 host route 命中现有 macOS 非默认路由",
            )

    async def execute_step(
        self,
        plan: NetworkPlan,
        step: NetworkPlanStep,
        *,
        secret_reference: str,
        creation_nonce: str,
        idempotency_key: str,
    ) -> str:
        del idempotency_key
        desired = plan.desired
        config = self._materials.config_path(desired.interface_name, desired.revision)
        if step.kind is PlanStepKind.WRITE_CONFIG:
            return self._materials.write(desired, secret_reference, creation_nonce)
        if step.kind is PlanStepKind.CREATE_INTERFACE:
            before = await self._interfaces()
            result = await self._commands.up(desired.interface_name, config)
            self._require_success(result.returncode, step)
            after = await self._interfaces()
            created = tuple(item for item in after if item not in before)
            if len(created) != 1:
                raise MacOSBackendError(
                    NetworkErrorCode.APPLY_FAILED,
                    "macOS 无法唯一确认新建 utun 接口",
                )
            self._materials.record_runtime_interface(
                desired.interface_name,
                creation_nonce=creation_nonce,
                revision=desired.revision,
                runtime_interface=created[0],
            )
            return canonical_sha256({"kind": "create_interface", "runtime": created[0]})
        if step.kind is PlanStepKind.STOP_INTERFACE:
            result = await self._commands.down(desired.interface_name, config)
            return self._require_success(result.returncode, step)
        if step.kind is PlanStepKind.REMOVE_INTERFACE:
            return canonical_sha256({"kind": "remove_interface", "handled_by": "wg-quick-down"})
        if step.kind is PlanStepKind.DELETE_CONFIG:
            return self._materials.delete_config(desired.interface_name, desired.revision)
        if step.kind is PlanStepKind.DELETE_SECRET:
            return self._materials.delete_secret(desired, secret_reference)
        return canonical_sha256({"kind": "wg_quick_config_effect", "step": step.kind.value})

    async def rollback_step(
        self,
        plan: NetworkPlan,
        step: NetworkPlanStep,
        *,
        secret_reference: str,
        creation_nonce: str,
        idempotency_key: str,
    ) -> str:
        del idempotency_key
        desired = plan.desired
        if step.kind is PlanStepKind.CREATE_INTERFACE:
            result = await self._commands.down(
                desired.interface_name,
                self._materials.config_path(desired.interface_name, desired.revision),
            )
            return self._require_success(result.returncode, step)
        if step.kind is PlanStepKind.WRITE_CONFIG:
            return self._materials.delete_config(desired.interface_name, desired.revision)
        if step.kind is PlanStepKind.STOP_INTERFACE and desired.parent_revision > 0:
            result = await self._commands.up(
                desired.interface_name,
                self._materials.config_path(
                    desired.interface_name,
                    desired.parent_revision,
                ),
            )
            return self._require_success(result.returncode, step)
        if step.kind is PlanStepKind.DELETE_SECRET:
            raise MacOSBackendError(
                NetworkErrorCode.ROLLBACK_FAILED,
                "已删除的 macOS 私钥不能自动重建",
            )
        return canonical_sha256(
            {
                "kind": "reverse_wg_quick_effect",
                "step": step.kind.value,
                "secret_reference_configured": bool(secret_reference),
                "creation_nonce_configured": bool(creation_nonce),
            }
        )

    async def _interfaces(self) -> tuple[str, ...]:
        result = await self._commands.interfaces()
        if result.returncode != 0:
            raise MacOSBackendError(
                NetworkErrorCode.PROVIDER_UNAVAILABLE,
                "无法读取 macOS WireGuard 接口清单",
            )
        return tuple(result.stdout.split())

    @staticmethod
    def _require_success(returncode: int, step: NetworkPlanStep) -> str:
        if returncode != 0:
            raise MacOSBackendError(
                NetworkErrorCode.APPLY_FAILED,
                f"macOS 固定步骤失败：{step.kind.value}",
                retryable=True,
            )
        return canonical_sha256(
            {"kind": step.kind.value, "target": step.target, "returncode": returncode}
        )


def _parse_macos_ipv4_route_records(
    stdout: str,
) -> tuple[tuple[ipaddress.IPv4Network, str], ...]:
    values: list[tuple[ipaddress.IPv4Network, str]] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        token = parts[0]
        if token == "default":
            network = ipaddress.IPv4Network("0.0.0.0/0")
            values.append(
                (
                    network,
                    canonical_sha256({"route": str(network), "interface_locator": parts[3]}),
                )
            )
            continue
        try:
            network = _macos_route_token(token)
        except ValueError:
            continue
        values.append(
            (
                network,
                canonical_sha256(
                    {
                        "route": str(network),
                        "interface_locator": parts[3],
                    }
                ),
            )
        )
    return tuple(dict.fromkeys(values))


def _macos_route_token(token: str) -> ipaddress.IPv4Network:
    if "/" not in token:
        return ipaddress.IPv4Network(f"{token}/32", strict=False)
    address, prefix = token.split("/", 1)
    octets = address.split(".")
    if not 1 <= len(octets) <= 4:
        raise ValueError("macOS route address 无效")
    padded = ".".join((*octets, *(["0"] * (4 - len(octets)))))
    return ipaddress.IPv4Network(f"{padded}/{prefix}", strict=False)
