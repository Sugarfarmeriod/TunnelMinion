"""Windows 官方 tunnel service 后端与 ACL 受限配置材料。"""

from __future__ import annotations

import base64
import getpass
import ipaddress
import json
import os
import re
import secrets
from pathlib import Path
from typing import Protocol, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from tunnelminion.network.contracts import (
    DesiredNetworkConfig,
    NetworkErrorCode,
    NetworkPlan,
    NetworkPlanStep,
    PlanStepKind,
    canonical_sha256,
)
from tunnelminion.platforms.windows.managed_system import (
    FixedWindowsWireGuardCommands,
    WindowsProviderPreflight,
    WindowsTunnelSnapshot,
)
from tunnelminion.platforms.windows.network_provider import WindowsBackendError
from tunnelminion.platforms.windows.system import CommandRunner

_SAFE_ACCOUNT = re.compile(r"^[A-Za-z0-9_.\\-]{1,128}$")


class WindowsSecretStore(Protocol):
    """与 keyring/受限文件秘密后端兼容的最小协议。"""

    def get(self, name: str) -> str | None: ...  # pragma: no cover - Protocol 无运行时实现

    def set(self, name: str, value: str) -> None: ...  # pragma: no cover - Protocol 无运行时实现

    def delete(self, name: str) -> None: ...  # pragma: no cover - Protocol 无运行时实现


class WindowsSnapshotObserver(Protocol):
    """官方后端依赖的只读快照边界。"""

    async def observe(
        self,
        interface_name: str,
    ) -> WindowsTunnelSnapshot: ...  # pragma: no cover - Protocol 无运行时实现


class AclRestrictedWindowsConfigStore:
    """私钥只从秘密后端短暂装配到 ACL 受限 revision 配置。"""

    def __init__(
        self,
        root: Path,
        secrets_store: WindowsSecretStore,
        runner: CommandRunner,
        icacls_path: Path,
        *,
        account_name: str | None = None,
    ) -> None:
        if not root.is_absolute() or not icacls_path.is_absolute():
            raise ValueError("Windows 配置根和 icacls 必须是绝对路径")
        account = account_name or getpass.getuser()
        if _SAFE_ACCOUNT.fullmatch(account) is None:
            raise ValueError("Windows ACL 账户名称格式无效")
        self.root = root
        self._secrets = secrets_store
        self._runner = runner
        self._icacls_path = icacls_path
        self._account = account

    def ensure_secret(self, desired: DesiredNetworkConfig) -> tuple[str, str]:
        name = self._secret_name(desired)
        private_text = self._secrets.get(name)
        if private_text is None:
            private = X25519PrivateKey.generate()
            raw = private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            private_text = base64.b64encode(raw).decode()
            self._secrets.set(name, private_text)
        else:
            private = X25519PrivateKey.from_private_bytes(base64.b64decode(private_text))
        public_raw = private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return f"keyring:{name}", canonical_sha256(
            {"public_key": base64.b64encode(public_raw).decode()}
        )

    async def write(
        self,
        desired: DesiredNetworkConfig,
        secret_reference: str,
        creation_nonce: str,
    ) -> str:
        private_text = self._load_secret(secret_reference)
        self.root.mkdir(parents=True, exist_ok=True)
        config_path = self.config_path(desired.interface_name, desired.revision)
        temporary = self.root / f".{config_path.name}.{secrets.token_hex(8)}.tmp"
        material = self._render_config(desired, private_text)
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(material)
            os.chmod(temporary, 0o600)
            await self._restrict_acl(temporary)
            os.replace(temporary, config_path)
            await self._write_marker(
                desired.interface_name,
                desired.revision,
                creation_nonce,
            )
        finally:
            if temporary.exists():
                temporary.unlink()
        return canonical_sha256(
            {
                "kind": "write_config",
                "path": config_path.name,
                "revision": desired.revision,
            }
        )

    async def delete_config(self, interface_name: str, revision: int) -> str:
        path = self.config_path(interface_name, revision)
        if path.exists():
            path.unlink()
        return canonical_sha256({"kind": "delete_config", "path": path.name, "revision": revision})

    async def delete_secret(
        self,
        desired: DesiredNetworkConfig,
        secret_reference: str,
    ) -> str:
        name = self._reference_name(secret_reference)
        self._secrets.delete(name)
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

    def read_creation_nonce(self, interface_name: str) -> str | None:
        marker = self.marker_path(interface_name)
        if not marker.exists():
            return None
        parsed = json.loads(marker.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict) or not isinstance(
            cast(dict[str, object], parsed).get("creation_nonce"), str
        ):
            raise ValueError("Windows 所有权 marker 结构无效")
        nonce = cast(str, cast(dict[str, object], parsed)["creation_nonce"])
        if re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
            raise ValueError("Windows 所有权 marker 结构无效")
        return nonce

    def config_path(self, interface_name: str, revision: int) -> Path:
        if re.fullmatch(r"tmn-[a-z0-9-]{1,48}", interface_name) is None or revision < 1:
            raise ValueError("Windows 受管配置身份无效")
        return self.root / f"{interface_name}.r{revision}.conf"

    def marker_path(self, interface_name: str) -> Path:
        if re.fullmatch(r"tmn-[a-z0-9-]{1,48}", interface_name) is None:
            raise ValueError("Windows 受管接口名称无效")
        return self.root / f"{interface_name}.owner.json"

    async def _write_marker(
        self,
        interface_name: str,
        revision: int,
        creation_nonce: str,
    ) -> None:
        marker = self.marker_path(interface_name)
        temporary = self.root / f".{marker.name}.{secrets.token_hex(8)}.tmp"
        temporary.write_text(
            json.dumps(
                {"creation_nonce": creation_nonce, "revision": revision},
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        try:
            await self._restrict_acl(temporary)
            os.replace(temporary, marker)
        finally:
            if temporary.exists():
                temporary.unlink()

    async def _restrict_acl(self, path: Path) -> None:
        result = await self._runner.run(
            (
                str(self._icacls_path),
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"{self._account}:(F)",
                "/grant:r",
                "*S-1-5-18:(F)",
            ),
            10,
        )
        if result.returncode != 0:
            raise WindowsBackendError(
                NetworkErrorCode.PERMISSION_DENIED,
                "无法限制 Windows 运行配置 ACL",
            )

    def _load_secret(self, secret_reference: str) -> str:
        value = self._secrets.get(self._reference_name(secret_reference))
        if value is None:
            raise WindowsBackendError(
                NetworkErrorCode.RECOVERY_REQUIRED,
                "Windows WireGuard 秘密引用不存在",
            )
        return value

    @staticmethod
    def _reference_name(secret_reference: str) -> str:
        if not secret_reference.startswith("keyring:"):
            raise ValueError("Windows Provider 只接受 keyring 秘密引用")
        return secret_reference.removeprefix("keyring:")

    @staticmethod
    def _secret_name(desired: DesiredNetworkConfig) -> str:
        return f"tunnelminion/{desired.network_id}/{desired.target_node_id}/wg"

    @staticmethod
    def _render_config(desired: DesiredNetworkConfig, private_key: str) -> str:
        lines = ("[Interface]", f"PrivateKey = {private_key}", f"Address = {desired.address}")
        peer_lines: list[str] = list(lines)
        for peer in desired.peers:
            peer_lines.extend(("", "[Peer]", f"PublicKey = {peer.public_key}"))
            peer_lines.append(f"AllowedIPs = {','.join(peer.allowed_host_routes)}")
            if peer.candidates:
                candidate = peer.candidates[0]
                peer_lines.append(f"Endpoint = {candidate.host}:{candidate.port}")
            if peer.persistent_keepalive_seconds is not None:
                peer_lines.append(f"PersistentKeepalive = {peer.persistent_keepalive_seconds}")
        return "\n".join(peer_lines) + "\n"


class OfficialWindowsManagedBackend:
    """把通用 Provider 步骤映射到官方 manager/SCM 固定 argv。"""

    def __init__(
        self,
        commands: FixedWindowsWireGuardCommands,
        observer: WindowsSnapshotObserver,
        materials: AclRestrictedWindowsConfigStore,
    ) -> None:
        self._commands = commands
        self._observer = observer
        self._materials = materials

    def preflight(self) -> WindowsProviderPreflight:
        return self._commands.preflight()

    async def observe(self, interface_name: str) -> WindowsTunnelSnapshot:
        snapshot = await self._observer.observe(interface_name)
        nonce = (
            self._materials.read_creation_nonce(interface_name)
            if interface_name.startswith("tmn-")
            else None
        )
        return snapshot.model_copy(update={"creation_nonce": nonce})

    def ensure_secret(self, desired: DesiredNetworkConfig) -> tuple[str, str]:
        return self._materials.ensure_secret(desired)

    async def validate_no_conflicts(self, desired: DesiredNetworkConfig) -> None:
        result = await self._commands.route_table()
        if result.returncode != 0:
            raise WindowsBackendError(
                NetworkErrorCode.PROVIDER_UNAVAILABLE,
                "无法读取 Windows IPv4 路由冲突基线",
            )
        networks = _parse_ipv4_route_networks(result.stdout)
        requested_addresses = {
            ipaddress.ip_interface(desired.address).ip,
            *(
                ipaddress.ip_network(route, strict=True).network_address
                for peer in desired.peers
                for route in peer.allowed_host_routes
            ),
        }
        conflict = next(
            (
                network
                for network in networks
                if network.prefixlen != 0
                and any(address in network for address in requested_addresses)
            ),
            None,
        )
        if conflict is not None:
            raise WindowsBackendError(
                NetworkErrorCode.ROUTE_NOT_ALLOWED,
                "候选地址或 host route 命中现有 Windows 非默认路由",
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
        if step.kind is PlanStepKind.WRITE_CONFIG:
            return await self._materials.write(desired, secret_reference, creation_nonce)
        if step.kind is PlanStepKind.CREATE_INTERFACE:
            result = await self._commands.install_tunnel(
                desired.interface_name,
                self._materials.config_path(desired.interface_name, desired.revision),
            )
            return self._require_success(result.returncode, step)
        if step.kind is PlanStepKind.STOP_INTERFACE:
            result = await self._commands.stop_tunnel(desired.interface_name)
            return self._require_success(result.returncode, step)
        if step.kind is PlanStepKind.REMOVE_INTERFACE:
            result = await self._commands.uninstall_tunnel(desired.interface_name)
            return self._require_success(result.returncode, step)
        if step.kind is PlanStepKind.DELETE_CONFIG:
            return await self._materials.delete_config(
                desired.interface_name,
                desired.revision,
            )
        if step.kind is PlanStepKind.DELETE_SECRET:
            return await self._materials.delete_secret(desired, secret_reference)
        return canonical_sha256(
            {
                "kind": "service_config_effect",
                "step": step.kind.value,
                "revision": desired.revision,
            }
        )

    async def rollback_step(
        self,
        plan: NetworkPlan,
        step: NetworkPlanStep,
        *,
        secret_reference: str,
        creation_nonce: str,
        idempotency_key: str,
    ) -> str:
        del creation_nonce, idempotency_key
        desired = plan.desired
        if step.kind is PlanStepKind.CREATE_INTERFACE:
            result = await self._commands.uninstall_tunnel(desired.interface_name)
            return self._require_success(result.returncode, step)
        if step.kind is PlanStepKind.WRITE_CONFIG:
            return await self._materials.delete_config(
                desired.interface_name,
                desired.revision,
            )
        if step.kind in {PlanStepKind.STOP_INTERFACE, PlanStepKind.REMOVE_INTERFACE}:
            parent = desired.parent_revision
            if parent < 1:
                return canonical_sha256({"kind": "no_parent_revision"})
            result = await self._commands.install_tunnel(
                desired.interface_name,
                self._materials.config_path(desired.interface_name, parent),
            )
            return self._require_success(result.returncode, step)
        if step.kind is PlanStepKind.DELETE_SECRET:
            raise WindowsBackendError(
                NetworkErrorCode.ROLLBACK_FAILED,
                "已删除的 Windows 私钥不能自动重建",
            )
        return canonical_sha256(
            {
                "kind": "reverse_service_config_effect",
                "step": step.kind.value,
                "revision": desired.parent_revision,
                "secret_reference_configured": bool(secret_reference),
            }
        )

    @staticmethod
    def _require_success(returncode: int, step: NetworkPlanStep) -> str:
        if returncode != 0:
            raise WindowsBackendError(
                NetworkErrorCode.APPLY_FAILED,
                f"Windows 固定步骤失败：{step.kind.value}",
                retryable=True,
            )
        return canonical_sha256(
            {"kind": step.kind.value, "target": step.target, "returncode": returncode}
        )


def _parse_ipv4_route_networks(stdout: str) -> tuple[ipaddress.IPv4Network, ...]:
    """解析 route.exe 数字行，忽略接口名称、网关正文和本地化标题。"""
    values: list[ipaddress.IPv4Network] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            destination = ipaddress.IPv4Address(parts[0])
            mask = ipaddress.IPv4Address(parts[1])
            network = ipaddress.IPv4Network(f"{destination}/{mask}", strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            continue
        values.append(network)
    return tuple(dict.fromkeys(values))
