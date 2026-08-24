"""只供 fake 验收使用的本地控制面组装器。"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from tunnelminion.domain.identifiers import AuthorizationId
from tunnelminion.network.governance import (
    KillSwitchCapability,
    LocalControlAuthority,
    LocalControlCapability,
    NetworkAuthorizationGrant,
    NetworkAuthorizationReadPort,
)
from tunnelminion.network.governance import (
    NetworkOperationPolicy as _NetworkOperationPolicy,
)
from tunnelminion.network.governance import (
    SQLiteNetworkAuthorizationRepository as _SQLiteNetworkAuthorizationRepository,
)


class HarnessAuthorizationRepository(_SQLiteNetworkAuthorizationRepository):
    """由 fake 本地控制面显式持有 authority 的测试仓储。"""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        connection: sqlite3.Connection | None = None,
        control: LocalControlAuthority | None = None,
    ) -> None:
        self.local_control = control or LocalControlAuthority()
        super().__init__(path, connection=connection, control=self.local_control)

    def authorization_capability(self) -> LocalControlCapability:
        return self.local_control.authorization_capability()

    def kill_switch_capability(self) -> KillSwitchCapability:
        return self.local_control.kill_switch_capability()


class HarnessPolicy(_NetworkOperationPolicy):
    """只在测试控制面中把写仓储和 authority 放在一起。"""

    def __init__(
        self,
        repository: HarnessAuthorizationRepository | None = None,
    ) -> None:
        self._writer: HarnessAuthorizationRepository | None = repository
        super().__init__(repository.read_only if repository is not None else None)

    def attach_writer(self, repository: HarnessAuthorizationRepository) -> None:
        if self._writer is not None and self._writer is not repository:
            raise ValueError("fake policy 不得绑定多个控制面仓储")
        self._writer = repository
        if self._repository is None:
            self.bind(repository.read_only)

    def _require_writer(self) -> HarnessAuthorizationRepository:
        if self._writer is None:
            raise RuntimeError("fake policy 尚未绑定本地控制面")
        return self._writer

    def local_control_capability(self) -> LocalControlCapability:
        return self._require_writer().authorization_capability()

    def kill_switch_capability(self) -> KillSwitchCapability:
        return self._require_writer().kill_switch_capability()

    def approve(
        self,
        grant: NetworkAuthorizationGrant,
        *,
        capability: LocalControlCapability,
    ) -> NetworkAuthorizationGrant:
        return self._require_writer().approve(grant, capability=capability)

    def revoke(
        self,
        authorization_id: AuthorizationId,
        *,
        revoked_at: datetime,
        capability: LocalControlCapability,
    ) -> NetworkAuthorizationGrant:
        return self._require_writer().revoke(
            authorization_id,
            revoked_at=revoked_at,
            capability=capability,
        )


NetworkOperationPolicy = HarnessPolicy
SQLiteNetworkAuthorizationRepository = HarnessAuthorizationRepository


def bind_control_plane(
    path: Path,
    policy: HarnessPolicy,
) -> tuple[HarnessAuthorizationRepository, NetworkAuthorizationReadPort]:
    """创建 fake 控制面并把只读端口交给 lifecycle。"""
    repository = HarnessAuthorizationRepository(path)
    policy.attach_writer(repository)
    return repository, repository.read_only
