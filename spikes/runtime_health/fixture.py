"""用无系统写入的 fixture 固定本机生命周期与 peer 验收的边界。"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import StrEnum


class FixtureScenario(StrEnum):
    """隔离 fixture 覆盖的两个相反场景。"""

    HAIRPIN_FAILED_PEER_REACHABLE = "hairpin_failed_peer_reachable"
    LISTENER_PRESENT_PEER_HUNG = "listener_present_peer_hung"


class LocalReadiness(StrEnum):
    """只描述 B 本机进程与监听器的结论。"""

    RUNNING = "running"


class PeerAcceptance(StrEnum):
    """只描述独立 peer 对 B 的端到端结论。"""

    PEER_REACHABLE = "peer_reachable"
    PEER_UNREACHABLE = "peer_unreachable"


@dataclass(frozen=True)
class FixtureObservation:
    """不包含秘密的隔离场景观察结果。"""

    scenario: FixtureScenario
    process_owned: bool
    listener_owned: bool
    local_hairpin_error: str
    peer_http_status: int | None
    peer_error: str | None
    local_readiness: LocalReadiness
    peer_acceptance: PeerAcceptance


def build_fixture_report() -> dict[str, object]:
    """生成可重复的 fake 报告，不触碰生产进程、路由或 SecretStore。"""
    observations = (
        FixtureObservation(
            scenario=FixtureScenario.HAIRPIN_FAILED_PEER_REACHABLE,
            process_owned=True,
            listener_owned=True,
            local_hairpin_error="hairpin_timeout",
            peer_http_status=401,
            peer_error=None,
            local_readiness=LocalReadiness.RUNNING,
            peer_acceptance=PeerAcceptance.PEER_REACHABLE,
        ),
        FixtureObservation(
            scenario=FixtureScenario.LISTENER_PRESENT_PEER_HUNG,
            process_owned=True,
            listener_owned=True,
            local_hairpin_error="hairpin_timeout",
            peer_http_status=None,
            peer_error="peer_timeout",
            local_readiness=LocalReadiness.RUNNING,
            peer_acceptance=PeerAcceptance.PEER_UNREACHABLE,
        ),
    )
    return {
        "schema_version": "macos-gateway-runtime-health-spike.v1",
        "mode": "fake_no_system_writes",
        "production_secret_store_read": False,
        "production_process_touched": False,
        "scenarios": [
            {
                **asdict(observation),
                "scenario": observation.scenario.value,
                "local_readiness": observation.local_readiness.value,
                "peer_acceptance": observation.peer_acceptance.value,
            }
            for observation in observations
        ],
        "conclusion": {
            "local_running_requires_process_and_listener_ownership": True,
            "peer_401_is_independent_acceptance_evidence": True,
            "hairpin_timeout_is_not_local_startup_failure": True,
            "listener_presence_is_not_peer_acceptance": True,
        },
    }


def main() -> None:
    """输出脱敏 fixture 报告，供隔离验收记录使用。"""
    print(json.dumps(build_fixture_report(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
