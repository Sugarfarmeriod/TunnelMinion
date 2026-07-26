from __future__ import annotations

from typing import cast

import pytest
from spikes.managed_connectivity.lifecycle_probe import (
    Action,
    Platform,
    build_report,
    decide_recovery,
    macos_semantics,
    windows_semantics,
)


def test_windows_matrix_requires_admin_and_never_claims_atomicity() -> None:
    values = [windows_semantics(action) for action in Action]

    assert all(item.platform is Platform.WINDOWS for item in values)
    assert all(item.permission == "administrator_or_local_system" for item in values)
    assert all(not item.atomic for item in values)
    assert "install_parent_revision_tunnel_service" in windows_semantics(Action.REPLACE).rollback


def test_macos_matrix_forbids_interactive_sudo_and_separates_routes() -> None:
    create = macos_semantics(Action.CREATE)
    replace = macos_semantics(Action.REPLACE)

    assert create.permission == "network_administrator_without_interactive_sudo"
    assert "write_mode_0600_revision_config_without_hooks" in create.fixed_steps
    assert "reconcile_owned_host_routes" in replace.fixed_steps
    assert "syncconf_does_not_manage_wg_quick_addresses_or_routes" in replace.notes


def test_recovery_uses_only_confirmed_steps() -> None:
    semantics = windows_semantics(Action.CREATE)

    assert (
        decide_recovery(semantics, confirmed_step_count=0, ownership_matches=True).state
        == "unchanged"
    )
    recovery = decide_recovery(semantics, confirmed_step_count=2, ownership_matches=True)
    assert recovery.state == "rolling_back"
    assert recovery.rollback_steps == semantics.rollback


def test_recovery_stops_on_ownership_conflict() -> None:
    recovery = decide_recovery(
        macos_semantics(Action.DELETE),
        confirmed_step_count=1,
        ownership_matches=False,
    )

    assert recovery.state == "manual_intervention"
    assert recovery.rollback_steps == ()
    assert recovery.reason == "ownership_conflict"


@pytest.mark.parametrize("confirmed_step_count", [-1, 4])
def test_recovery_rejects_invalid_receipt_count(confirmed_step_count: int) -> None:
    with pytest.raises(ValueError, match="固定步骤范围"):
        decide_recovery(
            windows_semantics(Action.CREATE),
            confirmed_step_count=confirmed_step_count,
            ownership_matches=True,
        )


def test_report_contains_both_platforms_and_failure_cases() -> None:
    report = build_report()
    matrix = cast(list[object], report["matrix"])
    failure_cases = cast(dict[str, object], report["failure_cases"])

    assert report["mode"] == "fake_no_system_writes"
    assert len(matrix) == 8
    assert set(failure_cases) == {
        "response_lost_after_create",
        "peer_step_failed",
        "resource_replaced_externally",
    }
