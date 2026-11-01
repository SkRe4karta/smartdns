"""Bounded beta suite: 23 Python scenarios + 6 frontend + 1 installation scenario."""

import argparse
import subprocess
import sys

BACKEND = [
    "test_accounts_api.py::test_user_cannot_reach_admin_endpoints",
    "test_accounts_api.py::test_csrf_and_cross_origin_are_rejected",
    "test_accounts_api.py::test_invitation_expiry_reuse_and_atomic_consumption",
    "test_accounts_api.py::test_disabled_account_loses_session_and_dns_key",
    "test_accounts_api.py::test_password_change_revokes_other_sessions",
    "test_accounts_api.py::test_credential_encrypted_at_rest_and_rotation",
    "test_accounts_api.py::test_filter_exceptions_are_personal_and_not_routes",
    "test_accounts_api.py::test_recovery_and_profile_are_scoped",
    "test_accounts_api.py::test_unconfigured_telegram_is_disabled_without_affecting_password_login",
    "test_catalog_pool.py::test_manual_direct_override_beats_more_specific_import",
    "test_catalog_pool.py::test_failed_activation_restores_catalog_and_leaves_accounts_intact",
]
INTEGRATION = [
    "test_gateway.py::test_routing_preserves_blocking_and_normal_ipv6",
    "test_gateway.py::test_agent_failure_fails_closed_for_routed_domains",
    "test_gateway.py::test_unknown_keys_and_multi_question_messages_are_rejected",
    "test_gateway.py::test_doh_get_post_and_spoofed_headers",
    "test_gateway.py::test_real_dot_multiple_frames_and_revoke_open_connection",
    "test_gateway.py::test_cached_lease_never_hides_agent_failure",
    "test_gateway.py::test_legacy_plain_dns_requires_active_network_and_has_no_personal_stats",
    "test_gateway.py::test_gateway_reassigns_service_when_selected_exit_cannot_acknowledge",
    "test_agent_migration.py::test_agent_rotation_and_watchdog_are_fail_closed",
    "test_agent_migration.py::test_reconciliation_does_not_accumulate_sqlite_descriptors",
    "test_catalog_pool.py::test_pool_assignment_is_sticky_and_fails_over",
    "test_node.py::test_real_node_tls_requires_client_certificate",
]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("group", choices=["backend", "integration"])
    args = parser.parse_args()
    tests = BACKEND if args.group == "backend" else INTEGRATION
    raise SystemExit(
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", *["tests/" + test for test in tests]], timeout=120
        ).returncode
    )
