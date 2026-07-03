"""Tests fuer apply_user_decline P5 — bewusster Mess-Verzicht).

Pure Transformation: offene NEEDS_ADMIN-Checks -> USER_DECLINED; alles andere
unveraendert.
"""

from __future__ import annotations

from core.security.severity import Severity
from tools.system_scanner.application.hardening_overrides import apply_user_decline
from tools.system_scanner.domain.entities import HardeningCheck
from tools.system_scanner.domain.enums import UnmeasuredReason


def _chk(check_id, *, measurable=True, reason=None):
    return HardeningCheck(
        check_id=check_id,
        label=check_id,
        passed=measurable,
        severity=Severity.HIGH,
        measurable=measurable,
        unmeasured_reason=None if measurable else reason,
    )


class TestApplyUserDecline:
    def test_needs_admin_becomes_declined(self):
        out = apply_user_decline(
            [_chk("SH-001", measurable=False, reason=UnmeasuredReason.NEEDS_ADMIN)],
            note="bewusst",
        )
        assert out[0].unmeasured_reason == UnmeasuredReason.USER_DECLINED
        assert out[0].measurable is False
        assert out[0].skip_reason == "bewusst"

    def test_default_note_nonempty(self):
        out = apply_user_decline(
            [_chk("SH-001", measurable=False, reason=UnmeasuredReason.NEEDS_ADMIN)]
        )
        assert out[0].skip_reason

    def test_parse_failed_untouched(self):
        out = apply_user_decline(
            [_chk("SH-001", measurable=False, reason=UnmeasuredReason.PARSE_FAILED)]
        )
        assert out[0].unmeasured_reason == UnmeasuredReason.PARSE_FAILED

    def test_measured_untouched(self):
        out = apply_user_decline([_chk("SH-002", measurable=True)])
        assert out[0].unmeasured_reason is None
