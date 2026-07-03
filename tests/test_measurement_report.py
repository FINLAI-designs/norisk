"""Tests fuer build_measurement_report Phase 4 / R6b).

Pure Transformation — kein I/O. Prueft die Vier-Sektionen-Partition nach
Mess-Zustand + dass verzichtete Checks ihre Begruendung tragen.
"""

from __future__ import annotations

from core.security.severity import Severity
from tools.system_scanner.application.measurement_report import (
    build_measurement_report,
)
from tools.system_scanner.domain.entities import HardeningCheck
from tools.system_scanner.domain.enums import UnmeasuredReason


def _chk(check_id, *, measurable=True, reason=None, skip_reason="", detail=""):
    return HardeningCheck(
        check_id=check_id,
        label=check_id,
        passed=measurable,
        severity=Severity.MEDIUM,
        detail=detail,
        measurable=measurable,
        unmeasured_reason=None if measurable else reason,
        skip_reason=skip_reason,
    )


class TestBuildMeasurementReport:
    def test_sections_partitioned(self):
        checks = [
            _chk("M1", detail="ok"),
            _chk("A1", measurable=False, reason=UnmeasuredReason.NEEDS_ADMIN),
            _chk("P1", measurable=False, reason=UnmeasuredReason.PARSE_FAILED),
            _chk("D1", measurable=False, reason=UnmeasuredReason.USER_DECLINED,
                 skip_reason="nutzt anderes Tool"),
            _chk("N1", measurable=False, reason=UnmeasuredReason.NOT_APPLICABLE,
                 skip_reason="Home-Edition"),
        ]
        r = build_measurement_report(checks)
        assert [i.check_id for i in r.measured] == ["M1"]
        # NEEDS_ADMIN + PARSE_FAILED -> Handlungsbedarf
        assert {i.check_id for i in r.needs_action} == {"A1", "P1"}
        assert [i.check_id for i in r.declined] == ["D1"]
        assert [i.check_id for i in r.not_applicable] == ["N1"]

    def test_declined_carries_reason_note(self):
        # R6b: "nicht gemessen MIT Begruendung".
        checks = [
            _chk("D1", measurable=False, reason=UnmeasuredReason.USER_DECLINED,
                 skip_reason="bewusst verzichtet: X")
        ]
        r = build_measurement_report(checks)
        assert r.declined[0].note == "bewusst verzichtet: X"
        assert r.declined[0].reason == UnmeasuredReason.USER_DECLINED

    def test_has_open_items(self):
        open_r = build_measurement_report(
            [_chk("A1", measurable=False, reason=UnmeasuredReason.NEEDS_ADMIN)]
        )
        assert open_r.has_open_items is True
        assert build_measurement_report([_chk("M1")]).has_open_items is False

    def test_measured_item_reason_none(self):
        r = build_measurement_report([_chk("M1", detail="UAC ok")])
        assert r.measured[0].reason is None
        assert r.measured[0].note == "UAC ok"

    def test_empty(self):
        r = build_measurement_report([])
        assert r.measured == ()
        assert r.has_open_items is False
