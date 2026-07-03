"""Tests fuer hardening_recheck Phase 4d — HMAC-Marker + Merge).

HMAC-Signatur (FINLAI_HOME-abgeleitet), atomares Schreiben, Verify-und-Konsum
(Loeschen) + die Merge-Regel "echte Messung gewinnt". Datei-I/O gegen tmp_path.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from core.security.severity import Severity
from tools.system_scanner.application.hardening_recheck import (
    RecheckOutcome,
    merge_recheck_checks,
    read_and_consume_recheck_result,
    recheck_file_path,
    write_recheck_reject,
    write_recheck_result,
)
from tools.system_scanner.domain.entities import HardeningCheck, OSInfo, ScanResult
from tools.system_scanner.domain.enums import (
    OSPlatform,
    RecheckReason,
    UnmeasuredReason,
)


def _chk(cid, *, measurable=True, passed=True, reason=None):
    return HardeningCheck(
        cid, cid, passed, Severity.HIGH,
        measurable=measurable,
        unmeasured_reason=None if measurable else reason,
    )


def _scan(checks):
    return ScanResult(
        scan_id="s1",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        os_info=OSInfo(platform=OSPlatform.WINDOWS),
        hardening_checks=checks,
    )


class TestRecheckMarkerRoundtrip:
    def test_write_then_consume_roundtrips(self, tmp_path):
        scan = _scan([
            _chk("SH-001"),
            _chk("SH-003", measurable=False, passed=False,
                 reason=UnmeasuredReason.NEEDS_ADMIN),
        ])
        write_recheck_result(scan, nonce="n1", home=tmp_path)
        assert recheck_file_path(tmp_path).exists()
        out = read_and_consume_recheck_result(expected_nonce="n1", home=tmp_path)
        assert out is not None
        assert out.ok
        assert out.scan is not None
        assert [c.check_id for c in out.scan.hardening_checks] == ["SH-001", "SH-003"]
        # Nach Konsum geloescht (kein stale Marker).
        assert not recheck_file_path(tmp_path).exists()

    def test_missing_returns_none(self, tmp_path):
        assert read_and_consume_recheck_result(home=tmp_path) is None

    def test_nonce_mismatch_rejected_and_deleted(self, tmp_path):
        # Replay/Frische: gueltige Signatur, aber falsche Nonce -> verworfen.
        write_recheck_result(_scan([_chk("SH-001")]), nonce="n1", home=tmp_path)
        p = recheck_file_path(tmp_path)
        assert read_and_consume_recheck_result(expected_nonce="n2", home=tmp_path) is None
        assert not p.exists()

    def test_tampered_payload_rejected_and_deleted(self, tmp_path):
        write_recheck_result(_scan([_chk("SH-001")]), home=tmp_path)
        p = recheck_file_path(tmp_path)
        env = json.loads(p.read_text(encoding="utf-8"))
        env["payload"] = env["payload"].replace("SH-001", "SH-XXX")  # HMAC passt nicht
        p.write_text(json.dumps(env), encoding="utf-8")
        assert read_and_consume_recheck_result(home=tmp_path) is None
        assert not p.exists()  # verworfen + entfernt

    def test_dek_marker_is_home_independent(self, tmp_path):
        # Schluessel kommt aus dem DEK, NICHT mehr aus dem Pfad. Ein in
        # home_a geschriebener Marker ist daher in home_b lesbar (derselbe DEK) —
        # genau der Fix gegen den Pfad-Drift, der korrekte Marker verwarf (D6).
        home_a = tmp_path / "a"
        home_b = tmp_path / "b"
        home_a.mkdir()
        home_b.mkdir()
        write_recheck_result(_scan([_chk("SH-001")]), home=home_a)
        (home_b / recheck_file_path(home_a).name).write_text(
            recheck_file_path(home_a).read_text(encoding="utf-8"), encoding="utf-8"
        )
        out = read_and_consume_recheck_result(home=home_b)
        assert out is not None and out.ok
        assert [c.check_id for c in out.scan.hardening_checks] == ["SH-001"]

    def test_status_field_tamper_rejected(self, tmp_path):
        # status ist mitsigniert: ein zu "ok" geflippter Reject muss scheitern.
        write_recheck_reject(RecheckReason.SCAN_FAILED, nonce="n1", home=tmp_path)
        p = recheck_file_path(tmp_path)
        env = json.loads(p.read_text(encoding="utf-8"))
        env["status"] = "ok"  # HMAC deckt status -> Manipulation faellt auf
        p.write_text(json.dumps(env), encoding="utf-8")
        assert read_and_consume_recheck_result(expected_nonce="n1", home=tmp_path) is None
        assert not p.exists()


class TestRecheckReject:
    def test_reject_roundtrips_as_outcome(self, tmp_path):
        write_recheck_reject(
            RecheckReason.PROBE_UNAVAILABLE, "Probe weg", nonce="n1", home=tmp_path
        )
        out = read_and_consume_recheck_result(expected_nonce="n1", home=tmp_path)
        assert isinstance(out, RecheckOutcome)
        assert not out.ok
        assert out.scan is None
        assert out.reason is RecheckReason.PROBE_UNAVAILABLE
        assert out.detail == "Probe weg"
        assert not recheck_file_path(tmp_path).exists()

    def test_reject_never_merges(self, tmp_path):
        # Ein Reject darf nie als Mess-Ergebnis in den Merge gelangen.
        write_recheck_reject(RecheckReason.INTERNAL, nonce="n1", home=tmp_path)
        out = read_and_consume_recheck_result(expected_nonce="n1", home=tmp_path)
        assert out is not None and out.scan is None  # kein scan -> nichts zu mergen


class TestMergeRecheckChecks:
    def test_needs_admin_replaced_by_measured(self):
        base = [_chk("SH-003", measurable=False, passed=False,
                     reason=UnmeasuredReason.NEEDS_ADMIN)]
        recheck = [_chk("SH-003", measurable=True, passed=True)]
        out = merge_recheck_checks(base, recheck)
        assert out[0].measurable is True
        assert out[0].passed is True

    def test_measured_base_unchanged(self):
        base = [_chk("SH-001", measurable=True, passed=False)]
        recheck = [_chk("SH-001", measurable=True, passed=True)]
        out = merge_recheck_checks(base, recheck)
        assert out[0].passed is False  # echte Basis-Messung gewinnt

    def test_declined_survives_recheck(self):
        base = [_chk("SH-003", measurable=False, passed=False,
                     reason=UnmeasuredReason.USER_DECLINED)]
        recheck = [_chk("SH-003", measurable=True, passed=True)]
        out = merge_recheck_checks(base, recheck)
        assert out[0].unmeasured_reason == UnmeasuredReason.USER_DECLINED

    def test_missing_in_recheck_unchanged(self):
        base = [_chk("SH-003", measurable=False, passed=False,
                     reason=UnmeasuredReason.NEEDS_ADMIN)]
        out = merge_recheck_checks(base, [])
        assert out[0].unmeasured_reason == UnmeasuredReason.NEEDS_ADMIN

    def test_needs_admin_still_unmeasurable_becomes_not_applicable(self):
        # KONVERGENZ (D6-Folge): Der elevierte Recheck HAT den Check, kann ihn
        # aber WEITER nicht messen -> kein Rechteproblem -> NOT_APPLICABLE, damit
        # das Banner nicht endlos "Mit Admin messen" fordert (SH-004/SH-010-Klasse).
        base = [_chk("SH-004", measurable=False, passed=False,
                     reason=UnmeasuredReason.NEEDS_ADMIN)]
        recheck = [_chk("SH-004", measurable=False, passed=False,
                        reason=UnmeasuredReason.NEEDS_ADMIN)]
        out = merge_recheck_checks(base, recheck)
        assert out[0].measurable is False
        assert out[0].unmeasured_reason == UnmeasuredReason.NOT_APPLICABLE
