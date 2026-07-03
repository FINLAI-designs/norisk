"""
test_scoring_dashboard_widget — GUI-Tests fuer den Security-Scoring-Tab.

Verifiziert, dass Subtitle, Status und Verlauf nach einer
Berechnung den EINEN Hardening-Score zeigen — der Legacy-Score (frueher
die 85/69/96-Divergenz auf einem Screen) fliesst nicht mehr in die
Anzeige. Das Widget wird mit gemocktem ScoringService + TechStack
aufgebaut, damit kein echter DB-/License-Zugriff noetig ist.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.security.severity import Severity
from tools.security_scoring.domain.hardening_score import (
    HardeningScoreResult,
    compute_hardening_score,
)
from tools.security_scoring.domain.models import ScoreComponent, SecurityScore
from tools.system_scanner.domain.entities import (
    HardeningCheck,
    OSInfo,
    ScanResult,
)
from tools.system_scanner.domain.enums import OSPlatform, UnmeasuredReason

# ---------------------------------------------------------------------------
# Test-Helpers
# ---------------------------------------------------------------------------


def _hardening_result(score: float) -> HardeningScoreResult:
    """Baut ein vollstaendiges HardeningScoreResult mit gegebenem Overall.

    Alle 5 Kategorien mit demselben Score → Overall == score, keine
    Hard-Caps, nichts fehlt.
    """
    comps = [
        ScoreComponent(name="X", score=score, weight=0.5, source_tool=tool)
        for tool in (
            "cve_exposure",
            "network_scanner",
            "password_policy",
            "api_security",
            "system_scanner",
        )
    ]
    return compute_hardening_score(comps)


def _legacy_score() -> SecurityScore:
    """Legacy-SecurityScore mit der alten 69%-Summary (darf nicht erscheinen)."""
    return SecurityScore(
        id="legacy-1",
        target_name="Mein System",
        timestamp="2026-06-03T10:00:00+00:00",
        overall_score=69.0,
        grade="C",
        components=[],
        summary="Dein System erfüllt 69% der geprüften Kriterien.",
    )


def _build_widget(*, org_service_present: bool = False):
    """Baut das ScoringDashboardWidget mit kontrollierter Org-Sektions-Verfuegbarkeit.

    kein Lizenz-Gate mehr — die technische Bewertung ist immer
    verfuegbar; die organisatorische haengt nur noch an der Injektion des
    org_security_service.

    Args:
        org_service_present: Ob ein org_security_service injiziert wird
            (steuert ``_org_assessment_available``).

    Returns:
        Tuple ``(widget, service)``.
    """
    from tools.security_scoring.gui import scoring_dashboard_widget as mod

    fake_uc = MagicMock()
    fake_uc.ensure_own_system.return_value = SimpleNamespace(name="Mein System")

    service = MagicMock()
    service.previous_hardening_score.return_value = None
    service.lade_hardening_verlauf.return_value = [
        ("2026-06-03T10:00:00", 80.0),
        ("2026-06-02T10:00:00", 76.0),
    ]

    org_service = MagicMock() if org_service_present else None

    with patch.object(
        mod, "create_default_manage_profiles_use_case", return_value=fake_uc
    ):
        w = mod.ScoringDashboardWidget(
            service=service, org_security_service=org_service
        )
    return w, service


@pytest.fixture
def widget(app):
    """Baut das ScoringDashboardWidget mit gemocktem Service + TechStack."""
    return _build_widget()


# ===========================================================================
# eine Zahl ueberall (Regression 85/69/96)
# ===========================================================================


class TestScoreEmpfangenT296:
    def test_subtitle_und_status_zeigen_hardening_nicht_legacy(self, widget):
        w, _service = widget
        hardening = _hardening_result(80.0)  # Hardening = 80
        legacy = _legacy_score()             # Legacy = 69

        w._score_empfangen(legacy, hardening)

        subtitle = w._lbl_summary.text()
        status = w._lbl_status.text()
        # Hardening-Zahl ueberall, Legacy-69 / Legacy-Summary nirgends.
        assert "80" in subtitle
        assert "69" not in subtitle
        assert "erfüllt 69%" not in subtitle
        assert "80/100" in status

    def test_verlauf_chart_entfernt_kein_history_load(self, widget):
        # G (Live-Test 2026-07-01): Das scrollbare Verlaufs-Chart wurde vom Tab
        # entfernt. _score_empfangen laedt daher KEINE Verlaufs-History mehr
        # (weder Hardening- noch Legacy-Verlauf); der Delta-Pfeil neben dem
        # Gauge nutzt weiterhin previous_hardening_score.
        w, service = widget
        w._score_empfangen(_legacy_score(), _hardening_result(80.0))

        service.lade_hardening_verlauf.assert_not_called()
        service.lade_verlauf.assert_not_called()
        service.previous_hardening_score.assert_called()


# ===========================================================================
# Phase 4 — Soft-Mess-Banner (D4)
# ===========================================================================


def _hardening_with_open(n_open: int):
    """HardeningScoreResult + ScanResult mit ``n_open`` offenen (NEEDS_ADMIN) Checks."""
    checks = [
        HardeningCheck(f"M{i}", "m", True, Severity.MEDIUM) for i in range(3)
    ]
    checks += [
        HardeningCheck(
            f"A{i}", "a", False, Severity.HIGH,
            measurable=False, unmeasured_reason=UnmeasuredReason.NEEDS_ADMIN,
        )
        for i in range(n_open)
    ]
    scan = ScanResult(
        scan_id="t",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        os_info=OSInfo(platform=OSPlatform.WINDOWS),
        hardening_checks=checks,
    )
    comps = [
        ScoreComponent(name="X", score=100.0, weight=1.0, source_tool="system_scanner")
    ]
    return compute_hardening_score(comps, scan_result=scan), scan


class TestMeasurementGateBanner:
    def test_banner_visible_when_open(self, widget):
        w, _service = widget
        hardening, scan = _hardening_with_open(2)
        w._score_empfangen(_legacy_score(), hardening, scan)
        # isHidden reflektiert das explizite Sichtbarkeits-Flag (ohne show).
        assert w._gate_banner.isHidden() is False
        assert "2" in w._gate_banner._title_label.text()

    def test_banner_hidden_when_no_disposition(self, widget):
        w, _service = widget
        w._score_empfangen(_legacy_score(), _hardening_result(80.0), None)
        assert w._gate_banner.isHidden() is True

    def test_decline_recomputes_and_closes_gate(self, widget):
        w, service = widget
        hardening, scan = _hardening_with_open(2)
        w._score_empfangen(_legacy_score(), hardening, scan)
        assert w._gate_banner.isHidden() is False
        # Nach Verzicht liefert der Service ein Ergebnis ohne offene Posten.
        declined_result, _ = _hardening_with_open(0)
        service.compute_hardening_score.return_value = declined_result
        w._on_gate_decline()
        service.compute_hardening_score.assert_called()  # Neuberechnung ausgeloest
        assert w._gate_banner.isHidden() is True  # Gate zu

    def test_recheck_merge_closes_gate(self, widget):
        w, service = widget
        hardening, scan = _hardening_with_open(2)  # M0..M2 + A0,A1 (NEEDS_ADMIN)
        w._score_empfangen(_legacy_score(), hardening, scan)
        assert w._gate_banner.isHidden() is False
        # Elevierter Recheck hat die 2 offenen Checks (A0, A1) gemessen.
        measured = [
            HardeningCheck(f"M{i}", "m", True, Severity.MEDIUM) for i in range(3)
        ] + [
            HardeningCheck(f"A{i}", "a", True, Severity.HIGH) for i in range(2)
        ]
        recheck_scan = ScanResult(
            scan_id="r",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            os_info=OSInfo(platform=OSPlatform.WINDOWS),
            hardening_checks=measured,
        )
        declined_result, _ = _hardening_with_open(0)
        service.compute_hardening_score.return_value = declined_result
        w._apply_recheck_result(recheck_scan)
        # Merge: die zuvor grauen A0/A1 sind jetzt gemessen -> neu berechnet.
        called_scan = service.compute_hardening_score.call_args.kwargs["scan_result"]
        assert all(c.measurable for c in called_scan.hardening_checks)
        assert w._gate_banner.isHidden() is True

    def test_recalc_button_reenabled_even_if_banner_update_raises(self, app):
        """RECALC-BUG (T-livetest): "Neu berechnen" muss IMMER wieder bedienbar
        werden — auch wenn ``_gate_banner.update_from`` wirft (z.B. nach einem
        elevierten Recheck mit unerwarteter Disposition)."""
        from unittest.mock import MagicMock as _MM

        w, _service = _build_widget()
        # Button war während der Berechnung deaktiviert.
        w._btn_calc.setEnabled(False)
        # Banner-Update wirft simuliert eine RuntimeError.
        w._gate_banner.update_from = _MM(side_effect=RuntimeError("boom"))

        hardening = _hardening_result(80.0)
        with pytest.raises(RuntimeError):
            w._score_empfangen(_legacy_score(), hardening)

        # Trotz geworfener Exception ist der Button wieder bedienbar.
        assert w._btn_calc.isEnabled() is True


# ===========================================================================
# D6 Phase 2 — Banner-Zustandsautomat fuer den elevierten Recheck
# ===========================================================================


_RECHECK_MOD = (
    "tools.system_scanner.application.hardening_recheck.read_and_consume_recheck_result"
)


class TestRecheckOutcomeUI:
    def test_running_disables_measure_and_hides_decline(self, widget):
        from tools.security_scoring.gui.widgets.measurement_gate_banner import (
            GateBannerState,
        )

        w, _ = widget
        w._gate_banner.set_state(GateBannerState.RUNNING)
        assert not w._gate_banner._measure_button.isEnabled()
        assert "Wird gemessen" in w._gate_banner._measure_button.text()
        assert w._gate_banner._decline_button.isHidden() is True

    def test_reject_shows_reason_and_retry(self, widget):
        from tools.system_scanner.domain.enums import RecheckReason

        w, _ = widget
        w._show_recheck_reject(RecheckReason.SCAN_FAILED)
        assert w._gate_banner.isHidden() is False
        assert w._gate_banner._measure_button.text() == "Erneut messen"
        assert w._gate_banner._measure_button.isEnabled() is True
        assert "fehlgeschlagen" in w._lbl_status.text()

    def test_path_untrusted_reject_shows_dialog(self, widget):
        from tools.security_scoring.gui import scoring_dashboard_widget as mod
        from tools.system_scanner.domain.enums import RecheckReason

        w, _ = widget
        with patch.object(mod, "FinlaiInfoDialog") as dlg:
            w._show_recheck_reject(RecheckReason.PATH_UNTRUSTED)
            dlg.assert_called_once()
            dlg.return_value.exec.assert_called_once()

    def test_timeout_sets_banner_and_dialog(self, widget):
        from tools.security_scoring.gui import scoring_dashboard_widget as mod

        w, _ = widget
        w._recheck_timer = MagicMock()
        w._recheck_elapsed_s = 89
        w._recheck_nonce = "x"
        with (
            patch(_RECHECK_MOD, return_value=None),
            patch.object(mod, "FinlaiInfoDialog") as dlg,
        ):
            w._poll_recheck()
        assert "kein Ergebnis in 90" in w._lbl_status.text()
        dlg.return_value.exec.assert_called_once()
        assert w._gate_banner._measure_button.text() == "Erneut messen"

    def test_success_outcome_merges_and_closes_gate(self, widget):
        from tools.system_scanner.application.hardening_recheck import RecheckOutcome

        w, service = widget
        hardening, scan = _hardening_with_open(2)
        w._score_empfangen(_legacy_score(), hardening, scan)
        w._recheck_timer = MagicMock()
        w._recheck_elapsed_s = 1
        w._recheck_nonce = "x"
        measured = [
            HardeningCheck(f"M{i}", "m", True, Severity.MEDIUM) for i in range(3)
        ] + [HardeningCheck(f"A{i}", "a", True, Severity.HIGH) for i in range(2)]
        recheck_scan = ScanResult(
            scan_id="r",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            os_info=OSInfo(platform=OSPlatform.WINDOWS),
            hardening_checks=measured,
        )
        declined_result, _ = _hardening_with_open(0)
        service.compute_hardening_score.return_value = declined_result
        with patch(
            _RECHECK_MOD, return_value=RecheckOutcome(scan=recheck_scan, reason=None)
        ):
            w._poll_recheck()
        assert w._gate_banner.isHidden() is True  # Gate zu nach Merge


# ===========================================================================
# D3 — Einstieg "Selbstbewertung" (GUI-Hülle, ersetzt 2 Buttons)
# ===========================================================================


class TestSelbstbewertungEinstieg:
    def test_einstieg_immer_sichtbar(self, app):
        """: Technik-Bewertung ist immer verfügbar → Einstiegs-Button da."""
        w, _service = _build_widget(org_service_present=False)
        assert w._btn_self_assessment is not None
        assert w._btn_self_assessment.text() == "Selbstbewertung starten"

    def test_tech_immer_verfuegbar_org_an_service(self, app):
        """Technik immer True; Organisation = org_security_service-Präsenz."""
        w_ohne, _ = _build_widget(org_service_present=False)
        assert w_ohne._tech_assessment_available is True
        assert w_ohne._org_assessment_available is False

        w_mit, _ = _build_widget(org_service_present=True)
        assert w_mit._tech_assessment_available is True
        assert w_mit._org_assessment_available is True

    def test_alte_einzelbuttons_entfernt(self, app):
        """Die zwei gleichrangigen Buttons existieren nicht mehr als Attribute."""
        w, _service = _build_widget(org_service_present=True)
        assert not hasattr(w, "_btn_assessment")
        assert not hasattr(w, "_btn_org_assessment")


class TestSelbstbewertungDialog:
    """GUI-Hülle: Auswahl-Dialog mit zwei Sektions-Karten."""

    def _dialog(self, *, tech_available, org_available):
        from tools.security_scoring.gui.dialogs.selbstbewertung_dialog import (
            SelbstbewertungDialog,
        )

        started = {"tech": 0, "org": 0}
        dlg = SelbstbewertungDialog(
            tech_available=tech_available,
            org_available=org_available,
            on_start_tech=lambda: started.__setitem__("tech", started["tech"] + 1),
            on_start_org=lambda: started.__setitem__("org", started["org"] + 1),
        )
        return dlg, started

    def _alle_label_texte(self, dlg) -> str:
        from PySide6.QtWidgets import QLabel

        return "\n".join(lbl.text() for lbl in dlg.findChildren(QLabel))

    def test_lock_hinweis_fuer_gegatete_org_sektion(self, app):
        """Nicht verfügbare org-Sektion (kein Org-Service) verschwindet NICHT —
        zeigt einen Verfügbarkeits-Hinweis: kein Lizenz-Framing mehr)."""
        dlg, _started = self._dialog(tech_available=True, org_available=False)
        texte = self._alle_label_texte(dlg)
        # Sektion ist weiterhin sichtbar (Titel da)...
        assert "Organisatorische Sicherheit" in texte
        #... aber mit Verfügbarkeits-Hinweis (kein Lizenz-Text mehr).
        assert "nicht verfügbar" in texte

    def test_lock_hinweis_fuer_gegatete_tech_sektion(self, app):
        """Nicht verfügbare technische Sektion zeigt ebenfalls einen Hinweis
: in Produktion immer verfügbar; hier defensiv getestet)."""
        dlg, _started = self._dialog(tech_available=False, org_available=True)
        texte = self._alle_label_texte(dlg)
        assert "Technische Bewertung" in texte
        assert "nicht verfügbar" in texte

    def test_start_buttons_nur_fuer_verfuegbare_sektionen(self, app):
        """Nur die verfügbare Sektion hat einen "Starten"-Button."""
        from PySide6.QtWidgets import QPushButton

        dlg, _started = self._dialog(tech_available=True, org_available=False)
        start_buttons = [
            b for b in dlg.findChildren(QPushButton) if b.text() == "Starten"
        ]
        # Genau eine verfügbare Sektion → genau ein Starten-Button.
        assert len(start_buttons) == 1

    def test_start_tech_callback_und_dialog_schliesst(self, app):
        """Start-Handler delegiert an den injizierten Callback (eigener Wizard)."""
        dlg, started = self._dialog(tech_available=True, org_available=True)
        dlg._handle_start_tech()
        assert started["tech"] == 1
        assert started["org"] == 0

    def test_start_org_callback(self, app):
        """Org-Start-Handler ruft den org-Callback (eigener Wizard)."""
        dlg, started = self._dialog(tech_available=True, org_available=True)
        dlg._handle_start_org()
        assert started["org"] == 1
        assert started["tech"] == 0


# ===========================================================================
# R6b — Mess-Transparenz-Sektion (Lost-Feature measurement_report)
# ===========================================================================


class TestMeasurementTransparency:
    def test_mess_section_zeigt_buckets_bei_live_scan(self, widget):
        w, _service = widget
        # _hardening_with_open(2) -> 3 gemessene + 2 Handlungsbedarf-Checks.
        hardening, scan = _hardening_with_open(2)
        w._score_empfangen(_legacy_score(), hardening, scan)
        assert w._mess_section.isHidden() is False
        body = w._mess_body.text()
        assert "Gemessen: 3" in body
        assert "Handlungsbedarf: 2" in body

    def test_mess_section_versteckt_ohne_scan(self, widget):
        w, _service = widget
        w._score_empfangen(_legacy_score(), _hardening_result(80.0), None)
        assert w._mess_section.isHidden() is True
