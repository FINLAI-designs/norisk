"""
test_patch_console_widget — Tests fuer die Patch-Monitor-UI.

PM-1.7. Fokus auf Logik (Filter, Detail-Render, Status-Format), nicht
auf Qt-Rendering. Tests, die das Widget echt instanziieren, brauchen
``pytest-qt`` und sind via ``@pytest.mark.gui`` markiert.

Modul-Funktionen werden direkt importiert und getestet — keine
QApplication noetig.
"""

from __future__ import annotations

import pytest

from core import theme
from core.patch_result import PatchScanResult
from core.patch_upgrade import UpgradeRequest, UpgradeResult, UpgradeStatus
from tools.patch_monitor.application.batch_upgrade_service import BatchSummary
from tools.patch_monitor.gui import patch_console_widget as pc


def _result(
    name="App",
    recommendation="up_to_date",
    cve_ids=(),
    cvss_max=None,
    channel="latest",
    exploit=False,
    winget_id=None,
    available_version=None,
    installed_version="1.0",
    is_update_available=None,
):
    # „Updates verfuegbar"-Filter/-Zaehlung basieren jetzt auf is_update_available
    # (roh), nicht auf der recommendation-Klasse. Default aus der Recommendation
    # ableiten (bestehende Test-Intent), per Param ueberschreibbar (z. B.
    # notify_only-App MIT verfuegbarem Update).
    if is_update_available is None:
        is_update_available = recommendation in (
            "update",
            "update_urgent",
            "update_available",
        )
    return PatchScanResult(
        name=name,
        normalized_name=name.lower(),
        vendor=None,
        winget_id=winget_id,
        source="winget",
        installed_version=installed_version,
        available_version=available_version,
        channel=channel,
        policy_source="policy",
        cve_ids=cve_ids,
        cvss_max=cvss_max,
        exploit_available=exploit,
        eol=False,
        confidence_score=0.9,
        recommendation=recommendation,
        is_update_available=is_update_available,
    )


# ===========================================================================
# Filter-Logik (modul-funktion)
# ===========================================================================


class TestFilter:
    def test_filter_alle_passes_alles(self):
        r = _result(recommendation="update_urgent")
        assert pc._passes_filter(r, "all") is True
        r2 = _result(recommendation="up_to_date")
        assert pc._passes_filter(r2, "all") is True

    def test_filter_critical_nur_update_urgent(self):
        urgent = _result(recommendation="update_urgent")
        update = _result(recommendation="update")
        ok = _result(recommendation="up_to_date")
        assert pc._passes_filter(urgent, "critical") is True
        assert pc._passes_filter(update, "critical") is False
        assert pc._passes_filter(ok, "critical") is False

    def test_filter_needs_update_alle_aktiven(self):
        for rec in ("update_urgent", "update", "update_available"):
            assert pc._passes_filter(_result(recommendation=rec), "needs_update")
        # OHNE verfuegbares Update draussen (Default is_update_available=False).
        for rec in ("up_to_date", "notify_only", "pinned"):
            assert not pc._passes_filter(_result(recommendation=rec), "needs_update")

    def test_filter_needs_update_notify_only_mit_update(self):
        # Option A (Live-Test 2026-07-02): eine notify_only-/skipped-App MIT
        # verfuegbarem Update erscheint im „Updates verfuegbar"-Filter (das Popup
        # zeigt sie, der User kann Kanal wechseln + patchen) — unabhaengig von der
        # kanal-/strategie-basierten Recommendation.
        for rec in ("notify_only", "skipped_by_user", "pinned"):
            assert pc._passes_filter(
                _result(recommendation=rec, is_update_available=True), "needs_update"
            )
            assert not pc._passes_filter(
                _result(recommendation=rec, is_update_available=False), "needs_update"
            )

    def test_filter_up_to_date(self):
        assert pc._passes_filter(_result(recommendation="up_to_date"), "up_to_date")
        assert not pc._passes_filter(_result(recommendation="update"), "up_to_date")

    def test_filter_notify_only(self):
        assert pc._passes_filter(_result(recommendation="notify_only"), "notify_only")
        assert not pc._passes_filter(
            _result(recommendation="up_to_date"), "notify_only"
        )

    def test_filter_unbekannter_key_alles_passes(self):
        # Defensive: unbekannter Filter darf nichts ausfiltern
        assert pc._passes_filter(_result(), "garbage") is True


# ===========================================================================
# Freitext-Suche (D, Live-Test 2026-07-01) — modul-funktion, kein QApplication
# ===========================================================================


class TestSearch:
    def test_leerer_query_matcht_alles(self):
        assert pc._passes_search(_result(name="KeePassXC"), "") is True

    def test_substring_case_insensitive(self):
        # Der Slot uebergibt den Query bereits casefold-normalisiert.
        r = _result(name="KeePassXC")
        assert pc._passes_search(r, "keepass") is True
        assert pc._passes_search(r, "xc") is True

    def test_kein_treffer(self):
        assert pc._passes_search(_result(name="Firefox"), "chrome") is False


# ===========================================================================
# CVSS-Ampel
# ===========================================================================


class TestCvssColor:
    """FE-2: seit dem Theme-Refactor liefern die _cvss_color-
    Werte die theme.SEVERITY_SIGNAL_*-Hex (statt der frueheren Inline-
    Hex-Palette). Semantik bleibt gleich (Ampel: rot/orange/gelb/gruen/grau)."""

    def test_critical_rot(self):
        assert pc._cvss_color(9.5) == theme.SEVERITY_SIGNAL_CRITICAL
        assert pc._cvss_color(9.0) == theme.SEVERITY_SIGNAL_CRITICAL

    def test_high_orange(self):
        assert pc._cvss_color(8.0) == theme.SEVERITY_SIGNAL_HIGH
        assert pc._cvss_color(7.0) == theme.SEVERITY_SIGNAL_HIGH

    def test_medium_gelb(self):
        assert pc._cvss_color(5.0) == theme.SEVERITY_SIGNAL_MEDIUM
        assert pc._cvss_color(4.0) == theme.SEVERITY_SIGNAL_MEDIUM

    def test_low_gruen(self):
        assert pc._cvss_color(2.5) == theme.SEVERITY_SIGNAL_OK

    def test_none_grau(self):
        assert pc._cvss_color(None) == theme.SEVERITY_SIGNAL_INFO


# ===========================================================================
# Recommendation-Glyph + Channel-Color
# ===========================================================================


class TestVisualMappings:
    def test_alle_recommendations_haben_icon(self):
        # FE-1: _REC_GLYPH → _REC_ICON nach Material-Symbol-Migration.
        for rec in (
            "update_urgent",
            "update",
            "update_available",
            "up_to_date",
            "notify_only",
            "pinned",
        ):
            assert rec in pc._REC_ICON
            assert pc._REC_ICON[rec]

    def test_update_urgent_icon_warnung(self):
        # Status-Spec verlangt visuelles Warnsignal — Material-Symbol mit
        # Warn-Semantik (priority_high / warning / error).
        from core.icons import Icons

        assert pc._REC_ICON["update_urgent"] in (
            Icons.PRIORITY_HIGH,
            Icons.WARNING,
            Icons.ERROR,
        )

    def test_alle_channels_haben_farbe(self):
        # FE-2: _CHANNEL_COLOR-Dict ist jetzt _channel_color
        # Funktion. Wir pruefen dass jeder Channel einen nicht-leeren
        # Farb-String liefert.
        for ch in ("latest", "stable", "patch_only", "pinned", "notify_only"):
            assert pc._channel_color(ch), f"Channel {ch!r} hat keine Farbe"


# ===========================================================================
# Statuszeile
# ===========================================================================


class TestStatusLine:
    def test_format_status_line_zaehlt_korrekt(self):
        results = [
            _result(recommendation="update_urgent"),
            _result(recommendation="update_urgent"),
            _result(recommendation="update"),
            _result(recommendation="up_to_date"),
            _result(recommendation="notify_only"),
        ]
        line = pc._format_status_line(results)
        assert "5 Apps" in line
        assert "2 kritisch" in line
        assert "3 Updates verfuegbar" in line  # 2 urgent + 1 update
        assert "Letzter Scan:" in line

    def test_format_status_line_leer(self):
        line = pc._format_status_line([])
        assert "0 Apps" in line
        assert "0 kritisch" in line
        assert "0 Updates verfuegbar" in line


# ===========================================================================
# Detail-Render-HTML
# ===========================================================================


class TestDetailRender:
    def test_basis_felder_im_html(self):
        r = _result(
            name="Mozilla Firefox",
            channel="latest",
            recommendation="update_urgent",
            cve_ids=("CVE-2024-1", "CVE-2024-2"),
            cvss_max=9.5,
            exploit=True,
        )
        html = pc._render_detail_html(r)
        assert "Mozilla Firefox" in html
        assert "latest" in html
        assert "update_urgent" in html
        assert "9.5" in html
        assert "CVE-2024-1" in html
        assert "CVE-2024-2" in html
        assert "JA" in html  # exploit_available

    def test_keine_cves_zeigt_hinweis(self):
        r = _result(cve_ids=())
        html = pc._render_detail_html(r)
        assert "Keine CVEs" in html

    def test_viele_cves_kuerzt_auf_20(self):
        many = tuple(f"CVE-2024-{i:04d}" for i in range(35))
        r = _result(cve_ids=many)
        html = pc._render_detail_html(r)
        assert "und 15 weitere" in html


# ===========================================================================
# Widget-Smoke (mit pytest-qt)
# ===========================================================================


@pytest.mark.gui
class TestWidgetSmoke:
    def test_konstruktion_ohne_crash(self, qapp):
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        assert w is not None
        assert w._scan_btn.isEnabled()
        assert not w._cancel_btn.isEnabled()
        # Progress ist visible-Property = False; isVisible wuerde
        # ohnehin False liefern, weil Parent nicht gezeigt ist.
        assert not w._progress.isVisibleTo(w)

    def test_on_scan_started_setzt_ui_in_lauf_zustand(self, qapp):
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        w.on_scan_started()
        assert not w._scan_btn.isEnabled()
        assert w._cancel_btn.isEnabled()
        # isVisibleTo(parent) fragt das visible-Property unabhaengig
        # davon, ob das Top-Level-Widget show bekommen hat.
        assert w._progress.isVisibleTo(w)
        assert w._table.rowCount() == 0

    def test_on_scan_complete_befuellt_tabelle(self, qapp):
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        results = [
            _result(name="Firefox", recommendation="update_urgent", cvss_max=9.5),
            _result(name="VLC", recommendation="up_to_date"),
        ]
        w.on_scan_complete(results)
        assert w._table.rowCount() == 2
        assert w._scan_btn.isEnabled()
        assert not w._cancel_btn.isEnabled()
        assert not w._progress.isVisible()

    def test_filter_kritisch_nur_urgent_sichtbar(self, qapp):
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        results = [
            _result(name="Firefox", recommendation="update_urgent"),
            _result(name="VLC", recommendation="up_to_date"),
            _result(name="Notion", recommendation="update"),
        ]
        w.on_scan_complete(results)
        assert w._table.rowCount() == 3

        # Filter "Nur kritisch" → nur 1 Zeile
        w._filter_combo.setCurrentIndex(1)  # "Nur kritisch (urgent)"
        assert w._table.rowCount() == 1

    def test_on_scan_failed_zeigt_fehler(self, qapp):
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        w.on_scan_failed("NVD offline")
        assert "NVD offline" in w._status_label.text()
        assert w._scan_btn.isEnabled()
        assert not w._cancel_btn.isEnabled()
        assert not w._progress.isVisible()

    def test_tabelle_leer_nach_on_scan_started(self, qapp):
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        w.on_scan_complete([_result(name="A"), _result(name="B")])
        assert w._table.rowCount() == 2
        w.on_scan_started()
        assert w._table.rowCount() == 0


# ===========================================================================
# Bug-Fix-Sprint C-5 — Modul-Status-Banner
# ===========================================================================


class TestShouldShowBanner:
    """``_should_show_banner(status)`` — Sichtbarkeit des Banners."""

    def test_available_kein_banner(self):
        from core.patch_collector import ModuleStatus

        assert pc._should_show_banner(ModuleStatus.AVAILABLE) is False

    def test_needs_install_zeigt_banner(self):
        from core.patch_collector import ModuleStatus

        assert pc._should_show_banner(ModuleStatus.NEEDS_INSTALL) is True

    def test_blocked_zeigt_banner(self):
        from core.patch_collector import ModuleStatus

        assert pc._should_show_banner(ModuleStatus.BLOCKED) is True


class TestBannerTextForReason:
    """``_banner_text_for_reason(reason)`` — Privacy-Filter-konformer Text."""

    def test_alle_reason_klassen_haben_text(self):
        from core.patch_collector import MODULE_REASON_CLASSES

        # Jede ``reason``-Klasse aus dem Vokabular muss einen Banner-Text
        # haben — sonst zeigt der Banner einen generischen Fallback.
        # Ausnahme: ``probe-succeeded`` ist AVAILABLE-Pfad und triggert
        # keinen Banner; trotzdem darf ein Lookup nicht crashen.
        for reason in MODULE_REASON_CLASSES:
            text = pc._banner_text_for_reason(reason)
            assert text  # nicht leer
            assert isinstance(text, str)

    def test_text_enthaelt_keine_stderr_excerpts(self):
        # Auch bei ``probe-failed`` und ``get-module-failed`` darf der
        # Banner-Text keine Pfad-/Domain-Info enthalten — der stderr-Excerpt
        # lebt ausschliesslich in ``reason_detail`` und nur im
        # Diagnose-Opt-in der UI.
        for reason in ("probe-failed", "get-module-failed"):
            text = pc._banner_text_for_reason(reason)
            assert "C:\\" not in text
            assert "Users" not in text
            assert "stderr" not in text.lower()
            assert "<" not in text  # keine Excerpt-Markierungen

    def test_unbekannte_klasse_fallback_text(self):
        text = pc._banner_text_for_reason("future-class-not-yet-defined")
        # Generischer Fallback — verraet nichts Internes.
        assert "Fallback" in text or "Modul" in text

    def test_specific_text_je_klasse(self):
        # Stichprobe: Klassen liefern unterschiedliche, aussagekraeftige Texte.
        not_found = pc._banner_text_for_reason("module-not-found")
        restricted = pc._banner_text_for_reason("execution-policy-restricted")
        assert "nicht installiert" in not_found
        assert "Restricted" in restricted
        assert not_found != restricted


# ===========================================================================
# PM-2.x — Modul-Funktionen fuer Batch-Upgrade
# ===========================================================================


class TestIsUpgradeable:
    def test_update_urgent_mit_winget_id_ja(self):
        r = _result(recommendation="update_urgent", winget_id="Mozilla.Firefox")
        assert pc._is_upgradeable(r) is True

    def test_update_mit_winget_id_ja(self):
        r = _result(recommendation="update", winget_id="X.Y")
        assert pc._is_upgradeable(r) is True

    def test_update_available_mit_winget_id_ja(self):
        r = _result(recommendation="update_available", winget_id="X.Y")
        assert pc._is_upgradeable(r) is True

    def test_ohne_winget_id_nein(self):
        """Registry-/MSIX-Apps haben winget_id=None — koennen via
        ``winget upgrade`` nicht installiert werden."""
        r = _result(recommendation="update_urgent", winget_id=None)
        assert pc._is_upgradeable(r) is False

    @pytest.mark.parametrize("synthetic_id", ["regid:7-zip", "msix:Microsoft.Photos"])
    def test_synthetische_id_nein(self, synthetic_id):
        """Synthetische Ids (regid:/msix:) sind nie selektierbar — winget
        kann sie nicht installieren, auch nicht mit Update-Empfehlung."""
        r = _result(recommendation="update_urgent", winget_id=synthetic_id)
        assert pc._is_upgradeable(r) is False

    @pytest.mark.parametrize(
        "rec",
        [
            "up_to_date",
            "notify_only",
            "pinned",
        ],
    )
    def test_nicht_update_klassen_nein(self, rec):
        r = _result(recommendation=rec, winget_id="X.Y")
        assert pc._is_upgradeable(r) is False


class TestToUpgradeRequest:
    def test_alle_felder_uebernommen(self):
        r = _result(
            name="Mozilla Firefox",
            recommendation="update",
            winget_id="Mozilla.Firefox",
            installed_version="123.0",
            available_version="124.0",
        )
        req = pc._to_upgrade_request(r)
        assert isinstance(req, UpgradeRequest)
        assert req.winget_id == "Mozilla.Firefox"
        assert req.version_from == "123.0"
        assert req.version_to == "124.0"
        assert req.display_name == "Mozilla Firefox"

    def test_keine_available_version(self):
        r = _result(
            winget_id="X.Y",
            installed_version="1.0",
            available_version=None,
        )
        req = pc._to_upgrade_request(r)
        assert req.version_to is None

    def test_synthetische_id_wirft(self):
        """Defense-in-depth: eine synthetische Id darf nie in einen
        UpgradeRequest gelangen (sonst Pfad zu winget moeglich)."""
        r = _result(recommendation="update", winget_id="regid:7-zip")
        with pytest.raises(ValueError, match="[Ss]ynthetisch"):
            pc._to_upgrade_request(r)


class TestFormatSelectCount:
    def test_null(self):
        assert "Keine" in pc._format_select_count(0)

    def test_eins(self):
        assert pc._format_select_count(1) == "1 Update ausgewaehlt"

    def test_mehrere(self):
        assert pc._format_select_count(11) == "11 Updates ausgewaehlt"


class TestLogLineFormatting:
    def _req(self, name="Firefox", wid="Mozilla.Firefox"):
        return UpgradeRequest(
            winget_id=wid,
            version_from="1.0",
            version_to="2.0",
            display_name=name,
        )

    def test_started_enthaelt_index_und_namen(self):
        line = pc._format_log_line_started(2, 5, self._req())
        assert "[2/5]" in line
        assert "Firefox" in line
        assert "Mozilla.Firefox" in line

    def test_finished_success(self):
        result = UpgradeResult(
            winget_id="Mozilla.Firefox",
            status=UpgradeStatus.SUCCESS,
            exit_code=0,
            duration_ms=1500,
            stdout="",
            stderr="",
        )
        line = pc._format_log_line_finished(1, 3, self._req(), result)
        assert "OK:" in line
        assert "1.5s" in line

    def test_finished_failed_zeigt_error_text(self):
        """2026-05-12: Log nutzt result.error (mit Exit-Code-Hint) statt
        des nackten Exit-Codes — bessere UX bei NO_APPLICABLE_INSTALLER."""
        result = UpgradeResult(
            winget_id="X.Y",
            status=UpgradeStatus.FAILED,
            exit_code=-1978,
            duration_ms=500,
            stdout="",
            stderr="",
            error="winget Exit-Code -1978 — bereits aktuell",
        )
        line = pc._format_log_line_finished(1, 1, self._req(), result)
        assert "Fehler:" in line
        assert "bereits aktuell" in line
        assert "-1978" in line  # Code bleibt im Text drin (via error)

    def test_finished_failed_ohne_error_fallback_auf_exit_code(self):
        """Falls error leer ist (sollte nicht passieren, aber Defense-in-Depth)
        fallen wir auf den nackten exit_code zurueck."""
        result = UpgradeResult(
            winget_id="X.Y",
            status=UpgradeStatus.FAILED,
            exit_code=-9999,
            duration_ms=500,
            stdout="",
            stderr="",
            error=None,
        )
        line = pc._format_log_line_finished(1, 1, self._req(), result)
        assert "-9999" in line

    def test_finished_timeout(self):
        result = UpgradeResult(
            winget_id="X.Y",
            status=UpgradeStatus.TIMEOUT,
            exit_code=None,
            duration_ms=300000,
            stdout="",
            stderr="",
        )
        line = pc._format_log_line_finished(1, 1, self._req(), result)
        assert "Timeout:" in line

    def test_finished_skipped(self):
        result = UpgradeResult(
            winget_id="X.Y",
            status=UpgradeStatus.SKIPPED,
            exit_code=None,
            duration_ms=0,
            stdout="",
            stderr="",
        )
        line = pc._format_log_line_finished(1, 1, self._req(), result)
        assert "uebersprungen" in line


class TestFormatScanFreshness:
    """ Stop-Step D — Banner-Text Helpers."""

    def test_kein_vollscan_hinweis(self) -> None:
        text = pc._format_scan_freshness(None, None)
        assert "noch nicht aufgebaut" in text
        assert "Erst-Vollscan" in text or "Erst-Scan" in text

    def test_vollscan_ohne_daily(self) -> None:
        from datetime import UTC, timedelta
        from datetime import datetime as dt

        now = dt(2026, 5, 12, 12, 0, tzinfo=UTC)
        last_full = now - timedelta(days=2)
        text = pc._format_scan_freshness(last_full, None, now=now)
        assert "Vollscan" in text
        assert "2 Tag" in text
        assert "Daily-Refresh ausstehend" in text

    def test_vollscan_und_daily(self) -> None:
        from datetime import UTC, timedelta
        from datetime import datetime as dt

        now = dt(2026, 5, 12, 12, 0, tzinfo=UTC)
        last_full = now - timedelta(days=5)
        last_daily = now - timedelta(hours=3)
        text = pc._format_scan_freshness(last_full, last_daily, now=now)
        assert "5 Tag" in text
        assert "3 Stunde" in text


class TestFormatAge:
    """Menschenlesbare Zeit-Deltas im Banner."""

    @pytest.mark.parametrize(
        "td, expected_substr",
        [
            ("seconds:30", "wenigen Sekunden"),
            ("minutes:1", "1 Minute"),
            ("minutes:15", "15 Minuten"),
            ("hours:1", "1 Stunde"),
            ("hours:5", "5 Stunden"),
            ("days:1", "1 Tag"),
            ("days:7", "7 Tagen"),
            ("days:60", "2 Monaten"),
        ],
    )
    def test_einheit_auswahl(self, td: str, expected_substr: str) -> None:
        from datetime import timedelta

        unit, value = td.split(":")
        delta = timedelta(**{unit: int(value)})
        assert expected_substr in pc._format_age(delta)


class TestFormatBatchSummary:
    def _summary(self, **kwargs):
        defaults = dict(
            total=0,
            succeeded=0,
            failed=0,
            timed_out=0,
            skipped=0,
            results=[],
        )
        defaults.update(kwargs)
        return BatchSummary(**defaults)

    def test_nur_erfolgreich(self):
        text = pc._format_batch_summary(self._summary(total=3, succeeded=3))
        assert "3 erfolgreich" in text
        assert "fehlgeschlagen" not in text

    def test_gemischt(self):
        text = pc._format_batch_summary(
            self._summary(total=4, succeeded=2, failed=1, timed_out=1)
        )
        assert "2 erfolgreich" in text
        assert "1 fehlgeschlagen" in text
        assert "1 Timeout" in text

    def test_leer(self):
        text = pc._format_batch_summary(self._summary())
        assert "0 Aktionen" in text


# ===========================================================================
# Widget-Smoke (PM-2.x): Checkbox-Spalte + Footer + Worker-State
# ===========================================================================


class TestWidgetUpgradeSmoke:
    """Smoke-Tests fuer die Stop-Step-D-Integration im Widget."""

    def test_widget_hat_10_spalten(self, qapp):
        # Strategie-Spalte → 9; 2026-06-30: Quelle-Spalte ergaenzt → 10.
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        assert w._table.columnCount() == 10

    def test_install_button_initial_disabled(self, qapp):
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        assert not w._install_btn.isEnabled()

    def test_footer_zaehler_initial_null(self, qapp):
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        assert "Keine" in w._select_count_label.text()

    def test_collect_selected_leer_wenn_keine_checkboxen(self, qapp):
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        w.on_scan_complete(
            [
                _result(name="VLC", recommendation="up_to_date"),
                _result(
                    name="Firefox", recommendation="update_urgent", winget_id=None
                ),  # nicht upgradeable
            ]
        )
        assert w._collect_selected_requests() == []

    def test_collect_selected_nach_check(self, qapp):
        from PySide6.QtCore import Qt

        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        w.on_scan_complete(
            [
                _result(
                    name="Firefox",
                    recommendation="update",
                    winget_id="Mozilla.Firefox",
                    installed_version="123.0",
                    available_version="124.0",
                ),
            ]
        )
        check_item = w._table.item(0, w._COL_CHECKBOX)
        assert check_item is not None
        check_item.setCheckState(Qt.CheckState.Checked)
        selected = w._collect_selected_requests()
        assert len(selected) == 1
        assert selected[0].winget_id == "Mozilla.Firefox"
        assert selected[0].version_to == "124.0"
        # Install-Button ist jetzt enabled
        assert w._install_btn.isEnabled()
        assert "1 Update" in w._select_count_label.text()

    def test_select_all_updates_checks_only_upgradeable(self, qapp):
        # C (Live-Test 2026-07-01): 'Alle Updates markieren' kreuzt nur die
        # installierbaren Update-Zeilen an (mit Checkbox), nicht Registry-Apps
        # ohne winget_id oder up-to-date-Zeilen.
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        w.on_scan_complete(
            [
                _result(
                    name="Firefox",
                    recommendation="update",
                    winget_id="Mozilla.Firefox",
                    installed_version="123.0",
                    available_version="124.0",
                ),
                _result(
                    name="RegApp", recommendation="update_urgent", winget_id=None
                ),  # kein Package-Id -> nicht upgradeable, keine Checkbox
                _result(
                    name="VLC", recommendation="up_to_date", winget_id="VideoLAN.VLC"
                ),  # kein Update -> keine Checkbox
            ]
        )
        w._select_all_updates()
        selected = w._collect_selected_requests()
        assert len(selected) == 1
        assert selected[0].winget_id == "Mozilla.Firefox"
        assert w._install_btn.isEnabled()

    def test_show_found_updates_springt_in_update_filter(self, qapp):
        # C: nach dem on-demand-Quick-Check macht _show_found_updates die
        # gefundenen Updates sichtbar (Filter -> needs_update) + Status-Hinweis.
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        w.on_scan_complete(
            [
                _result(
                    name="Firefox",
                    recommendation="update",
                    winget_id="Mozilla.Firefox",
                    installed_version="123.0",
                    available_version="124.0",
                ),
            ]
        )
        w._show_found_updates()
        assert w._filter_key == "needs_update"
        assert "Update(s) gefunden" in w._status_label.text()


# ===========================================================================
# Strategie-Labels (pure Helfer, kein QApplication noetig)
# ===========================================================================


class TestStrategyLabels:
    def test_alle_strategien_haben_label(self):
        from core.patch_strategy import PatchStrategy
        from tools.patch_monitor.gui.patch_console_widget import (
            _STRATEGY_LABELS,
            _strategy_label,
        )

        for s in PatchStrategy:
            assert s in _STRATEGY_LABELS
            assert _strategy_label(s)


# ===========================================================================
# Strategie-Spalte / Dropdown
# ===========================================================================


@pytest.mark.gui
class TestStrategyColumn:
    def test_dropdown_fuer_winget_id_row(self, qapp):
        from PySide6.QtWidgets import QComboBox

        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        w.on_scan_complete([_result(name="Firefox", winget_id="Mozilla.Firefox")])
        combo = w._table.cellWidget(0, w._COL_STRATEGY)
        assert isinstance(combo, QComboBox)
        assert combo.count() == 3

    def test_kein_dropdown_ohne_winget_id(self, qapp):
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        w.on_scan_complete([_result(name="RegistryApp", winget_id=None)])
        assert w._table.cellWidget(0, w._COL_STRATEGY) is None

    def test_on_strategy_changed_persistiert(self, qapp):
        from datetime import UTC, datetime

        from core.patch_strategy import PatchStrategy
        from tools.patch_monitor.data.patch_inventory_repository import (
            InventoryEntry,
        )
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        service = w._get_inventory_service()
        assert service is not None
        now = datetime.now(UTC)
        service._repo.upsert_inventory(  # noqa: SLF001
            InventoryEntry(
                winget_id="A.A",
                name="A",
                normalized_name="a",
                vendor="v",
                source="winget",
                installed_version="1.0",
                cpe_string=None,
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=now,
                last_full_scan_at=now,
            )
        )
        w._on_strategy_changed("A.A", PatchStrategy.NONE)
        loaded = service._repo.get_inventory("A.A")  # noqa: SLF001
        assert loaded is not None
        assert loaded.patch_strategy is PatchStrategy.NONE


# ===========================================================================
# "App hinzufuegen"-Button (kein Pro-Tier-Gate mehr, immer aktiv)
# ===========================================================================


@pytest.mark.gui
class TestAddSourceButton:
    def test_button_always_enabled(self, qapp) -> None:
        # Custom-Sources sind für alle frei — Button immer aktiv,
        # kein is_pro_tier-Gate mehr.
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        w = PatchConsoleWidget()
        assert w._add_source_btn.isEnabled()
