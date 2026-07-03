"""
test_help_system — Tests für das In-App-Hilfesystem (Phase 1 + 2).

Deckt ab:
  * HelpRegistry — Auto-Registration, get/register/clear, fehlende Keys
  * HelpContent — alle 17 Pflicht-Einträge, Mindestdichte der Tooltips
  * HelpPanel — Instanziierung, Collapsed/Expanded-Toggle, QSettings-Persistenz
  * HelpButton + InfoDialog — Kurztexte vs. Langtexte, Non-Modality
  * HelpDialog — Welcome-Init, initial_nav_key-Sprung, Volltextsuche

Die Phase-2-Integration (Panel/Buttons in jedem Widget, F1-Shortcut,
Singleton) ist durch den Smoke-Test abgedeckt — das Widget-Mapping wird
hier zusätzlich statisch validiert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest
from PySide6.QtCore import QSettings, Qt

from core.help.help_content import ALL_HELP_CONTENTS, HelpContent
from core.help.help_dialog import HelpDialog
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton, InfoDialog

pytestmark = pytest.mark.gui

# ---------------------------------------------------------------------------
# HelpContent — Datenbasis-Integrität
# ---------------------------------------------------------------------------


class TestHelpContentDataset:
    """Statische Tests an den 17 HelpContent-Einträgen."""

    def test_count(self) -> None:
        """Es sind genau 17 Tool-Einträge registriert: ki:deepl entfernt)."""
        assert len(ALL_HELP_CONTENTS) == 17

    def test_expected_nav_keys(self) -> None:
        """Alle 17 NoRisk-Tools sind abgedeckt: ki:deepl entfernt durch)."""
        expected = {
            "api_security",
            "cert_monitor",
            "csaf_advisor",
            "customer_audit",
            "cyber_dashboard",
            "dependency_auditor",
            "email_scanner",
            "ki:ollama",
            "network_monitor",
            "network_scanner",
            "nis2_incidents",
            "norisk:dashboard",
            "password_checker",
            "pdf_risk_scanner",
            "security_scoring",
            "system_scanner",
            "techstack",
        }
        found = {c.nav_key for c in ALL_HELP_CONTENTS}
        assert found == expected

    def test_nis2_incidents_compliance_coverage(self) -> None:
        """: nis2_incidents deckt NIS2-Compliance-kritische Elemente ab."""
        from core.help.help_content import HELP_NIS2_INCIDENTS

        # Pflicht-Tooltips fuer alle Form-Felder und Tabellen-Spalten
        required_tooltips = {
            "btn_new_incident",
            "btn_refresh",
            "tab_open",
            "tab_archive",
            "col_severity",
            "col_phase",
            "col_deadline",
            "combo_audit",
            "input_title",
            "combo_severity",
            "edit_detected",
            "input_description",
            "input_actor",
        }
        assert required_tooltips.issubset(HELP_NIS2_INCIDENTS.tooltips.keys()), (
            "nis2_incidents-Tooltips fehlen Compliance-Felder: "
            f"{required_tooltips - HELP_NIS2_INCIDENTS.tooltips.keys()}"
        )

        # Pflicht-Erklaer-Layer fuer DSGVO-/NIS2-kritische Felder
        required_explanations = {"col_deadline", "combo_severity", "btn_new_incident"}
        assert required_explanations.issubset(HELP_NIS2_INCIDENTS.explanations.keys()), (
            "nis2_incidents-Explanations fehlen kritische Felder: "
            f"{required_explanations - HELP_NIS2_INCIDENTS.explanations.keys()}"
        )

        # Heuristik: Geschaeftsleitungs-Haftung aus UX_TOOLTIP_STRATEGY) muss erwaehnt sein
        gf_explanation = HELP_NIS2_INCIDENTS.explanations.get("btn_new_incident", "")
        assert "Inhaberin" in gf_explanation or "Geschäftsführer" in gf_explanation, (
            "GF-Haftung (NIS2 Art. 20) muss in btn_new_incident-Explanation erklaert sein"
        )

    def test_mandatory_fields_filled(self) -> None:
        """Alle Pflichtfelder sind nicht leer; steps ≥ 3; tooltips ≥ 2."""
        for c in ALL_HELP_CONTENTS:
            assert c.tool_name.strip(), f"tool_name empty in {c.nav_key}"
            assert c.nav_key.strip(), "nav_key empty"
            assert c.short_description.strip(), f"short_description empty in {c.nav_key}"
            assert c.purpose.strip(), f"purpose empty in {c.nav_key}"
            assert c.when_to_use.strip(), f"when_to_use empty in {c.nav_key}"
            assert len(c.steps) >= 3, f"steps < 3 in {c.nav_key}"
            assert c.result_explanation.strip(), (
                f"result_explanation empty in {c.nav_key}"
            )
            assert c.next_steps.strip(), f"next_steps empty in {c.nav_key}"
            assert len(c.tooltips) >= 2, f"tooltips < 2 in {c.nav_key}"
            for k, v in c.tooltips.items():
                assert k.strip(), f"empty tooltip key in {c.nav_key}"
                assert v.strip(), f"empty tooltip text for '{k}' in {c.nav_key}"


# ---------------------------------------------------------------------------
# HelpRegistry — Class-Level-Singleton
# ---------------------------------------------------------------------------


class TestHelpRegistry:
    """Tests für die HelpRegistry-Klasse (Auto-Registration + CRUD)."""

    @pytest.fixture(autouse=True)
    def _ensure_registry_initialized(self):
        """Cleanup-Sprint 2026-04-29: Audit-Befund S2-2 (
        ``core/help/help_registry.py:88-90``) hat die Modul-Level-Auto-
        Registrierung entfernt. ``init_registry`` wird produktiv aus
        ``apps/__init__.py:launch_app`` aufgerufen — im Test-Kontext
        nicht. Wir füllen die Registry deshalb zu Beginn jedes Tests
        in dieser Klasse einmalig."""
        from core.help.help_registry import init_registry  # noqa: PLC0415

        init_registry()
        yield

    def test_auto_register_after_import(self) -> None:
        """Nach Import sind ALLE HelpContents registriert (Anzahl == Dataset).

        Gegen len(ALL_HELP_CONTENTS) statt Magic-Number — bleibt korrekt, wenn
        Phase-1.4-WPs Einträge hinzufügen/entfernen (vgl.-Halbfix, bei dem
        test_count auf 18 zog, dieser Test aber auf 17 stehen blieb).
        """
        assert HelpRegistry.count() == len(ALL_HELP_CONTENTS)

    def test_get_known_key(self) -> None:
        hc = HelpRegistry.get("password_checker")
        assert hc is not None
        assert hc.nav_key == "password_checker"

    def test_get_unknown_returns_none(self) -> None:
        assert HelpRegistry.get("__nonexistent__") is None

    def test_get_all_returns_copy(self) -> None:
        """get_all liefert eine Kopie — externe Mutation darf Registry nicht treffen."""
        snapshot = HelpRegistry.get_all()
        snapshot.pop("password_checker")
        assert HelpRegistry.get("password_checker") is not None

    def test_register_overwrites_existing(self) -> None:
        """register mit gleichem Key überschreibt den Eintrag."""
        original = HelpRegistry.get("password_checker")
        try:
            fake = HelpContent(
                tool_name="FAKE",
                nav_key="password_checker",
                short_description="fake",
                purpose="fake",
                when_to_use="fake",
                steps=["a", "b", "c"],
                result_explanation="fake",
                next_steps="fake",
                tooltips={"x": "y", "a": "b"},
            )
            HelpRegistry.register(fake)
            assert HelpRegistry.get("password_checker").tool_name == "FAKE"
        finally:
            if original is not None:
                HelpRegistry.register(original)


# ---------------------------------------------------------------------------
# HelpPanel — Widget
# ---------------------------------------------------------------------------


class TestHelpPanel:
    """HelpPanel-Instanziierung, Collapse-State, QSettings-Persistenz."""

    @pytest.fixture(autouse=True)
    def _cleanup_settings(self) -> None:
        """Löscht QSettings vor jedem Test für deterministische Zustände."""
        qs = QSettings("finLai", "HelpPanel")
        qs.clear()
        qs.sync()
        yield
        qs.clear()
        qs.sync()

    def test_init_collapsed_by_default(self, qapp) -> None:
        hc = HelpRegistry.get("password_checker")
        panel = HelpPanel(hc)
        assert panel.maximumHeight() <= 40  # collapsed

    def test_signal_open_full_help_exists(self, qapp) -> None:
        hc = HelpRegistry.get("password_checker")
        panel = HelpPanel(hc)
        assert hasattr(panel, "open_full_help")

    def test_toggle_persists_state(self, qapp) -> None:
        """Nach Toggle bleibt der Zustand via QSettings erhalten."""
        hc = HelpRegistry.get("password_checker")
        panel_a = HelpPanel(hc)
        panel_a._on_toggle_clicked()  # öffnet → True
        panel_b = HelpPanel(hc)
        assert panel_b._expanded is True


# ---------------------------------------------------------------------------
# HelpButton + InfoDialog
# ---------------------------------------------------------------------------


class TestHelpButton:
    """HelpButton und InfoDialog-Verhalten."""

    def test_button_has_fixed_size(self, qapp) -> None:
        btn = HelpButton("Kurzer Tooltip")
        # 18×18 per Spec
        assert btn.width() == 18
        assert btn.height() == 18

    def test_short_text_uses_tooltip(self, qapp) -> None:
        """Texte < 120 Zeichen werden über QToolTip angezeigt, nicht Dialog."""
        btn = HelpButton("Kurzer Text unter 120 Zeichen.")
        # Simulate click
        btn._on_clicked()
        # Kein InfoDialog erzeugt
        assert btn._dialog is None

    def test_long_text_opens_info_dialog(self, qapp) -> None:
        """Texte ≥ 120 Zeichen öffnen den InfoDialog."""
        long_text = (
            "Dies ist ein sehr langer Tooltip-Text, der die 120-Zeichen-Grenze "
            "deutlich überschreitet um das Verhalten des HelpButtons zu prüfen. "
            "Genau deshalb öffnet sich dann ein InfoDialog."
        )
        btn = HelpButton(long_text)
        btn._on_clicked()
        assert btn._dialog is not None
        assert isinstance(btn._dialog, InfoDialog)
        assert not btn._dialog.isModal()
        btn._dialog.close()

    def test_info_dialog_is_non_modal(self, qapp) -> None:
        dlg = InfoDialog("Titel", "Body")
        assert not dlg.isModal()
        assert dlg.windowModality() == Qt.WindowModality.NonModal


# ---------------------------------------------------------------------------
# HelpDialog
# ---------------------------------------------------------------------------


class TestHelpDialog:
    @pytest.fixture(autouse=True)
    def _ensure_registry_initialized(self):
        """Cleanup-Sprint 2026-04-29: HelpDialog liest aus der HelpRegistry
        — vgl. Begründung in ``TestHelpRegistry._ensure_registry_initialized``."""
        from core.help.help_registry import init_registry  # noqa: PLC0415

        init_registry()
        yield

    """HelpDialog (kombiniertes Handbuch + KI-Launcher)."""

    def test_init_without_key_shows_welcome(self, qapp) -> None:
        dlg = HelpDialog()
        assert dlg._current_key == HelpDialog.WELCOME_KEY
        assert not dlg.isModal()

    def test_init_with_nav_key_jumps_to_chapter(self, qapp) -> None:
        # Tool-Deeplink → passender Handbuch-Abschnitt (password_checker → 10.2).
        dlg = HelpDialog(initial_nav_key="password_checker")
        assert dlg._current_key == "10.2"

    def test_md_handbook_mode_toggle_hidden_and_content_stable(self, qapp) -> None:
        """: Das.md-Handbuch hat EINE Stimme — der Einfach/Profi-Umschalter ist
        ausgeblendet und der Kapitel-Text ändert sich beim Moduswechsel nicht."""
        from core.help.display_mode import DisplayMode
        from core.help.display_mode_state import DisplayModeState

        DisplayModeState.reset_for_tests()
        DisplayModeState.instance().set_mode(DisplayMode.EXPERT)
        dlg = HelpDialog(initial_nav_key="api_security")
        assert dlg._sections, "Handbuch-Abschnitte müssen geladen sein"
        assert dlg._mode_check.isHidden()  # Umschalter im.md-Modus ausgeblendet
        expert_text = dlg._content_view.toPlainText()
        DisplayModeState.instance().set_mode(DisplayMode.EASY)
        assert dlg._content_view.toPlainText() == expert_text  # modus-unabhängig

    def test_close_trennt_mode_changed(self, qapp) -> None:
        """: closeEvent trennt die mode_changed-Verbindung (kein Zombie-Render).

        Funktional: nach close darf ein globaler Modus-Wechsel das (versteckte)
        Content-View des geschlossenen Dialogs NICHT mehr neu rendern.
        """
        from core.help.display_mode import DisplayMode
        from core.help.display_mode_state import DisplayModeState

        DisplayModeState.reset_for_tests()
        DisplayModeState.instance().set_mode(DisplayMode.EXPERT)
        dlg = HelpDialog(initial_nav_key="api_security")
        text_before = dlg._content_view.toPlainText()
        dlg.close()
        DisplayModeState.instance().toggle()  # würde bei aktiver Verbindung re-rendern
        assert dlg._content_view.toPlainText() == text_before

    def test_search_filters_list(self, qapp) -> None:
        """Volltextsuche über Tool-Texte filtert die Navigationsliste."""
        dlg = HelpDialog()
        dlg._search_edit.setText("passwort")
        dlg._apply_search()
        hits_text = dlg._search_hits_lbl.text()
        assert "Treffer" in hits_text
        # Mindestens ein Eintrag matcht
        assert hits_text != "keine Treffer"

    def test_search_no_match(self, qapp) -> None:
        dlg = HelpDialog()
        dlg._search_edit.setText("xyz_definitiv_kein_treffer_123")
        dlg._apply_search()
        assert dlg._search_hits_lbl.text() == "keine Treffer"

    def test_search_empty_shows_all(self, qapp) -> None:
        dlg = HelpDialog()
        dlg._search_edit.setText("")
        dlg._apply_search()
        # Alle Items sichtbar
        hidden = [
            i
            for i in range(dlg._nav_list.count())
            if dlg._nav_list.item(i).isHidden()
        ]
        assert hidden == []

    def test_tabs_present(self, qapp) -> None:
        """Zwei Tabs: Handbuch + FINLAI-Assistent: Inline-Assistent)."""
        dlg = HelpDialog()
        assert dlg._tabs.count() == 2
        assert dlg._tabs.tabText(0) == "Handbuch"
        assert dlg._tabs.tabText(1) == "FINLAI-Assistent"

    def test_assistant_key_opens_assistant_tab(self, qapp) -> None:
        """: ASSISTANT_KEY öffnet den Dialog direkt auf dem Assistenz-Reiter.

        Pfad für umgeleitete ``ki:ollama``-Alt-Deeplinks
        (NavigationMixin._on_sidebar_navigate)."""
        dlg = HelpDialog(initial_nav_key=HelpDialog.ASSISTANT_KEY)
        assert dlg._tabs.currentIndex() == HelpDialog._ASSISTANT_TAB_INDEX
        assert dlg._tabs.tabText(dlg._tabs.currentIndex()) == "FINLAI-Assistent"

    def test_show_assistant_switches_tab_on_reuse(self, qapp) -> None:
        """ (Review-P2): show_assistant holt den Assistenz-Reiter auch bei
        einem bereits offenen Dialog nach vorn (Mascot-Reklick / ki:ollama-Deeplink
        bei offenem Handbuch-Reiter)."""
        dlg = HelpDialog()
        dlg._tabs.setCurrentIndex(0)  # auf Handbuch-Reiter
        dlg.show_assistant()
        assert dlg._tabs.currentIndex() == HelpDialog._ASSISTANT_TAB_INDEX


# ---------------------------------------------------------------------------
# QApplication-Fixture (reused across tests)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def qapp():
    """Liefert eine QApplication-Instanz für alle Widget-Tests."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app
