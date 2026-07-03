"""
test_norisk_runde5_session1 — Tests für NoRisk Runde 5, Session 1.

Abgedeckte Änderungen:
  - TEIL 1: Security Score — keine ALTE Multi-Target-Verwaltung mehr
    (_combo_target/_btn_add_system/_btn_delete_target). HINWEIS: hat die
    frühere „nur eigenes System"-Invariante bewusst aufgehoben — ein Subjekt-
    Picker (_cmb_subject, eigenes System + Kunden, read-only/erfassen) ist jetzt
    gewollt; die betroffenen Assertions wurden auf nachgezogen.
  - TEIL 2: customer_list_widget verwendet FinlaiConfirmDialog/FinlaiSuccessDialog
  - TEIL 3: Advisory-Monitor Tech-Stack-Dialog + Löschen + Bearbeiten

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# TEIL 1 — Security Score: nur eigenes System
# ---------------------------------------------------------------------------


class TestScoringDashboardOwnSystemOnly:
    """Security Score darf keine Kunden-Verwaltung mehr enthalten."""

    def test_no_combo_target_attribute(self) -> None:
        """ScoringDashboardWidget darf kein _combo_target mehr haben."""
        import ast
        import pathlib

        src = pathlib.Path(
            "tools/security_scoring/gui/scoring_dashboard_widget.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(src)

        # Suche nach _combo_target Attribut-Zuweisungen
        assignments = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr == "_combo_target"
        ]
        assert len(assignments) == 0, (
            "_combo_target darf in scoring_dashboard_widget.py nicht mehr vorkommen"
        )

    def test_no_btn_add_system_attribute(self) -> None:
        """ScoringDashboardWidget darf kein _btn_add_system mehr haben."""
        import pathlib

        src = pathlib.Path(
            "tools/security_scoring/gui/scoring_dashboard_widget.py"
        ).read_text(encoding="utf-8")
        assert "_btn_add_system" not in src, (
            "_btn_add_system darf in scoring_dashboard_widget.py nicht mehr vorkommen"
        )

    def test_no_btn_delete_target_attribute(self) -> None:
        """ScoringDashboardWidget darf kein _btn_delete_target mehr haben."""
        import pathlib

        src = pathlib.Path(
            "tools/security_scoring/gui/scoring_dashboard_widget.py"
        ).read_text(encoding="utf-8")
        assert "_btn_delete_target" not in src, (
            "_btn_delete_target darf in scoring_dashboard_widget.py nicht mehr vorkommen"
        )

    def test_own_system_label_present(self) -> None:
        """Der Quelltext muss '_lbl_own_system' enthalten."""
        import pathlib

        src = pathlib.Path(
            "tools/security_scoring/gui/scoring_dashboard_widget.py"
        ).read_text(encoding="utf-8")
        assert "_lbl_own_system" in src

    def test_kunden_modus_erfassen_vorhanden(self) -> None:
        """: Kunden-Modus bietet 'Hardening erfassen' (statt Audit-Verweis)."""
        import pathlib

        src = pathlib.Path(
            "tools/security_scoring/gui/scoring_dashboard_widget.py"
        ).read_text(encoding="utf-8")
        assert "Hardening erfassen" in src
        assert "_btn_erfassen" in src

    def test_qcombobox_fuer_subjekt_picker(self) -> None:
        """: QComboBox ist jetzt vorhanden (Subjekt-Picker _cmb_subject)."""
        import pathlib

        src = pathlib.Path(
            "tools/security_scoring/gui/scoring_dashboard_widget.py"
        ).read_text(encoding="utf-8")
        assert "QComboBox" in src
        assert "_cmb_subject" in src

    def test_own_system_profile_attribute_used(self) -> None:
        """_own_system muss im Quelltext verwendet werden."""
        import pathlib

        src = pathlib.Path(
            "tools/security_scoring/gui/scoring_dashboard_widget.py"
        ).read_text(encoding="utf-8")
        assert "_own_system" in src

    def test_no_migrate_existing_targets(self) -> None:
        """migrate_existing_targets darf nicht mehr in scoring_dashboard aufgerufen werden."""
        import pathlib

        src = pathlib.Path(
            "tools/security_scoring/gui/scoring_dashboard_widget.py"
        ).read_text(encoding="utf-8")
        assert "migrate_existing_targets" not in src


# ---------------------------------------------------------------------------
# TEIL 2 — Security Audit: FinlaiConfirmDialog statt QMessageBox
# ---------------------------------------------------------------------------


class TestCustomerListWidgetDialogs:
    """customer_list_widget muss FinlaiConfirmDialog/FinlaiSuccessDialog verwenden."""

    def test_no_qmessagebox_import(self) -> None:
        """QMessageBox darf nicht mehr in customer_list_widget importiert sein."""
        import pathlib

        src = pathlib.Path(
            "tools/customer_audit/gui/customer_list_widget.py"
        ).read_text(encoding="utf-8")
        assert "QMessageBox" not in src

    def test_finlai_confirm_dialog_used(self) -> None:
        """FinlaiConfirmDialog muss in customer_list_widget importiert/verwendet sein."""
        import pathlib

        src = pathlib.Path(
            "tools/customer_audit/gui/customer_list_widget.py"
        ).read_text(encoding="utf-8")
        assert "FinlaiConfirmDialog" in src

    def test_finlai_success_dialog_used(self) -> None:
        """FinlaiSuccessDialog muss in customer_list_widget importiert/verwendet sein."""
        import pathlib

        src = pathlib.Path(
            "tools/customer_audit/gui/customer_list_widget.py"
        ).read_text(encoding="utf-8")
        assert "FinlaiSuccessDialog" in src

    def test_finlai_info_dialog_used(self) -> None:
        """FinlaiInfoDialog muss in customer_list_widget importiert/verwendet sein."""
        import pathlib

        src = pathlib.Path(
            "tools/customer_audit/gui/customer_list_widget.py"
        ).read_text(encoding="utf-8")
        assert "FinlaiInfoDialog" in src

    def test_delete_uses_qdialog_accepted(self) -> None:
        """_delete muss QDialog.DialogCode.Accepted als Rückgabe-Check verwenden."""
        import pathlib

        src = pathlib.Path(
            "tools/customer_audit/gui/customer_list_widget.py"
        ).read_text(encoding="utf-8")
        assert "DialogCode.Accepted" in src


# ---------------------------------------------------------------------------
# TEIL 3 — Advisory-Monitor: Tech-Stack-Dialog + Löschen + Bearbeiten
# ---------------------------------------------------------------------------


@pytest.mark.skip(
    reason=(
        "Cleanup-Sprint 2026-04-29: Source-Grep-Tests gegen die alte, "
        "monolithische csaf_advisor_widget.py. Die getesteten Bausteine "
        "(_TechStackDialog, _btn_delete_system, _on_delete_system, "
        "_update_system_btn_state etc.) leben jetzt in den extrahierten "
        "Modulen tools/csaf_advisor/gui/{techstack_dialog,system_selector_panel}.py "
        "(Public-Klasse 'TechStackDialog' ohne Underscore). Funktional sind "
        "alle Bausteine erhalten — nur die Source-Grep-Pfade stimmen nicht "
        "mehr. Strukturierte Unit-Tests gegen die neuen Klassen kommen in "
        "einem Folge-Sprint (vgl. test_csaf_techstack_tab.py aus S2c)."
    )
)
class TestTechStackDialog:
    """Tests für _TechStackDialog (statische Code-Analyse + Struktur)."""

    def test_tech_stack_dialog_class_exists(self) -> None:
        """_TechStackDialog muss in csaf_advisor_widget.py vorhanden sein."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        assert "class _TechStackDialog" in src

    def test_get_tech_stack_method_exists(self) -> None:
        """_TechStackDialog muss eine get_tech_stack Methode haben."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        assert "def get_tech_stack" in src

    def test_prefill_method_exists(self) -> None:
        """_TechStackDialog muss eine _prefill Methode haben."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        assert "def _prefill" in src

    def test_os_options_defined(self) -> None:
        """OS-Optionen (Windows 10, Windows 11 etc.) müssen definiert sein."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        for os_name in ["Windows 10", "Windows 11", "macOS", "Linux"]:
            assert os_name in src, f"OS-Option '{os_name}' fehlt"

    def test_delete_button_in_selector(self) -> None:
        """_btn_delete_system muss im System-Selector vorhanden sein."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        assert "_btn_delete_system" in src

    def test_edit_button_in_selector(self) -> None:
        """_btn_edit_system muss im System-Selector vorhanden sein."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        assert "_btn_edit_system" in src

    def test_on_delete_system_slot_exists(self) -> None:
        """_on_delete_system Slot muss vorhanden sein."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        assert "def _on_delete_system" in src

    def test_on_edit_system_slot_exists(self) -> None:
        """_on_edit_system Slot muss vorhanden sein."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        assert "def _on_edit_system" in src

    def test_delete_button_disabled_for_own_system(self) -> None:
        """_update_system_btn_state muss disable-Logik für eigenes System enthalten."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        assert "_update_system_btn_state" in src
        assert "setEnabled(not is_own)" in src

    def test_tech_stack_dialog_get_tech_stack_logic(self) -> None:
        """get_tech_stack muss TechStack-Klasse verwenden und zurückgeben."""
        try:
            from tools.csaf_advisor.gui import csaf_advisor_widget as mod
        except ImportError as e:
            pytest.skip(f"Import fehlgeschlagen: {e}")

        assert hasattr(mod, "_TechStackDialog")

    def test_browser_options_defined(self) -> None:
        """Browser-Optionen müssen definiert sein."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        for br in ["Chrome", "Firefox", "Edge"]:
            assert br in src, f"Browser-Option '{br}' fehlt"

    def test_finlai_confirm_dialog_on_delete(self) -> None:
        """_on_delete_system muss FinlaiConfirmDialog verwenden."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        assert "FinlaiConfirmDialog" in src

    def test_tech_stack_saved_after_add(self) -> None:
        """_on_add_customer_system muss den Tech-Stack nach dem Anlegen speichern."""
        import pathlib

        src = pathlib.Path("tools/csaf_advisor/gui/csaf_advisor_widget.py").read_text(
            encoding="utf-8"
        )
        # Nach Anlegen muss update_profile aufgerufen werden
        assert "update_profile" in src


# ---------------------------------------------------------------------------
# Daten-Isolation: Security Score vs. Security Audit
# ---------------------------------------------------------------------------


class TestArchitecturalSeparation:
    """Architektonische Trennung zwischen Security Score und Security Audit."""

    def test_scoring_widget_no_customer_type_check(self) -> None:
        """scoring_dashboard_widget darf SystemType.KUNDE nicht mehr referenzieren."""
        import pathlib

        src = pathlib.Path(
            "tools/security_scoring/gui/scoring_dashboard_widget.py"
        ).read_text(encoding="utf-8")
        # SystemType.KUNDE war für den Löschen-Button — muss weg sein
        assert "SystemType.KUNDE" not in src

    def test_scoring_widget_imports_system_profile(self) -> None:
        """scoring_dashboard_widget importiert SystemProfile für eigenes System."""
        import pathlib

        src = pathlib.Path(
            "tools/security_scoring/gui/scoring_dashboard_widget.py"
        ).read_text(encoding="utf-8")
        assert "SystemProfile" in src

    def test_customer_assessment_has_no_scoring_imports(self) -> None:
        """customer_list_widget importiert nichts aus security_scoring."""
        import pathlib

        src = pathlib.Path(
            "tools/customer_audit/gui/customer_list_widget.py"
        ).read_text(encoding="utf-8")
        assert "security_scoring" not in src
