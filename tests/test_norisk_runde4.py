"""
test_norisk_runde4 — Tests für NoRisk Feinschliff Runde 4.

Abgedeckte Features:
  - FIX A: ENABLE_LIGHT_THEME Feature-Flag in core/constants.py
  - FIX C: VideoEmbedWidget (gui/common/video_embed_widget.py)
  - Prompt 1: _techstack_to_components Konvertierung (Advisory-Monitor)

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# FIX A — ENABLE_LIGHT_THEME Feature-Flag
# ---------------------------------------------------------------------------


class TestEnableLightThemeFlag:
    """Tests für den ENABLE_LIGHT_THEME Feature-Flag."""

    def test_flag_exists_in_constants(self) -> None:
        """ENABLE_LIGHT_THEME muss in core.constants vorhanden sein."""
        from core.constants import ENABLE_LIGHT_THEME

        assert isinstance(ENABLE_LIGHT_THEME, bool)

    def test_flag_is_false(self) -> None:
        """Light-Theme wurde entfernt — Flag ist False."""
        from core.constants import ENABLE_LIGHT_THEME

        assert ENABLE_LIGHT_THEME is False

    def test_theme_selector_labels_only_dark(self) -> None:
        """_LOOK_LABELS_ALL enthält nur noch 'dark' — Light-Theme entfernt."""
        import tools.einstellungen.gui.theme_selector as mod

        assert len(mod._LOOK_LABELS_ALL) == 1
        assert mod._LOOK_LABELS_ALL[0][0] == "dark"

    def test_theme_selector_labels_gleich_all(self) -> None:
        """_LOOK_LABELS entspricht _LOOK_LABELS_ALL (kein weiteres Filtering nötig)."""
        import tools.einstellungen.gui.theme_selector as mod

        assert mod._LOOK_LABELS == mod._LOOK_LABELS_ALL


# FIX C (TestVideoEmbedWidget) entfernt im NoRisk-Repo:
# gui/common/video_embed_widget.py war die Reusable-Komponente fuer das
# geloeschte cybersec_videos-Tool. Mit der Tool-Loeschung (Schritt A der
# App-Trennungs-Vorbereitung, Commit e1b8341) ist der gui/-Top-Level
# obsolet und wird nicht in den NoRisk-Repo migriert.


# ---------------------------------------------------------------------------
# Prompt 1 — _techstack_to_components Konvertierung
# ---------------------------------------------------------------------------


class TestTechstackToComponents:
    """Tests für die _techstack_to_components Hilfsfunktion."""

    @staticmethod
    def _get_converter():
        """Importiert _techstack_to_components aus der aktuellen Stelle.

        Cleanup-Sprint 2026-04-29: ``_techstack_to_components`` wurde aus
        ``CsafAdvisorWidget`` in:class:`SystemSelectorPanel` ausgelagert
        (Modular-Refactor). Der Test prüft weiter dieselbe Logik, nur am
        richtigen Ort.
        """
        try:
            from tools.csaf_advisor.gui.system_selector_panel import (
                SystemSelectorPanel,
            )
        except ImportError as e:
            pytest.skip(f"Import fehlgeschlagen: {e}")
        return SystemSelectorPanel._techstack_to_components

    def _make_stack(self, **kwargs):
        """Erstellt einen TechStack mit den angegebenen Feldern."""
        from tools.security_scoring.domain.tech_stack.entities import (
            SecurityTool,
            TechStack,
        )
        from tools.security_scoring.domain.tech_stack.enums import ToolStatus

        defaults = {
            "operating_systems": [],
            "browsers": [],
            "antivirus": SecurityTool(name="", status=ToolStatus.UNBEKANNT),
            "firewall": SecurityTool(name="", status=ToolStatus.UNBEKANNT),
            "vpn": None,
            "remote_access": [],
            "custom_software": [],
        }
        defaults.update(kwargs)
        return TechStack(**defaults)

    def test_empty_stack_returns_empty_list(self) -> None:
        """Ein leerer TechStack ergibt eine leere Komponenten-Liste."""
        converter = self._get_converter()
        stack = self._make_stack()
        result = converter(stack)
        assert result == []

    def test_os_entry_converted(self) -> None:
        """OSEntry wird korrekt zu SoftwareComponent konvertiert."""
        from tools.security_scoring.domain.tech_stack.entities import OSEntry

        converter = self._get_converter()
        stack = self._make_stack(operating_systems=[OSEntry("Windows 11", "23H2")])
        result = converter(stack)

        assert len(result) == 1
        assert result[0].name == "Windows 11"
        assert result[0].version == "23H2"
        assert result[0].category == "OS"

    def test_browser_entry_converted(self) -> None:
        """BrowserEntry wird korrekt zu SoftwareComponent konvertiert."""
        from tools.security_scoring.domain.tech_stack.entities import BrowserEntry

        converter = self._get_converter()
        stack = self._make_stack(browsers=[BrowserEntry("Chrome", "124.0")])
        result = converter(stack)

        assert len(result) == 1
        assert result[0].name == "Chrome"
        assert result[0].category == "Browser"

    def test_antivirus_converted_when_named(self) -> None:
        """Antivirus mit Name wird als Komponente erfasst."""
        from tools.security_scoring.domain.tech_stack.entities import SecurityTool
        from tools.security_scoring.domain.tech_stack.enums import ToolStatus

        converter = self._get_converter()
        stack = self._make_stack(antivirus=SecurityTool("Defender", ToolStatus.AKTIV))
        result = converter(stack)

        assert len(result) == 1
        assert result[0].name == "Defender"
        assert result[0].category == "Antivirus"

    def test_antivirus_skipped_when_empty_name(self) -> None:
        """Antivirus ohne Namen wird nicht als Komponente erfasst."""
        from tools.security_scoring.domain.tech_stack.entities import SecurityTool
        from tools.security_scoring.domain.tech_stack.enums import ToolStatus

        converter = self._get_converter()
        stack = self._make_stack(antivirus=SecurityTool("", ToolStatus.FEHLT))
        result = converter(stack)
        assert result == []

    def test_vpn_converted(self) -> None:
        """VPN-String wird als Komponente erfasst."""
        converter = self._get_converter()
        stack = self._make_stack(vpn="NordVPN")
        result = converter(stack)

        assert len(result) == 1
        assert result[0].name == "NordVPN"
        assert result[0].category == "VPN"

    def test_custom_software_converted(self) -> None:
        """Custom-Software-Einträge werden erfasst."""
        converter = self._get_converter()
        stack = self._make_stack(custom_software=["Slack", "Zoom"])
        result = converter(stack)

        assert len(result) == 2
        names = [c.name for c in result]
        assert "Slack" in names
        assert "Zoom" in names

    def test_empty_string_entries_skipped(self) -> None:
        """Leere Strings in Custom-Software werden übersprungen."""
        converter = self._get_converter()
        stack = self._make_stack(custom_software=["", "Slack", ""])
        result = converter(stack)

        assert len(result) == 1
        assert result[0].name == "Slack"

    def test_full_stack_all_categories_present(self) -> None:
        """Ein voll befüllter Stack liefert Komponenten aller Kategorien."""
        from tools.security_scoring.domain.tech_stack.entities import (
            BrowserEntry,
            OSEntry,
            SecurityTool,
        )
        from tools.security_scoring.domain.tech_stack.enums import ToolStatus

        converter = self._get_converter()
        stack = self._make_stack(
            operating_systems=[OSEntry("Windows 11", "")],
            browsers=[BrowserEntry("Firefox", "")],
            antivirus=SecurityTool("Defender", ToolStatus.AKTIV),
            firewall=SecurityTool("Windows Firewall", ToolStatus.AKTIV),
            vpn="ProtonVPN",
            remote_access=["TeamViewer"],
            custom_software=["Slack"],
        )
        result = converter(stack)

        categories = {c.category for c in result}
        assert "OS" in categories
        assert "Browser" in categories
        assert "Antivirus" in categories
        assert "Firewall" in categories
        assert "VPN" in categories
        assert "Remote Access" in categories
        assert "Software" in categories


# ---------------------------------------------------------------------------
# Prompt 1 — SystemProfile.display_name
# ---------------------------------------------------------------------------


class TestSystemProfileDisplayName:
    """Tests für SystemProfile.display_name Eigenschaft."""

    def test_own_system_display_name(self) -> None:
        """Eigenes System hat Suffix '(Eigenes System)'."""
        from tools.security_scoring.domain.tech_stack.entities import SystemProfile
        from tools.security_scoring.domain.tech_stack.enums import SystemType

        profile = SystemProfile(
            id="1", name="Mein Laptop", system_type=SystemType.EIGENES
        )
        assert "(Eigenes System)" in profile.display_name
        assert "Mein Laptop" in profile.display_name

    def test_customer_system_display_name(self) -> None:
        """Kundensystem zeigt nur den Namen ohne Suffix."""
        from tools.security_scoring.domain.tech_stack.entities import SystemProfile
        from tools.security_scoring.domain.tech_stack.enums import SystemType

        profile = SystemProfile(id="2", name="Kunde AG", system_type=SystemType.KUNDE)
        assert profile.display_name == "Kunde AG"
