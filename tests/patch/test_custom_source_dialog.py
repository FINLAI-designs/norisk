"""test_custom_source_dialog — Tests fuer Stop-Step C (GUI-Dialog).

GUI-Tests (``@pytest.mark.gui``, ``qapp``-Fixture): Form-Werte + Validierung.
"""

from __future__ import annotations

import pytest


@pytest.mark.gui
class TestCustomSourceDialog:
    @staticmethod
    def _dialog():
        from tools.patch_monitor.gui.custom_source_dialog import CustomSourceDialog

        return CustomSourceDialog()

    def test_form_values_strippt_und_mappt(self, qapp) -> None:
        from core.patch_custom_source import Platform

        d = self._dialog()
        d._name_input.setText("  Vendor-Tool ")
        d._url_input.setText("https://vendor.example/dl")
        d._regex_input.setText(r"(\d+\.\d+)")
        d._installed_input.setText(" 1.0 ")
        vals = d.form_values()
        assert vals["name"] == "Vendor-Tool"
        assert vals["vendor_url"] == "https://vendor.example/dl"
        assert vals["version_regex"] == r"(\d+\.\d+)"
        assert vals["installed_version"] == "1.0"
        assert vals["platform"] == Platform.WINDOWS
        assert vals["notes"] is None  # leer → None

    def test_form_values_behaelt_gewaehlte_plattform(self, qapp) -> None:
        """: Qt unwrappt StrEnum-userData zu plain str.

        Der fruehere isinstance-Check schlug deshalb immer fehl und
        ersetzte die User-Wahl (macOS/Linux) still durch WINDOWS.
        """
        from core.patch_custom_source import Platform

        d = self._dialog()
        d._name_input.setText("Tool")
        idx = d._platform_combo.findData(Platform.LINUX)
        assert idx >= 0
        d._platform_combo.setCurrentIndex(idx)
        assert d.form_values()["platform"] is Platform.LINUX

    def test_accept_valid(self, qapp) -> None:
        from PySide6.QtWidgets import QDialog

        d = self._dialog()
        d._name_input.setText("Tool")
        d._url_input.setText("https://vendor.example/dl")
        d._regex_input.setText(r"(\d+\.\d+)")
        d._on_accept()
        assert d.result() == QDialog.DialogCode.Accepted

    def test_accept_leerer_name_zeigt_fehler(self, qapp) -> None:
        d = self._dialog()
        d._url_input.setText("https://vendor.example")
        d._regex_input.setText(r"(\d+)")
        d._on_accept()
        assert d._error_label.text()  # Fehlertext gesetzt

    def test_accept_non_http_url_zeigt_fehler(self, qapp) -> None:
        d = self._dialog()
        d._name_input.setText("Tool")
        d._url_input.setText("ftp://vendor.example")
        d._regex_input.setText(r"(\d+)")
        d._on_accept()
        assert d._error_label.text()

    def test_accept_ungueltiger_regex_zeigt_fehler(self, qapp) -> None:
        d = self._dialog()
        d._name_input.setText("Tool")
        d._url_input.setText("https://vendor.example")
        d._regex_input.setText(r"(\d+")  # offene Gruppe
        d._on_accept()
        assert d._error_label.text()
