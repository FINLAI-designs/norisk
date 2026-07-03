"""custom_source_dialog — Modaler Add-Dialog fuer Custom-Sources.

Notify-Only-Patch-Quelle manuell anlegen: Name, Vendor-URL, Versions-Regex,
Plattform, installierte Version, Notiz. Mit Warn-/Privacy-Banner gemaess
dialog-skill (Typ D, Einstellungs-Form). Liefert nach Accept die Form-Werte
fuer ``PatchInventoryService.add_custom_source``.

Schichtzugehoerigkeit: ``gui/`` — nur PySide6 + Theme + core-Domain
(``core.patch_custom_source``). Keine Business-Logik, kein DB-/HTTP-Zugriff.
"""

from __future__ import annotations

import re
from typing import Any, Final
from urllib.parse import urlparse

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.patch_custom_source import DEFAULT_PLATFORM, Platform

#: User-lesbare Plattform-Labels (Anzeige-Reihenfolge im Dropdown).
_PLATFORM_LABELS: Final[dict[Platform, str]] = {
    Platform.WINDOWS: "Windows",
    Platform.MACOS: "macOS",
    Platform.LINUX: "Linux",
}

_WARN_TEXT: Final[str] = (
    "Quelle aus eigener Verantwortung: Die Versions-Seite wird per HTTP "
    "abgefragt — das verraet dem Anbieter, dass Sie NoRisk nutzen. Es gibt "
    "KEINEN automatischen Download und KEINE automatische Installation, nur "
    "einen Hinweis 'Update verfuegbar' mit Vendor-Link."
)


def _is_http_url(url: str) -> bool:
    """``True`` wenn ``url`` ein ``http``/``https``-Schema + Host hat."""
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


class CustomSourceDialog(QDialog):
    """Modaler Dialog zum Anlegen einer Custom-Source.

    Benutzung::

        dialog = CustomSourceDialog(parent=self)
        if dialog.exec == QDialog.DialogCode.Accepted:
            service.add_custom_source(**dialog.form_values)
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("App manuell hinzufuegen")
        self.setMinimumWidth(480)
        self.setModal(True)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        layout.addWidget(self._build_warn_banner())

        form = QFormLayout()
        form.setSpacing(8)

        self._name_input = QLineEdit()
        self._name_input.setMaxLength(200)
        self._name_input.setPlaceholderText("z. B. Mein Vendor-Tool")
        form.addRow("Name", self._name_input)

        self._url_input = QLineEdit()
        self._url_input.setPlaceholderText("https://vendor.example/download")
        form.addRow("Vendor-URL", self._url_input)

        self._regex_input = QLineEdit()
        self._regex_input.setPlaceholderText(r"z. B. Version (\d+\.\d+\.\d+)")
        self._regex_input.setToolTip(
            "Regex mit Capture-Gruppe; die erste Gruppe ist die Version."
        )
        form.addRow("Versions-Regex", self._regex_input)

        self._platform_combo = QComboBox()
        for plat, label in _PLATFORM_LABELS.items():
            self._platform_combo.addItem(label, plat)
        default_idx = self._platform_combo.findData(DEFAULT_PLATFORM)
        if default_idx >= 0:
            self._platform_combo.setCurrentIndex(default_idx)
        form.addRow("Plattform", self._platform_combo)

        self._installed_input = QLineEdit()
        self._installed_input.setPlaceholderText("aktuell installierte Version (optional)")
        form.addRow("Installiert", self._installed_input)

        self._notes_input = QTextEdit()
        self._notes_input.setAcceptRichText(False)
        self._notes_input.setPlaceholderText("Notiz (optional)")
        self._notes_input.setMaximumHeight(80)
        form.addRow("Notiz", self._notes_input)

        layout.addLayout(form)

        self._error_label = QLabel("")
        self._error_label.setWordWrap(True)
        self._error_label.setStyleSheet(
            f"color: {theme.get().DANGER}; font-size: 11px;"
        )
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Hinzufuegen")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Abbrechen")
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _build_warn_banner(self) -> QLabel:
        """Warn-/Privacy-Banner (dialog-skill: WARNING-Token, gut sichtbar)."""
        c = theme.get()
        banner = QLabel(_WARN_TEXT)
        banner.setWordWrap(True)
        banner.setStyleSheet(
            f"color: {c.WARNING}; border: 1px solid {c.WARNING};"
            f"border-radius: 6px; padding: 8px; font-size: 12px;"
        )
        return banner

    def _on_accept(self) -> None:
        """Validiert die Pflichtfelder; bei Fehler Fokus + Fehlertext."""
        name = self._name_input.text().strip()
        url = self._url_input.text().strip()
        regex = self._regex_input.text().strip()

        if not name:
            self._show_error("Bitte einen Namen eingeben.", self._name_input)
            return
        if not _is_http_url(url):
            self._show_error(
                "Bitte eine gueltige http/https-URL eingeben.", self._url_input
            )
            return
        if not regex:
            self._show_error("Bitte einen Versions-Regex eingeben.", self._regex_input)
            return
        try:
            re.compile(regex)
        except re.error:
            self._show_error(
                "Der Versions-Regex ist ungueltig.", self._regex_input
            )
            return
        self.accept()

    def _show_error(self, message: str, focus_widget: QWidget) -> None:
        self._error_label.setText(message)
        self._error_label.setVisible(True)
        focus_widget.setFocus()

    def form_values(self) -> dict[str, Any]:
        """Liefert die Form-Werte als kwargs fuer ``add_custom_source``.

        ``installed_version`` / ``notes`` sind ``None`` wenn leer.
        """
        installed = self._installed_input.text().strip()
        notes = self._notes_input.toPlainText().strip()
        # Qt castet StrEnum-userData zu plain str — der fruehere
        # isinstance-Check schlug deshalb IMMER fehl und ersetzte die
        # User-Wahl still durch DEFAULT_PLATFORM. Value-Lookup rekonstruiert.
        raw_platform = self._platform_combo.currentData()
        platform = (
            Platform(raw_platform) if raw_platform is not None else DEFAULT_PLATFORM
        )
        return {
            "name": self._name_input.text().strip(),
            "vendor_url": self._url_input.text().strip(),
            "version_regex": self._regex_input.text().strip(),
            "platform": platform,
            "installed_version": installed or None,
            "notes": notes or None,
        }
