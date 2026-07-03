"""
api_keys_tab — Zentrale Verwaltung externer API-Keys.

Seit 2026-04-21 zentraler Ort für API-Keys die früher in einzelnen
Tools (Cyberrisiko-Dashboard, Document Scanner) verstreut waren:

- NVD API-Key (CVE-Abfragen, Rate-Limit 50/30s statt 5/30s)
- VirusTotal API-Key (Document Scanner Hash-Lookup, opt-in)

Alle Keys werden verschlüsselt in ``SecureStorage`` abgelegt.

DeepL-Sektion entfernt — NoRisk ist 100% lokal,
keine Cloud-Übersetzungen mehr.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import re

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.security.encryption import SecureStorage, get_secure_storage

_NVD_KEY_STORE = "nvd_api_key"
_NVD_KEY_URL = "https://nvd.nist.gov/developers/request-an-api-key"
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Document Scanner — VirusTotal-Hash-Lookup opt-in.
_VT_KEY_STORE = "virustotal_api_key"
_VT_KEY_URL = "https://www.virustotal.com/gui/join-us"
# VT-API-Keys sind 64-stellige Hex-Strings.
_VT_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class ApiKeysTab(QWidget):
    """Tab für zentrale API-Key-Verwaltung (NVD + VirusTotal)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._nvd_storage = SecureStorage()
        self._build_ui()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:  # noqa: D401
        """Theme-Update (Styles werden über inline setStyleSheet abgedeckt)."""
        return

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        layout.addWidget(self._build_nvd_section())
        layout.addWidget(self._build_vt_section())
        layout.addStretch()

    # ------------------------------------------------------------------
    # NVD
    # ------------------------------------------------------------------

    def _build_nvd_section(self) -> QGroupBox:
        c = theme.get()
        grp = QGroupBox("NVD API-Key (kostenlos)")
        grp.setStyleSheet(
            f"QGroupBox {{ color: {c.TEXT_MAIN}; font-weight: bold; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; "
            f"margin-top: 8px; padding-top: 12px; }}"
            f"QGroupBox::title {{ left: 8px; padding: 0 4px; }}"
        )
        lyt = QVBoxLayout(grp)
        lyt.setSpacing(8)

        info = QLabel(
            "Für bessere Rate-Limits bei CVE-Abfragen (50 statt 5 Anfragen/30s).\n"
            "Kostenlos registrieren auf nvd.nist.gov."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;")
        lyt.addWidget(info)

        btn_link = QPushButton("Zur NVD-Registrierung")
        btn_link.setMinimumHeight(32)
        btn_link.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl(_NVD_KEY_URL))
        )
        lyt.addWidget(btn_link)

        key_row = QHBoxLayout()
        self._nvd_input = QLineEdit()
        self._nvd_input.setPlaceholderText("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
        self._nvd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._nvd_input.setFixedHeight(32)
        key_row.addWidget(self._nvd_input)

        btn_show = QPushButton("")
        btn_show.setFixedSize(32, 32)
        btn_show.setCheckable(True)
        btn_show.setToolTip("Key anzeigen/verstecken")
        btn_show.toggled.connect(
            lambda checked: self._nvd_input.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            )
        )
        key_row.addWidget(btn_show)

        btn_save = QPushButton("Speichern")
        btn_save.setFixedHeight(32)
        # R11: Speichern-Button ist Strukturelement (CTA in Settings) →
        # theme.DARK_ACCENT (immer FINLAI-Teal), nicht c.ACCENT (per-App).
        btn_save.setStyleSheet(
            f"background-color: {theme.DARK_ACCENT}; color: {theme.TEXT_ON_ACCENT_DEEP}; "
            "border: none; border-radius: 4px; font-weight: bold; padding: 0 12px;"
        )
        btn_save.clicked.connect(self._save_nvd)
        key_row.addWidget(btn_save)
        lyt.addLayout(key_row)

        self._nvd_status = QLabel("")
        lyt.addWidget(self._nvd_status)
        self._refresh_nvd_status()

        return grp

    def _refresh_nvd_status(self) -> None:
        c = theme.get()
        try:
            has_key = bool(self._nvd_storage.get(_NVD_KEY_STORE))
        except Exception:  # noqa: BLE001
            has_key = False
        if has_key:
            self._nvd_status.setText("API-Key gespeichert.")
            # R11: Status-Indikator gehört zu Settings-Strukturelementen →
            # theme.DARK_ACCENT statt per-App c.ACCENT.
            self._nvd_status.setStyleSheet(
                f"color: {theme.DARK_ACCENT}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
        else:
            self._nvd_status.setText(
                "Kein API-Key — limitierte Anfragen (5/30s)."
            )
            self._nvd_status.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;")

    def _save_nvd(self) -> None:
        c = theme.get()
        key = self._nvd_input.text().strip()
        if not key:
            self._nvd_status.setText("Bitte Key eingeben.")
            self._nvd_status.setStyleSheet(
                f"color: {c.DANGER}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
            return
        if not _UUID_RE.match(key):
            self._nvd_status.setText(
                "Ungültiges Format (UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)."
            )
            self._nvd_status.setStyleSheet(
                f"color: {c.DANGER}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
            return
        self._nvd_storage.set(_NVD_KEY_STORE, key)
        self._nvd_input.clear()
        self._refresh_nvd_status()

    # ------------------------------------------------------------------
    # VirusTotal (Document Scanner, 2026-05-14)
    # ------------------------------------------------------------------

    def _build_vt_section(self) -> QGroupBox:
        c = theme.get()
        grp = QGroupBox("VirusTotal API-Key (optional)")
        grp.setStyleSheet(
            f"QGroupBox {{ color: {c.TEXT_MAIN}; font-weight: bold; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; "
            f"margin-top: 8px; padding-top: 12px; }}"
            f"QGroupBox::title {{ left: 8px; padding: 0 4px; }}"
        )
        lyt = QVBoxLayout(grp)
        lyt.setSpacing(8)

        info = QLabel(
            "Fuer den Document Scanner: optional kann per Klick auf "
            "'VirusTotal pruefen' der SHA-256-Hash einer Datei gegen die "
            "VirusTotal-Datenbank geprueft werden. Nur der Hash wird "
            "verschickt — die Datei verlaesst nie dein Geraet.\n"
            "Free-Plan: 4 Anfragen pro Minute. Kostenloser Account auf "
            "virustotal.com erforderlich."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;")
        lyt.addWidget(info)

        btn_link = QPushButton("Zur VirusTotal-Registrierung")
        btn_link.setMinimumHeight(32)
        btn_link.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl(_VT_KEY_URL))
        )
        lyt.addWidget(btn_link)

        key_row = QHBoxLayout()
        self._vt_input = QLineEdit()
        self._vt_input.setPlaceholderText("64-stelliger Hex-Key")
        self._vt_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._vt_input.setFixedHeight(32)
        self._vt_input.setMaxLength(96)
        key_row.addWidget(self._vt_input)

        btn_show = QPushButton("")
        btn_show.setFixedSize(32, 32)
        btn_show.setCheckable(True)
        btn_show.setToolTip("Key anzeigen/verstecken")
        btn_show.toggled.connect(
            lambda checked: self._vt_input.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            )
        )
        key_row.addWidget(btn_show)

        btn_save = QPushButton("Speichern")
        btn_save.setFixedHeight(32)
        btn_save.setStyleSheet(
            f"background-color: {theme.DARK_ACCENT}; color: {theme.TEXT_ON_ACCENT_DEEP}; "
            "border: none; border-radius: 4px; font-weight: bold; padding: 0 12px;"
        )
        btn_save.clicked.connect(self._save_vt)
        key_row.addWidget(btn_save)

        btn_delete = QPushButton("Loeschen")
        btn_delete.setFixedHeight(32)
        btn_delete.setStyleSheet(
            f"background-color: {c.DANGER}; color: {c.TEXT_MAIN}; "
            "border: none; border-radius: 4px; padding: 0 12px;"
        )
        btn_delete.clicked.connect(self._delete_vt)
        key_row.addWidget(btn_delete)
        lyt.addLayout(key_row)

        self._vt_status = QLabel("")
        lyt.addWidget(self._vt_status)
        self._refresh_vt_status()

        return grp

    def _refresh_vt_status(self) -> None:
        c = theme.get()
        storage = get_secure_storage()
        if not storage.is_available:
            self._vt_status.setText(
                "SecureStorage nicht verfuegbar — cryptography installieren."
            )
            self._vt_status.setStyleSheet(
                f"color: {c.DANGER}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
            return
        has_key = bool(storage.get(_VT_KEY_STORE))
        if has_key:
            self._vt_status.setText("API-Key gespeichert.")
            self._vt_status.setStyleSheet(
                f"color: {theme.DARK_ACCENT}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
        else:
            self._vt_status.setText("Kein API-Key — VT-Lookup im Document Scanner inaktiv.")
            self._vt_status.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )

    def _save_vt(self) -> None:
        c = theme.get()
        key = self._vt_input.text().strip()
        if not key:
            self._vt_status.setText("Bitte Key eingeben.")
            self._vt_status.setStyleSheet(
                f"color: {c.DANGER}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
            return
        if not _VT_KEY_RE.match(key):
            self._vt_status.setText(
                "Ungueltiges Format — VT-API-Keys sind 64-stellige Hex-Strings."
            )
            self._vt_status.setStyleSheet(
                f"color: {c.DANGER}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
            return
        storage = get_secure_storage()
        if not storage.is_available:
            self._vt_status.setText("SecureStorage nicht verfuegbar — Key nicht gespeichert.")
            self._vt_status.setStyleSheet(
                f"color: {c.DANGER}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
            return
        if not storage.set(_VT_KEY_STORE, key):
            self._vt_status.setText("Speichern fehlgeschlagen.")
            self._vt_status.setStyleSheet(
                f"color: {c.DANGER}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
            return
        self._vt_input.clear()
        self._refresh_vt_status()

    def _delete_vt(self) -> None:
        storage = get_secure_storage()
        storage.delete(_VT_KEY_STORE)
        self._vt_input.clear()
        self._refresh_vt_status()
