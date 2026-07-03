"""
password_setup_dialog — Erzwungener Passwort-Einrichtungsdialog für FINLAI.

Wird beim ersten Start angezeigt wenn kein Admin-Passwort gesetzt ist.
Der Dialog kann nicht abgebrochen werden — Passwort muss gesetzt werden.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from core import theme
from core.auth.user_store import UserStore
from core.dialogs import FinlaiInfoDialog
from core.icons import ICON_SIZE_DIALOG, Icons, get_accent_icon


class PasswordSetupDialog(QDialog):
    """Erzwingt Passwort-Einrichtung beim ersten Start von FINLAI.

    Kann nicht abgebrochen werden — der Dialog bleibt offen bis ein
    gültiges Passwort gesetzt wurde.
    """

    def __init__(
        self,
        user_store: UserStore,
        username: str,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._store = user_store
        self._username = username

        # Kein Schließen-Button — Setup ist Pflicht
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.CustomizeWindowHint
            | Qt.WindowType.WindowTitleHint
        )
        self.setModal(True)
        self.setWindowTitle("FINLAI — Erstkonfiguration")
        self.setMinimumWidth(440)

        self._build_ui()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme.

        Wird bei Theme-Wechsel aufgerufen (register_listener).
        TODO: setStyleSheet-Aufrufe mit theme.get-Farben ersetzen.
        """
        from core import theme  # noqa: PLC0415

        c = theme.get()  # noqa: F841

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        # Header
        icon = QLabel()
        icon.setPixmap(
            get_accent_icon(Icons.LOCK).pixmap(ICON_SIZE_DIALOG, ICON_SIZE_DIALOG)
        )
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)

        title = QLabel("Willkommen bei FINLAI!")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 16px; font-weight: bold;"
            f" color: {theme.get().ACCENT};"
        )
        layout.addWidget(title)

        subtitle = QLabel("Bitte legen Sie ein sicheres\nAdministrator-Passwort fest.")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(f"color: {theme.get().TEXT_DIM}; font-size: 13px;")
        layout.addWidget(subtitle)

        # Passwort-Felder
        self._pw1 = QLineEdit()
        self._pw1.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw1.setPlaceholderText("Neues Passwort (min. 10 Zeichen)...")
        self._pw1.setFixedHeight(38)

        self._pw2 = QLineEdit()
        self._pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw2.setPlaceholderText("Passwort wiederholen...")
        self._pw2.setFixedHeight(38)

        # Stärke-Anzeige
        self._strength = QLabel("")
        self._strength.setStyleSheet("font-size: 11px;")

        self._pw1.textChanged.connect(self._check_strength)
        self._pw2.returnPressed.connect(self._on_confirm)

        for w in (self._pw1, self._pw2, self._strength):
            layout.addWidget(w)

        # Anforderungen
        rules = QLabel(
            "• Mindestens 10 Zeichen\n"
            "• Mindestens eine Zahl\n"
            "• Mindestens ein Sonderzeichen"
        )
        rules.setStyleSheet(
            f"color: {theme.get().TEXT_DIM}; font-size: 11px;"
            f" padding: 8px;"
            f" border: 1px solid {theme.get().BORDER};"
            f" border-radius: 4px;"
        )
        layout.addWidget(rules)

        # Bestätigen-Button
        self._btn = QPushButton("Passwort festlegen")
        self._btn.setObjectName("primary")
        self._btn.setFixedHeight(40)
        self._btn.clicked.connect(self._on_confirm)
        layout.addWidget(self._btn)

    def _check_strength(self, pw: str) -> None:
        """Zeigt Passwort-Stärke live an."""
        if not pw:
            self._strength.setText("")
            return

        score = 0
        if len(pw) >= 10:
            score += 1
        if len(pw) >= 14:
            score += 1
        if any(c.isdigit() for c in pw):
            score += 1
        if any(not c.isalnum() for c in pw):
            score += 1

        # Strength-Indikator-Palette: helle Signal-Farben, bewusst nicht
        # auf DARK_SUCCESS/DARK_WARNING gemappt (visuell sichtbar dunkler).
        labels = [
            (1, "Sehr schwach", theme.SEVERITY_SIGNAL_CRITICAL),
            (2, "Schwach", "#ffb86c"),  # noqa: hex-color-pending — visueller Unterschied zu DARK_WARNING (Hue ~3°)
            (3, "Gut", "#50fa7b"),  # noqa: hex-color-pending — sichtbar heller als DARK_SUCCESS (Sprint 1 Risiko-Item)
            (4, "Sehr stark", theme.DARK_ACCENT),
        ]
        for threshold, text, color in labels:
            if score <= threshold:
                self._strength.setText(f"Stärke: {text}")
                self._strength.setStyleSheet(f"color: {color}; font-size: 11px;")
                break

    def _on_confirm(self) -> None:
        """Versucht das Passwort zu setzen."""
        pw1 = self._pw1.text()
        pw2 = self._pw2.text()

        if pw1 != pw2:
            FinlaiInfoDialog(
                title="Fehler",
                message="Passwörter stimmen nicht überein.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return

        try:
            self._store.complete_setup(self._username, pw1)
            self.accept()
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Passwort zu schwach",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()

    def closeEvent(self, event) -> None:  # type: ignore[override]
        """Verhindert Schließen ohne abgeschlossenen Passwort-Setup."""
        event.ignore()
        FinlaiInfoDialog(
            title="Setup erforderlich",
            message="Bitte legen Sie zuerst ein Passwort fest.",
            icon_name=Icons.INFO,
            parent=self,
        ).exec()
