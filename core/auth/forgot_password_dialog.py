"""
forgot_password_dialog — Dialog für „Passwort vergessen?".

Zwei Tabs:
    1. **Recovery-Code** — funktional (Username + Code + neues Passwort).
    2. **E-Mail-Reset** — Info-Seite, disabled (Pro-Launch-Feature).

Eingaben im Recovery-Code-Feld werden live normalisiert: alles in
Großbuchstaben, automatisch alle 4 Zeichen ein Bindestrich. Das Ergebnis
kann direkt an:func:`core.auth.recovery_code.verify_recovery_code`
übergeben werden.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.auth.password_reset import (
    PasswordResetService,
    ResetStatus,
)
from core.auth.recovery_code import CODE_LENGTH, GROUP_SIZE, normalize_recovery_code
from core.theme import (
    ACCENT_HOVER,
    ACCENT_PRESSED,
    BG_PANEL_LIGHT,
    DARK_ACCENT,
    DARK_BG_PRIMARY,
    DARK_BG_SECONDARY,
    DARK_BORDER,
    DARK_ERROR,
    DARK_SUCCESS,
    DARK_TEXT_DISABLED,
    DARK_TEXT_PRIMARY,
    DARK_TEXT_SECONDARY,
    TEXT_ON_ACCENT_DEEP,
)


class ForgotPasswordDialog(QDialog):
    """Dialog zum Zurücksetzen eines vergessenen Passworts."""

    password_reset = Signal(str)  # Username bei Erfolg

    def __init__(
        self,
        service: PasswordResetService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service or PasswordResetService()

        self.setWindowTitle("Passwort zurücksetzen")
        self.setFixedSize(600, 500)
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.setModal(True)
        self.setStyleSheet(
            f"QDialog {{ background-color: {DARK_BG_PRIMARY};"
            f" border: 1px solid {DARK_BORDER}; border-radius: 12px; }}"
        )

        self._build_ui()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(14)

        title = QLabel("Passwort zurücksetzen")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 18px; font-weight: bold;"
            f" color: {DARK_ACCENT};"
        )
        root.addWidget(title)

        tabs = QTabWidget()
        tabs.setStyleSheet(self._tab_style())
        tabs.addTab(self._build_recovery_tab(), "Recovery-Code")
        tabs.addTab(self._build_email_tab(), "E-Mail-Reset")
        tabs.setTabEnabled(1, False)
        root.addWidget(tabs, stretch=1)

        # Close-Button
        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        close_btn = QPushButton("Abbrechen")
        close_btn.setFixedHeight(34)
        close_btn.setStyleSheet(self._button_style(primary=False))
        close_btn.clicked.connect(self.reject)
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

    def _build_recovery_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 16, 12, 12)
        layout.setSpacing(10)

        hint = QLabel(
            "Gib deinen Benutzernamen, den beim Wizard gespeicherten "
            "Wiederherstellungs-Code und ein neues Passwort ein."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {DARK_TEXT_SECONDARY};"
        )
        layout.addWidget(hint)

        self._username_field = QLineEdit()
        self._username_field.setPlaceholderText("Benutzername")
        self._username_field.setFixedHeight(34)
        self._username_field.setStyleSheet(self._field_style())
        layout.addWidget(self._username_field)

        self._code_field = QLineEdit()
        self._code_field.setPlaceholderText("XXXX-XXXX-XXXX-XXXX")
        self._code_field.setFixedHeight(34)
        self._code_field.setMaxLength(CODE_LENGTH + (CODE_LENGTH // GROUP_SIZE) - 1)
        self._code_field.setStyleSheet(
            self._field_style()
            + " QLineEdit { font-family: 'JetBrains Mono', monospace;"
            " letter-spacing: 2px; }"
        )
        self._code_field.textChanged.connect(self._on_code_changed)
        layout.addWidget(self._code_field)

        self._password_field = QLineEdit()
        self._password_field.setPlaceholderText("Neues Passwort (min. 8 Zeichen)")
        self._password_field.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_field.setFixedHeight(34)
        self._password_field.setStyleSheet(self._field_style())
        layout.addWidget(self._password_field)

        self._password_repeat_field = QLineEdit()
        self._password_repeat_field.setPlaceholderText("Passwort wiederholen")
        self._password_repeat_field.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_repeat_field.setFixedHeight(34)
        self._password_repeat_field.setStyleSheet(self._field_style())
        layout.addWidget(self._password_repeat_field)

        self._status_label = QLabel(" ")
        self._status_label.setWordWrap(True)
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {DARK_ERROR};"
        )
        self._status_label.setMinimumHeight(36)
        layout.addWidget(self._status_label)

        self._submit_btn = QPushButton("Passwort zurücksetzen")
        self._submit_btn.setFixedHeight(38)
        self._submit_btn.setStyleSheet(self._button_style(primary=True))
        self._submit_btn.clicked.connect(self._on_submit)
        layout.addWidget(self._submit_btn)
        layout.addStretch(1)
        return tab

    def _build_email_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 16, 12, 12)
        layout.setSpacing(12)

        info = QLabel(
            "E-Mail-Reset ist in der aktuellen Version nicht verfügbar.\n\n"
            "Dieses Feature wird mit dem Pro-Launch (voraussichtlich 15.05.2026) "
            "freigeschaltet. Nutze solange den Tab »Recovery-Code«."
        )
        info.setWordWrap(True)
        info.setAlignment(Qt.AlignmentFlag.AlignTop)
        info.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {DARK_TEXT_SECONDARY};"
        )
        layout.addWidget(info)
        layout.addStretch(1)
        return tab

    # ------------------------------------------------------------------
    # Styling
    # ------------------------------------------------------------------

    def _field_style(self) -> str:
        return (
            "QLineEdit {"
            f" background-color: {DARK_BG_SECONDARY};"
            f" color: {DARK_TEXT_PRIMARY};"
            f" border: 1px solid {DARK_BORDER};"
            " border-radius: 6px; padding: 4px 10px;"
            " font-family: 'Raleway'; font-size: 13px;"
            f"}} QLineEdit:focus {{ border: 1px solid {ACCENT_HOVER}; }}"
        )

    def _button_style(self, primary: bool) -> str:
        if primary:
            return (
                "QPushButton {"
                f" background-color: {DARK_ACCENT}; color: {TEXT_ON_ACCENT_DEEP};"
                " border: none; border-radius: 6px;"
                " font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
                " padding: 0 16px;"
                f"}} QPushButton:hover {{ background-color: {ACCENT_PRESSED}; }}"
            )
        return (
            "QPushButton {"
            f" background-color: {DARK_BG_SECONDARY}; color: {DARK_TEXT_PRIMARY};"
            f" border: 1px solid {DARK_BORDER}; border-radius: 6px;"
            " font-family: 'Raleway'; font-size: 12px;"
            " padding: 0 16px;"
            f"}} QPushButton:hover {{ background-color: {BG_PANEL_LIGHT}; }}"
        )

    def _tab_style(self) -> str:
        return (
            "QTabWidget::pane {"
            f" background-color: {DARK_BG_PRIMARY};"
            f" border: 1px solid {DARK_BORDER}; border-radius: 8px;"
            " top: -1px;"
            "}"
            "QTabBar::tab {"
            f" background-color: {DARK_BG_SECONDARY};"
            f" color: {DARK_TEXT_SECONDARY};"
            " padding: 6px 18px; margin-right: 4px;"
            " border-top-left-radius: 6px; border-top-right-radius: 6px;"
            " font-family: 'Raleway'; font-size: 12px;"
            "}"
            "QTabBar::tab:selected {"
            f" background-color: {DARK_BG_PRIMARY};"
            f" color: {DARK_ACCENT}; font-weight: bold;"
            f" border-bottom: 2px solid {DARK_ACCENT};"
            "}"
            "QTabBar::tab:disabled {"
            f" color: {DARK_TEXT_DISABLED}; background-color: {DARK_BG_SECONDARY};"
            "}"
        )

    # ------------------------------------------------------------------
    # Interaktion
    # ------------------------------------------------------------------

    def _on_code_changed(self, text: str) -> None:
        """Normalisiert die Eingabe live: Großbuchstaben + Auto-Bindestriche."""
        normalized = normalize_recovery_code(text)
        if normalized == text:
            return
        cursor_pos = self._code_field.cursorPosition()
        self._code_field.blockSignals(True)
        self._code_field.setText(normalized)
        self._code_field.setCursorPosition(min(cursor_pos, len(normalized)))
        self._code_field.blockSignals(False)

    def _on_submit(self) -> None:
        """Führt den Reset-Versuch aus."""
        username = self._username_field.text().strip()
        code = self._code_field.text().strip()
        new_password = self._password_field.text()
        repeat = self._password_repeat_field.text()

        if not username:
            self._show_error("Benutzername darf nicht leer sein.")
            return
        if not code:
            self._show_error("Recovery-Code darf nicht leer sein.")
            return
        if new_password != repeat:
            self._show_error("Die Passwörter stimmen nicht überein.")
            return

        result = self._service.request_reset_via_recovery_code(
            username=username, code=code, new_password=new_password
        )

        if result.status is ResetStatus.SUCCESS:
            self._show_success(result.message)
            self.password_reset.emit(username)
            return

        self._show_error(result.message)

    def _show_error(self, msg: str) -> None:
        self._status_label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {DARK_ERROR};"
        )
        self._status_label.setText(msg)

    def _show_success(self, msg: str) -> None:
        self._status_label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {DARK_SUCCESS};"
        )
        self._status_label.setText(msg)

    # ------------------------------------------------------------------
    # Keyboard
    # ------------------------------------------------------------------

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.reject()
            event.accept()
            return
        super().keyPressEvent(event)
