"""Recovery-Code-Anzeige — einmalige Darstellung des Wiederherstellungs-Codes.

Die Seite wird direkt nach der Admin-Einrichtung eingeblendet. Sie erzeugt
einen neuen Code, zeigt ihn einmalig im Klartext an, persistiert ausschließlich
den bcrypt-Hash in ``users.json`` und erzwingt, dass der Benutzer den Code
sicher notiert hat (Checkbox + manueller Bestätigung).

Der Klartext-Code verlässt die Seite **nicht** — er liegt nur im Widget-State
und wird beim:meth:`commit` verworfen, nachdem der Hash persistiert wurde.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
)

from core.audit_log import AuditLogger
from core.auth.recovery_code import generate_recovery_code, hash_recovery_code
from core.auth.user_store import UserStore
from core.exceptions import AuthError
from core.first_run_wizard.pages.base_page import BasePage
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.theme import (
    BG_PANEL_LIGHT,
    DARK_ACCENT,
    DARK_BG_SECONDARY,
    DARK_BORDER,
    DARK_TEXT_PRIMARY,
    DARK_TEXT_SECONDARY,
    DARK_WARNING,
)

log = get_logger(__name__)


class RecoveryCodeDisplayPage(BasePage):
    """Seite mit einmaliger Anzeige des Recovery-Codes."""

    TITLE = "Wiederherstellungscode"

    def __init__(
        self,
        user_store: UserStore | None = None,
        username_provider=None,
    ) -> None:
        """Initialisiert die Seite.

        Args:
            user_store: Optionaler UserStore (für Tests injizierbar).
            username_provider: Callable, das zum Commit-Zeitpunkt den
                aktuellen Benutzernamen zurückgibt. Wenn ``None``, wird
                ``set_username`` erwartet.
        """
        super().__init__()
        self._user_store = user_store or UserStore()
        self._username_provider = username_provider
        self._username: str | None = None
        self._code = generate_recovery_code()
        self._committed = False

        title = QLabel("Wiederherstellungscode")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 20px; font-weight: bold;"
            f" color: {DARK_ACCENT};"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        warning_row = QHBoxLayout()
        warning_row.setSpacing(8)
        warning_icon = QLabel()
        warning_icon.setPixmap(get_icon(Icons.WARNING).pixmap(22, 22))
        warning_text = QLabel(
            "Dieser Code wird nur EINMAL angezeigt. Bewahre ihn sicher "
            "auf — er ist deine einzige Möglichkeit, das Passwort ohne E-Mail "
            "zurückzusetzen."
        )
        warning_text.setWordWrap(True)
        warning_text.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {DARK_WARNING};"
        )
        warning_row.addWidget(warning_icon, alignment=Qt.AlignmentFlag.AlignTop)
        warning_row.addWidget(warning_text, stretch=1)

        self._code_label = QLabel(self._code)
        self._code_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._code_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._code_label.setStyleSheet(
            "QLabel {"
            " font-family: 'JetBrains Mono', 'Consolas', monospace;"
            " font-size: 22pt;"
            " font-weight: bold;"
            " letter-spacing: 4px;"
            f" color: {DARK_ACCENT};"
            f" background-color: {DARK_BG_SECONDARY};"
            f" border: 1px solid {DARK_BORDER};"
            " border-radius: 8px;"
            " padding: 16px 12px;"
            "}"
        )

        button_row = QHBoxLayout()
        button_row.setSpacing(12)
        button_row.addStretch(1)

        self._copy_btn = QPushButton("In Zwischenablage kopieren")
        self._copy_btn.setIcon(get_icon(Icons.COPY))
        self._copy_btn.setFixedHeight(34)
        self._copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._copy_btn.setStyleSheet(self._btn_style())
        self._copy_btn.clicked.connect(self._on_copy)

        self._save_btn = QPushButton("Als PDF speichern")
        self._save_btn.setIcon(get_icon(Icons.PDF))
        self._save_btn.setFixedHeight(34)
        self._save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._save_btn.setStyleSheet(self._btn_style())
        self._save_btn.clicked.connect(self._on_save_pdf)

        button_row.addWidget(self._copy_btn)
        button_row.addWidget(self._save_btn)
        button_row.addStretch(1)

        self._status_label = QLabel(" ")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 11px; color: {DARK_TEXT_SECONDARY};"
        )
        self._status_label.setMinimumHeight(16)

        self._confirm_checkbox = QCheckBox(
            "Ich habe den Code an einem sicheren Ort notiert."
        )
        self._confirm_checkbox.setStyleSheet(
            f"QCheckBox {{ color: {DARK_TEXT_PRIMARY};"
            " font-family: 'Raleway'; font-size: 12px; spacing: 8px; }}"
        )
        self._confirm_checkbox.stateChanged.connect(
            lambda _state: self.completion_changed.emit(self.is_complete())
        )

        self._layout.addWidget(title)
        self._layout.addLayout(warning_row)
        self._layout.addSpacing(8)
        self._layout.addWidget(self._code_label)
        self._layout.addLayout(button_row)
        self._layout.addWidget(self._status_label)
        self._layout.addStretch(1)
        self._layout.addWidget(self._confirm_checkbox)

    def _btn_style(self) -> str:
        return (
            "QPushButton {"
            f" background-color: {DARK_BG_SECONDARY}; color: {DARK_TEXT_PRIMARY};"
            f" border: 1px solid {DARK_BORDER}; border-radius: 6px;"
            " font-family: 'Raleway'; font-size: 12px;"
            " padding: 0 14px;"
            f"}} QPushButton:hover {{ background-color: {BG_PANEL_LIGHT}; }}"
        )

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def set_username(self, username: str) -> None:
        """Setzt den Username, der beim Commit aktualisiert werden soll."""
        self._username = username

    def is_complete(self) -> bool:
        return self._confirm_checkbox.isChecked()

    def commit(self) -> None:
        """Persistiert den bcrypt-Hash des Codes in ``users.json``."""
        if self._committed:
            return
        username = self._username
        if username is None and self._username_provider is not None:
            username = self._username_provider()
        if not username:
            raise AuthError(
                "Recovery-Code kann nicht gespeichert werden — "
                "kein Benutzername bekannt."
            )

        try:
            hashed = hash_recovery_code(self._code)
            self._user_store.set_recovery_code_hash(username, hashed)
        except (ValueError, OSError) as exc:
            raise AuthError(
                f"Recovery-Code konnte nicht gespeichert werden: {exc}"
            ) from exc

        AuditLogger().log_action(
            "RECOVERY_CODE_GENERATED",
            {"username": username},
        )
        self._committed = True
        log.info("Recovery-Code generiert und gehashed für Benutzer '%s'.", username)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _on_copy(self) -> None:
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(self._code)
        self._status_label.setText("Code in Zwischenablage kopiert.")

    def _on_save_pdf(self) -> None:
        """Speichert den Code + Hinweistext als PDF.

        Nutzt:class:`QTextDocument` +:class:`QPrinter` — unabhängig
        von externen Reporting-Libraries und damit ohne neue
        hidden imports im Build.
        """
        from PySide6.QtCore import QMarginsF  # noqa: PLC0415
        from PySide6.QtGui import QPageLayout, QPageSize, QTextDocument  # noqa: PLC0415
        from PySide6.QtPrintSupport import QPrinter  # noqa: PLC0415
        from PySide6.QtWidgets import QFileDialog  # noqa: PLC0415

        target, _ = QFileDialog.getSaveFileName(
            self,
            "Recovery-Code speichern",
            "FINLAI_Recovery_Code.pdf",
            "PDF-Dateien (*.pdf)",
        )
        if not target:
            return

        doc = QTextDocument()
        # noqa-Begründung: HTML/PDF-Light-Kontext (QTextDocument-Ausdruck auf Papier).
        # Werte gehören semantisch zur Light-Palette in core/pdf/pdf_light_colors.py;
        # dieser einmalige inline-PDF-Block kann in Sprint 2 darauf migriert werden.
        html = (
            "<html><body style='font-family: Raleway, sans-serif; color: #111;'>"  # noqa: hex-color-pending — PDF-Light-Kontext
            "<h1 style='color:#0b1e1c;'>FINLAI — Wiederherstellungscode</h1>"  # noqa: hex-color-pending — PDF-Light-Kontext
            "<p>Bewahre dieses Dokument sicher auf. Dieser Code ist deine"
            " einzige Möglichkeit, das Passwort ohne E-Mail zurückzusetzen.</p>"
            "<p style='font-family: monospace; font-size: 22pt;"
            " letter-spacing: 4px; font-weight: bold;"
            " padding: 16px; border: 1px solid #888;'>"  # noqa: hex-color-pending — PDF-Light-Kontext
            f"{self._code}"
            "</p>"
            "<p style='font-size: 10pt; color: #555;'>"  # noqa: hex-color-pending — PDF-Light-Kontext
            "Halte diesen Code geheim. Jede Person, die den Code kennt,"
            " kann das Passwort deines Administrator-Kontos zurücksetzen."
            "</p></body></html>"
        )
        doc.setHtml(html)

        printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(target)
        layout = QPageLayout(
            QPageSize(QPageSize.PageSizeId.A4),
            QPageLayout.Orientation.Portrait,
            QMarginsF(20, 20, 20, 20),
            QPageLayout.Unit.Millimeter,
        )
        printer.setPageLayout(layout)
        doc.print_(printer)
        self._status_label.setText(f"PDF gespeichert: {target}")
