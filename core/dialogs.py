"""
dialogs — Wiederverwendbare FINLAI-konforme Dialoge.

Ersetzt native QMessageBox-Dialoge durch Theme-konforme Custom-Dialoge.

Dialog-Typen:
  FinlaiSuccessDialog — Erfolg (check_circle, SUCCESS_GREEN)
  FinlaiConfirmDialog — Bestätigung destruktiver Aktionen (warning, WARNING_YELLOW)
  FinlaiInfoDialog — Informations-/Fehler-Anzeige (info/error, TEAL/DANGER)

Schichtzugehörigkeit: core/ — keine Tool-Imports.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import ICON_SIZE_DIALOG, Icons, get_icon


class FinlaiSuccessDialog(QDialog):
    """FINLAI-konformer Erfolgs-Dialog.

    Zeigt ein Erfolgs-Icon, Titel, optionale Nachricht und optionalen
    Dateipfad. Wenn file_path angegeben ist, erscheint ein "Öffnen"-Button.

    Args:
        title: Dialogtitel (Raleway Bold).
        message: Optionale Nachrichtenzeile.
        file_path: Optionaler Dateipfad — aktiviert "Öffnen"-Button.
        parent: Eltern-Widget.
    """

    def __init__(
        self,
        title: str,
        message: str = "",
        file_path: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._file_path = file_path
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setModal(True)
        self._build_ui(title, message, file_path)

    def _build_ui(self, title: str, message: str, file_path: str | None) -> None:
        """Erstellt das Dialog-Layout."""
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 8px; }}"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        # Header-Zeile: Icon + Titel
        header = QHBoxLayout()
        header.setSpacing(10)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(get_icon(Icons.CHECK_CIRCLE).pixmap(ICON_SIZE_DIALOG, ICON_SIZE_DIALOG))
        header.addWidget(icon_lbl)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_H3}px; font-weight: 700;"
            f" color: {c.SUCCESS};"
        )
        header.addWidget(title_lbl)
        header.addStretch()
        root.addLayout(header)

        # Nachrichtentext
        if message:
            msg_lbl = QLabel(message)
            msg_lbl.setWordWrap(True)
            # R22: dynamischer Text nie als Auto-RichText
            msg_lbl.setTextFormat(Qt.TextFormat.PlainText)
            msg_lbl.setStyleSheet(
                f"font-family: 'Inter'; font-size: {theme.FONT_SIZE_BODY}px; color: {c.TEXT_MAIN};"
            )
            root.addWidget(msg_lbl)

        # Dateipfad
        if file_path:
            path_lbl = QLabel(file_path)
            path_lbl.setWordWrap(True)
            path_lbl.setTextFormat(Qt.TextFormat.PlainText)
            path_lbl.setStyleSheet(
                f"font-family: 'JetBrains Mono'; font-size: {theme.FONT_SIZE_BODY_SM}px;"
                f" color: {c.TEXT_DIM};"
                f" background: {c.BG_MAIN}; border-radius: 4px; padding: 6px 8px;"
            )
            root.addWidget(path_lbl)

        # Button-Leiste
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        if file_path:
            btn_open = QPushButton("Öffnen")
            btn_open.setStyleSheet(self._btn_style(c, accent=False))
            btn_open.clicked.connect(self._open_file)
            btn_row.addWidget(btn_open)

        btn_ok = QPushButton("OK")
        btn_ok.setDefault(True)
        btn_ok.setStyleSheet(self._btn_style(c, accent=True))
        btn_ok.clicked.connect(self.accept)
        btn_row.addWidget(btn_ok)

        root.addLayout(btn_row)
        self.setMinimumWidth(380)

    @staticmethod
    def _btn_style(c: object, *, accent: bool) -> str:
        """Gibt den Button-Stylesheet zurück."""
        bg = c.ACCENT if accent else c.BG_BUTTON  # type: ignore[attr-defined]
        text = c.TEXT_ON_LIGHT if accent else c.TEXT_MAIN  # type: ignore[attr-defined]
        hover = c.ACCENT_DIM if accent else c.BG_SIDEBAR_HOVER  # type: ignore[attr-defined]
        return (
            f"QPushButton {{ background: {bg}; color: {text}; border: none;"
            f" border-radius: 4px; padding: 7px 18px;"
            f" font-family: 'Raleway'; font-weight: 600; font-size: {theme.FONT_SIZE_BODY}px; }}"
            f"QPushButton:hover {{ background: {hover}; }}"
        )

    def _open_file(self) -> None:
        """Öffnet die Datei im Standard-Programm."""
        if self._file_path:
            from PySide6.QtCore import QUrl  # noqa: PLC0415

            QDesktopServices.openUrl(QUrl.fromLocalFile(self._file_path))


class FinlaiConfirmDialog(QDialog):
    """FINLAI-konformer Bestätigungs-Dialog für destruktive Aktionen.

    Zeigt ein Warn-Icon, Titel und Bestätigungsfrage.
    Gibt ``QDialog.DialogCode.Accepted`` zurück wenn der User bestätigt.

    Args:
        title: Dialogtitel (Raleway Bold).
        message: Bestätigungsfrage (Raleway Regular).
        confirm_text: Text für den Bestätigungs-Button. Default: "Bestätigen".
        parent: Eltern-Widget.
        cancel_text: Text für den Sekundär-/Abbruch-Button. Default: "Abbrechen".
            Bei "Aktion abbrechen?"-Dialogen explizit setzen (z. B.
            "Weiter einrichten"), damit nicht ZWEI Buttons "Abbrechen" heißen.

    Beispiel::

        dlg = FinlaiConfirmDialog(
            title="Eintrag löschen",
            message=f'Alle Scores für "{name}" löschen?',
            confirm_text="Löschen",
            parent=self,
)
        if dlg.exec == QDialog.DialogCode.Accepted:
            # Aktion ausführen
    """

    def __init__(
        self,
        title: str,
        message: str,
        confirm_text: str = "Bestätigen",
        parent: QWidget | None = None,
        cancel_text: str = "Abbrechen",
    ) -> None:
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setModal(True)
        self._build_ui(title, message, confirm_text, cancel_text)

    def _build_ui(
        self, title: str, message: str, confirm_text: str, cancel_text: str
    ) -> None:
        """Erstellt das Dialog-Layout."""
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 8px; }}"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        # Header: Icon + Titel
        header = QHBoxLayout()
        header.setSpacing(10)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(get_icon(Icons.WARNING, color=c.WARNING).pixmap(ICON_SIZE_DIALOG, ICON_SIZE_DIALOG))
        header.addWidget(icon_lbl)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_H3}px; font-weight: 700;"
            f" color: {c.TEXT_MAIN};"
        )
        header.addWidget(title_lbl)
        header.addStretch()
        root.addLayout(header)

        # Nachrichtentext
        msg_lbl = QLabel(message)
        msg_lbl.setWordWrap(True)
        # R22: dynamischer Text nie als Auto-RichText
        msg_lbl.setTextFormat(Qt.TextFormat.PlainText)
        msg_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px; color: {c.TEXT_DIM};"
        )
        root.addWidget(msg_lbl)

        # Button-Leiste: Abbrechen (sekundär) | Bestätigen (destruktiv)
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        btn_cancel = QPushButton(cancel_text)
        btn_cancel.setStyleSheet(self._secondary_style(c))
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)

        # RGB aus Danger-Farbe extrahieren für rgba-Hover
        btn_confirm = QPushButton(confirm_text)
        btn_confirm.setDefault(True)
        # FE-9 (Code-Review 2026-05-19): vorher rgba-Alpha-Variation
        # (Hover 220/255, Pressed 255/255). Pressed war identisch zum
        # Default — semantisch verkehrt. Jetzt explizite Theme-Tokens
        # DANGER_HOVER (heller) + DANGER_PRESSED (dunkler) — visuell
        # eindeutige Hover/Pressed-Richtung.
        btn_confirm.setStyleSheet(
            f"QPushButton {{ background: {c.DANGER}; color: #ffffff; border: none;"  # noqa: hex-color-pending — pures Weiss auf Danger-Rot bewusst; theme.DARK_TEXT_ON_ACCENT (#E0F2F1) wäre teal-getönt
            f" border-radius: 6px; padding: 7px 18px;"
            f" font-family: 'Raleway'; font-weight: 600; font-size: {theme.FONT_SIZE_BODY}px; }}"
            f"QPushButton:hover {{ background: {c.DANGER_HOVER}; }}"
            f"QPushButton:pressed {{ background: {c.DANGER_PRESSED}; }}"
        )
        btn_confirm.clicked.connect(self.accept)
        btn_row.addWidget(btn_confirm)

        root.addLayout(btn_row)
        self.setMinimumWidth(380)

    @staticmethod
    def _secondary_style(c: object) -> str:
        return (
            f"QPushButton {{ background: transparent; color: {c.TEXT_DIM};"  # type: ignore[attr-defined]
            f" border: 1px solid {c.BORDER}; border-radius: 6px;"  # type: ignore[attr-defined]
            f" padding: 7px 18px; font-family: 'Raleway'; font-weight: 600;"
            f" font-size: {theme.FONT_SIZE_BODY}px; }}"
            f"QPushButton:hover {{ background: {c.CARD_BG}; color: {c.TEXT_MAIN}; }}"  # type: ignore[attr-defined]
        )


class FinlaiInfoDialog(QDialog):
    """FINLAI-konformer Info-Dialog für Hinweise und Fehlermeldungen.

    Args:
        title: Dialogtitel (Raleway Bold).
        message: Informationstext (Raleway Regular).
        icon_name: Material-Symbol-Name (default: Icons.INFO).
        icon_color: Hex-Farbe für das Icon (default: TEAL ACCENT).
        parent: Eltern-Widget.
    """

    def __init__(
        self,
        title: str,
        message: str,
        icon_name: str | None = None,
        icon_color: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setModal(True)
        self._build_ui(title, message, icon_name, icon_color)

    def _build_ui(
        self,
        title: str,
        message: str,
        icon_name: str | None,
        icon_color: str | None,
    ) -> None:
        """Erstellt das Dialog-Layout."""
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 8px; }}"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        # Header: Icon + Titel
        header = QHBoxLayout()
        header.setSpacing(10)

        resolved_icon = icon_name or Icons.INFO
        resolved_color = icon_color or c.ACCENT
        icon_lbl = QLabel()
        icon_lbl.setPixmap(get_icon(resolved_icon, color=resolved_color).pixmap(ICON_SIZE_DIALOG, ICON_SIZE_DIALOG))
        header.addWidget(icon_lbl)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_H3}px; font-weight: 700;"
            f" color: {c.TEXT_MAIN};"
        )
        header.addWidget(title_lbl)
        header.addStretch()
        root.addLayout(header)

        # Nachrichtentext — PlainText: ein Info-/Fehler-Dialog rendert nie RichText;
        # schützt gegen RichText-Injektion aus (untrusted) Quellen wie der Collector-
        # Install-Marker-Datei (R22 F-C-5).
        msg_lbl = QLabel(message)
        msg_lbl.setTextFormat(Qt.TextFormat.PlainText)
        msg_lbl.setWordWrap(True)
        # R22: Exception-/Fehlertexte sind untrusted — nie Auto-RichText
        msg_lbl.setTextFormat(Qt.TextFormat.PlainText)
        msg_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px; color: {c.TEXT_DIM};"
        )
        root.addWidget(msg_lbl)

        # OK-Button
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        btn_ok = QPushButton("OK")
        btn_ok.setDefault(True)
        btn_ok.setStyleSheet(
            f"QPushButton {{ background: {c.ACCENT}; color: {c.BG_DARK}; border: none;"
            f" border-radius: 6px; padding: 7px 18px;"
            f" font-family: 'Raleway'; font-weight: 600; font-size: {theme.FONT_SIZE_BODY}px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT_DIM}; color: {c.BG_DARK}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT_DARK}; color: {c.BG_DARK}; }}"
        )
        btn_ok.clicked.connect(self.accept)
        btn_row.addWidget(btn_ok)

        root.addLayout(btn_row)
        self.setMinimumWidth(360)
