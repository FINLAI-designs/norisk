"""mail_detail_view — Detail-Panel für eine einzelne Mail.

Zeigt Meta-Daten (Betreff, From, To, Datum), den **Plaintext**-Body und
optional den HTML-Quelltext. HTML wird **nie** gerendert (Spec-Vorgabe:
keine Remote-Requests, keine Tracking-Pixel, keine ActiveX). Der
Quelltext läuft durch einen ``QPlainTextEdit`` — also als inerte
Zeichenkette.

Schichtzugehörigkeit: gui/ — keine Geschäftslogik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QLabel,
    QPlainTextEdit,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.email_scanner.domain.models import MailReport, ParsedMail


class MailDetailView(QWidget):
    """Detail-Ansicht: Meta-Header + Body (plain) + Body (HTML-Quelltext)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._current: MailReport | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        c = theme.get()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._lbl_header = QLabel("Keine Mail ausgewählt.")
        self._lbl_header.setWordWrap(True)
        self._lbl_header.setTextFormat(Qt.TextFormat.RichText)
        self._lbl_header.setStyleSheet(
            f"QLabel {{ background: {c.BG_INPUT}; border: 1px solid {c.BORDER};"
            f" border-radius: 4px; padding: 8px; color: {c.TEXT_MAIN};"
            f" font-family: 'Raleway'; font-size: 12px; }}"
        )
        layout.addWidget(self._lbl_header)

        # HTML-Quelltext-Toggle (standardmäßig aus)
        self._chk_quelltext = QCheckBox("HTML-Quelltext anzeigen (nicht gerendert)")
        self._chk_quelltext.setChecked(False)
        self._chk_quelltext.setStyleSheet(
            f"QCheckBox {{ color: {c.TEXT_DIM}; font-family: 'Raleway';"
            f" font-size: 11px; background: transparent; }}"
            f"QCheckBox::indicator {{ width: 14px; height: 14px; }}"
        )
        self._chk_quelltext.stateChanged.connect(self._on_toggle_quelltext)
        layout.addWidget(self._chk_quelltext)

        self._splitter = QSplitter(Qt.Orientation.Vertical)

        self._txt_plain = QPlainTextEdit()
        self._txt_plain.setReadOnly(True)
        self._txt_plain.setPlaceholderText("(kein Plaintext-Body)")
        self._txt_plain.setStyleSheet(self._editor_stylesheet())

        self._txt_html_src = QPlainTextEdit()
        self._txt_html_src.setReadOnly(True)
        self._txt_html_src.setPlaceholderText("(kein HTML-Body)")
        self._txt_html_src.setStyleSheet(self._editor_stylesheet())
        self._txt_html_src.setVisible(False)

        self._splitter.addWidget(
            self._build_labeled("Body (Plaintext)", self._txt_plain)
        )
        self._wrap_html = self._build_labeled(
            "Body (HTML-Quelltext — nicht gerendert)", self._txt_html_src
        )
        self._wrap_html.setVisible(False)
        self._splitter.addWidget(self._wrap_html)
        self._splitter.setSizes([300, 0])
        layout.addWidget(self._splitter, stretch=1)

    def _editor_stylesheet(self) -> str:
        c = theme.get()
        return (
            f"QPlainTextEdit {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" font-family: 'JetBrains Mono', monospace; font-size: 12px;"
            f" padding: 6px; }}"
        )

    def _build_labeled(self, label: str, editor: QPlainTextEdit) -> QWidget:
        c = theme.get()
        wrap = QFrame()
        wrap_lay = QVBoxLayout(wrap)
        wrap_lay.setContentsMargins(0, 0, 0, 0)
        wrap_lay.setSpacing(2)
        lbl = QLabel(label)
        lbl.setStyleSheet(
            f"color: {c.ACCENT}; font-family: 'Raleway'; font-size: 11px;"
            f" font-weight: bold; background: transparent; border: none;"
        )
        wrap_lay.addWidget(lbl)
        wrap_lay.addWidget(editor, stretch=1)
        return wrap

    def zeige(self, report: MailReport | None) -> None:
        """Füllt die Ansicht mit einer Mail (oder leert sie)."""
        self._current = report
        if report is None or report.mail is None:
            self._lbl_header.setText(
                "Keine Mail ausgewählt."
                + (
                    f"<br><br><b>Fehler:</b> {report.fehler}"
                    if report and report.fehler
                    else ""
                )
            )
            self._txt_plain.setPlainText("")
            self._txt_html_src.setPlainText("")
            self._chk_quelltext.setChecked(False)
            self._wrap_html.setVisible(False)
            return

        mail: ParsedMail = report.mail
        empfaenger = ", ".join(mail.to_addrs) if mail.to_addrs else "—"
        datum = mail.date.isoformat(timespec="seconds") if mail.date else "—"
        self._lbl_header.setText(
            f"<b>Betreff:</b> {self._escape(mail.subject)}<br>"
            f"<b>Von:</b> {self._escape(mail.from_addr)}<br>"
            f"<b>An:</b> {self._escape(empfaenger)}<br>"
            f"<b>Datum:</b> {datum}"
        )
        self._txt_plain.setPlainText(mail.body_text)
        self._txt_html_src.setPlainText(mail.body_html_source)
        has_html = bool(mail.body_html_source)
        self._chk_quelltext.setEnabled(has_html)
        if not has_html:
            self._chk_quelltext.setChecked(False)

    def _on_toggle_quelltext(self, state: int) -> None:
        sichtbar = state == Qt.CheckState.Checked.value
        self._wrap_html.setVisible(sichtbar)
        self._splitter.setSizes([220, 200] if sichtbar else [420, 0])

    @staticmethod
    def _escape(text: str) -> str:
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
