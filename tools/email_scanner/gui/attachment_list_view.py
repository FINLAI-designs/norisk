"""attachment_list_view — Darstellung der Anhänge einer gescannten Mail.

Zeigt je Anhang: Dateiname, MIME-Typ, Größe, Status, Risk-Score und
die erkannten Threats. Bietet "Hash kopieren" und "In Quarantäne
speichern" an — **kein** "Öffnen"-Button (Spec-Vorgabe).

Schichtzugehörigkeit: gui/ — keine Geschäftslogik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import Icons, get_icon
from core.security.validation_report import Severity
from tools.email_scanner.domain.models import AttachmentReport, MailScanStatus

_STATUS_FARBE: dict[MailScanStatus, str] = {
    MailScanStatus.SAFE: theme.SEVERITY_SIGNAL_OK,
    MailScanStatus.WARN: theme.SEVERITY_SIGNAL_MEDIUM,
    MailScanStatus.BLOCK: theme.SEVERITY_SIGNAL_CRITICAL,
}

_STATUS_LABEL: dict[MailScanStatus, str] = {
    MailScanStatus.SAFE: "Sicher",
    MailScanStatus.WARN: "Warnung",
    MailScanStatus.BLOCK: "Blockiert",
}

# noqa: domain-email-severity-variant — Severity.LOW (#88aadd) und Severity.HIGH
# (#ff8844) sind eigene Email/PDF-Risk-Varianten der Signal-Palette (etwas anders
# als theme.SEVERITY_SIGNAL_LOW="#44bbff" / SEVERITY_SIGNAL_HIGH="#ff8800"). Bewusst
# beibehalten — Vereinheitlichung in Sprint 2.
_SEVERITY_FARBE: dict[Severity, str] = {
    Severity.INFO: theme.SEVERITY_SIGNAL_INFO,
    Severity.LOW: "#88aadd",  # noqa: domain-email-severity-low
    Severity.MEDIUM: theme.SEVERITY_SIGNAL_MEDIUM,
    Severity.HIGH: "#ff8844",  # noqa: domain-email-severity-high
    Severity.CRITICAL: theme.SEVERITY_SIGNAL_CRITICAL,
}


def _format_groesse(size: int) -> str:
    """Formatiert eine Byte-Größe menschlich lesbar."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


class AttachmentListView(QScrollArea):
    """Scrollbare Liste der Anhänge einer Mail.

    Signale-Callbacks statt Qt-Signalen — einfacher in einem
    funktionsbasierten Widget. "Hash kopieren" verwendet die
    Qt-Zwischenablage, "In Quarantäne speichern" ruft einen
    Service-Callback.
    """

    def __init__(
        self,
        *,
        quarantine_callback: Callable[[AttachmentReport], None],
        status_callback: Callable[[str], None],
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert die Anhang-Liste.

        Args:
            quarantine_callback: Wird mit dem ``AttachmentReport`` aufgerufen,
                wenn der Nutzer "In Quarantäne speichern" drückt.
            status_callback: Status-Meldungen ("Hash kopiert",...).
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._quarantine_cb = quarantine_callback
        self._status_cb = status_callback
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self._inner = QWidget()
        self._layout = QVBoxLayout(self._inner)
        self._layout.setContentsMargins(8, 8, 8, 8)
        self._layout.setSpacing(8)
        self._layout.addStretch()
        self.setWidget(self._inner)
        self._apply_stylesheet()

    def _apply_stylesheet(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QScrollArea {{ background: {c.BG_INPUT}; border: 1px solid {c.BORDER};"
            f" border-radius: 4px; }}"
        )
        self._inner.setStyleSheet("background: transparent;")

    def zeige(self, reports: list[AttachmentReport]) -> None:
        """Baut die Liste neu auf."""
        self._clear()
        if not reports:
            hinweis = QLabel("Keine Anhänge in dieser Mail.")
            c = theme.get()
            hinweis.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
                f" background: transparent; border: none;"
            )
            self._layout.insertWidget(self._layout.count() - 1, hinweis)
            return
        for report in reports:
            self._layout.insertWidget(self._layout.count() - 1, self._card(report))

    def _clear(self) -> None:
        while self._layout.count() > 1:
            item = self._layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

    def _card(self, report: AttachmentReport) -> QWidget:
        c = theme.get()
        card = QFrame()
        card.setStyleSheet(
            f"QFrame {{ background: {c.BG_DARK}; border: 1px solid {c.BORDER};"
            f" border-radius: 4px; }}"
        )
        lay = QVBoxLayout(card)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(4)

        # Kopfzeile: Name + Status
        kopf = QHBoxLayout()
        kopf.setSpacing(8)

        name = QLabel(report.attachment.filename)
        name.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {c.TEXT_MAIN}; background: transparent; border: none;"
        )
        name.setWordWrap(True)
        kopf.addWidget(name, stretch=1)

        status = QLabel(_STATUS_LABEL.get(report.status, "—"))
        farbe = _STATUS_FARBE.get(report.status, theme.SEVERITY_SIGNAL_INFO)
        status.setStyleSheet(
            f"color: {farbe}; font-weight: bold; font-family: 'Raleway';"
            f" font-size: 12px; background: transparent; border: none;"
        )
        kopf.addWidget(status)
        lay.addLayout(kopf)

        # Meta-Zeile
        meta = QLabel(
            f"{report.attachment.content_type} · "
            f"{_format_groesse(report.attachment.size)} · "
            f"Score {report.validation.risk_score} · "
            f"SHA-256 {report.attachment.sha256[:16]}…"
        )
        meta.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'JetBrains Mono', monospace;"
            f" font-size: 11px; background: transparent; border: none;"
        )
        meta.setWordWrap(True)
        lay.addWidget(meta)

        # Threats
        for threat in report.validation.threats:
            lay.addWidget(self._threat_zeile(threat))
        if report.pdf_scan is not None:
            for threat in report.pdf_scan.report.threats:
                lay.addWidget(self._threat_zeile(threat))

        # Aktionen
        btn_zeile = QHBoxLayout()
        btn_zeile.setSpacing(6)
        btn_zeile.addStretch()

        btn_hash = QPushButton("Hash kopieren")
        btn_hash.setIcon(get_icon(Icons.COPY))
        btn_hash.setFixedHeight(28)
        btn_hash.setStyleSheet(self._aktions_stylesheet())
        btn_hash.clicked.connect(lambda *_: self._on_hash_kopieren(report))
        btn_zeile.addWidget(btn_hash)

        btn_quar = QPushButton("In Quarantäne speichern")
        btn_quar.setIcon(get_icon(Icons.LOCK))
        btn_quar.setFixedHeight(28)
        btn_quar.setStyleSheet(self._aktions_stylesheet())
        btn_quar.clicked.connect(lambda *_: self._on_quarantine(report))
        btn_zeile.addWidget(btn_quar)

        lay.addLayout(btn_zeile)
        return card

    def _threat_zeile(self, threat) -> QLabel:
        c = theme.get()
        farbe = _SEVERITY_FARBE.get(threat.severity, c.TEXT_MAIN)
        lbl = QLabel(
            f"<b style='color:{farbe};'>[{threat.severity.value}]</b> "
            f"<b>{threat.code}</b> — {threat.message}"
        )
        lbl.setWordWrap(True)
        lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_MAIN};"
            f" background: transparent; border: none;"
        )
        return lbl

    def _aktions_stylesheet(self) -> str:
        c = theme.get()
        return (
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 3px;"
            f" padding: 3px 10px; font-family: 'Raleway'; font-size: 11px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; }}"
        )

    def _on_hash_kopieren(self, report: AttachmentReport) -> None:
        clip = QGuiApplication.clipboard()
        if clip is not None:
            clip.setText(report.attachment.sha256)
        self._status_cb(
            f"SHA-256 von {report.attachment.filename} in Zwischenablage kopiert."
        )

    def _on_quarantine(self, report: AttachmentReport) -> None:
        self._quarantine_cb(report)
