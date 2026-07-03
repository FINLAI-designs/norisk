"""
result_card — Karte mit Risiko-Score + Befunden fuer einen Scan.

Zeigt fuer einen ``DocumentScanResult``:

- Original-Dateiname + Magika-Typ + Datei-Groesse
- Verdict-Badge (Sicher / Verdaechtig / Gefaehrlich) mit Score
- Threat-Liste (Severity-Farbe + Code + Message)
- Aktions-Buttons: [Loeschen] [Speichern (mit Warnung)]

Speichern + Trotzdem-Oeffnen sind Iter 1 noch keine sichtbaren Buttons —
Patrick's Konzept sieht den expliziten "Mark-of-the-Web"-Pfad vor; in
Iter 1 zeigen wir den Pfad nur als Hinweis und stellen erstmal den
Loeschen-Knopf bereit.

Schichtzugehoerigkeit: gui/ — darf application/, core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiInfoDialog
from core.icons import Icons
from core.logger import get_logger
from core.security.validation_report import Severity
from core.security.virustotal_client import VtResult, has_api_key, lookup_hash
from tools.document_scanner.domain.models import DocumentScanResult, ScanVerdict

_log = get_logger(__name__)

_VERDICT_LABEL: dict[ScanVerdict, str] = {
    ScanVerdict.SAFE: "Sicher",
    ScanVerdict.SUSPICIOUS: "Verdaechtig",
    ScanVerdict.DANGEROUS: "Gefaehrlich",
}


def _verdict_color(verdict: ScanVerdict) -> str:
    """Mappt einen Verdict auf eine SEVERITY_SIGNAL_*-Farbe."""
    if verdict is ScanVerdict.DANGEROUS:
        return theme.SEVERITY_SIGNAL_CRITICAL
    if verdict is ScanVerdict.SUSPICIOUS:
        return theme.SEVERITY_SIGNAL_HIGH
    return theme.SEVERITY_SIGNAL_OK


def _severity_color(sev: Severity) -> str:
    """Mappt eine Severity auf eine Signal-Farbe."""
    match sev:
        case Severity.CRITICAL:
            return theme.SEVERITY_SIGNAL_CRITICAL
        case Severity.HIGH:
            return theme.SEVERITY_SIGNAL_HIGH
        case Severity.MEDIUM:
            return theme.SEVERITY_SIGNAL_MEDIUM
        case Severity.LOW:
            return theme.SEVERITY_SIGNAL_LOW
        case _:
            return theme.SEVERITY_SIGNAL_INFO


def _human_size(num_bytes: int) -> str:
    """Formatiert Bytes als KB/MB/GB."""
    units = ["B", "KB", "MB", "GB"]
    n = float(num_bytes)
    for unit in units:
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


class ResultCard(QFrame):
    """Eine Karte je gescannter Datei.

    Signals:
        delete_requested: Loeschen-Button geklickt — der Owner soll
            den:class:`DocumentScanResult` aus der UI entfernen und
            den Quarantaene-Slot abraeumen.
    """

    delete_requested = Signal()

    def __init__(self, result: DocumentScanResult, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._result = result
        self.setObjectName("DocumentScannerResultCard")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(8)

        # ── Header: Name + Verdict-Badge
        header = QHBoxLayout()
        header.setSpacing(8)
        name_lbl = QLabel(result.entry.original_name)
        name_lbl.setObjectName("ResultName")
        header.addWidget(name_lbl, stretch=1)

        badge = QLabel(
            f"  {_VERDICT_LABEL[result.verdict]}  ·  Score {result.risk_score}/100  "
        )
        badge.setObjectName("ResultBadge")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setStyleSheet(
            f"background-color: {_verdict_color(result.verdict)};"
            f" color: #1a1a1a; font-weight: bold;"
            f" border-radius: 10px; padding: 2px 8px;"
        )
        header.addWidget(badge)
        outer.addLayout(header)

        # ── Meta-Zeile: Magika + Groesse + Spoof-Hinweis
        spoof_hint = "" if result.type_match else "  ·  TYP-SPOOFING ERKANNT"
        meta = QLabel(
            f"Magika: {result.magika_label or 'unbekannt'}  ·  "
            f"{_human_size(result.entry.size_bytes)}{spoof_hint}"
        )
        meta.setObjectName("ResultMeta")
        outer.addWidget(meta)

        # ── Befunde
        if result.threats:
            threats_lbl = QLabel("Befunde:")
            threats_lbl.setObjectName("ResultSectionHeader")
            outer.addWidget(threats_lbl)
            for threat in result.threats:
                row = QHBoxLayout()
                row.setSpacing(6)
                sev_chip = QLabel(f" {threat.severity.value.upper()} ")
                sev_chip.setStyleSheet(
                    f"background-color: {_severity_color(threat.severity)};"
                    f" color: #1a1a1a; font-weight: bold;"
                    f" border-radius: 6px; padding: 1px 4px; font-size: {theme.FONT_SIZE_CAPTION_XS}px;"
                )
                row.addWidget(sev_chip)
                msg = QLabel(threat.message)
                msg.setObjectName("ResultThreatMessage")
                msg.setWordWrap(True)
                row.addWidget(msg, stretch=1)
                outer.addLayout(row)
        else:
            ok_lbl = QLabel("Keine Auffaelligkeiten erkannt.")
            ok_lbl.setObjectName("ResultMeta")
            outer.addWidget(ok_lbl)

        # ── Hash + Pfad (Detail-Info)
        detail = QLabel(
            f"SHA-256: {result.entry.sha256[:16]}…  ·  Quarantaene: "
            f"{result.entry.quarantine_dir}"
        )
        detail.setObjectName("ResultDetail")
        detail.setWordWrap(True)
        outer.addWidget(detail)

        # ── VT-Result-Anzeige (Iter 4) — Initial leer, wird nach Klick
        # auf "VirusTotal pruefen" befuellt.
        self._vt_status_lbl = QLabel("")
        self._vt_status_lbl.setObjectName("ResultVtStatus")
        self._vt_status_lbl.setWordWrap(True)
        self._vt_status_lbl.hide()
        outer.addWidget(self._vt_status_lbl)

        # ── Aktionen
        actions = QHBoxLayout()
        actions.setSpacing(6)
        actions.addStretch()

        self._vt_btn = QPushButton("VirusTotal pruefen")
        self._vt_btn.setObjectName("ResultVtBtn")
        self._vt_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._vt_btn.setToolTip(
            "Schickt NUR den SHA-256-Hash an VirusTotal — die Datei "
            "verlaesst nie dein Geraet. Opt-in pro Datei."
        )
        self._vt_btn.clicked.connect(self._on_vt_clicked)
        actions.addWidget(self._vt_btn)

        delete_btn = QPushButton("Loeschen")
        delete_btn.setObjectName("ResultDeleteBtn")
        delete_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        delete_btn.clicked.connect(self.delete_requested)
        actions.addWidget(delete_btn)
        outer.addLayout(actions)

        self._vt_worker: _VtWorker | None = None
        self._apply_style()
        theme.register_listener(self._apply_style)

    # ------------------------------------------------------------------
    # VirusTotal-Opt-in (Iter 4)
    # ------------------------------------------------------------------

    def _on_vt_clicked(self) -> None:
        """Startet einen VT-Hash-Lookup in einem Worker-Thread."""
        if not has_api_key():
            FinlaiInfoDialog(
                title="VirusTotal nicht konfiguriert",
                message=(
                    "In Einstellungen → API-Keys einen kostenlosen "
                    "VirusTotal-API-Key hinterlegen. Es wird nur der "
                    "SHA-256-Hash der Datei verschickt — niemals die "
                    "Datei selbst."
                ),
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return
        if self._vt_worker is not None and self._vt_worker.isRunning():
            return
        self._vt_btn.setEnabled(False)
        self._vt_btn.setText("VirusTotal pruefen …")
        self._vt_status_lbl.show()
        self._vt_status_lbl.setText("VirusTotal-Hash-Lookup laeuft …")

        self._vt_worker = _VtWorker(self._result.entry.sha256, parent=self)
        self._vt_worker.finished_with.connect(self._on_vt_done)
        self._vt_worker.finished.connect(self._vt_worker.deleteLater)
        self._vt_worker.start()

    def _on_vt_done(self, vt: VtResult) -> None:
        """Slot fuer ``_VtWorker.finished_with`` — Result rendern."""
        self._vt_btn.setEnabled(True)
        self._vt_btn.setText("VirusTotal erneut pruefen")
        text = vt.message
        color = theme.SEVERITY_SIGNAL_INFO
        if vt.status == "malicious":
            color = theme.SEVERITY_SIGNAL_CRITICAL
        elif vt.status == "suspicious":
            color = theme.SEVERITY_SIGNAL_HIGH
        elif vt.status == "clean":
            color = theme.SEVERITY_SIGNAL_OK
        if vt.permalink:
            text = f"{text}  ·  Details: {vt.permalink}"
        self._vt_status_lbl.setText(text)
        self._vt_status_lbl.setStyleSheet(
            f"color: {color}; font-size: {theme.FONT_SIZE_CAPTION}px; font-weight: bold;"
            f" background: transparent; border: none; padding: 4px 0;"
        )
        if vt.permalink:
            # Klick auf Status oeffnet Permalink
            def _open_permalink(_event, url=vt.permalink):  # noqa: ANN001
                QDesktopServices.openUrl(QUrl(url))

            self._vt_status_lbl.mousePressEvent = _open_permalink  # type: ignore[method-assign]
            self._vt_status_lbl.setCursor(Qt.CursorShape.PointingHandCursor)

    def _apply_style(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QFrame#DocumentScannerResultCard {{"
            f"  background-color: {c.CARD_BG};"
            f"  border: 1px solid {c.BORDER}; border-radius: 6px;"
            f"}}"
            f"QLabel#ResultName {{"
            f"  color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY}px; font-weight: bold;"
            f"  background: transparent; border: none;"
            f"}}"
            f"QLabel#ResultMeta {{"
            f"  color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f"  background: transparent; border: none;"
            f"}}"
            f"QLabel#ResultSectionHeader {{"
            f"  color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: bold;"
            f"  background: transparent; border: none; margin-top: 4px;"
            f"}}"
            f"QLabel#ResultThreatMessage {{"
            f"  color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px;"
            f"  background: transparent; border: none;"
            f"}}"
            f"QLabel#ResultDetail {{"
            f"  color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION_XS}px;"
            f"  background: transparent; border: none;"
            f"}}"
            f"QPushButton#ResultDeleteBtn {{"
            f"  background-color: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f"  border: 1px solid {c.BORDER}; border-radius: 4px;"
            f"  padding: 4px 12px; font-size: {theme.FONT_SIZE_BODY_SM}px;"
            f"}}"
            f"QPushButton#ResultDeleteBtn:hover {{"
            f"  background-color: {c.DANGER}; color: {c.TEXT_MAIN};"
            f"  border-color: {c.DANGER};"
            f"}}"
            f"QPushButton#ResultVtBtn {{"
            f"  background-color: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f"  border: 1px solid {c.ACCENT}; border-radius: 4px;"
            f"  padding: 4px 12px; font-size: {theme.FONT_SIZE_BODY_SM}px;"
            f"}}"
            f"QPushButton#ResultVtBtn:hover {{"
            f"  background-color: {c.ACCENT}; color: {c.BG_DARK};"
            f"  border-color: {c.ACCENT};"
            f"}}"
            f"QPushButton#ResultVtBtn:disabled {{"
            f"  background-color: {c.BG_BUTTON}; color: {c.TEXT_DIM};"
            f"  border-color: {c.BORDER};"
            f"}}"
        )


class _VtWorker(QThread):
    """Hintergrund-Thread fuer den VT-Hash-Lookup (vermeidet UI-Freeze)."""

    finished_with = Signal(object)  # VtResult

    def __init__(self, sha256: str, parent=None) -> None:
        super().__init__(parent)
        self._sha256 = sha256

    def run(self) -> None:
        try:
            result = lookup_hash(self._sha256)
        except Exception as exc:  # noqa: BLE001 -- Lookup darf nie crashen
            _log.exception("VT-Worker: unerwartete Exception")
            result = VtResult(status="error", message=f"VT-Fehler: {type(exc).__name__}")
        self.finished_with.emit(result)
