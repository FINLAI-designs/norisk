"""phishing_wellen_tab — Tab 2 "Phishing-Wellen" des Cyber-Dashboards.

Qualitativer als die frueheren Keyword-Kurztitel: strukturierte Karten je Welle
mit Zielgruppe (Unternehmen/Privat), Herkunft (Watchlist AT / Mimikama DE /
NCSC CH / …), Datum und Beschreibung, plus ein kompakter deterministischer
Ueberblick. Toggle Unternehmen/Privat/Beide.

Datenquelle: ``DashboardService.lade_phishing_alerts`` (RSS-Cache, GUI-thread-
sicher) -> ``waehle_phishing_kandidaten`` (DETERMINISTISCHE KMU/Consumer-
Klassifikation, kein LLM). Off-thread geladen.

Hinweis: Die optionale KI-Trend-Zusammenfassung (Patrick Q2 "Beides kombiniert")
ist eine spaetere Phase-4-Erweiterung (LLM, off-thread, injection-gescreent) —
hier steht zunaechst der deterministische Ueberblick + die strukturierten Karten.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
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
from core.logger import get_logger

log = get_logger(__name__)

#: QuelleTyp.name -> Herkunftsland (Default INT).
_LAND: dict[str, str] = {
    "WATCHLIST_AT": "AT",
    "MIMIKAMA": "DE",
    "POLIZEI_NDS": "DE",
    "ESET_WLS_DE": "DE",
    "NCSC_CH": "CH",
}

#: Toggle-Ebenen (Combo-Index -> interner Schluessel).
_EBENEN: tuple[tuple[str, str], ...] = (
    ("Beide", "beide"),
    ("Unternehmen", "kmu"),
    ("Privat", "consumer"),
)


def _quelle_label(quelle: object) -> tuple[str, str]:
    """(Anzeige-Name, Land) fuer eine ``QuelleTyp``-Meldungsquelle."""
    name = str(getattr(quelle, "value", quelle))
    land = _LAND.get(str(getattr(quelle, "name", "")), "INT")
    return name, land


class _PhishingLadeThread(QThread):
    """Laedt + klassifiziert die Phishing-Meldungen off-thread (RSS-Cache)."""

    fertig: Signal = Signal(object)  # (kmu, consumer)
    fehlgeschlagen: Signal = Signal(str)

    def __init__(self, service: object, max_pro_gruppe: int = 8) -> None:
        super().__init__()
        self._service = service
        self._max = max_pro_gruppe

    def run(self) -> None:
        try:
            from tools.cyber_dashboard.application.phishing_briefing import (  # noqa: PLC0415
                PHISHING_KATEGORIEN,
                waehle_phishing_kandidaten,
            )

            meldungen = self._service.lade_phishing_alerts(
                kategorien=PHISHING_KATEGORIEN, nur_cache=True, limit=300
            )
            kmu, consumer = waehle_phishing_kandidaten(
                meldungen, max_pro_gruppe=self._max
            )
        except (OSError, RuntimeError, ValueError, AttributeError, TypeError) as exc:
            log.warning(
                "Phishing-Wellen laden fehlgeschlagen: %s",
                type(exc).__name__,
                exc_info=True,
            )
            self.fehlgeschlagen.emit(type(exc).__name__)
            return
        self.fertig.emit((kmu, consumer))


_ACTIVE_WORKERS: set[_PhishingLadeThread] = set()


class _TrendThread(QThread):
    """Generiert die KI-Trend-Zusammenfassung off-thread (LLM, on-demand)."""

    fertig: Signal = Signal(str)

    def __init__(self, kmu: list[object], consumer: list[object]) -> None:
        super().__init__()
        self._kmu = kmu
        self._consumer = consumer

    def run(self) -> None:
        try:
            from tools.cyber_dashboard.application.briefing_service import (  # noqa: PLC0415
                BriefingService,
            )

            trend = BriefingService().generiere_phishing_trend(
                self._kmu, self._consumer
            )
        except (OSError, RuntimeError, ValueError, AttributeError, TypeError) as exc:
            log.warning("KI-Trend fehlgeschlagen: %s", type(exc).__name__)
            self.fertig.emit("")
            return
        self.fertig.emit(trend)


_ACTIVE_TREND_WORKERS: set[_TrendThread] = set()


class _PhishingCard(QFrame):
    """Karte einer Phishing-Welle: Zielgruppe + Herkunft + Datum + Titel + Text."""

    def __init__(
        self, meldung: object, ist_kmu: bool, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._meldung = meldung
        self._ist_kmu = ist_kmu
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        kopf = QHBoxLayout()
        kopf.setSpacing(6)
        self._lbl_ziel = QLabel("Unternehmen" if self._ist_kmu else "Privat")
        self._lbl_ziel.setObjectName("ziel_badge")
        kopf.addWidget(self._lbl_ziel)

        name, land = _quelle_label(getattr(self._meldung, "quelle", ""))
        herkunft = f"{name} · {land}" if land else name
        self._lbl_herkunft = QLabel(herkunft)
        self._lbl_herkunft.setObjectName("herkunft")
        kopf.addWidget(self._lbl_herkunft)
        kopf.addStretch()

        datum = getattr(self._meldung, "veroeffentlicht", None)
        self._lbl_datum = QLabel(datum.strftime("%d.%m.%Y") if datum else "")
        self._lbl_datum.setObjectName("datum")
        kopf.addWidget(self._lbl_datum)
        layout.addLayout(kopf)

        self._lbl_titel = QLabel(str(getattr(self._meldung, "titel", "")))
        self._lbl_titel.setObjectName("titel")
        self._lbl_titel.setWordWrap(True)
        # PlainText: Feed-Inhalte nie als Rich-Text/HTML rendern (Injection-Hardening).
        self._lbl_titel.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self._lbl_titel)

        self._lbl_text = QLabel(str(getattr(self._meldung, "beschreibung", "")))
        self._lbl_text.setObjectName("text")
        self._lbl_text.setWordWrap(True)
        self._lbl_text.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self._lbl_text)

    def apply_theme(self) -> None:
        c = theme.get()
        badge = c.WARNING if self._ist_kmu else c.INFO
        self.setStyleSheet(
            f"QFrame {{ background-color: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-left: 3px solid {badge}; border-radius: 4px; }}"
            f"QLabel#ziel_badge {{ background-color: {badge}; color: {c.BG_DARK};"
            f" padding: 1px 7px; border-radius: 8px; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" font-weight: 700; border: none; }}"
            f"QLabel#herkunft {{ color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" border: none; background: transparent; }}"
            f"QLabel#datum {{ color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" border: none; background: transparent; }}"
            f"QLabel#titel {{ color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY}px;"
            f" font-weight: 700; border: none; background: transparent; }}"
            f"QLabel#text {{ color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" border: none; background: transparent; }}"
        )


class PhishingWellenTab(QWidget):
    """Tab 2 — Phishing-Wellen (strukturierte Karten + Ueberblick).

    Args:
        service: ``DashboardService`` (liefert ``lade_phishing_alerts``).
        parent: Eltern-Widget.
        auto_load: ``False`` fuer deterministische Tests (kein Worker-Thread).
    """

    def __init__(
        self,
        service: object,
        parent: QWidget | None = None,
        *,
        auto_load: bool = True,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._worker: _PhishingLadeThread | None = None
        self._trend_worker: _TrendThread | None = None
        self._kmu: list[object] = []
        self._consumer: list[object] = []
        self._ebene = "beide"
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()
        if auto_load:
            QTimer.singleShot(0, self.aktualisieren)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        kopf = QHBoxLayout()
        self._lbl_titel = QLabel("Phishing-Wellen")
        self._lbl_titel.setObjectName("seiten_titel")
        kopf.addWidget(self._lbl_titel)
        kopf.addStretch()
        self._combo = QComboBox()
        for label, _ in _EBENEN:
            self._combo.addItem(label)
        self._combo.currentIndexChanged.connect(self._on_ebene_changed)
        kopf.addWidget(self._combo)
        self._btn_trend = QPushButton("KI-Trend")
        self._btn_trend.setToolTip(
            "Kurze KI-Zusammenfassung der aktuellen Phishing-Wellen (lokal, on-demand)."
        )
        self._btn_trend.clicked.connect(self._trend_generieren)
        kopf.addWidget(self._btn_trend)
        self._btn_refresh = QPushButton("Aktualisieren")
        self._btn_refresh.setIcon(get_icon(Icons.SYNC))
        self._btn_refresh.clicked.connect(self.aktualisieren)
        kopf.addWidget(self._btn_refresh)
        root.addLayout(kopf)

        self._lbl_ueberblick = QLabel("")
        self._lbl_ueberblick.setObjectName("ueberblick")
        self._lbl_ueberblick.setWordWrap(True)
        root.addWidget(self._lbl_ueberblick)

        # KI-Trend (on-demand, off-thread) — LLM-Output, daher PlainText.
        self._lbl_ki_trend = QLabel("")
        self._lbl_ki_trend.setObjectName("ki_trend")
        self._lbl_ki_trend.setWordWrap(True)
        self._lbl_ki_trend.setTextFormat(Qt.TextFormat.PlainText)
        self._lbl_ki_trend.setVisible(False)
        root.addWidget(self._lbl_ki_trend)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._inhalt = QWidget()
        self._karten_box = QVBoxLayout(self._inhalt)
        self._karten_box.setContentsMargins(0, 0, 0, 0)
        self._karten_box.setSpacing(6)
        self._karten_box.addStretch()
        scroll.setWidget(self._inhalt)
        root.addWidget(scroll, 1)

    # -- Laden ----------------------------------------------------------
    def aktualisieren(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self._lbl_ueberblick.setText("Lade …")
        worker = _PhishingLadeThread(self._service)
        worker.fertig.connect(self._on_fertig)
        worker.fehlgeschlagen.connect(self._on_fehler)
        worker.finished.connect(lambda: _ACTIVE_WORKERS.discard(worker))
        self._worker = worker
        _ACTIVE_WORKERS.add(worker)
        worker.start()

    @Slot(object)
    def _on_fertig(self, paar: tuple) -> None:
        kmu, consumer = paar
        self.render(list(kmu), list(consumer))

    @Slot(str)
    def _on_fehler(self, fehler: str) -> None:
        self._lbl_ueberblick.setText(f"Fehler: {fehler}")

    def _on_ebene_changed(self, index: int) -> None:
        self._ebene = _EBENEN[index][1] if 0 <= index < len(_EBENEN) else "beide"
        self._fuelle_karten()

    # -- KI-Trend (on-demand, off-thread) -------------------------------
    def _trend_generieren(self) -> None:
        if self._trend_worker is not None and self._trend_worker.isRunning():
            return
        if not self._kmu and not self._consumer:
            self._lbl_ki_trend.setText(
                "Erst Wellen laden ('Aktualisieren'), dann KI-Trend erstellen."
            )
            self._lbl_ki_trend.setVisible(True)
            return
        self._btn_trend.setEnabled(False)
        self._lbl_ki_trend.setText("KI-Trend wird erstellt …")
        self._lbl_ki_trend.setVisible(True)
        worker = _TrendThread(list(self._kmu), list(self._consumer))
        worker.fertig.connect(self._on_trend_fertig)
        worker.finished.connect(lambda: _ACTIVE_TREND_WORKERS.discard(worker))
        self._trend_worker = worker
        _ACTIVE_TREND_WORKERS.add(worker)
        worker.start()

    @Slot(str)
    def _on_trend_fertig(self, trend: str) -> None:
        self._btn_trend.setEnabled(True)
        if trend:
            self._lbl_ki_trend.setText(f"KI-Trend: {trend}")
        else:
            self._lbl_ki_trend.setText(
                "KI-Trend nicht verfügbar (Ollama nicht erreichbar oder kein Modell)."
            )
        self._lbl_ki_trend.setVisible(True)

    # -- Rendern --------------------------------------------------------
    def render(self, kmu: list[object], consumer: list[object]) -> None:
        """Befuellt Ueberblick + Karten aus den klassifizierten Meldungen."""
        self._kmu = kmu
        self._consumer = consumer
        self._setze_ueberblick()
        self._fuelle_karten()

    def _setze_ueberblick(self) -> None:
        gesamt = len(self._kmu) + len(self._consumer)
        if gesamt == 0:
            self._lbl_ueberblick.setText(
                "Aktuell keine Phishing-Wellen im Cache. Über 'Aktualisieren' "
                "werden die neuesten Warnungen geladen."
            )
            return
        self._lbl_ueberblick.setText(
            f"{gesamt} aktuelle Phishing-Wellen · {len(self._kmu)} mit "
            f"Unternehmens-Bezug · {len(self._consumer)} für Privatpersonen."
        )

    def _sichtbare(self) -> list[tuple[object, bool]]:
        eintraege: list[tuple[object, bool]] = []
        if self._ebene in ("beide", "kmu"):
            eintraege += [(m, True) for m in self._kmu]
        if self._ebene in ("beide", "consumer"):
            eintraege += [(m, False) for m in self._consumer]
        return eintraege

    def _fuelle_karten(self) -> None:
        # Stretch (letztes Item) erhalten, Karten davor entfernen.
        while self._karten_box.count() > 1:
            item = self._karten_box.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
        sichtbar = self._sichtbare()
        if not sichtbar:
            leer = QLabel("Keine Wellen in dieser Ansicht.")
            leer.setObjectName("text")
            self._karten_box.insertWidget(0, leer)
            return
        for i, (meldung, ist_kmu) in enumerate(sichtbar):
            self._karten_box.insertWidget(i, _PhishingCard(meldung, ist_kmu))

    def apply_theme(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QLabel#seiten_titel {{ color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_H2}px;"
            f" font-weight: 700; }}"
            f"QLabel#ueberblick {{ color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; }}"
            f"QLabel#ki_trend {{ color: {c.ACCENT}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" font-style: italic; }}"
            f"QLabel#text {{ color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_CAPTION}px; }}"
        )
