"""risiko_lage_tab — Tab 1 "Risikobriefing" des Cyber-Dashboards.

Zeigt das **erklaerte Risikobild**: aus den echten Systemdaten abgeleitete
priorisierte "wichtige Punkte" mit der Folge bei Nichtbeachtung
(Patrick-Leitsatz 2026-06-29), plus die zwei getrennten Score-Kacheln
(Selbsteinschaetzung/Audit + Messung/Haertung — NIE gemittelt) und die
tatsaechlich betroffenen CVEs (2 Konfidenz-Stufen).

Datenfluss: ``RisikoBriefingService.build_snapshot`` laeuft OFF dem UI-Thread
(``_RisikoLadeThread``, vgl./ — kein DB-I/O im UI-Slot); nur das
Befuellen der Widgets passiert im Haupt-Thread.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, QTimer, Signal, Slot
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
from core.logger import get_logger
from tools.cyber_dashboard.domain.risiko_briefing import (
    Konfidenz,
    Prioritaet,
    RiskBriefingSnapshot,
)

log = get_logger(__name__)

#: Prioritaet -> Theme-Farb-Token (kein hardcoded Hex, FE-Regel).
_PRIO_FARBE: dict[Prioritaet, str] = {
    Prioritaet.KRITISCH: "DANGER",
    Prioritaet.HOCH: "ERROR",
    Prioritaet.MITTEL: "WARNING",
    Prioritaet.NIEDRIG: "INFO",
}


def _plain(*labels: QLabel) -> None:
    """Setzt QLabel auf PlainText — daten-/inventargetriebene Inhalte nie als
    Rich-Text/HTML rendern (Injection-Hardening / Review)."""
    for lbl in labels:
        lbl.setTextFormat(Qt.TextFormat.PlainText)


class _RisikoLadeThread(QThread):
    """Baut den RiskBriefingSnapshot off-thread (DB-Reads, kein UI-Thread)."""

    fertig: Signal = Signal(object)
    fehlgeschlagen: Signal = Signal(str)

    def __init__(self, service: object) -> None:
        super().__init__()
        self._service = service

    def run(self) -> None:
        try:
            snapshot = self._service.build_snapshot()
        except (OSError, RuntimeError, ValueError, AttributeError, TypeError) as exc:
            log.warning(
                "Risikobriefing-Aufbau fehlgeschlagen: %s",
                type(exc).__name__,
                exc_info=True,
            )
            self.fehlgeschlagen.emit(type(exc).__name__)
            return
        self.fertig.emit(snapshot)


#: Haelt parentlose Worker am Leben bis ``finished``-Teardown-Klasse).
_ACTIVE_WORKERS: set[_RisikoLadeThread] = set()


class _ScoreKachel(QFrame):
    """Eine der zwei getrennten Score-Kacheln (Audit ODER Haertung)."""

    def __init__(self, titel: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._titel = titel
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)
        self._lbl_titel = QLabel(self._titel)
        self._lbl_titel.setObjectName("kachel_titel")
        self._lbl_wert = QLabel("—")
        self._lbl_wert.setObjectName("kachel_wert")
        self._lbl_zusatz = QLabel("")
        self._lbl_zusatz.setObjectName("kachel_zusatz")
        layout.addWidget(self._lbl_titel)
        layout.addWidget(self._lbl_wert)
        layout.addWidget(self._lbl_zusatz)
        _plain(self._lbl_titel, self._lbl_wert, self._lbl_zusatz)

    def setze(
        self, wert: float | None, zusatz: str = "", leer_text: str = "Noch keine Daten"
    ) -> None:
        if wert is None:
            self._lbl_wert.setText("—")
            self._lbl_zusatz.setText(leer_text)
        else:
            self._lbl_wert.setText(f"{wert:.0f}/100")
            self._lbl_zusatz.setText(zusatz)

    def apply_theme(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QFrame {{ background-color: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 6px; }}"
            f"QLabel#kachel_titel {{ color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" font-weight: 600; border: none; background: transparent; }}"
            f"QLabel#kachel_wert {{ color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_H1}px;"
            f" font-weight: 700; border: none; background: transparent; }}"
            f"QLabel#kachel_zusatz {{ color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" border: none; background: transparent; }}"
        )


class _RisikoPunktCard(QFrame):
    """Karte eines RisikoPunkts: Prioritaet-Badge + Titel + Befund + Risiko + Massnahme."""

    def __init__(self, punkt, parent: QWidget | None = None) -> None:  # noqa: ANN001
        super().__init__(parent)
        self._punkt = punkt
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        kopf = QHBoxLayout()
        kopf.setSpacing(6)
        self._lbl_badge = QLabel(self._punkt.prioritaet.value.upper())
        self._lbl_badge.setObjectName("prio_badge")
        kopf.addWidget(self._lbl_badge)
        self._lbl_titel = QLabel(self._punkt.titel)
        self._lbl_titel.setObjectName("punkt_titel")
        self._lbl_titel.setWordWrap(True)
        kopf.addWidget(self._lbl_titel, 1)
        layout.addLayout(kopf)

        self._lbl_befund = QLabel(self._punkt.befund)
        self._lbl_befund.setObjectName("punkt_body")
        self._lbl_befund.setWordWrap(True)
        layout.addWidget(self._lbl_befund)

        self._lbl_risiko = QLabel(
            f"Risiko bei Nichtbeachtung: {self._punkt.risiko_bei_nichtbeachtung}"
        )
        self._lbl_risiko.setObjectName("punkt_risiko")
        self._lbl_risiko.setWordWrap(True)
        layout.addWidget(self._lbl_risiko)

        self._lbl_massnahme = QLabel(
            f"Empfehlung: {self._punkt.empfohlene_massnahme}  ·  Quelle: {self._punkt.quelle}"
        )
        self._lbl_massnahme.setObjectName("punkt_massnahme")
        self._lbl_massnahme.setWordWrap(True)
        layout.addWidget(self._lbl_massnahme)
        _plain(
            self._lbl_titel, self._lbl_befund, self._lbl_risiko, self._lbl_massnahme
        )

    def apply_theme(self) -> None:
        c = theme.get()
        farbe = getattr(c, _PRIO_FARBE.get(self._punkt.prioritaet, "ACCENT"), c.ACCENT)
        self.setStyleSheet(
            f"QFrame {{ background-color: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-left: 3px solid {farbe}; border-radius: 4px; }}"
            f"QLabel#prio_badge {{ background-color: {farbe}; color: {c.BG_DARK};"
            f" padding: 1px 7px; border-radius: 8px; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" font-weight: 700; border: none; }}"
            f"QLabel#punkt_titel {{ color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY}px;"
            f" font-weight: 700; border: none; background: transparent; }}"
            f"QLabel#punkt_body {{ color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" border: none; background: transparent; }}"
            f"QLabel#punkt_risiko {{ color: {c.WARNING}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" border: none; background: transparent; }}"
            f"QLabel#punkt_massnahme {{ color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" border: none; background: transparent; }}"
        )


class _CveZeile(QFrame):
    """Kompakte Zeile eines betroffenen CVE (Badge + ID + Apps + CVSS)."""

    def __init__(self, item, parent: QWidget | None = None) -> None:  # noqa: ANN001
        super().__init__(parent)
        self._item = item
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(6)
        bestaetigt = self._item.konfidenz is Konfidenz.BESTAETIGT
        self._lbl_badge = QLabel("betroffen" if bestaetigt else "moeglich")
        self._lbl_badge.setObjectName("kon_badge_b" if bestaetigt else "kon_badge_m")
        layout.addWidget(self._lbl_badge)
        self._lbl_cve = QLabel(self._item.cve_id)
        self._lbl_cve.setObjectName("cve_id")
        layout.addWidget(self._lbl_cve)
        apps = ", ".join(self._item.affected_apps) or "—"
        marker = "  ⚠ aktiv ausgenutzt" if self._item.exploit_available else ""
        self._lbl_apps = QLabel(f"{apps}{marker}")
        self._lbl_apps.setObjectName("cve_apps")
        self._lbl_apps.setWordWrap(True)
        layout.addWidget(self._lbl_apps, 1)
        score = "—" if self._item.cvss_score is None else f"{self._item.cvss_score:.1f}"
        self._lbl_cvss = QLabel(score)
        self._lbl_cvss.setObjectName("cve_cvss")
        layout.addWidget(self._lbl_cvss)
        _plain(self._lbl_cve, self._lbl_apps, self._lbl_cvss)

    def apply_theme(self) -> None:
        c = theme.get()
        layout_warn = c.WARNING if self._item.exploit_available else c.TEXT_DIM
        self.setStyleSheet(
            f"QFrame {{ background-color: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 4px; }}"
            f"QLabel#kon_badge_b {{ background-color: {c.DANGER}; color: {c.BG_DARK};"
            f" padding: 1px 6px; border-radius: 7px; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" font-weight: 700; border: none; }}"
            f"QLabel#kon_badge_m {{ background-color: {c.WARNING}; color: {c.BG_DARK};"
            f" padding: 1px 6px; border-radius: 7px; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" font-weight: 700; border: none; }}"
            f"QLabel#cve_id {{ color: {c.TEXT_DIM}; font-family: 'JetBrains Mono', Consolas,"
            f" monospace; font-size: {theme.FONT_SIZE_CAPTION}px; border: none; background: transparent; }}"
            f"QLabel#cve_apps {{ color: {layout_warn}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" border: none; background: transparent; }}"
            f"QLabel#cve_cvss {{ color: {c.TEXT_MAIN}; font-weight: 700;"
            f" font-size: {theme.FONT_SIZE_CAPTION}px; border: none; background: transparent; }}"
        )


class RisikoLageTab(QWidget):
    """Tab 1 — Risikobriefing (erklaertes Risikobild).

    Args:
        service: Optionaler vorbereiteter ``RisikoBriefingService`` (Tests
            injizieren ein Surrogat). Default: lazy ueber die Factory.
        parent: Eltern-Widget.
    """

    def __init__(
        self,
        service: object | None = None,
        parent: QWidget | None = None,
        *,
        auto_load: bool = True,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._worker: _RisikoLadeThread | None = None
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()
        # Initial-Last off-ctor (kein DB-I/O im Konstruktor — Perf).
        # ``auto_load=False`` fuer deterministische Tests (kein Worker-Thread).
        if auto_load:
            QTimer.singleShot(0, self.aktualisieren)

    # -- Aufbau ---------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        kopf = QHBoxLayout()
        self._lbl_titel = QLabel("Risikobriefing")
        self._lbl_titel.setObjectName("seiten_titel")
        kopf.addWidget(self._lbl_titel)
        kopf.addStretch()
        self._lbl_status = QLabel("")
        self._lbl_status.setObjectName("status")
        kopf.addWidget(self._lbl_status)
        self._btn_refresh = QPushButton("Aktualisieren")
        self._btn_refresh.setIcon(get_icon(Icons.SYNC))
        self._btn_refresh.clicked.connect(self.aktualisieren)
        kopf.addWidget(self._btn_refresh)
        root.addLayout(kopf)

        # Zwei getrennte Score-Kacheln — nie gemittelt).
        kacheln = QHBoxLayout()
        kacheln.setSpacing(10)
        self._tile_audit = _ScoreKachel("Selbsteinschaetzung (Audit)")
        self._tile_hardening = _ScoreKachel("Messung (Haertung)")
        kacheln.addWidget(self._tile_audit)
        kacheln.addWidget(self._tile_hardening)
        root.addLayout(kacheln)

        self._lbl_hinweis = QLabel("")
        self._lbl_hinweis.setObjectName("hinweis")
        self._lbl_hinweis.setWordWrap(True)
        self._lbl_hinweis.setVisible(False)
        root.addWidget(self._lbl_hinweis)

        # Scrollbereich: Risiko-Punkte (oben) + betroffene CVEs (unten).
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._inhalt = QWidget()
        self._inhalt_layout = QVBoxLayout(self._inhalt)
        self._inhalt_layout.setContentsMargins(0, 0, 0, 0)
        self._inhalt_layout.setSpacing(6)

        self._lbl_punkte_titel = QLabel("Wichtige Punkte")
        self._lbl_punkte_titel.setObjectName("block_titel")
        self._inhalt_layout.addWidget(self._lbl_punkte_titel)
        self._punkte_box = QVBoxLayout()
        self._punkte_box.setSpacing(6)
        self._inhalt_layout.addLayout(self._punkte_box)

        self._lbl_cve_titel = QLabel("Betroffene CVEs")
        self._lbl_cve_titel.setObjectName("block_titel")
        self._inhalt_layout.addWidget(self._lbl_cve_titel)
        self._cve_box = QVBoxLayout()
        self._cve_box.setSpacing(4)
        self._inhalt_layout.addLayout(self._cve_box)

        self._inhalt_layout.addStretch()
        scroll.setWidget(self._inhalt)
        root.addWidget(scroll, 1)

    # -- Laden ----------------------------------------------------------
    def _ensure_service(self) -> object:
        if self._service is None:
            from tools.cyber_dashboard.application.risiko_briefing_factory import (  # noqa: PLC0415
                create_risiko_briefing_service,
            )

            self._service = create_risiko_briefing_service()
        return self._service

    def aktualisieren(self) -> None:
        """Startet den Off-Thread-Aufbau des Risikobilds."""
        if self._worker is not None and self._worker.isRunning():
            return
        self._lbl_status.setText("Lade …")
        self._btn_refresh.setEnabled(False)
        try:
            service = self._ensure_service()
        except (ImportError, OSError, RuntimeError) as exc:  # Service-Bau scheiterte
            self._on_fehler(type(exc).__name__)
            return
        worker = _RisikoLadeThread(service)
        worker.fertig.connect(self._on_fertig)
        worker.fehlgeschlagen.connect(self._on_fehler)
        worker.finished.connect(lambda: _ACTIVE_WORKERS.discard(worker))
        self._worker = worker
        _ACTIVE_WORKERS.add(worker)
        worker.start()

    @Slot(object)
    def _on_fertig(self, snapshot: RiskBriefingSnapshot) -> None:
        self._btn_refresh.setEnabled(True)
        self._lbl_status.setText("")
        self.render_snapshot(snapshot)

    @Slot(str)
    def _on_fehler(self, fehler: str) -> None:
        self._btn_refresh.setEnabled(True)
        self._lbl_status.setText(f"Fehler: {fehler}")

    # -- Rendern --------------------------------------------------------
    def render_snapshot(self, snapshot: RiskBriefingSnapshot) -> None:
        """Befuellt die Widgets aus dem Snapshot (Haupt-Thread)."""
        self._tile_audit.setze(
            snapshot.audit.score if snapshot.audit else None,
            leer_text="Noch kein Audit",
        )
        self._tile_hardening.setze(
            snapshot.hardening.score if snapshot.hardening else None,
            zusatz=snapshot.hardening.stage_label if snapshot.hardening else "",
            leer_text="Noch keine Messung",
        )

        self._setze_hinweise(snapshot)
        self._fuelle_punkte(snapshot)
        self._fuelle_cves(snapshot)

    def _setze_hinweise(self, snapshot: RiskBriefingSnapshot) -> None:
        hinweise: list[str] = []
        if snapshot.apps_without_cpe > 0:
            hinweise.append(
                f"{snapshot.apps_without_cpe} Programme konnten nicht per CPE geprueft "
                "werden — fuer vollstaendige Abdeckung einen Patch-Scan ausfuehren."
            )
        backlog = snapshot.patch_backlog
        if backlog is not None and backlog.last_scan_at is not None:
            hinweise.append(f"Patch-Daten vom {backlog.last_scan_at:%d.%m.%Y}.")
        self._lbl_hinweis.setText("  ".join(hinweise))
        self._lbl_hinweis.setVisible(bool(hinweise))

    def _fuelle_punkte(self, snapshot: RiskBriefingSnapshot) -> None:
        _leere_layout(self._punkte_box)
        if not snapshot.risiko_punkte:
            leer = QLabel(
                "Keine besonderen Risiko-Punkte erkannt. Fuer ein vollstaendiges "
                "Bild Patch-Scan und Security-Audit ausfuehren."
            )
            leer.setObjectName("punkt_body")
            leer.setWordWrap(True)
            self._punkte_box.addWidget(leer)
            return
        for punkt in snapshot.risiko_punkte:
            self._punkte_box.addWidget(_RisikoPunktCard(punkt))

    def _fuelle_cves(self, snapshot: RiskBriefingSnapshot) -> None:
        _leere_layout(self._cve_box)
        cves = snapshot.affected_cves
        if not cves:
            leer = QLabel("Keine betroffenen CVEs aus dem Inventar.")
            leer.setObjectName("punkt_body")
            self._cve_box.addWidget(leer)
            self._lbl_cve_titel.setText("Betroffene CVEs")
            return
        self._lbl_cve_titel.setText(
            f"Betroffene CVEs ({len(snapshot.bestaetigte_cves)} bestaetigt, "
            f"{len(snapshot.moegliche_cves)} moeglich)"
        )
        for item in cves:
            self._cve_box.addWidget(_CveZeile(item))

    # -- Theme ----------------------------------------------------------
    def apply_theme(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QLabel#seiten_titel {{ color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_H2}px;"
            f" font-weight: 700; }}"
            f"QLabel#block_titel {{ color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" font-weight: 700; }}"
            f"QLabel#status {{ color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; }}"
            f"QLabel#hinweis {{ color: {c.WARNING}; font-size: {theme.FONT_SIZE_CAPTION}px; }}"
        )


def _leere_layout(layout: QVBoxLayout) -> None:
    """Entfernt alle Widgets aus einem Layout (fuer Refresh)."""
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w is not None:
            w.deleteLater()
