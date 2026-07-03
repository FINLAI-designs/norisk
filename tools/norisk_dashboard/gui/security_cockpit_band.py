"""security_cockpit_band — Einstiegs-Cockpit mit zwei getrennten Score-Kacheln.

 Phase 4). Ersetzt oben im NoRisk-Cockpit den frueheren
Hardening-Hero-Gauge durch ZWEI gleichwertige, beschriftete Score-Kacheln der
EIGENEN Sicherheitslage:

  * **Selbsteinschaetzung (Audit)** — der selbst-deklarierte Audit-Score des
    eigenen Systems (``customer_audit``-SELF-Audit).
  * **Messung (Hardening)** — der technisch gemessene Hardening-Score
    (``security_scoring``).

Kernprinzip aus: **zwei Dimensionen, NIE gemittelt, kein Misch-Score.**
Jede Kachel traegt ihre Herkunft im Titel (``self_declared`` vs. ``measured``),
weil ein gemessener Score 72 anderen Beweiswert hat (NIS2/Berufshaftung) als ein
selbst-deklarierter 72. Beide Kacheln zeigen IMMER das eigene System (SELF) —
unabhaengig vom Header-Subjekt-Selektor (Hardening ist technisch self-only,
 §4); Kunden-Audits leben in der separaten ``CustomerAuditCard``.

Navigation: je eine CTA fuehrt in den Audit-Wizard (``customer_audit``) bzw. das
Scoring-Dashboard (``security_scoring``).

Sicherheitsdesign: ``firmenname`` ist (beim SELF-Subjekt) der eigene Org-Name,
wird aber wie in der ``CustomerAuditCard`` als ``PlainText`` gerendert (kein
Rich-Text-Auto-Parsing — Lehre/). Das Band zeigt nie Kundendaten.

Schichtzugehoerigkeit: gui/ — keine Domain-Logik (Score-Farbe ist reines
Anzeige-Mapping; Risikostufen-Strings stammen aus ``customer_audit/domain``,
Stage-Farben aus ``core.theme``).

Author: Patrick Riederich
Version: 1.0 Phase 4)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
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
from tools.norisk_dashboard.domain.models import CustomerAuditSummary
from tools.norisk_dashboard.domain.score_abweichung import bewerte_score_abweichung

if TYPE_CHECKING:
    from tools.security_scoring.domain.hardening_score import HardeningScoreResult

# Effekt: färbt die Audit-Kachel (Score-Zahl + Rahmen-Linkskante) nach
# Risikostufe.
# Risikostufe (customer_audit, deutsch) → Severity-Signal-Theme-Token. Bewusst
# lokales Mapping (kein customer_audit-Import → kein tool→tool); identisch zur
# ``CustomerAuditCard``-Konvention. Aendert sich der Wortlaut der Stufen-Strings
# in ``customer_audit/domain``, hier nachziehen (Drift-Wächter-Test:
# ``test_security_cockpit_band.test_risk_color_mapping_covers_all_levels``).
_RISK_FARBE: dict[str, str] = {
    "kritisch": theme.SEVERITY_SIGNAL_CRITICAL,
    "hoch": theme.SEVERITY_SIGNAL_HIGH,
    "mittel": theme.SEVERITY_SIGNAL_MEDIUM,
    "niedrig": theme.SEVERITY_SIGNAL_OK,
}


class SecurityCockpitBand(QFrame):
    """Zwei-Kachel-Band (Audit + Hardening) der eigenen Sicherheitslage.

    Signals:
        open_audit: „Zum Audit"-Klick → ``navigate("customer_audit")``.
        open_scoring: „Zum Scoring"-Klick → ``navigate("security_scoring")``.
    """

    open_audit = Signal()
    open_scoring = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Baut das Band (initial leer; ``set_data`` befuellt es)."""
        super().__init__(parent)
        self.setObjectName("securityCockpitBand")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        c = theme.get()
        self.setStyleSheet(
            "#securityCockpitBand { background: transparent; border: none; }"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(6)

        # Eigen-System-Beschriftung: macht unmissverstaendlich, dass beide
        # Kacheln das EIGENE System zeigen — auch wenn im Header ein Kunde
        # gewaehlt ist (D3 SELF-only). Verhindert die „ist das die
        # Kunden-Haertung?"-Verwechslung.
        self._caption = QLabel("EIGENE SICHERHEITSLAGE", self)
        self._caption.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 10px; font-weight: bold; "
            f"letter-spacing: 1px; background: transparent;"
        )
        root.addWidget(self._caption)

        tiles = QHBoxLayout()
        tiles.setContentsMargins(0, 0, 0, 0)
        tiles.setSpacing(12)

        self._audit_tile = _ScoreTile(
            caption="SELBSTEINSCHÄTZUNG (AUDIT)",
            herkunft="selbst deklariert",
            tooltip=(
                "Selbst deklarierte Reife aus dem Audit-Wizard "
                "(Selbsteinschätzung). Hat einen anderen Beweiswert als eine "
                "technische Messung — bewusst getrennt ausgewiesen."
            ),
            parent=self,
        )
        self._audit_tile.clicked.connect(self.open_audit.emit)
        tiles.addWidget(self._audit_tile, stretch=1)

        self._hardening_tile = _ScoreTile(
            caption="MESSUNG (HARDENING)",
            herkunft="gemessen",
            tooltip=(
                "Technisch gemessenes Härtungsniveau des eigenen Systems "
                "(SH-Checks aus dem Security-Scoring). Nur für das eigene "
                "System aussagekräftig (lokale Messung)."
            ),
            parent=self,
        )
        self._hardening_tile.clicked.connect(self.open_scoring.emit)
        tiles.addWidget(self._hardening_tile, stretch=1)

        root.addLayout(tiles)

        # E1: Abweichungs-Hinweis (nur bei DRASTISCHER Differenz sichtbar).
        # Markiert, mischt NIE — der Beweiswert beider Dimensionen bleibt getrennt.
        self._lbl_abweichung = QLabel("", self)
        self._lbl_abweichung.setObjectName("cockpitAbweichung")
        self._lbl_abweichung.setWordWrap(True)
        self._lbl_abweichung.setTextFormat(Qt.TextFormat.PlainText)
        self._lbl_abweichung.setStyleSheet(
            f"color: {theme.SEVERITY_SIGNAL_HIGH}; font-size: {theme.FONT_SIZE_CAPTION}px;"
        )
        self._lbl_abweichung.setVisible(False)
        root.addWidget(self._lbl_abweichung)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_data(
        self,
        self_audit: CustomerAuditSummary | None,
        hardening: HardeningScoreResult | None,
    ) -> None:
        """Aktualisiert beide Kacheln aus den SELF-Daten (``None`` → Empty-State).

        Args:
            self_audit: Jüngste SELF-Audit-Zusammenfassung oder ``None``.
            hardening: Gemessenes ``HardeningScoreResult`` oder ``None``.
        """
        self._apply_audit(self_audit)
        self._apply_hardening(hardening)
        self._apply_abweichung(self_audit, hardening)

    # ------------------------------------------------------------------
    # Interna
    # ------------------------------------------------------------------

    def _apply_abweichung(
        self,
        self_audit: CustomerAuditSummary | None,
        hardening: HardeningScoreResult | None,
    ) -> None:
        """Zeigt einen Hinweis bei drastischer Abweichung Selbsteinschätzung↔Messung.

 E1: beide Scores bleiben getrennt (kein Misch-Score) — der Hinweis
        markiert nur eine prüfwürdige Differenz (Eingabefehler/Fehleinschätzung).
        """
        audit_score = self_audit.overall_score if self_audit is not None else None
        hardening_score = hardening.overall_score if hardening is not None else None
        abweichung = bewerte_score_abweichung(audit_score, hardening_score)
        if abweichung is not None and abweichung.drastisch:
            self._lbl_abweichung.setText(f"⚠ {abweichung.hinweis}")
            self._lbl_abweichung.setVisible(True)
        else:
            self._lbl_abweichung.setVisible(False)

    def _apply_audit(self, summary: CustomerAuditSummary | None) -> None:
        if summary is None:
            self._audit_tile.show_empty(
                subtitle="Noch kein Audit durchgeführt",
                cta="Audit starten",
            )
            return
        farbe = _RISK_FARBE.get(
            summary.risk_level.casefold(), theme.SEVERITY_SIGNAL_INFO
        )
        self._audit_tile.show_value(
            score=summary.overall_score,
            accent=farbe,
            subtitle=self._audit_subtitle(summary),
            cta="Zum Audit",
        )

    def _apply_hardening(self, result: HardeningScoreResult | None) -> None:
        if result is None:
            self._hardening_tile.show_empty(
                subtitle="Noch nicht gemessen",
                cta="Jetzt messen",
            )
            return
        farbe = theme.SCORE_STAGE_COLORS.get(
            result.stage.color_key, theme.get().TEXT_MAIN
        )
        self._hardening_tile.show_value(
            score=result.overall_score,
            accent=farbe,
            subtitle=f"Stufe: {result.stage.label}",
            cta="Zum Scoring",
        )

    @staticmethod
    def _audit_subtitle(summary: CustomerAuditSummary) -> str:
        """Baut die Subline der Audit-Kachel (Risikostufe + Stand)."""
        parts: list[str] = []
        if summary.risk_level:
            parts.append(f"Risikostufe: {summary.risk_level}")
        if summary.created_at is not None:
            parts.append(f"Stand {summary.created_at:%d.%m.%Y}")
        return "  ·  ".join(parts)


class _ScoreTile(QFrame):
    """Eine read-only Score-Kachel: Titel + grosse Zahl/100 + Subline + CTA.

    Signals:
        clicked: CTA-Klick (Navigation ins zugehoerige Tool).
    """

    clicked = Signal()

    def __init__(
        self,
        caption: str,
        herkunft: str,
        tooltip: str,
        parent: QWidget | None = None,
    ) -> None:
        """Baut die Kachel im neutralen Leerzustand.

        Args:
            caption: Titelzeile (z. B. ``"MESSUNG (HARDENING)"``).
            herkunft: Herkunfts-Badge-Text (``"gemessen"`` / ``"selbst
                deklariert"``) — macht die-Dimensionstrennung sichtbar.
            tooltip: Erklärungs-Tooltip auf der ganzen Kachel.
            parent: Eltern-Widget.
        """
        super().__init__(parent)
        self.setObjectName("cockpitScoreTile")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setToolTip(tooltip)
        c = theme.get()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 14, 18, 14)
        outer.setSpacing(6)

        # Kopfzeile: Titel links, Herkunfts-Badge rechts.
        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(8)
        self._caption = QLabel(caption, self)
        self._caption.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 10px; font-weight: bold; "
            f"letter-spacing: 1px; background: transparent;"
        )
        head.addWidget(self._caption)
        head.addStretch()
        self._herkunft = QLabel(herkunft, self)
        self._herkunft.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 10px; font-style: italic; "
            f"background: transparent;"
        )
        head.addWidget(self._herkunft)
        outer.addLayout(head)

        # Score-Zeile: grosse Zahl + „/ 100".
        score_row = QHBoxLayout()
        score_row.setContentsMargins(0, 0, 0, 0)
        score_row.setSpacing(6)
        self._score = QLabel("—", self)
        self._score.setTextFormat(Qt.TextFormat.PlainText)
        self._score.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 40px; font-weight: bold; "
            f"background: transparent;"
        )
        score_row.addWidget(self._score)
        self._unit = QLabel("/ 100", self)
        self._unit.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 13px; background: transparent;"
        )
        score_row.addWidget(self._unit, alignment=Qt.AlignmentFlag.AlignBottom)
        score_row.addStretch()
        outer.addLayout(score_row)

        # Subline (Risikostufe/Stage/Stand).
        self._subtitle = QLabel("", self)
        self._subtitle.setTextFormat(Qt.TextFormat.PlainText)
        self._subtitle.setWordWrap(True)
        self._subtitle.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 12px; background: transparent;"
        )
        outer.addWidget(self._subtitle)

        # CTA-Zeile.
        cta_row = QHBoxLayout()
        cta_row.setContentsMargins(0, 0, 0, 0)
        cta_row.addStretch()
        self._cta = QPushButton("", self)
        self._cta.setObjectName("cockpitScoreTileCta")
        self._cta.setCursor(Qt.CursorShape.PointingHandCursor)
        self._cta.clicked.connect(self.clicked.emit)
        self._cta.setStyleSheet(
            f"QPushButton#cockpitScoreTileCta {{ color: {c.TEXT_MAIN}; "
            f"background: {c.BG_SIDEBAR}; border: 1px solid {c.BORDER}; "
            f"border-radius: 4px; padding: 5px 12px; }} "
            f"QPushButton#cockpitScoreTileCta:hover {{ "
            f"border-color: {theme.DARK_ACCENT}; color: {theme.DARK_ACCENT}; }}"
        )
        cta_row.addWidget(self._cta)
        outer.addLayout(cta_row)

        self._apply_frame(theme.SEVERITY_SIGNAL_INFO)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def show_value(
        self, score: float, accent: str, subtitle: str, cta: str
    ) -> None:
        """Zeigt einen vorhandenen Score (gefärbt) + Subline + CTA-Text."""
        c = theme.get()
        self._score.setText(f"{score:.0f}")
        self._score.setStyleSheet(
            f"color: {accent}; font-size: 40px; font-weight: bold; "
            f"background: transparent;"
        )
        self._unit.setVisible(True)
        # PlainText defensiv re-asserten (Lehre/): die Subline kann
        # aus DB-Inhalt gespeist sein; setText ändert das Format nicht, aber ein
        # späterer Refactor darf den PlainText-Schutz nicht still verlieren.
        self._subtitle.setTextFormat(Qt.TextFormat.PlainText)
        self._subtitle.setText(subtitle)
        self._subtitle.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 12px; background: transparent;"
        )
        self._cta.setText(f"{cta}  →")
        self._apply_frame(accent)

    def show_empty(self, subtitle: str, cta: str) -> None:
        """Setzt den neutralen Leerzustand („—") + Hinweis + Start-CTA."""
        c = theme.get()
        self._score.setText("—")
        self._score.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 40px; font-weight: bold; "
            f"background: transparent;"
        )
        # Kein „— / 100": die „/ 100"-Einheit nur bei vorhandenem Score zeigen.
        self._unit.setVisible(False)
        self._subtitle.setTextFormat(Qt.TextFormat.PlainText)
        self._subtitle.setText(subtitle)
        self._subtitle.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 12px; background: transparent;"
        )
        self._cta.setText(f"{cta}  →")
        self._apply_frame(c.BORDER)

    # ------------------------------------------------------------------
    # Interna
    # ------------------------------------------------------------------

    def _apply_frame(self, akzent: str) -> None:
        """Setzt Rahmen + Akzent-Linkskante (Severity-/Stage-Farbe)."""
        c = theme.get()
        self.setStyleSheet(
            f"#cockpitScoreTile {{ background: {c.CARD_BG}; "
            f"border: 1px solid {c.BORDER}; "
            f"border-left: 4px solid {akzent}; "
            f"border-radius: 6px; }}"
        )
