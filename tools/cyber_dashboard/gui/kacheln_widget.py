"""
kacheln_widget — Statistik-Kacheln für das Cyberrisiko-Dashboard.

Zeigt 3 farbige Kacheln: Kritisch, Hoch, KEV.
Wird nach jedem Ladevorgang mit aktuellen Zählwerten befüllt.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from core import theme


class StatistikKacheln(QWidget):
    """Zeigt Dashboard-Zusammenfassung als farbige Kacheln.

    3 Kacheln: Kritisch (24h), Hoch (24h), KEV (aktiv ausgenutzt).

    Args:
        parent: Optionales Eltern-Widget.
    """

    # KEV ("Known Exploited Vulnerability") hat eigene Semantik (US-CISA-Liste)
    # — bewusst NICHT als HIGH gemappt; eigene Domain-Farbe.
    _FARBEN: dict[str, str] = {
        "kritisch": theme.SEVERITY_SIGNAL_CRITICAL,
        "hoch": theme.SEVERITY_SIGNAL_HIGH,
        "kev": "#ff6600",  # noqa: domain-kev-status — Known Exploited Vulnerability
    }

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert die Kacheln-Leiste."""
        super().__init__(parent)
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        """Erstellt die 4 Kacheln in einem horizontalen Layout."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        definitionen = [
            ("kritisch", "!", "Kritisch", "letzte 24h"),
            ("hoch", "!", "Hoch", "letzte 24h"),
            ("kev", "", "KEV", "aktiv ausgenutzt"),
        ]

        self._kacheln: dict[str, QFrame] = {}
        for key, emoji, titel, untertitel in definitionen:
            kachel = self._kachel_erstellen(emoji, titel, untertitel, "—")
            self._kacheln[key] = kachel
            layout.addWidget(kachel)

    def _kachel_erstellen(
        self,
        emoji: str,
        titel: str,
        untertitel: str,
        wert: str,
    ) -> QFrame:
        """Erstellt eine einzelne Statistik-Kachel.

        Args:
            emoji: Emoji-Icon.
            titel: Kachel-Titel.
            untertitel: Beschreibungszeile.
            wert: Initialwert (z.B. "—" oder "0").

        Returns:
            QFrame mit internem Layout und _wert_label Attribut.
        """
        frame = QFrame()
        frame.setFixedHeight(70)
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(10, 6, 10, 6)
        fl.setSpacing(2)

        kopf = QHBoxLayout()
        lbl_emoji = QLabel(emoji)
        lbl_emoji.setStyleSheet(
            "font-size: 18px; background: transparent; border: none;"
        )
        lbl_titel = QLabel(titel)
        lbl_titel.setStyleSheet(
            "font-weight: bold; font-size: 12px; background: transparent; border: none;"
        )
        kopf.addWidget(lbl_emoji)
        kopf.addWidget(lbl_titel)
        kopf.addStretch()
        fl.addLayout(kopf)

        lbl_wert = QLabel(wert)
        lbl_wert.setObjectName("wert")
        lbl_wert.setStyleSheet(
            "font-size: 22px; font-weight: bold; background: transparent; border: none;"
        )
        fl.addWidget(lbl_wert)

        lbl_sub = QLabel(untertitel)
        lbl_sub.setStyleSheet("font-size: 10px; background: transparent; border: none;")
        fl.addWidget(lbl_sub)

        # Referenz für spätere Aktualisierung
        frame._wert_label = lbl_wert  # type: ignore[attr-defined]
        return frame

    def aktualisiere(
        self,
        kritisch: int,
        hoch: int,
        kev: int,
    ) -> None:
        """Aktualisiert alle Kachel-Werte.

        Args:
            kritisch: Anzahl kritischer CVEs (letzte 24h).
            hoch: Anzahl hoher CVEs (letzte 24h).
            kev: Anzahl KEV CVEs.
        """
        werte = {
            "kritisch": str(kritisch),
            "hoch": str(hoch),
            "kev": str(kev),
        }
        for key, wert in werte.items():
            self._kacheln[key]._wert_label.setText(wert)  # type: ignore[attr-defined]

    def apply_theme(self) -> None:
        """Aktualisiert Kachel-Farben für das aktive Theme."""
        c = theme.get()
        for key, kachel in self._kacheln.items():
            farbe = self._FARBEN[key]
            kachel.setStyleSheet(
                f"QFrame {{"
                f" background-color: {c.CARD_BG};"
                f" border-left: 4px solid {farbe};"
                f" border-radius: 6px;"
                f"}}"
            )
