"""selbstbewertung_dialog — Auswahl-Dialog für die Selbstbewertung (D3 GUI-Hülle).

Ersetzt die zwei zuvor gleichrangigen Buttons "Assessment starten" und
"Organisatorische Sicherheit" im Scoring-Dashboard durch EINEN Einstieg.
Der Dialog zeigt zwei Sektionen als Karten:

  - "Technische Bewertung" → startet den bestehenden AssessmentWizard
  - "Organisatorische Sicherheit" → startet den bestehenden OrgAssessmentWizard

Wichtig (GUI-Hülle, KEIN Service-Merge): jede Sektion startet ihren EIGENEN
bestehenden Wizard (eigener State/Repo) über einen injizierten Callback. Es
gibt KEINEN gemeinsamen Step-State und KEINE Assessment-Facade. Eine nicht
verfügbare/lizenzierte Sektion verschwindet nicht spurlos, sondern zeigt einen
Lock-Hinweis mit nächstem Schritt.
Die eigentliche Gate-Prüfung bleibt am Wizard-/Service-Start — das Ausblenden
hier ist Komfort, keine Zugriffskontrolle.

Schichtzugehörigkeit: gui/ — keine Business-Logik, ruft nur die injizierten
Start-Callbacks des Dashboards auf.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import ICON_SIZE_DIALOG, ICON_SIZE_LG, Icons, get_icon

# Hinweise für nicht verfügbare Sektionen (Sie-Form, R-Sie).:
# kein Lizenz-Gating mehr — die technische Bewertung ist immer verfügbar; die
# organisatorische hängt nur an der Einrichtung des Organisations-Service.
_TECH_LOCK_HINWEIS = "Die technische Bewertung ist auf diesem Gerät nicht verfügbar."
_ORG_LOCK_HINWEIS = (
    "Die organisatorische Selbstbewertung ist auf diesem Gerät nicht verfügbar "
    "(kein Organisations-Service eingerichtet)."
)


class SelbstbewertungDialog(QDialog):
    """Auswahl-Dialog mit zwei Sektions-Karten für die Selbstbewertung.

    Attributes:
        _tech_available: Ob die technische Sektion verfügbar ist.
        _org_available: Ob die organisatorische Sektion verfügbar ist.
        _on_start_tech: Callback, der den technischen Wizard startet.
        _on_start_org: Callback, der den organisatorischen Wizard startet.
    """

    def __init__(
        self,
        *,
        tech_available: bool,
        org_available: bool,
        on_start_tech: Callable[[], None],
        on_start_org: Callable[[], None],
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert den Auswahl-Dialog.

        Args:
            tech_available: True, wenn die technische Bewertung lizenziert ist.
            org_available: True, wenn die organisatorische Bewertung verfügbar
                            (lizenziert + Service vorhanden) ist.
            on_start_tech: Wird aufgerufen, wenn der Nutzer die technische
                            Bewertung startet (startet den AssessmentWizard).
            on_start_org: Wird aufgerufen, wenn der Nutzer die organisatorische
                            Bewertung startet (startet den OrgAssessmentWizard).
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._tech_available = tech_available
        self._org_available = org_available
        self._on_start_tech = on_start_tech
        self._on_start_org = on_start_org
        self.setModal(True)
        self.setWindowTitle("Selbstbewertung")
        self._build_ui()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Erstellt Header, die zwei Sektions-Karten und den Schließen-Button."""
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 8px; }}"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        # Header: Icon + Titel
        header = QHBoxLayout()
        header.setSpacing(10)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(
            get_icon(Icons.SHIELD, color=c.ACCENT).pixmap(
                ICON_SIZE_DIALOG, ICON_SIZE_DIALOG
            )
        )
        header.addWidget(icon_lbl)
        title_lbl = QLabel("Selbstbewertung")
        title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_H3}px;"
            f" font-weight: 700; color: {c.TEXT_MAIN};"
        )
        header.addWidget(title_lbl)
        header.addStretch()
        root.addLayout(header)

        intro = QLabel(
            "Bewerten Sie Ihr eigenes System technisch und organisatorisch. "
            "Jede Bewertung läuft in einem eigenen Wizard."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px;"
            f" color: {c.TEXT_DIM};"
        )
        root.addWidget(intro)

        # Sektion 1: Technische Bewertung
        root.addWidget(
            self._build_card(
                icon_name=Icons.SECURITY,
                titel="Technische Bewertung",
                beschreibung=(
                    "Geführter Assessment-Wizard über API-Sicherheit, Netzwerk "
                    "und Zertifikate für das eigene System."
                ),
                available=self._tech_available,
                lock_hinweis=_TECH_LOCK_HINWEIS,
                on_start=self._handle_start_tech,
            )
        )

        # Sektion 2: Organisatorische Sicherheit
        root.addWidget(
            self._build_card(
                icon_name=Icons.PEOPLE,
                titel="Organisatorische Sicherheit",
                beschreibung=(
                    "Selbstbewertung zu DSGVO, Phishing-Schutz, MFA und "
                    "Passwort-Manager."
                ),
                available=self._org_available,
                lock_hinweis=_ORG_LOCK_HINWEIS,
                on_start=self._handle_start_org,
            )
        )

        # Schließen-Button
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_close = QPushButton("Schließen")
        btn_close.setStyleSheet(self._secondary_button_qss())
        btn_close.clicked.connect(self.reject)
        btn_row.addWidget(btn_close)
        root.addLayout(btn_row)

        self.setMinimumWidth(440)

    def _build_card(
        self,
        *,
        icon_name: str,
        titel: str,
        beschreibung: str,
        available: bool,
        lock_hinweis: str,
        on_start: Callable[[], None],
    ) -> QFrame:
        """Baut eine Sektions-Karte (verfügbar mit Start-Button ODER gesperrt).

        Args:
            icon_name: Material-Symbol-Name für das Karten-Icon.
            titel: Karten-Überschrift.
            beschreibung: Kurzbeschreibung der Sektion.
            available: True → Start-Button; False → Lock-Icon + Hinweis.
            lock_hinweis: Anzuzeigender Hinweis mit nächstem Schritt, wenn
                          die Sektion gesperrt ist.
            on_start: Callback für den Start-Button (nur wenn verfügbar).

        Returns:
            Die fertig aufgebaute Karte als QFrame.
        """
        c = theme.get()
        card = QFrame()
        card.setObjectName("SelbstbewertungCard")
        card.setStyleSheet(
            f"#SelbstbewertungCard {{ background: {c.BG_INPUT};"
            f" border: 1px solid {c.BORDER}; border-radius: 6px; }}"
        )
        layout = QHBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(12)

        # Leit-Icon links: bei gesperrter Sektion das Lock-Icon (gedämpft).
        icon_lbl = QLabel()
        leit_icon = icon_name if available else Icons.LOCK
        icon_color = c.ACCENT if available else c.TEXT_DIM
        icon_lbl.setPixmap(
            get_icon(leit_icon, color=icon_color).pixmap(
                QSize(ICON_SIZE_LG, ICON_SIZE_LG)
            )
        )
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(icon_lbl)

        text_box = QVBoxLayout()
        text_box.setSpacing(4)
        titel_lbl = QLabel(titel)
        titel_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px;"
            f" font-weight: 600; color: {c.TEXT_MAIN};"
        )
        text_box.addWidget(titel_lbl)

        # Verfügbar: Beschreibung. Gesperrt: Lock-Hinweis mit nächstem Schritt.
        body_lbl = QLabel(beschreibung if available else lock_hinweis)
        body_lbl.setWordWrap(True)
        body_color = c.TEXT_DIM if available else c.WARNING
        body_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" color: {body_color};"
        )
        text_box.addWidget(body_lbl)
        layout.addLayout(text_box, stretch=1)

        if available:
            btn_start = QPushButton("Starten")
            btn_start.setStyleSheet(self._primary_button_qss())
            btn_start.clicked.connect(on_start)
            layout.addWidget(btn_start, alignment=Qt.AlignmentFlag.AlignVCenter)

        return card

    # ------------------------------------------------------------------
    # Start-Handler — schließen den Dialog und delegieren an den Wizard
    # ------------------------------------------------------------------

    def _handle_start_tech(self) -> None:
        """Schließt den Dialog und startet den technischen Wizard."""
        self.accept()
        self._on_start_tech()

    def _handle_start_org(self) -> None:
        """Schließt den Dialog und startet den organisatorischen Wizard."""
        self.accept()
        self._on_start_org()

    # ------------------------------------------------------------------
    # Button-Styles (Theme-Tokens, keine Hex-Hardcodes)
    # ------------------------------------------------------------------

    @staticmethod
    def _primary_button_qss() -> str:
        """Primär-Button (Teal) mit allen vier States."""
        c = theme.get()
        return (
            f"QPushButton {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border: 1px solid {c.ACCENT}; border-radius: 6px;"
            f" padding: 6px 16px; font-family: 'Raleway'; font-weight: 600;"
            f" font-size: {theme.FONT_SIZE_BODY_SM}px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT_DIM}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT_DIM}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT_DARK}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT_DARK}; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER_BUTTON_DISABLED}; }}"
        )

    @staticmethod
    def _secondary_button_qss() -> str:
        """Sekundär-Button (gedämpft) mit allen vier States."""
        c = theme.get()
        return (
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 6px;"
            f" padding: 6px 16px; font-family: 'Raleway'; font-weight: 600;"
            f" font-size: {theme.FONT_SIZE_BODY_SM}px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_MAIN};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT_DARK}; color: {c.BG_MAIN};"
            f" border-color: {c.ACCENT_DARK}; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER_BUTTON_DISABLED}; }}"
        )


__all__ = ["SelbstbewertungDialog"]
