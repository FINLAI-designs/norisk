"""
techstack_import_dialog — Vorschau-/Kuratierungs-Dialog für den Tech-Stack-Sync.

Zeigt die beim Sync aus System-Scan + Patch-Monitor erkannten
Produkte als Liste mit Checkboxen (vorausgewählt). Der User wählt ab, was
nicht übernommen werden soll; nur die angehakten Einträge gibt
:meth:`TechStackImportDialog.ausgewaehlte_eintraege` zurück.

FINLAI-konform (dialog-skill, Typ D): frameless modal, CARD_BG-Chrome,
Theme-Farben, Material-Symbol-Header, Raleway/JetBrains-Mono-Fonts.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import ICON_SIZE_DIALOG, Icons, get_icon
from tools.cyber_dashboard.domain.models import TechStackEintrag, TechStackKandidat


class TechStackImportDialog(QDialog):
    """Kuratierungs-Dialog für vom Sync vorgeschlagene Tech-Stack-Einträge.

    Args:
        kandidaten: Erkannte Übernahme-Vorschläge (jeweils Eintrag + Quellen).
        parent: Eltern-Widget.
    """

    def __init__(
        self,
        kandidaten: list[TechStackKandidat],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._kandidaten = kandidaten
        self._checkboxen: list[tuple[QCheckBox, TechStackKandidat]] = []
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setModal(True)
        self._build_ui()

    def _build_ui(self) -> None:
        """Erstellt das Dialog-Layout."""
        c = theme.get()
        self.setStyleSheet(self._dialog_qss(c))

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        # Header: Sync-Icon + Titel
        header = QHBoxLayout()
        header.setSpacing(10)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(
            get_icon(Icons.SYNC, color=c.ACCENT).pixmap(
                ICON_SIZE_DIALOG, ICON_SIZE_DIALOG
            )
        )
        header.addWidget(icon_lbl)
        title_lbl = QLabel("Tech-Stack-Einträge übernehmen")
        title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 16px; font-weight: 700;"
            f" color: {c.TEXT_MAIN};"
        )
        header.addWidget(title_lbl)
        header.addStretch()
        root.addLayout(header)

        # Untertitel
        sub_lbl = QLabel(
            f"{len(self._kandidaten)} neue Produkte aus System-Scan & "
            f"Patch-Monitor erkannt. Wähle aus, was in deinen Tech-Stack "
            f"übernommen werden soll."
        )
        sub_lbl.setWordWrap(True)
        sub_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {c.TEXT_DIM};"
        )
        root.addWidget(sub_lbl)

        # "Alle auswählen"-Schalter
        self._alle_cb = QCheckBox("Alle auswählen")
        self._alle_cb.setChecked(True)
        self._alle_cb.toggled.connect(self._alle_umschalten)
        root.addWidget(self._alle_cb)

        # Scrollbare Kandidaten-Liste
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        liste = QWidget()
        liste_layout = QVBoxLayout(liste)
        liste_layout.setContentsMargins(0, 0, 0, 0)
        liste_layout.setSpacing(2)

        for kandidat in self._kandidaten:
            liste_layout.addWidget(self._kandidat_zeile(c, kandidat))
        liste_layout.addStretch()

        scroll.setWidget(liste)
        root.addWidget(scroll, stretch=1)

        # Button-Leiste: Abbrechen (sekundär) | Übernehmen (primär)
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        btn_cancel = QPushButton("Abbrechen")
        btn_cancel.setStyleSheet(self._secondary_style(c))
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)

        btn_ok = QPushButton("Übernehmen")
        btn_ok.setDefault(True)
        btn_ok.setStyleSheet(self._primary_style(c))
        btn_ok.clicked.connect(self.accept)
        btn_row.addWidget(btn_ok)

        root.addLayout(btn_row)
        self.setMinimumSize(520, 440)

    def _kandidat_zeile(self, c: object, kandidat: TechStackKandidat) -> QWidget:
        """Baut eine Zeile: Checkbox + Name/Version/Quelle (+ CPE als Subzeile)."""
        eintrag = kandidat.eintrag
        zeile = QWidget()
        layout = QHBoxLayout(zeile)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(10)

        cb = QCheckBox()
        cb.setChecked(True)
        cb.toggled.connect(self._einzel_umschalten)
        layout.addWidget(cb, alignment=Qt.AlignmentFlag.AlignTop)
        self._checkboxen.append((cb, kandidat))

        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(1)

        # Produktnamen/Versionen stammen aus den Scan-/Inventar-DBs (Registry-
        # DisplayName, winget, Paketmanager) — untrusted. RichText-QLabel würde
        # Markup interpretieren, daher html.escape-Lehre). Quellen sind
        # Konstanten, werden der Vollständigkeit halber mit-escaped.
        name_esc = html.escape(eintrag.name)
        version = f"  {html.escape(eintrag.version)}" if eintrag.version else ""
        quellen = (
            "  ·  " + html.escape(", ".join(kandidat.quellen))
            if kandidat.quellen
            else ""
        )
        kopf = QLabel(f"<b>{name_esc}</b>{version}{quellen}")
        kopf.setTextFormat(Qt.TextFormat.RichText)
        kopf.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {c.TEXT_MAIN};"  # type: ignore[attr-defined]
        )
        text_layout.addWidget(kopf)

        if eintrag.cpe:
            cpe_lbl = QLabel(eintrag.cpe)
            cpe_lbl.setStyleSheet(
                f"font-family: 'JetBrains Mono'; font-size: 11px;"
                f" color: {c.TEXT_DIM};"  # type: ignore[attr-defined]
            )
            cpe_lbl.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            text_layout.addWidget(cpe_lbl)

        layout.addLayout(text_layout, stretch=1)
        return zeile

    def _alle_umschalten(self, checked: bool) -> None:
        """Setzt alle Einzel-Checkboxen auf den Zustand des Sammel-Schalters."""
        for cb, _ in self._checkboxen:
            cb.blockSignals(True)
            cb.setChecked(checked)
            cb.blockSignals(False)

    def _einzel_umschalten(self, _checked: bool) -> None:
        """Synchronisiert den Sammel-Schalter mit den Einzel-Checkboxen."""
        alle = all(cb.isChecked() for cb, _ in self._checkboxen)
        self._alle_cb.blockSignals(True)
        self._alle_cb.setChecked(alle)
        self._alle_cb.blockSignals(False)

    def ausgewaehlte_eintraege(self) -> list[TechStackEintrag]:
        """Gibt die Einträge der angehakten Kandidaten zurück.

        Returns:
            Ausgewählte:class:`TechStackEintrag`, leer wenn nichts gewählt.
        """
        return [
            kandidat.eintrag
            for cb, kandidat in self._checkboxen
            if cb.isChecked()
        ]

    # ------------------------------------------------------------------
    # Styling
    # ------------------------------------------------------------------

    @staticmethod
    def _dialog_qss(c: object) -> str:
        """Dialog-Chrome + Checkbox-Styling (dialog-skill Regel 6)."""
        return (
            f"QDialog {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"  # type: ignore[attr-defined]
            f" border-radius: 8px; }}"
            f"QCheckBox {{ color: {c.TEXT_MAIN}; font-family: 'Raleway';"  # type: ignore[attr-defined]
            f" font-size: 12px; spacing: 8px; }}"
            f"QCheckBox::indicator {{ width: 18px; height: 18px;"
            f" border: 2px solid {c.BORDER}; border-radius: 3px;"  # type: ignore[attr-defined]
            f" background: transparent; }}"
            f"QCheckBox::indicator:checked {{ background: {c.ACCENT};"  # type: ignore[attr-defined]
            f" border-color: {c.ACCENT}; }}"  # type: ignore[attr-defined]
            f"QCheckBox::indicator:hover {{ border-color: {c.ACCENT}; }}"  # type: ignore[attr-defined]
        )

    @staticmethod
    def _primary_style(c: object) -> str:
        return (
            f"QPushButton {{ background: {c.ACCENT}; color: {c.BG_DARK};"  # type: ignore[attr-defined]
            f" border: none; border-radius: 6px; padding: 7px 18px;"
            f" font-family: 'Raleway'; font-weight: 600; font-size: 13px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT_DIM}; color: {c.BG_DARK}; }}"  # type: ignore[attr-defined]
            f"QPushButton:pressed {{ background: {c.ACCENT_DARK}; color: {c.BG_DARK}; }}"  # type: ignore[attr-defined]
        )

    @staticmethod
    def _secondary_style(c: object) -> str:
        return (
            f"QPushButton {{ background: transparent; color: {c.TEXT_DIM};"  # type: ignore[attr-defined]
            f" border: 1px solid {c.BORDER}; border-radius: 6px;"  # type: ignore[attr-defined]
            f" padding: 7px 18px; font-family: 'Raleway'; font-weight: 600;"
            f" font-size: 13px; }}"
            f"QPushButton:hover {{ background: {c.CARD_BG}; color: {c.TEXT_MAIN}; }}"  # type: ignore[attr-defined]
        )
