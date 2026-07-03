"""kunden_hardening_dialog — Manuelle Hardening-Erfassung für einen Kunden E2).

Eine Kundenmaschine ist nicht fern-messbar; der Berater trägt die Hardening-
Fakten hier manuell ein (Tri-State Ja/Nein/Unbekannt pro Fakt). Das Ergebnis
wird mit Provenance ``erfasst`` (nie „gemessen") gespeichert.

Schichtzugehörigkeit: gui/ — keine Business-Logik; liefert nur das Fakten-Dict
zurück, das das Dashboard an ``ScoringService.erfasse_kunden_hardening`` reicht.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme

# Tri-State-Anzeige <-> Wert. None = nicht beantwortet (fällt aus dem Score-Nenner).
_OPTIONEN: tuple[tuple[str, bool | None], ...] = (
    ("Unbekannt", None),
    ("Ja", True),
    ("Nein", False),
)
_WERT_ZU_INDEX = {wert: i for i, (_, wert) in enumerate(_OPTIONEN)}


class KundenHardeningDialog(QDialog):
    """Dialog zur manuellen Erfassung der Hardening-Fakten eines Kunden.

    Attributes:
        _facts_def: Sequenz von ``(key, label)`` der erfassbaren Fakten.
        _combos: Mapping ``key -> QComboBox`` (Tri-State).
    """

    def __init__(
        self,
        facts_def: Sequence[tuple[str, str]],
        *,
        current: dict[str, bool | None] | None = None,
        kunde_name: str = "",
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert den Erfassungs-Dialog.

        Args:
            facts_def: ``(key, label)``-Paare in Anzeige-Reihenfolge.
            current: Optionale Vorbelegung ``key -> True/False/None``.
            kunde_name: Anzeigename des Kunden (nur Titel/Intro, kein PII-Log).
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._facts_def = list(facts_def)
        self._current = current or {}
        self._kunde_name = kunde_name
        self._combos: dict[str, QComboBox] = {}
        self.setModal(True)
        self.setWindowTitle("Hardening erfassen")
        self._build_ui()

    def _build_ui(self) -> None:
        """Baut Header, das Fakten-Formular und die Aktionsbuttons."""
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 8px; }}"
        )
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        titel = QLabel("Hardening-Fakten erfassen")
        titel.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_H3}px;"
            f" font-weight: 700; color: {c.TEXT_MAIN};"
        )
        root.addWidget(titel)

        intro_text = (
            "Tragen Sie die Härtungsmaßnahmen des Kundensystems ein. Diese "
            "Werte werden als 'erfasst' gespeichert — nicht als gemessen "
            "(eine Kundenmaschine ist nicht fern-messbar)."
        )
        intro = QLabel(intro_text)
        intro.setWordWrap(True)
        intro.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px;"
            f" color: {c.TEXT_DIM};"
        )
        root.addWidget(intro)

        form = QFormLayout()
        form.setSpacing(8)
        for key, label in self._facts_def:
            combo = QComboBox()
            for anzeige, _ in _OPTIONEN:
                combo.addItem(anzeige)
            combo.setCurrentIndex(_WERT_ZU_INDEX.get(self._current.get(key), 0))
            combo.setStyleSheet(self._combo_qss())
            self._combos[key] = combo
            lbl = QLabel(label)
            lbl.setStyleSheet(
                f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px;"
                f" color: {c.TEXT_MAIN};"
            )
            form.addRow(lbl, combo)
        root.addLayout(form)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_cancel = QPushButton("Abbrechen")
        btn_cancel.setStyleSheet(self._secondary_button_qss())
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_save = QPushButton("Speichern")
        btn_save.setStyleSheet(self._primary_button_qss())
        btn_save.clicked.connect(self.accept)
        btn_row.addWidget(btn_save)
        root.addLayout(btn_row)

        self.setMinimumWidth(460)

    def get_facts(self) -> dict[str, bool | None]:
        """Liefert die erfassten Fakten als ``key -> True/False/None``."""
        return {
            key: _OPTIONEN[combo.currentIndex()][1]
            for key, combo in self._combos.items()
        }

    # ------------------------------------------------------------------
    # Styles (Theme-Tokens)
    # ------------------------------------------------------------------

    @staticmethod
    def _combo_qss() -> str:
        c = theme.get()
        return (
            f"QComboBox {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px 8px;"
            f" min-width: 140px; font-size: {theme.FONT_SIZE_BODY_SM}px; }}"
        )

    @staticmethod
    def _primary_button_qss() -> str:
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
        )

    @staticmethod
    def _secondary_button_qss() -> str:
        c = theme.get()
        return (
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 6px;"
            f" padding: 6px 16px; font-family: 'Raleway'; font-weight: 600;"
            f" font-size: {theme.FONT_SIZE_BODY_SM}px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_MAIN};"
            f" border-color: {c.ACCENT}; }}"
        )


__all__ = ["KundenHardeningDialog"]
