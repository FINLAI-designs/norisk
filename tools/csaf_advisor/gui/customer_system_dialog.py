"""
customer_system_dialog — Dialog zum Anlegen eines neuen Kundensystems.

Sprint 6 Phase 1: Aus csaf_advisor_widget.py extrahiert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme


class AddCustomerSystemDialog(QDialog):
    """Dialog zum Anlegen eines neuen Kundensystems.

    Attributes:
        _edit_name: Eingabefeld für den Systemnamen.
        _edit_description: Eingabefeld für eine optionale Beschreibung.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert den Dialog."""
        super().__init__(parent)
        self.setWindowTitle("Neues Kundensystem anlegen")
        self.setMinimumWidth(420)
        t = theme.get()
        self.setStyleSheet(f"background-color: {t.BG_MAIN}; color: {t.TEXT_MAIN};")

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._edit_name = QLineEdit()
        self._edit_name.setPlaceholderText("z. B. Kunde Müller GmbH")
        form.addRow("Name:", self._edit_name)

        self._edit_description = QLineEdit()
        self._edit_description.setPlaceholderText("Optional — z. B. Produktionsnetz")
        form.addRow("Beschreibung:", self._edit_description)

        layout.addLayout(form)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        btn_cancel = QPushButton("Abbrechen")
        btn_cancel.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {t.TEXT_DIM};"
            f" border: 1px solid {t.BORDER}; border-radius: 6px;"
            f" padding: 6px 16px; font-family: 'Raleway'; font-weight: 600; }}"
            f"QPushButton:hover {{ background: {t.CARD_BG}; color: {t.TEXT_MAIN}; }}"
        )
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)

        btn_ok = QPushButton("Anlegen")
        btn_ok.setDefault(True)
        btn_ok.setStyleSheet(
            f"QPushButton {{ background: {t.ACCENT}; color: {t.BG_DARK}; border: none;"
            f" border-radius: 6px; padding: 6px 16px;"
            f" font-family: 'Raleway'; font-weight: 600; }}"
            f"QPushButton:hover {{ background: {t.ACCENT_DIM}; color: {t.BG_DARK}; }}"
        )
        btn_ok.clicked.connect(self.accept)
        btn_row.addWidget(btn_ok)

        layout.addLayout(btn_row)

    def get_values(self) -> tuple[str, str]:
        """Gibt die eingegebenen Werte zurück.

        Returns:
            Tuple aus (name, description).
        """
        return (
            self._edit_name.text().strip(),
            self._edit_description.text().strip(),
        )
