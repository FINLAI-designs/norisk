"""
provider_dialogs — CSAF Provider-Verwaltungsdialoge.

Sprint 6 Phase 1: Aus csaf_advisor_widget.py extrahiert.
Enthaelt zwei zusammengehoerige Dialoge:

* ProviderSettingsDialog -- Liste aller Provider, Toggle aktiv/inaktiv,
  Loeschen user-definierter Provider.
* AddProviderDialog -- Eingabe-Form fuer neue user-definierte Provider.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import uuid

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import Icons, get_icon
from tools.csaf_advisor.application.advisory_service import AdvisoryService
from tools.csaf_advisor.domain.csaf_provider import CsafProvider


class ProviderSettingsDialog(QDialog):
    """Dialog zum Verwalten der CSAF Provider.

    Zeigt alle Provider mit Toggle (aktiv/inaktiv) und erlaubt das
    Hinzufügen eigener Provider. Kuratierte Provider können nicht gelöscht werden.

    Attributes:
        _service: AdvisoryService für Provider-Operationen.
    """

    def __init__(self, service: AdvisoryService, parent: QWidget | None = None) -> None:
        """Initialisiert den Dialog.

        Args:
            service: AdvisoryService-Instanz.
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._service = service
        self.setWindowTitle("CSAF Provider verwalten")
        self.setMinimumSize(600, 450)
        self._build_ui()
        self._load_providers()

    def _build_ui(self) -> None:
        """Erstellt die UI-Elemente des Dialogs."""
        t = theme.get()
        self.setStyleSheet(f"background-color: {t.BG_MAIN}; color: {t.TEXT_MAIN};")

        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(16, 12, 16, 12)

        title = QLabel("CSAF Trusted Provider")
        title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {t.ACCENT};")
        root.addWidget(title)

        info = QLabel(
            "Kuratierte Provider (vordefiniert) können nur aktiviert/deaktiviert werden.\n"
            "Eigene Provider können hinzugefügt und gelöscht werden."
        )
        info.setStyleSheet(f"color: {t.TEXT_DIM}; font-size: 12px;")
        info.setWordWrap(True)
        root.addWidget(info)

        # Provider-Liste
        self._list = QListWidget()
        self._list.setStyleSheet(
            f"""
            QListWidget {{
                background-color: {t.CARD_BG};
                color: {t.TEXT_MAIN};
                border: 1px solid {t.BORDER};
                border-radius: 4px;
            }}
            QListWidget::item {{
                padding: 6px 8px;
            }}
            QListWidget::item:selected {{
                background-color: {t.ACCENT};
                color: {t.BG_MAIN};
            }}
            """
        )
        root.addWidget(self._list)

        # Aktionsleiste
        btn_row = QHBoxLayout()

        btn_add = QPushButton("Provider hinzufügen")
        btn_add.setIcon(get_icon(Icons.ADD))
        btn_add.clicked.connect(self._on_add_provider)
        btn_add.setStyleSheet(self._btn_style(accent=True))
        btn_row.addWidget(btn_add)

        self._btn_delete = QPushButton("Ausgewählt löschen")
        self._btn_delete.setIcon(get_icon(Icons.DELETE))
        self._btn_delete.clicked.connect(self._on_delete_selected)
        self._btn_delete.setStyleSheet(self._btn_style())
        self._btn_delete.setEnabled(False)
        btn_row.addWidget(self._btn_delete)

        btn_row.addStretch()
        root.addLayout(btn_row)

        # Schließen-Button
        close_row = QHBoxLayout()
        close_row.addStretch()
        btn_close = QPushButton("Schließen")
        btn_close.setStyleSheet(self._btn_style(accent=True))
        btn_close.clicked.connect(self.accept)
        close_row.addWidget(btn_close)
        root.addLayout(close_row)

        self._list.currentRowChanged.connect(self._on_selection_changed)

    def _load_providers(self) -> None:
        """Lädt und zeigt alle Provider."""
        self._list.clear()
        providers = self._service.list_providers()
        for provider in providers:
            # FE-1 (Code-Review 2026-05-19): vorher Unicode-Glyphs '✓/✗'
            # am Label-Ende. Jetzt Material-Icon links vom Text — Standard-
            # Pattern fuer QListWidgetItem-Status-Indikatoren.
            label = (
                f"{'[Kuratiert] ' if provider.is_curated else '[Eigener] '}"
                f"{provider.name}"
            )
            item = QListWidgetItem(label)
            item.setIcon(
                get_icon(Icons.CHECK_CIRCLE if provider.enabled else Icons.BLOCK)
            )
            item.setData(Qt.ItemDataRole.UserRole, provider.id)
            if provider.enabled:
                item.setForeground(QColor(theme.get().TEXT_MAIN))
            else:
                item.setForeground(QColor(theme.get().TEXT_DIM))
            self._list.addItem(item)

        # Toggle-Checkboxen direkt in die Items integrieren
        # (für Einfachheit: Doppelklick zum Togglen)
        self._list.itemDoubleClicked.connect(self._on_toggle_provider)

    @Slot(object)
    def _on_toggle_provider(self, item: QListWidgetItem) -> None:
        """Aktiviert/deaktiviert einen Provider per Doppelklick.

        Args:
            item: Geklicktes Listen-Item.
        """
        provider_id = item.data(Qt.ItemDataRole.UserRole)
        provider = self._service._repo.get_provider(provider_id)  # noqa: SLF001
        if provider is None:
            return
        self._service.toggle_provider(provider_id, not provider.enabled)
        self._load_providers()

    @Slot(int)
    def _on_selection_changed(self, row: int) -> None:
        """Aktiviert den Löschen-Button nur für user-definierte Provider.

        Args:
            row: Ausgewählte Zeile (oder -1).
        """
        if row < 0:
            self._btn_delete.setEnabled(False)
            return
        item = self._list.item(row)
        if item is None:
            self._btn_delete.setEnabled(False)
            return
        provider_id = item.data(Qt.ItemDataRole.UserRole)
        provider = self._service._repo.get_provider(provider_id)  # noqa: SLF001
        self._btn_delete.setEnabled(provider is not None and not provider.is_curated)

    @Slot()
    def _on_add_provider(self) -> None:
        """Öffnet einen Dialog zum Hinzufügen eines neuen Providers."""
        dialog = AddProviderDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        name, provider_url, feed_url = dialog.get_values()
        if not name or not provider_url:
            return
        provider = CsafProvider(
            id=f"user-{uuid.uuid4().hex[:8]}",
            name=name,
            provider_url=provider_url,
            feed_url=feed_url,
            source="user",
            enabled=True,
        )
        self._service.add_provider(provider)
        self._load_providers()

    @Slot()
    def _on_delete_selected(self) -> None:
        """Löscht den ausgewählten user-definierten Provider."""
        item = self._list.currentItem()
        if item is None:
            return
        provider_id = item.data(Qt.ItemDataRole.UserRole)
        self._service.delete_provider(provider_id)
        self._load_providers()

    @staticmethod
    def _btn_style(accent: bool = False) -> str:
        t = theme.get()
        bg = t.ACCENT if accent else t.BG_BUTTON
        text = t.BG_MAIN if accent else t.TEXT_MAIN
        return (
            f"QPushButton {{ background-color: {bg}; color: {text};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px;"
            f" padding: 5px 12px; font-size: 12px; }}"
            f"QPushButton:hover {{ background-color: {t.ACCENT}; color: {t.BG_MAIN}; }}"
        )


class AddProviderDialog(QDialog):
    """Dialog zum Hinzufügen eines neuen CSAF Providers.

    Attributes:
        _edit_name: Eingabefeld für den Anzeigenamen.
        _edit_provider_url: Eingabefeld für die provider-metadata.json URL.
        _edit_feed_url: Eingabefeld für die optionale Feed-URL.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert den Dialog."""
        super().__init__(parent)
        self.setWindowTitle("Neuen CSAF Provider hinzufügen")
        self.setMinimumWidth(500)
        t = theme.get()
        self.setStyleSheet(f"background-color: {t.BG_MAIN}; color: {t.TEXT_MAIN};")

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._edit_name = QLineEdit()
        self._edit_name.setPlaceholderText("z. B. Cisco PSIRT")
        form.addRow("Name:", self._edit_name)

        self._edit_provider_url = QLineEdit()
        self._edit_provider_url.setPlaceholderText(
            "https://example.com/.well-known/csaf/provider-metadata.json"
        )
        form.addRow("Provider-Metadata-URL:", self._edit_provider_url)

        self._edit_feed_url = QLineEdit()
        self._edit_feed_url.setPlaceholderText("Optional — ROLIE-Feed oder index.txt")
        form.addRow("Feed-URL (optional):", self._edit_feed_url)

        layout.addLayout(form)

        # Buttons
        t = theme.get()
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

        btn_ok = QPushButton("Hinzufügen")
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

    def get_values(self) -> tuple[str, str, str]:
        """Gibt die eingegebenen Werte zurück.

        Returns:
            Tuple aus (name, provider_url, feed_url).
        """
        return (
            self._edit_name.text().strip(),
            self._edit_provider_url.text().strip(),
            self._edit_feed_url.text().strip(),
        )
