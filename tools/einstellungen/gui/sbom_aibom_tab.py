"""einstellungen.gui.sbom_aibom_tab — Settings-Tab fuer SBOM und AI-BOM.

Zwei Compliance-Artefakte zum Export:

* **SBOM** (Software Bill of Materials) im CycloneDX-1.5-JSON-Format —
  Treiber: EU Cyber Resilience Act, NIS2-Lieferkette.
* **AI-BOM** (AI Bill of Materials) als strukturiertes JSON mit den
  tatsaechlich genutzten KI-Komponenten (lokale Ollama-Modelle + aktiv
  konfigurierte Cloud-Dienste) — Treiber: EU AI Act.

Schicht: ``gui/`` — keine Business-Logik. SBOM-/AI-BOM-Erzeugung liegt in
:mod:`core.sbom_aibom`..
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiInfoDialog
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.sbom_aibom import AiBomService, SbomService

log = get_logger(__name__)


class SbomAiBomTab(QWidget):
    """Settings-Tab: SBOM und AI-BOM erzeugen und als JSON exportieren."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._sbom_service = SbomService()
        self._ai_bom_service = AiBomService()
        self._build_ui()

    # -- UI ------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        header = QLabel("SBOM / AI-BOM — Compliance-Stuecklisten")
        header.setStyleSheet(
            "font-family: 'Raleway'; font-size: 14px; font-weight: bold;"
        )
        layout.addWidget(header)

        intro = QLabel(
            "Erzeuge zwei maschinenlesbare Stuecklisten zur Vorlage bei "
            "Audits und Behoerden:\n"
            "• SBOM (Software Bill of Materials) — alle in NoRisk installierten "
            "Software-Komponenten im CycloneDX-1.5-Format (EU Cyber Resilience "
            "Act, NIS2, BSI).\n"
            "• AI-BOM (AI Bill of Materials) — alle aktiv genutzten KI-"
            "Komponenten mit Datenfluss-Hinweis lokal/Cloud (EU AI Act)."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("font-family: 'Raleway'; font-size: 13px;")
        layout.addWidget(intro)

        layout.addWidget(self._build_separator())
        layout.addWidget(self._build_sbom_section())

        layout.addWidget(self._build_separator())
        layout.addWidget(self._build_ai_bom_section())

        layout.addStretch()

    def _build_separator(self) -> QFrame:
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {theme.get().BORDER};")
        return sep

    def _build_sbom_section(self) -> QWidget:
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        title = QLabel("SBOM — Software-Stueckliste (CycloneDX 1.5)")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {theme.get().ACCENT};"
        )
        layout.addWidget(title)

        desc = QLabel(
            "Erstellt eine vollstaendige Stueckliste der installierten "
            "Python-Dependencies im CycloneDX-1.5-JSON-Format mit purl, "
            "Version und Lizenz."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("font-family: 'Raleway'; font-size: 12px;")
        layout.addWidget(desc)

        button_row = QHBoxLayout()
        self._sbom_button = QPushButton("SBOM erzeugen und exportieren …")
        self._sbom_button.setIcon(get_icon(Icons.SAVE))
        self._sbom_button.clicked.connect(self._on_export_sbom_clicked)
        button_row.addWidget(self._sbom_button)
        button_row.addStretch()
        layout.addLayout(button_row)

        self._sbom_status = QLabel("")
        self._sbom_status.setWordWrap(True)
        self._sbom_status.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {theme.get().TEXT_DIM};"
        )
        layout.addWidget(self._sbom_status)
        return section

    def _build_ai_bom_section(self) -> QWidget:
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        title = QLabel("AI-BOM — KI-Stueckliste (EU AI Act)")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {theme.get().ACCENT};"
        )
        layout.addWidget(title)

        desc = QLabel(
            "Erstellt eine Uebersicht aller eingesetzten KI-Komponenten: "
            "installierte Ollama-Modelle (lokal) inklusive Zweck und "
            "Datenflussrichtung. NoRisk ist seit T-244r zu 100% lokal — "
            "die AI-BOM listet keine Cloud-Dienste mehr."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("font-family: 'Raleway'; font-size: 12px;")
        layout.addWidget(desc)

        button_row = QHBoxLayout()
        self._ai_bom_button = QPushButton("AI-BOM erzeugen und exportieren …")
        self._ai_bom_button.setIcon(get_icon(Icons.SAVE))
        self._ai_bom_button.clicked.connect(self._on_export_ai_bom_clicked)
        button_row.addWidget(self._ai_bom_button)
        button_row.addStretch()
        layout.addLayout(button_row)

        self._ai_bom_status = QLabel("")
        self._ai_bom_status.setWordWrap(True)
        self._ai_bom_status.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {theme.get().TEXT_DIM};"
        )
        layout.addWidget(self._ai_bom_status)
        return section

    # -- Slots ---------------------------------------------------------

    @Slot()
    def _on_export_sbom_clicked(self) -> None:
        """Erzeugt die SBOM und laesst den Nutzer eine Zieldatei waehlen."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"norisk_sbom_{timestamp}.cdx.json"
        target = self._ask_save_path(
            title="SBOM exportieren",
            default_name=default_name,
            file_filter="CycloneDX JSON (*.cdx.json *.json)",
        )
        if target is None:
            return
        try:
            bom = self._sbom_service.generate()
            written = self._sbom_service.export_json(bom, target)
        except Exception as exc:  # noqa: BLE001 — defensiv: Fehler dem Nutzer zeigen.
            log.exception("SBOM-Export fehlgeschlagen: %s", type(exc).__name__)
            self._sbom_status.setText(f"Fehler beim Export: {type(exc).__name__}")
            FinlaiInfoDialog(
                title="SBOM-Export fehlgeschlagen",
                message=(
                    "Die SBOM konnte nicht erzeugt oder geschrieben werden. "
                    "Details siehe Anwendungs-Log."
                ),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        components = bom.get("components", [])
        count = len(components) if isinstance(components, list) else 0
        self._sbom_status.setText(
            f"SBOM mit {count} Komponenten gespeichert: {written}"
        )
        FinlaiInfoDialog(
            title="SBOM exportiert",
            message=(
                f"Die SBOM enthaelt {count} Komponenten und wurde gespeichert "
                f"unter:\n{written}"
            ),
            icon_name=Icons.CHECK_CIRCLE,
            parent=self,
        ).exec()

    @Slot()
    def _on_export_ai_bom_clicked(self) -> None:
        """Erzeugt die AI-BOM und laesst den Nutzer eine Zieldatei waehlen."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"norisk_ai_bom_{timestamp}.json"
        target = self._ask_save_path(
            title="AI-BOM exportieren",
            default_name=default_name,
            file_filter="JSON-Dateien (*.json)",
        )
        if target is None:
            return
        try:
            document = self._ai_bom_service.generate()
            written = self._ai_bom_service.export_json(document, target)
        except Exception as exc:  # noqa: BLE001
            log.exception("AI-BOM-Export fehlgeschlagen: %s", type(exc).__name__)
            self._ai_bom_status.setText(f"Fehler beim Export: {type(exc).__name__}")
            FinlaiInfoDialog(
                title="AI-BOM-Export fehlgeschlagen",
                message=(
                    "Die AI-BOM konnte nicht erzeugt oder geschrieben werden. "
                    "Details siehe Anwendungs-Log."
                ),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        components = document.get("components", [])
        count = len(components) if isinstance(components, list) else 0
        local = sum(
            1
            for c in components
            if isinstance(c, dict) and c.get("location") == "local"
        ) if isinstance(components, list) else 0
        cloud = count - local
        self._ai_bom_status.setText(
            f"AI-BOM mit {local} lokalen Modellen und {cloud} Cloud-Diensten "
            f"gespeichert: {written}"
        )
        FinlaiInfoDialog(
            title="AI-BOM exportiert",
            message=(
                f"Die AI-BOM enthaelt {local} lokale Modelle und {cloud} "
                f"Cloud-Dienste und wurde gespeichert unter:\n{written}"
            ),
            icon_name=Icons.CHECK_CIRCLE,
            parent=self,
        ).exec()

    # -- Helpers -------------------------------------------------------

    def _ask_save_path(
        self,
        *,
        title: str,
        default_name: str,
        file_filter: str,
    ) -> Path | None:
        """Oeffnet einen Speicher-unter-Dialog und gibt den gewaehlten Pfad zurueck.

        Args:
            title: Dialog-Titel.
            default_name: Vorgeschlagener Dateiname.
            file_filter: Qt-File-Filter (z. B. ``"JSON (*.json)"``).

        Returns:
            Pfad-Objekt oder ``None`` falls Nutzer abbricht.
        """
        default_dir = Path.home() / "Documents"
        if not default_dir.exists():
            default_dir = Path.home()
        suggested = str(default_dir / default_name)
        chosen, _ = QFileDialog.getSaveFileName(
            self,
            title,
            suggested,
            file_filter,
        )
        if not chosen:
            return None
        return Path(chosen)
