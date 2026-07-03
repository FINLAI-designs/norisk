"""
base_exporter — ABC für alle FINLAI Tool-Exporter.

Definiert das Drei-Format-Interface (JSON, XLSX, PDF) das jeder
Tool-Exporter implementieren muss.

Schichtzugehörigkeit: core/ — keine Tool-Imports, kein PySide6.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseExporter(ABC):
    """Basisklasse für alle FINLAI Tool-Exporter.

    Jeder Tool-Exporter muss die drei Exportmethoden implementieren.
    Die GUI-seitige Dialogsteuerung übernimmt:mod:`core.export.export_actions`.

    Beispiel::

        class MeinExporter(BaseExporter):
            @property
            def default_filename_stem(self) -> str:
                return "mein_tool_export"

            def export_json(self, data, path: str) -> bool:
...

            def export_xlsx(self, data, path: str) -> bool:
...

            def export_pdf(self, data, path: str, title: str = "", subtitle: str = "") -> bool:
...
    """

    @property
    @abstractmethod
    def default_filename_stem(self) -> str:
        """Dateiname ohne Erweiterung für den Speichern-Dialog.

        Returns:
            Basis-Dateiname (z.B. "system_scan_export").
        """

    @abstractmethod
    def export_json(self, data: object, path: str) -> bool:
        """Exportiert data als JSON-Datei.

        Args:
            data: Tool-spezifisches Datenobjekt.
            path: Zieldateipfad.

        Returns:
            True bei Erfolg, False bei Fehler.
        """

    @abstractmethod
    def export_xlsx(self, data: object, path: str) -> bool:
        """Exportiert data als Excel-Datei (.xlsx).

        Args:
            data: Tool-spezifisches Datenobjekt.
            path: Zieldateipfad.

        Returns:
            True bei Erfolg, False bei Fehler.
        """

    @abstractmethod
    def export_pdf(
        self,
        data: object,
        path: str,
        title: str = "",
        subtitle: str = "",
    ) -> bool:
        """Exportiert data als Dark-Theme PDF-Report.

        Args:
            data: Tool-spezifisches Datenobjekt.
            path: Zieldateipfad.
            title: Optionaler Report-Titel (überschreibt Default).
            subtitle: Optionaler Report-Untertitel.

        Returns:
            True bei Erfolg, False bei Fehler.
        """
