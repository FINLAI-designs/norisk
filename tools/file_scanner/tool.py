"""tool — FileScannerTool Plugin-Definition Phase 3b).

Registriert den verschmolzenen Datei-Scanner (E-Mail / PDF / Office) als
EINEN Eintrag in der NoRisk-ToolRegistry. Löst die drei zuvor getrennten
Sidebar-Einträge ``email_scanner`` / ``pdf_risk_scanner`` /
``document_scanner`` ab (Refactoring-Plan §4/§8).

Dieses Modul ist der Composition-Root des Containers: Die Tab-Factories
delegieren an die bereits vorhandenen ``create_widget`` der drei Sub-Tools
(DRY — identische Service-/Repository-Verdrahtung), sodass die GUI-Schicht
keine ``data``-Module importieren muss (Hexagonal-Contract gui↛data).

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from PySide6.QtWidgets import QWidget

from core.base_tool import BaseTool


def _make_email(parent: QWidget | None) -> QWidget:
    """Baut das E-Mail-Anhang-Scanner-Widget via bestehende Komposition."""
    from tools.email_scanner.tool import EmailScannerTool  # noqa: PLC0415

    return EmailScannerTool().create_widget(parent)


def _make_pdf(parent: QWidget | None) -> QWidget:
    """Baut das PDF-Risiko-Scanner-Widget via bestehende Komposition."""
    from tools.pdf_risk_scanner.tool import PdfRiskScannerTool  # noqa: PLC0415

    return PdfRiskScannerTool().create_widget(parent)


def _make_office(parent: QWidget | None) -> QWidget:
    """Baut das Dokument-/Office-Scanner-Widget via bestehende Komposition."""
    from tools.document_scanner.tool import DocumentScannerTool  # noqa: PLC0415

    return DocumentScannerTool().create_widget(parent)


def _build_tab_specs() -> list:
    """Baut die Tab-Definitionen für das Container-Widget.

    Returns:
        Liste von ``(deeplink_key, license_feature, tool_name, tab_title,
        factory)``-Tupeln in Anzeige-Reihenfolge.
    """
    return [
        (
            "email",
            "email_attachment_scanner",
            "E-Mail-Anhang-Scanner",
            "E-Mail-Anhang",
            _make_email,
        ),
        ("pdf", "pdf_risk_scanner", "PDF-Risiko-Scanner", "PDF", _make_pdf),
        (
            "office",
            "document_scanner",
            "Dokument-Scanner",
            "Office / Dokument",
            _make_office,
        ),
    ]


class FileScannerTool(BaseTool):
    """Plugin-Definition für den verschmolzenen Datei-Scanner.

    Attributes:
        name (str): ``"Datei-Scanner"`` — muss zum ``_NAV_TOOL_MAP``-Eintrag
            passen (Routing über den Tool-Namen).
        icon (str): Material-Symbol ``"description"``.
        feature_name (str): Leer — der Container ist immer sichtbar; die
            einzelnen Sub-Tabs werden im Widget pro Lizenz-Feature
            (``email_attachment_scanner`` / ``pdf_risk_scanner`` /
            ``document_scanner``) freigeschaltet. So bleibt das bestehende
            Lizenzmodell unverändert (kein neues Feature, kein
            License-Server-Change).
    """

    name = "Datei-Scanner"
    icon = "description"
    feature_name = ""

    def create_widget(self, parent=None):
        """Baut das Container-Widget mit den drei Scanner-Sub-Tabs.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
            FileScannerWidget-Instanz.
        """
        from tools.file_scanner.gui.file_scanner_widget import (  # noqa: PLC0415
            FileScannerWidget,
        )

        widget = FileScannerWidget(tab_specs=_build_tab_specs(), parent=parent)
        widget.setMinimumSize(900, 600)
        return widget
