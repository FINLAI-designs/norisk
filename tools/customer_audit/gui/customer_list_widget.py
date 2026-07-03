"""
customer_list_widget — Übersicht gespeicherter Kunden-Audits.

Listet alle Audits, ermöglicht Öffnen, Löschen, JSON- und PDF-Export.

Schichtzugehörigkeit: gui/ — nur UI-Logik + Use-Case-Aufrufe.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog, FinlaiSuccessDialog
from core.escape import escape_html
from core.logger import get_logger
from tools.customer_audit.application.services import (
    CustomerAuditServices,
)

log = get_logger(__name__)

# noqa: domain-customer-risk-palette — eigene Risiko-Achse der Customer-Domäne
# (Niedrig=Neonblau, Mittel=Bernstein, Hoch=Lachs, Kritisch=Tiefrot). Bewusst
# NICHT in core/theme.py vereinheitlicht — zentrale Definition für das ganze Tool.
RISK_COLORS = {
    "Niedrig": "#00D4FF",  # noqa: domain-customer-risk-niedrig-neonblau
    "Mittel": "#F5A623",  # noqa: domain-customer-risk-mittel-bernstein
    "Hoch": "#E05C5C",  # noqa: domain-customer-risk-hoch-lachs
    "Kritisch": "#B91C1C",  # noqa: domain-customer-risk-kritisch-tiefrot
}
# Alter Name beibehalten (Backwards-Compat für bestehenden Code in dieser Datei)
_RISK_COLORS = RISK_COLORS


class CustomerListWidget(QWidget):
    """Übersichts-Widget für gespeicherte Kunden-Audits.

    Signals:
        open_requested: Emittiert mit audit_id wenn der User ein Audit öffnen möchte.

    Attributes:
        _load_use_case: LoadAuditUseCase-Instanz.
        _export_use_case: ExportAuditUseCase-Instanz.
        _report_use_case: GenerateReportUseCase-Instanz.
    """

    open_requested = Signal(str)  # audit_id

    def __init__(
        self,
        services: CustomerAuditServices,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Widget.

        Args:
            services: Use-Case-Buendel: GUI nutzt application-
                Services statt direkter Repository-Anbindung).
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._load_use_case = services.load
        self._export_use_case = services.export
        self._report_use_case = services.report
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        """Baut das Layout auf."""
        c = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        # --- Kopfzeile ---
        header = QWidget()
        header.setStyleSheet(
            f"background: {c.CARD_BG}; border-bottom: 1px solid {c.BORDER};"
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 10, 16, 10)

        lbl_title = QLabel("Gespeicherte Audits")
        lbl_title.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway;"
            " font-weight: 700; font-size: 14px; border: none;"
        )
        header_layout.addWidget(lbl_title)
        header_layout.addStretch()

        btn_refresh = QPushButton("Aktualisieren")
        btn_refresh.clicked.connect(self.refresh)
        btn_refresh.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {c.ACCENT};"
            f" border: 1px solid {c.ACCENT}; border-radius: 4px; padding: 6px 14px;"
            f" font-family: Raleway; font-weight: 600; font-size: 13px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}22; }}"
        )
        header_layout.addWidget(btn_refresh)
        root.addWidget(header)

        # --- Scroll-Liste ---
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self._scroll.setStyleSheet("background: transparent; border: none;")

        self._list_container = QWidget()
        self._list_layout = QVBoxLayout(self._list_container)
        self._list_layout.setContentsMargins(16, 8, 16, 8)
        self._list_layout.setSpacing(6)
        self._list_layout.addStretch()

        self._scroll.setWidget(self._list_container)
        root.addWidget(self._scroll)

    def refresh(self) -> None:
        """Lädt die Liste neu aus dem Repository."""
        # Alle vorhandenen Einträge entfernen
        while self._list_layout.count() > 1:
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        summaries = self._load_use_case.get_all_summaries(limit=100)

        if not summaries:
            c = theme.get()
            lbl_empty = QLabel("Noch keine Audits vorhanden.")
            lbl_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_empty.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 13px;")
            self._list_layout.insertWidget(0, lbl_empty)
            return

        # Ketten-Groesse je root_audit_id: bestimmt, ob eine Karte zusaetzlich
        # die "Ganze Historie loeschen"-Aktion (DSGVO Art. 17) anbietet (I). Fuer
        # Einzel-Audits (Kette = 1) genuegt der normale "Loeschen"-Button.
        from collections import Counter  # noqa: PLC0415

        chain_sizes = Counter(
            (s.get("root_audit_id") or s.get("audit_id")) for s in summaries
        )
        for i, summary in enumerate(summaries):
            root = summary.get("root_audit_id") or summary.get("audit_id")
            card = self._build_card(summary, chain_size=chain_sizes[root])
            self._list_layout.insertWidget(i, card)

    def _build_card(self, summary: dict, chain_size: int = 1) -> QFrame:
        """Erstellt eine Audit-Karte.

        Args:
            summary: Summary-Dict mit id, firmenname, created_at, overall_score, risk_level.
            chain_size: Anzahl Versionen der Kette dieses Audits. Bei > 1 wird
                zusaetzlich die "Ganze Historie loeschen"-Aktion angeboten (I).

        Returns:
            QFrame mit Informationen und Aktions-Buttons.
        """
        c = theme.get()
        audit_id = summary.get("audit_id", "")
        risk_level = summary.get("risk_level", "Kritisch")
        risk_color = _RISK_COLORS.get(risk_level, c.TEXT_MAIN)

        card = QFrame()
        card.setStyleSheet(
            f"QFrame {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 6px; }}"
        )
        layout = QHBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(12)

        # Info-Block
        info = QVBoxLayout()
        info.setSpacing(2)

        lbl_firma = QLabel(summary.get("firmenname", "Unbekannt"))
        # Freitext ist seit Klartext — nie als Auto-RichText (R22)
        lbl_firma.setTextFormat(Qt.TextFormat.PlainText)
        lbl_firma.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway; font-weight: 700; font-size: 13px;"
        )
        info.addWidget(lbl_firma)

        date_str = summary.get("created_at", "")[:10]
        lbl_date = QLabel(f"Erstellt: {date_str}")
        lbl_date.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 13px;")
        info.addWidget(lbl_date)

        layout.addLayout(info)
        layout.addStretch()

        # Score + Risiko + Versions-Badge
        score_val = summary.get("overall_score", 0.0)
        version = summary.get("version", 1)
        lbl_score = QLabel(f"{score_val:.0f}/100  |  {risk_level}  ·  v{version}")
        lbl_score.setStyleSheet(
            f"color: {risk_color}; font-family: JetBrains Mono;"
            " font-weight: 700; font-size: 13px;"
        )
        layout.addWidget(lbl_score)

        # Aktions-Buttons
        btn_open = QPushButton("Öffnen")
        btn_open.setStyleSheet(
            f"QPushButton {{ background: {c.ACCENT}; color: {theme.TEXT_ON_ACCENT_DEEP};"
            f" border: none; border-radius: 4px; padding: 5px 12px;"
            f" font-family: Raleway; font-weight: 700; font-size: 13px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}cc; }}"
        )
        btn_open.clicked.connect(
            lambda _=False, aid=audit_id: self.open_requested.emit(aid)
        )
        layout.addWidget(btn_open)

        btn_export = QPushButton("JSON")
        btn_export.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {c.TEXT_DIM};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 5px 12px;"
            f" font-family: Raleway; font-weight: 600; font-size: 13px; }}"
            f"QPushButton:hover {{ color: {c.TEXT_MAIN}; border-color: {c.TEXT_MAIN}; }}"
        )
        btn_export.clicked.connect(
            lambda _=False, aid=audit_id: self._export_json(aid)
        )
        layout.addWidget(btn_export)

        btn_pdf = QPushButton("PDF")
        btn_pdf.setStyleSheet(
            f"QPushButton {{ background: {c.ACCENT}22; color: {c.ACCENT};"
            f" border: 1px solid {c.ACCENT}; border-radius: 4px; padding: 5px 12px;"
            f" font-family: Raleway; font-weight: 700; font-size: 13px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}44; }}"
        )
        btn_pdf.clicked.connect(
            lambda _=False, aid=audit_id: self._export_pdf(aid)
        )
        layout.addWidget(btn_pdf)

        danger_qss = (
            f"QPushButton {{ background: transparent; color: {c.DANGER};"
            f" border: 1px solid {c.DANGER}; border-radius: 4px; padding: 5px 12px;"
            f" font-family: Raleway; font-weight: 600; font-size: 13px; }}"
            # Hover setzt color+background+border gemeinsam (R26/FD-X1).
            f"QPushButton:hover {{ background: {c.DANGER}22; color: {c.DANGER};"
            f" border-color: {c.DANGER}; }}"
        )
        btn_delete = QPushButton("Löschen")
        btn_delete.setStyleSheet(danger_qss)
        btn_delete.setToolTip("Nur diese Version löschen — andere bleiben erhalten")
        btn_delete.clicked.connect(
            lambda _=False, aid=audit_id: self._delete_version(aid)
        )
        layout.addWidget(btn_delete)

        # Nur bei mehreren Versionen: zusaetzlich die DSGVO-Art.-17-
        # Komplettloeschung der ganzen Kette anbieten (I).
        if chain_size > 1:
            btn_delete_chain = QPushButton("Ganze Historie")
            btn_delete_chain.setStyleSheet(danger_qss)
            btn_delete_chain.setToolTip(
                "Diese UND alle anderen Versionen löschen (DSGVO Art. 17)"
            )
            btn_delete_chain.clicked.connect(
                lambda _=False, aid=audit_id: self._delete_chain(aid)
            )
            layout.addWidget(btn_delete_chain)

        return card

    def _export_json(self, audit_id: str) -> None:
        """Exportiert ein Audit als JSON-Datei.

        Args:
            audit_id: UUID des Audits.
        """
        result = self._load_use_case.get_by_id(audit_id)
        if result is None:
            FinlaiInfoDialog(
                title="Fehler",
                message="Audit nicht gefunden.",
                icon_name="error",
                parent=self,
            ).exec()
            return

        # Pfad-Traversal-Schutz: Slashes / Backslashes / Drive-Letter
        # aus dem Firmennamen entfernen, sonst landet das JSON in einem
        # unerwarteten Unterordner.
        import re  # noqa: PLC0415
        safe_firma = re.sub(r"[\\/:*?\"<>|]", "_", result.customer_data.firmenname)
        default_name = f"audit_{safe_firma}_{result.created_at[:10]}.json"
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Audit exportieren", default_name, "JSON (*.json)"
        )
        if not file_path:
            return

        try:
            saved_path = self._export_use_case.export_json(result, Path(file_path))
            FinlaiSuccessDialog(
                title="JSON-Export erfolgreich",
                # Dialog-Label rendert AutoText — Freitext escapen, R22)
                message=f"{escape_html(result.customer_data.firmenname)} exportiert.",
                file_path=str(saved_path),
                parent=self,
            ).exec()
        except OSError as exc:
            log.warning("JSON-Export fehlgeschlagen: %s", exc)
            FinlaiInfoDialog(
                title="Export fehlgeschlagen",
                message=str(exc),
                icon_name="error",
                parent=self,
            ).exec()

    def _delete_version(self, audit_id: str) -> None:
        """Löscht NUR die ausgewählte Version nach Bestätigung (I).

        Alle anderen Versionen desselben Kunden bleiben erhalten. War die
        gelöschte Version die aktuelle, hebt das Repository die neueste
        verbleibende wieder auf ``is_latest`` (kein Verschwinden aus dem
        Dashboard).

        Args:
            audit_id: UUID der zu löschenden Einzelversion (PK).
        """
        result = self._load_use_case.get_by_id(audit_id)
        firma = result.customer_data.firmenname if result else "Dieses Audit"
        version = result.version if result else 1

        dlg = FinlaiConfirmDialog(
            title="Version löschen",
            # Dialog-Label rendert AutoText — Freitext escapen, R22)
            message=(
                f'Nur Version v{version} von "{escape_html(firma)}" löschen?\n'
                "Alle anderen Versionen dieses Kunden bleiben erhalten.\n"
                "Dieser Vorgang kann nicht rückgängig gemacht werden."
            ),
            confirm_text="Version löschen",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        deleted = self._load_use_case.delete_version(audit_id)
        if deleted:
            self.refresh()
        else:
            FinlaiInfoDialog(
                title="Fehler",
                message="Version konnte nicht gelöscht werden.",
                icon_name="error",
                parent=self,
            ).exec()

    def _delete_chain(self, audit_id: str) -> None:
        """Löscht die GANZE Versionskette eines Audits (DSGVO Art. 17).

        Alle Versionen dieses Kunden werden entfernt; die zugehörigen
        NIS2-Incidents aller Versionen werden anonymisiert §5).

        Args:
            audit_id: UUID einer Version der Kette (beliebig).
        """
        result = self._load_use_case.get_by_id(audit_id)
        firma = result.customer_data.firmenname if result else "Dieses Audit"

        dlg = FinlaiConfirmDialog(
            title="Ganze Historie löschen",
            # Dialog-Label rendert AutoText — Freitext escapen, R22)
            message=(
                f'Audit "{escape_html(firma)}" und ALLE zugehörigen Versionen '
                "wirklich löschen (DSGVO Art. 17)?\nDieser Vorgang kann nicht "
                "rückgängig gemacht werden."
            ),
            confirm_text="Alle löschen",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        deleted = self._load_use_case.delete(audit_id)
        if deleted:
            self.refresh()
        else:
            FinlaiInfoDialog(
                title="Fehler",
                message="Audit konnte nicht gelöscht werden.",
                icon_name="error",
                parent=self,
            ).exec()

    def _export_pdf(self, audit_id: str) -> None:
        """Exportiert ein Audit als PDF-Report im Dark Theme.

        Args:
            audit_id: UUID des Audits.
        """
        result = self._load_use_case.get_by_id(audit_id)
        if result is None:
            FinlaiInfoDialog(
                title="Fehler",
                message="Audit nicht gefunden.",
                icon_name="error",
                parent=self,
            ).exec()
            return

        # Pfad-/Dateinamens-Schutz wie beim JSON-Export — seit kann
        # firmenname rohe Sonderzeichen (<>:"|?*) enthalten.
        import re  # noqa: PLC0415

        safe_firma = re.sub(r"[\\/:*?\"<>|]", "_", result.customer_data.firmenname)
        default_name = (
            f"Security_Report_{safe_firma}_{result.created_at[:10]}.pdf"
        )
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Security-Report als PDF speichern", default_name, "PDF (*.pdf)"
        )
        if not file_path:
            return

        try:
            saved_path = self._report_use_case.generate_for_result(
                result, Path(file_path)
            )
            FinlaiSuccessDialog(
                title="PDF erfolgreich gespeichert",
                # Dialog-Label rendert AutoText — Freitext escapen, R22)
                message=f"Report für {escape_html(result.customer_data.firmenname)}.",
                file_path=str(saved_path),
                parent=self,
            ).exec()
        except (OSError, RuntimeError) as exc:
            log.warning("PDF-Export fehlgeschlagen: %s", exc)
            FinlaiInfoDialog(
                title="PDF-Export fehlgeschlagen",
                message=str(exc),
                icon_name="error",
                parent=self,
            ).exec()
