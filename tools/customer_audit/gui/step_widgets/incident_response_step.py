"""
incident_response_step — Wizard-Page fuer Incident-Response-Plan.

Bereiche:
1. Koordinator + Kontakt
2. Eskalationskette (Multi-Select aus MELDEKANAELE)
3. Kritische Systeme (Frei-Text)
4. Backup-Verweis (Frei-Text; Iter 1a-Ergebnis kann hier eingetragen
   werden)
5. Forensik-Vendor + Kontakt
6. Cyber-Versicherung + Police
7. Letzte Notfall-Uebung + Erkenntnisse
8. Export-Button "Notfallhandbuch als Markdown speichern"
9. Aufklappbarer Info-Block "Warum ein IR-Plan?"

Patrick-Direktive 2026-05-15: Fragebogen-gefuehrter Plan + DSGVO-72h-
Meldepflicht-Vorlagen werden im Markdown-Export mitgeneriert.

Schichtzugehoerigkeit: gui/ — darf application/, core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiInfoDialog
from core.icons import Icons
from tools.customer_audit.application.ir_plan_generator import export_plan
from tools.customer_audit.domain.entities import (
    MELDEKANAELE,
    IncidentResponsePlan,
    compute_ir_score,
    sanitize_text,
)
from tools.customer_audit.gui.step_widgets import field_styles

_INFO_TEXT = (
    "<b>Warum ein Incident-Response-Plan?</b><br><br>"
    "BSI-Lagebericht 2024/2025: 80 % der Ransomware-Faelle treffen KMU. "
    "Ein dokumentierter Plan reduziert die Reaktionszeit von Stunden "
    "auf Minuten — das ist der Unterschied zwischen <b>Zahlung des "
    "Loesegeldes</b> und <b>Wiederherstellung aus Backup</b>.<br><br>"
    "<b>BSI DER.2.1</b> verlangt: definierte Meldekanaele, Phasenplan, "
    "Forensik-Vorsorge.<br>"
    "<b>NIST CSF 2.0 RS/RC</b>: Incident-Management + Recovery-Plan.<br>"
    "<b>DSGVO Art. 33</b>: 72-Stunden-Meldepflicht an die "
    "Datenschutzbehoerde.<br>"
    "<b>DSGVO Art. 34</b>: Mandanten-Benachrichtigung bei hohem Risiko.<br>"
    "<b>NIS2 Art. 23</b>: 24-Stunden-Fruehwarnung — pflichtig fuer "
    "NIS2-Einrichtungen.<br><br>"
    "Beim Klick auf <b>'Notfallhandbuch als Markdown speichern'</b> "
    "werden die hier eingegebenen Daten in ein dokumentierfertiges "
    "Notfallhandbuch ausgeschrieben — inklusive Vorlagen fuer alle "
    "vier Meldekanaele."
)


class IncidentResponseStep(QWidget):
    """Wizard-Schritt fuer den Incident-Response-Plan."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._exported_path: Path | None = None
        self._build_ui()

    # ------------------------------------------------------------------
    # Read / Write API
    # ------------------------------------------------------------------

    def get_data(self) -> IncidentResponsePlan:
        # sanitize_text gegen Markdown-/HTML-/Reportlab-Injection in den
        # IR-Plan-Exporten (analog zu den anderen Step-Widgets).
        chain = [name for name, chk in self._escalation_chks.items() if chk.isChecked()]
        plan = IncidentResponsePlan(
            coordinator_name=sanitize_text(self._edt_coord_name.text().strip()),
            coordinator_contact=sanitize_text(
                self._edt_coord_contact.text().strip()
            ),
            escalation_chain=chain,
            critical_systems=sanitize_text(
                self._edt_critical.toPlainText().strip()
            ),
            backup_location_ref=sanitize_text(
                self._edt_backup_ref.text().strip()
            ),
            forensic_vendor=sanitize_text(self._edt_forensic.text().strip()),
            forensic_vendor_contact=sanitize_text(
                self._edt_forensic_contact.text().strip()
            ),
            cyber_insurance=self._chk_insurance.isChecked(),
            cyber_insurance_policy=sanitize_text(
                self._edt_policy.text().strip()
            ),
            last_drill_date=self._edt_drill_date.text().strip(),
            drill_findings=sanitize_text(
                self._edt_drill_findings.toPlainText().strip()
            ),
            plan_pdf_exported=self._exported_path is not None,
            info_block_shown=True,
        )
        return replace(plan, score=compute_ir_score(plan))

    def set_data(self, plan: IncidentResponsePlan) -> None:
        self._edt_coord_name.setText(plan.coordinator_name)
        self._edt_coord_contact.setText(plan.coordinator_contact)
        for name, chk in self._escalation_chks.items():
            chk.setChecked(name in plan.escalation_chain)
        self._edt_critical.setPlainText(plan.critical_systems)
        self._edt_backup_ref.setText(plan.backup_location_ref)
        self._edt_forensic.setText(plan.forensic_vendor)
        self._edt_forensic_contact.setText(plan.forensic_vendor_contact)
        self._chk_insurance.setChecked(plan.cyber_insurance)
        self._edt_policy.setText(plan.cyber_insurance_policy)
        self._edt_drill_date.setText(plan.last_drill_date)
        self._edt_drill_findings.setPlainText(plan.drill_findings)

    def is_valid(self) -> bool:
        return True

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        c = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        hdr = QLabel("Incident-Response-Plan")
        hdr.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway; "
            f"font-weight: 700; font-size: 14px;"
        )
        root.addWidget(hdr)

        # geteilte Feld-Styles (einheitliche Fokus-Hervorhebung) fuer
        # QLineEdit + QTextEdit — der kombinierte Sheet wirkt je Widget-Typ.
        _input_qss = field_styles.input_style() + field_styles.textedit_style()

        form_top = QFormLayout()
        form_top.setSpacing(6)
        self._edt_coord_name = QLineEdit()
        self._edt_coord_name.setPlaceholderText("z. B. RA Dr. Mueller")
        self._edt_coord_name.setStyleSheet(_input_qss)
        form_top.addRow("Koordinator (Name):", self._edt_coord_name)

        self._edt_coord_contact = QLineEdit()
        self._edt_coord_contact.setPlaceholderText(
            "Telefon / E-Mail des Koordinators"
        )
        self._edt_coord_contact.setStyleSheet(_input_qss)
        form_top.addRow("Kontakt:", self._edt_coord_contact)
        root.addLayout(form_top)

        # ── Eskalationskette ─────────────────────────────────────
        chain_grp = QGroupBox("Eskalationskette (wer wird wann benachrichtigt?)")
        chain_grp.setStyleSheet(
            f"QGroupBox {{ color: {c.TEXT_MAIN}; font-weight: bold; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; "
            f"margin-top: 8px; padding-top: 12px; }}"
            f"QGroupBox::title {{ left: 8px; padding: 0 4px; }}"
        )
        chain_lyt = QVBoxLayout(chain_grp)
        chain_lyt.setSpacing(2)
        self._escalation_chks: dict[str, QCheckBox] = {}
        for name in MELDEKANAELE:
            chk = QCheckBox(name)
            chk.setStyleSheet(f"color: {c.TEXT_MAIN};")
            chain_lyt.addWidget(chk)
            self._escalation_chks[name] = chk
        root.addWidget(chain_grp)

        # ── Kritische Systeme + Backup-Ref ──────────────────────
        form_mid = QFormLayout()
        form_mid.setSpacing(6)

        self._edt_critical = QTextEdit()
        self._edt_critical.setPlaceholderText(
            "z. B. RA-MICRO, Mail-Server, beA-Client, Telefonanlage"
        )
        self._edt_critical.setFixedHeight(60)
        self._edt_critical.setStyleSheet(_input_qss)
        form_mid.addRow("Kritische Systeme:", self._edt_critical)

        self._edt_backup_ref = QLineEdit()
        self._edt_backup_ref.setPlaceholderText(
            "z. B. Hetzner Storage Box / NAS im Serverraum"
        )
        self._edt_backup_ref.setStyleSheet(_input_qss)
        form_mid.addRow("Backup-Speicherort:", self._edt_backup_ref)
        root.addLayout(form_mid)

        # ── Forensik + Versicherung ─────────────────────────────
        forensic_grp = QGroupBox("Externer Forensik-Dienstleister + Versicherung")
        forensic_grp.setStyleSheet(chain_grp.styleSheet())
        forensic_lyt = QFormLayout(forensic_grp)
        forensic_lyt.setSpacing(6)

        self._edt_forensic = QLineEdit()
        self._edt_forensic.setPlaceholderText("z. B. CrowdStrike / FireEye / lokaler MSP")
        self._edt_forensic.setStyleSheet(_input_qss)
        forensic_lyt.addRow("Vendor:", self._edt_forensic)

        self._edt_forensic_contact = QLineEdit()
        self._edt_forensic_contact.setPlaceholderText("Hotline / Vertragsnummer")
        self._edt_forensic_contact.setStyleSheet(_input_qss)
        forensic_lyt.addRow("Kontakt:", self._edt_forensic_contact)

        self._chk_insurance = QCheckBox("Cyber-Versicherung vorhanden")
        self._chk_insurance.setStyleSheet(f"color: {c.TEXT_MAIN};")
        forensic_lyt.addRow("", self._chk_insurance)

        self._edt_policy = QLineEdit()
        self._edt_policy.setPlaceholderText("Anbieter + Police-Nr.")
        self._edt_policy.setStyleSheet(_input_qss)
        forensic_lyt.addRow("Police:", self._edt_policy)
        root.addWidget(forensic_grp)

        # ── Letzte Notfall-Uebung ───────────────────────────────
        drill_grp = QGroupBox("Letzte Notfall-Uebung")
        drill_grp.setStyleSheet(chain_grp.styleSheet())
        drill_lyt = QFormLayout(drill_grp)
        drill_lyt.setSpacing(6)

        self._edt_drill_date = QLineEdit()
        self._edt_drill_date.setPlaceholderText("ISO-Datum YYYY-MM-DD")
        self._edt_drill_date.setStyleSheet(_input_qss)
        drill_lyt.addRow("Datum:", self._edt_drill_date)

        self._edt_drill_findings = QTextEdit()
        self._edt_drill_findings.setPlaceholderText(
            "Was hat gut funktioniert? Was muss verbessert werden?"
        )
        self._edt_drill_findings.setFixedHeight(50)
        self._edt_drill_findings.setStyleSheet(_input_qss)
        drill_lyt.addRow("Erkenntnisse:", self._edt_drill_findings)
        root.addWidget(drill_grp)

        # ── Export-Button ───────────────────────────────────────
        export_row = QHBoxLayout()
        self._btn_export = QPushButton("Notfallhandbuch als Markdown speichern …")
        self._btn_export.setStyleSheet(
            f"QPushButton {{ background: {c.ACCENT}; "
            f"color: {theme.TEXT_ON_ACCENT_DEEP}; "
            f"border: none; border-radius: 4px; padding: 8px 18px; "
            f"font-family: Raleway; font-weight: 700; font-size: 12px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}cc; }}"
        )
        self._btn_export.clicked.connect(self._on_export)
        export_row.addWidget(self._btn_export)
        export_row.addStretch()
        self._lbl_export_status = QLabel("")
        self._lbl_export_status.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px;"
        )
        export_row.addWidget(self._lbl_export_status)
        root.addLayout(export_row)

        # ── Info-Block ───────────────────────────────────────────
        info_grp = QGroupBox("Hintergrund-Information")
        info_grp.setCheckable(True)
        info_grp.setChecked(False)
        info_grp.setStyleSheet(chain_grp.styleSheet())
        info_lyt = QVBoxLayout(info_grp)
        # einheitlicher Hintergrund-Info-Abstand (wie backup_step).
        info_lyt.setContentsMargins(12, 10, 12, 12)
        info_lyt.setSpacing(8)
        info_lbl = QLabel(_INFO_TEXT)
        info_lbl.setTextFormat(Qt.TextFormat.RichText)
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 12px; line-height: 1.4;"
        )
        info_lyt.addWidget(info_lbl)
        # deutlicher Abstand zwischen Ausfuell-Bereich und Hintergrund-Info.
        root.addSpacing(14)
        root.addWidget(info_grp)

        root.addStretch()

        # Tab-Reihenfolge (F4) — logische Feld-Folge ueber alle Eingaben.
        for prev, nxt in (
            (self._edt_coord_name, self._edt_coord_contact),
            (self._edt_coord_contact, self._edt_critical),
            (self._edt_critical, self._edt_backup_ref),
            (self._edt_backup_ref, self._edt_forensic),
            (self._edt_forensic, self._edt_forensic_contact),
            (self._edt_forensic_contact, self._chk_insurance),
            (self._chk_insurance, self._edt_policy),
            (self._edt_policy, self._edt_drill_date),
            (self._edt_drill_date, self._edt_drill_findings),
        ):
            QWidget.setTabOrder(prev, nxt)

    # ------------------------------------------------------------------

    def _on_export(self) -> None:
        target, _ = QFileDialog.getSaveFileName(
            self,
            "Notfallhandbuch speichern",
            "Notfallhandbuch.md",
            "Markdown-Dateien (*.md);;PDF-Dateien (*.pdf);;Alle Dateien (*.*)",
        )
        if not target:
            return
        path = Path(target)
        fmt = "pdf" if path.suffix.lower() == ".pdf" else "markdown"
        plan = self.get_data()
        ok = export_plan(plan, path, fmt=fmt)
        if ok:
            self._exported_path = path
            self._lbl_export_status.setText(f"Gespeichert: {path.name}")
            self._lbl_export_status.setStyleSheet(
                f"color: {theme.SEVERITY_SIGNAL_OK}; font-size: 11px;"
            )
        else:
            FinlaiInfoDialog(
                title="Export fehlgeschlagen",
                message="Konnte Datei nicht schreiben. Pruefen Sie Zugriff/Format.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
