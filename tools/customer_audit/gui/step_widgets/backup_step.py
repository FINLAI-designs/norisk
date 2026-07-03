"""
backup_step — Wizard-Schritt fuer das Backup-Audit.

Drei Bereiche auf einer Seite:

A) **Optionaler Detektor-Switch** (Patrick-Direktive: muss aus-/
   anschaltbar sein, nicht jeder Anwender nutzt Backup-Software).
   Wenn AN: scannt Windows-Registry nach Veeam/Acronis/Macrium/…
   und listet Treffer. Bei OFF/keine Treffer: zeigt B + C.

B) **3-2-1-1-0-Regel-Checkboxen** + RPO/RTO + Verschluesselung +
   Aufbewahrungs-Konzept-PDF-Upload + Datum des letzten Test-Restore.

C) **Info-Block "Warum Backup-Systematik?"** — erklaert die Regel
   mit Kanzlei-Beispiel, BSI-Bezug und Berufsrechts-Pflichten.
   Aufklappbar, immer sichtbar (auch bei aktivem Detector als
   Hintergrund-Info).

Schichtzugehoerigkeit: gui/ — darf application/, core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import replace
from datetime import date

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractSpinBox,
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.customer_audit.application.backup_detector import BackupDetector
from tools.customer_audit.domain.entities import (
    BackupAuditResult,
    compute_backup_score,
    sanitize_text,
)
from tools.customer_audit.gui.step_widgets import field_styles

_INFO_BACKUP_TEXT = (
    "<b>Warum eine systematische Backup-Sicherung?</b><br><br>"
    "Bei einem Ransomware-Befall ist das Backup oft die einzige "
    "Moeglichkeit, Mandantendaten wiederherzustellen ohne Loesegeld zu "
    "zahlen. BSI-Lagebericht 2024/2025: 80% der Ransomware-Faelle "
    "treffen kleine und mittlere Organisationen.<br><br>"
    "Die <b>3-2-1-1-0-Regel</b> (BSI CON.3, NIST RC.RP):<br>"
    "• <b>3</b> Datenkopien (Original + 2 Backups).<br>"
    "• <b>2</b> verschiedene Medien (z.B. NAS + Cloud).<br>"
    "• <b>1</b> Kopie offsite (raeumlich getrennt, z.B. anderer Standort).<br>"
    "• <b>1</b> Kopie immutable/offline (gegen Ransomware: Tape, S3 "
    "Object Lock, abgesteckte Wechselplatte).<br>"
    "• <b>0</b> Fehler beim letzten verifizierten Restore-Test.<br><br>"
    "<b>Berufsrechtlich</b> verlangt §43e BRAO (DE) / §9 RAO (AT) + "
    "DSGVO Art. 32, dass Mandantendaten verfuegbar gehalten und wieder-"
    "hergestellt werden koennen — ein Backup-Konzept ist <i>Teil der "
    "Verschwiegenheits-Pflicht</i>."
)


class BackupStep(QWidget):
    """Wizard-Schritt fuer Backup-Audit (Selbst- und Kunden-Modus)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._detector = BackupDetector()
        self._detected_tools: list[str] = []
        self._build_ui()

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def get_data(self) -> BackupAuditResult:
        rule = {
            "3_copies": self._chk_3_copies.isChecked(),
            "2_media": self._chk_2_media.isChecked(),
            "1_offsite": self._chk_1_offsite.isChecked(),
            "1_immutable": self._chk_1_immutable.isChecked(),
            "0_restore_tested": self._chk_0_tested.isChecked(),
        }
        audit = BackupAuditResult(
            detection_enabled=self._chk_detection.isChecked(),
            detected_tools=list(self._detected_tools),
            rule_3_2_1_1_0=rule,
            rpo_hours=self._sp_rpo.value() if self._sp_rpo.value() > 0 else None,
            rto_hours=self._sp_rto.value() if self._sp_rto.value() > 0 else None,
            encryption_enabled=self._chk_encryption.isChecked(),
            key_separately_stored=self._chk_key_separate.isChecked(),
            konzept_pdf_uploaded=self._chk_konzept.isChecked(),
            last_restore_test=sanitize_text(self._restore_date_text()),
            info_block_shown=True,
        )
        return replace(audit, score=compute_backup_score(audit))

    def set_data(self, audit: BackupAuditResult) -> None:
        self._chk_detection.setChecked(audit.detection_enabled)
        self._detected_tools = list(audit.detected_tools)
        self._refresh_detected_label()
        rule = audit.rule_3_2_1_1_0 or {}
        self._chk_3_copies.setChecked(bool(rule.get("3_copies")))
        self._chk_2_media.setChecked(bool(rule.get("2_media")))
        self._chk_1_offsite.setChecked(bool(rule.get("1_offsite")))
        self._chk_1_immutable.setChecked(bool(rule.get("1_immutable")))
        self._chk_0_tested.setChecked(bool(rule.get("0_restore_tested")))
        self._sp_rpo.setValue(int(audit.rpo_hours or 0))
        self._sp_rto.setValue(int(audit.rto_hours or 0))
        self._chk_encryption.setChecked(audit.encryption_enabled)
        self._chk_key_separate.setChecked(audit.key_separately_stored)
        self._chk_konzept.setChecked(audit.konzept_pdf_uploaded)
        self._restore_test_edit.setPlainText(audit.last_restore_test)

    def is_valid(self) -> bool:
        # Backup-Step hat keine Pflichtfelder — Selbst-Audit erlaubt "weiss nicht".
        return True

    def set_detection_available(self, available: bool) -> None:
        """Sperrt die Backup-Auto-Detektion im Kunden-Audit.

        Ein Fremd-Audit darf keine Eigenscan-Daten tragen — die autoritative
        Sperre sitzt in der Use-Case-Assertion. Diese GUI-Sperre verhindert,
        dass der Nutzer im CUSTOMER-Modus ueberhaupt erst einen Scan ausloest
        (sonst scheiterte erst die Berechnung am Ende).

        Args:
            available: ``True`` (SELF) gibt die Detektion frei; ``False``
                (CUSTOMER) deaktiviert und leert sie.
        """
        if not available:
            self._chk_detection.setChecked(False)
            self._detected_tools = []
            self._refresh_detected_label()
        self._chk_detection.setEnabled(available)
        self._chk_detection.setToolTip(
            ""
            if available
            else "Im Kunden-Audit nicht verfuegbar — Scanner laufen nicht "
            "auf der Mandanten-Maschine."
        )

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        c = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        hdr = QLabel("Backup-Audit")
        hdr.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway; "
            f"font-weight: 700; font-size: 14px;"
        )
        root.addWidget(hdr)

        # ── Detector-Switch ───────────────────────────────────────
        self._chk_detection = QCheckBox(
            "Automatische Backup-Software-Detektion (Veeam, Acronis, "
            "Macrium, Windows Backup …) — optional"
        )
        self._chk_detection.setStyleSheet(f"color: {c.TEXT_MAIN};")
        self._chk_detection.stateChanged.connect(self._on_detection_toggled)
        root.addWidget(self._chk_detection)

        self._lbl_detected = QLabel(
            "Detektion deaktiviert — Auswertung erfolgt nur ueber das Formular unten."
        )
        # Zeigt Software-Scan-Namen (untrusted) — nie als Auto-RichText
        # interpretieren/, R22).
        self._lbl_detected.setTextFormat(Qt.TextFormat.PlainText)
        self._lbl_detected.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; padding-left: 24px;"
        )
        self._lbl_detected.setWordWrap(True)
        root.addWidget(self._lbl_detected)

        # ── 3-2-1-1-0-Regel ──────────────────────────────────────
        grp = QGroupBox("3-2-1-1-0-Regel")
        grp.setStyleSheet(
            f"QGroupBox {{ color: {c.TEXT_MAIN}; font-weight: bold; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; "
            f"margin-top: 8px; padding-top: 12px; }}"
            f"QGroupBox::title {{ left: 8px; padding: 0 4px; }}"
        )
        lyt = QVBoxLayout(grp)
        lyt.setSpacing(4)

        self._chk_3_copies = QCheckBox("3 Datenkopien (Original + 2 Backups)")
        self._chk_2_media = QCheckBox("2 verschiedene Medien (NAS + Cloud o.a.)")
        self._chk_1_offsite = QCheckBox("1 Kopie offsite (raeumlich getrennt)")
        self._chk_1_immutable = QCheckBox(
            "1 Kopie immutable/offline (Ransomware-Schutz)"
        )
        self._chk_0_tested = QCheckBox(
            "Letzter Test-Restore in den letzten 12 Monaten erfolgreich"
        )
        for chk in (
            self._chk_3_copies,
            self._chk_2_media,
            self._chk_1_offsite,
            self._chk_1_immutable,
            self._chk_0_tested,
        ):
            chk.setStyleSheet(f"color: {c.TEXT_MAIN};")
            lyt.addWidget(chk)
        root.addWidget(grp)

        # ── RPO / RTO + Verschluesselung ──────────────────────────
        form = QFormLayout()
        form.setSpacing(6)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._sp_rpo = QSpinBox()
        self._sp_rpo.setRange(0, 720)
        self._sp_rpo.setSuffix(" h")
        # Spinbox-Pfeile aus (Eingabe per Tastatur) — ruhigere Optik.
        self._sp_rpo.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        # Feste Feldbreite (Patrick: Eingabefelder mit "unendlicher Laenge"):
        # ohne diesen Style waechst die Spinbox auf die volle Formspalte.
        self._sp_rpo.setStyleSheet(field_styles.spinbox_style())
        self._sp_rpo.setToolTip("Recovery Point Objective — max tolerabler Datenverlust")
        form.addRow("RPO (max. Datenverlust):", self._sp_rpo)

        self._sp_rto = QSpinBox()
        self._sp_rto.setRange(0, 720)
        self._sp_rto.setSuffix(" h")
        self._sp_rto.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        self._sp_rto.setStyleSheet(field_styles.spinbox_style())
        self._sp_rto.setToolTip(
            "Recovery Time Objective — max tolerable Wiederherstellungs-Dauer"
        )
        form.addRow("RTO (max. Ausfall):", self._sp_rto)

        self._chk_encryption = QCheckBox(
            "Backups sind verschluesselt (AES-256 o. besser)"
        )
        self._chk_encryption.setStyleSheet(f"color: {c.TEXT_MAIN};")
        form.addRow("", self._chk_encryption)

        self._chk_key_separate = QCheckBox(
            "Schluesselverwahrung getrennt vom Backup"
        )
        self._chk_key_separate.setStyleSheet(f"color: {c.TEXT_MAIN};")
        form.addRow("", self._chk_key_separate)

        self._chk_konzept = QCheckBox(
            "Datensicherungskonzept dokumentiert (PDF vorhanden)"
        )
        self._chk_konzept.setStyleSheet(f"color: {c.TEXT_MAIN};")
        form.addRow("", self._chk_konzept)

        root.addLayout(form)

        # ── Letzter Test-Restore ──────────────────────────────────
        lbl_test = QLabel("Datum letzter verifizierter Restore-Test (ISO YYYY-MM-DD):")
        lbl_test.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 11px;")
        root.addWidget(lbl_test)
        self._restore_test_edit = QTextEdit()
        self._restore_test_edit.setPlaceholderText(date.today().isoformat())
        self._restore_test_edit.setFixedHeight(28)
        # Einzeiliges Datumsfeld -> Breite fixieren (Patrick: "unendliche
        # Laenge"). textedit_style setzt bewusst keine Breite (mehrzeilige
        # Freitexte bleiben voll breit), daher hier explizit kappen — buendig
        # zu den QLineEdit-/Combo-Feldern.
        self._restore_test_edit.setMaximumWidth(field_styles.FIELD_MIN_WIDTH)
        # geteilter Feld-Style (einheitliche Fokus-Hervorhebung).
        self._restore_test_edit.setStyleSheet(field_styles.textedit_style())
        root.addWidget(self._restore_test_edit)

        # ── Info-Block (immer sichtbar) ───────────────────────────
        info_grp = QGroupBox("Hintergrund-Information")
        info_grp.setCheckable(True)
        info_grp.setChecked(False)  # Default zugeklappt
        info_grp.setStyleSheet(
            f"QGroupBox {{ color: {c.TEXT_MAIN}; font-weight: bold; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; "
            f"margin-top: 8px; padding-top: 12px; }}"
            f"QGroupBox::title {{ left: 8px; padding: 0 4px; }}"
        )
        info_lyt = QVBoxLayout(info_grp)
        # Luft zwischen Rahmen/Titel und dem Erklaer-Text — sonst klebt der
        # RichText direkt an der GroupBox-Kante (Patrick: "zu geringer Hoehenabstand").
        info_lyt.setContentsMargins(12, 10, 12, 12)
        info_lyt.setSpacing(8)
        info_lbl = QLabel(_INFO_BACKUP_TEXT)
        info_lbl.setTextFormat(Qt.TextFormat.RichText)
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 12px; line-height: 1.4;"
        )
        info_lyt.addWidget(info_lbl)
        # deutlicher Abstand zwischen Ausfuell-Bereich und Hintergrund-Info
        # (Patrick: "Hoehenabstand weiter zu gering" trotz).
        root.addSpacing(14)
        root.addWidget(info_grp)

        root.addStretch()

        # Tab-Reihenfolge (F4) — logische Feld-Folge ueber alle Eingaben.
        for prev, nxt in (
            (self._chk_detection, self._chk_3_copies),
            (self._chk_3_copies, self._chk_2_media),
            (self._chk_2_media, self._chk_1_offsite),
            (self._chk_1_offsite, self._chk_1_immutable),
            (self._chk_1_immutable, self._chk_0_tested),
            (self._chk_0_tested, self._sp_rpo),
            (self._sp_rpo, self._sp_rto),
            (self._sp_rto, self._chk_encryption),
            (self._chk_encryption, self._chk_key_separate),
            (self._chk_key_separate, self._chk_konzept),
            (self._chk_konzept, self._restore_test_edit),
        ):
            QWidget.setTabOrder(prev, nxt)

    # ------------------------------------------------------------------
    def _on_detection_toggled(self, _state) -> None:  # noqa: ANN001
        enabled = self._chk_detection.isChecked()
        if not enabled:
            self._detected_tools = []
        else:
            tools = self._detector.detect(enabled=True)
            self._detected_tools = [
                f"{t.canonical_name}{' ' + t.version if t.version else ''}"
                for t in tools
            ]
        self._refresh_detected_label()

    def _refresh_detected_label(self) -> None:
        c = theme.get()
        if not self._chk_detection.isChecked():
            self._lbl_detected.setText(
                "Detektion deaktiviert — Auswertung erfolgt nur ueber das "
                "Formular unten. (Hintergrund-Info ausklappen fuer Erklaerung.)"
            )
            self._lbl_detected.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-size: 11px; padding-left: 24px;"
            )
            return
        if not self._detected_tools:
            self._lbl_detected.setText(
                "Detektion aktiv — keine bekannte Backup-Software gefunden. "
                "Fuelle das Formular unten aus."
            )
            self._lbl_detected.setStyleSheet(
                f"color: {theme.SEVERITY_SIGNAL_MEDIUM}; font-size: 11px; "
                f"padding-left: 24px;"
            )
            return
        joined = "  •  ".join(self._detected_tools)
        self._lbl_detected.setText(f"Erkannt: {joined}")
        self._lbl_detected.setStyleSheet(
            f"color: {theme.SEVERITY_SIGNAL_OK}; font-size: 11px; "
            f"padding-left: 24px;"
        )

    def _restore_date_text(self) -> str:
        return self._restore_test_edit.toPlainText().strip()
