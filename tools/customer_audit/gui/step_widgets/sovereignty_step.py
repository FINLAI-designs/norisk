"""
sovereignty_step — Datensouveraenitaets-Audit.

Drei Bereiche:

A) Optionaler Auto-Detection-Switch + Domain-Eingabe (DNS-MX + SPF +
   Installed-Software). Patrick-Direktive: ein-/ausschaltbar.

B) Liste der erkannten + selbst-deklarierten Provider mit Status-Badge
   (gruen = EU-souveraen, gelb = EU-Boundary, rot = CLOUD-Act).

C) Selbst-Deklarations-Fragebogen fuer Buchhaltung/DMS, VPN,
   Videokonferenz, Backup-Ziel.

D) Aufklappbarer Info-Block "Warum Datensouveraenitaet?" mit Schrems-
   II-/§43e-BRAO-Bezug und Provider-Risiko-Hinweisen.

Schichtzugehoerigkeit: gui/ — darf application/, core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import replace

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.escape import escape_html
from core.icons import Icons, get_icon
from core.widgets.button_styles import outline_button_qss
from tools.customer_audit.application.provider_catalog import (
    all_providers,
    find_by_keyword,
)
from tools.customer_audit.application.sovereignty_scanner import (
    SovereigntyScanner,
    build_rechtshinweise,
)
from tools.customer_audit.domain.entities import (
    DetectedProvider,
    SovereigntyAuditResult,
    compute_sovereignty_score,
    sanitize_text,
)
from tools.customer_audit.gui.step_widgets import field_styles

_INFO_TEXT = (
    "<b>Warum Datensouveraenitaet?</b><br><br>"
    "Der <b>US Cloud Act (2018)</b> erlaubt US-Behoerden Zugriff auf "
    "Daten von Anbietern mit US-Bezug — unabhaengig vom physischen "
    "Speicherort. Das betrifft Microsoft 365, Google Workspace, AWS, "
    "Dropbox, Zoom, Slack und viele mehr.<br><br>"
    "<b>Schrems II</b> (EuGH C-311/18, 16.07.2020) verlangt fuer "
    "Drittland-Transfer technische Zusatzmassnahmen wie E2EE oder "
    "BYOK — vertragliche Standardvertragsklauseln allein reichen NICHT.<br><br>"
    "<b>Berufsrechtlich</b> verpflichten §43e BRAO (DE) / §9 RAO (AT) "
    "Anwaelte zur sorgfaeltigen Auswahl von IT-Dienstleistern mit "
    "vergleichbarem Schutzniveau. Auslandsdatenverarbeitung nur bei "
    "vergleichbarem Schutz.<br><br>"
    "<b>Status-Codes:</b><br>"
    "• <b>EU-souveraen</b> (gruen, 0 Pkt) — z. B. Hetzner, mailbox.org, "
    "DATEV, BMD.<br>"
    "• <b>EU-Boundary</b> (gelb, -5 Pkt) — z. B. Microsoft 365 mit "
    "EU Data Boundary; Restrisiko durch Mutterkonzern bleibt.<br>"
    "• <b>CLOUD Act</b> (rot, -10 Pkt) — keine EU-Variante verfuegbar.<br>"
    "• <b>Self-hosted</b> (+5 Pkt) — eigene/gemietete Infrastruktur."
)

_STATUS_LABEL: dict[str, str] = {
    "eu_sovereign": "EU-souveraen",
    "eu_boundary": "EU-Boundary",
    "cloud_act": "CLOUD Act",
    "self_hosted": "Self-hosted",
}


def _status_color(status: str) -> str:
    if status == "cloud_act":
        return theme.SEVERITY_SIGNAL_CRITICAL
    if status == "eu_boundary":
        return theme.SEVERITY_SIGNAL_HIGH
    if status == "self_hosted":
        return theme.SEVERITY_SIGNAL_OK
    return theme.SEVERITY_SIGNAL_OK


class SovereigntyStep(QWidget):
    """Wizard-Schritt fuer Datensouveraenitaets-Audit."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._scanner = SovereigntyScanner()
        self._detected: list[DetectedProvider] = []
        self._scan_errors: list[str] = []
        self._build_ui()

    # ------------------------------------------------------------------
    # Read / Write API
    # ------------------------------------------------------------------

    def get_data(self) -> SovereigntyAuditResult:
        declared = self._collect_declared()
        if self._chk_detection.isChecked() and not self._detected:
            # User wollte Scan aber hat noch nicht geklickt — wir
            # triggern beim Auslesen automatisch.
            self._run_scan()
        rechts = build_rechtshinweise("Kanzlei", self._detected + declared)
        audit = SovereigntyAuditResult(
            detection_enabled=self._chk_detection.isChecked(),
            domain=sanitize_text(self._edt_domain.text().strip()),
            detected=list(self._detected),
            declared=declared,
            scan_errors=list(self._scan_errors),
            rechtshinweise=rechts,
            info_block_shown=True,
        )
        return replace(audit, score=compute_sovereignty_score(audit))

    def set_data(self, audit: SovereigntyAuditResult) -> None:
        self._chk_detection.setChecked(audit.detection_enabled)
        self._edt_domain.setText(audit.domain)
        self._detected = list(audit.detected)
        self._scan_errors = list(audit.scan_errors)
        self._refresh_provider_list(scan_errors=self._scan_errors)
        # Deklarationen aus dem Audit-Result in die Checkboxes
        # zuruecksetzen.: Match label-treu ueber ``original_label``
        # (Original-Checkbox-Label), damit "Microsoft Teams" beim Reload
        # nicht verloren geht, wenn ``find_by_keyword`` es im Catalog auf
        # "Microsoft 365" kollabiert. Fallback auf ``name`` fuer Alt-Audits
        # ohne ``original_label`` (abwaertskompatibel, Score unveraendert).
        declared_labels = {(p.original_label or p.name) for p in audit.declared}
        # zuvor erfasste EIGENE Dienste (nicht in der festen Liste) wieder
        # als Checkbox anlegen, sonst gehen sie beim Reload verloren. Idempotent.
        for label in declared_labels:
            if label and label not in self._declaration_combos:
                self._add_custom_service(label, checked=False)
        for combo in self._declaration_combos.values():
            combo.setChecked(combo.text() in declared_labels)

    def is_valid(self) -> bool:
        # Kein Pflichtfeld — Selbst-Audit erlaubt "weiss nicht".
        return True

    def set_detection_available(self, available: bool) -> None:
        """Sperrt die Souveränitäts-Auto-Detektion im Kunden-Audit.

        Wie:meth:`BackupStep.set_detection_available` — verhindert einen
        DNS-MX-/SPF-/Software-Scan des Beraterrechners im Fremd-Audit. Das
        Domain-Feld bleibt erfassbar; nur der Scan wird gesperrt und der
        bereits erkannte Bestand geleert.

        Args:
            available: ``True`` (SELF) gibt die Detektion frei; ``False``
                (CUSTOMER) deaktiviert und leert sie.
        """
        if not available:
            self._chk_detection.setChecked(False)
            self._detected = []
            self._scan_errors = []
            self._refresh_provider_list()
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

        hdr = QLabel("Datensouveraenitaets-Audit")
        hdr.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway; "
            f"font-weight: 700; font-size: {theme.FONT_SIZE_BODY_LG}px;"
        )
        root.addWidget(hdr)

        # ── Detector-Switch + Domain-Feld ────────────────────────
        self._chk_detection = QCheckBox(
            "Auto-Detection aktivieren (DNS-MX + SPF + installierte Software)"
        )
        self._chk_detection.setStyleSheet(f"color: {c.TEXT_MAIN};")
        self._chk_detection.stateChanged.connect(self._on_detection_toggled)
        root.addWidget(self._chk_detection)

        domain_row = QHBoxLayout()
        domain_row.setSpacing(6)
        self._lbl_domain = QLabel("Kanzlei-Domain:")
        self._lbl_domain.setStyleSheet(f"color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px;")
        self._edt_domain = QLineEdit()
        self._edt_domain.setPlaceholderText("z. B. kanzlei-mueller.at")
        # geteilter Feld-Style (einheitliche Fokus-Hervorhebung).
        self._edt_domain.setStyleSheet(field_styles.input_style())
        self._edt_domain.editingFinished.connect(self._on_domain_changed)
        domain_row.addWidget(self._lbl_domain)
        # Feste Feldbreite: KEIN stretch=1 — der Stretch-Faktor wuerde die
        # max-width aus input_style aushebeln und das Feld auf die ganze Zeile
        # ziehen (Patrick: "unendliche Laenge"). Der Trailing-Stretch schluckt
        # stattdessen den Rest der Zeile.
        domain_row.addWidget(self._edt_domain)
        domain_row.addStretch(1)
        root.addLayout(domain_row)

        # ── Erkannte Provider ────────────────────────────────────
        self._provider_list_label = QLabel(
            "Detection deaktiviert — Fragebogen unten ausfuellen."
        )
        self._provider_list_label.setWordWrap(True)
        self._provider_list_label.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; padding-left: 4px;"
        )
        root.addWidget(self._provider_list_label)

        self._provider_container = QVBoxLayout()
        self._provider_container.setSpacing(4)
        root.addLayout(self._provider_container)

        # ── Selbst-Deklarations-Checkboxes ───────────────────────
        decl_grp = QGroupBox("Selbst-Deklaration: welche Dienste nutzt du?")
        decl_grp.setStyleSheet(
            f"QGroupBox {{ color: {c.TEXT_MAIN}; font-weight: bold; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; "
            f"margin-top: 8px; padding-top: 12px; }}"
            f"QGroupBox::title {{ left: 8px; padding: 0 4px; }}"
        )
        decl_form = QFormLayout(decl_grp)
        decl_form.setSpacing(4)
        decl_form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        # Wir bieten eine kompakte Auswahl der haeufigsten Kanzlei-
        # Provider — der Rest wird ueber die Auto-Detection erfasst.
        self._declaration_combos: dict[str, QCheckBox] = {}
        decl_choices = [
            "DATEV",
            "BMD",
            "RA-MICRO",
            "advoware",
            "AnNoText",
            "Microsoft 365",
            "Google Workspace",
            "Dropbox",
            "Nextcloud (Self-hosted)",
            "Hetzner",
            "IONOS",
            "Mullvad VPN",
            "ProtonVPN",
            "Zoom",
            "Microsoft Teams",
            "Apple iCloud",
        ]
        for name in decl_choices:
            chk = QCheckBox(name)
            chk.setStyleSheet(f"color: {c.TEXT_MAIN};")
            decl_form.addRow("", chk)
            self._declaration_combos[name] = chk

        # eigene Dienste erfassbar machen (die feste Liste deckt nicht
        # jede Kanzlei ab). Inline-Eingabe statt Popup: Name eintippen ->
        # "+ Hinzufuegen" -> neue (angehakte) Checkbox. _collect_declared traegt
        # beliebige Namen ueber den Fallback-Zweig (status=cloud_act), die
        # Persistenz ist frei-form (DetectedProvider.name) -> kein Schema-Change.
        self._decl_form = decl_form
        add_row = QHBoxLayout()
        self._edt_custom_service = QLineEdit()
        self._edt_custom_service.setPlaceholderText("Weiterer Dienst (z. B. Notion) …")
        self._edt_custom_service.setStyleSheet(field_styles.input_style())
        self._edt_custom_service.returnPressed.connect(self._on_add_custom_service)
        # Feste Feldbreite (kein stretch=1, sonst aushebelt der Stretch die
        # max-width) — der Trailing-Stretch nach dem Button packt Feld + Button
        # linksbuendig.
        add_row.addWidget(self._edt_custom_service)
        # Eigene Factory-States (das decl_grp-Stylesheet unterbricht sonst die
        # globale QPushButton-Kaskade -> Plattform-Default statt Dark-Theme).
        self._btn_add_service = QPushButton("Hinzufügen")
        self._btn_add_service.setIcon(get_icon(Icons.ADD))
        self._btn_add_service.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_add_service.setStyleSheet(outline_button_qss())
        self._btn_add_service.clicked.connect(self._on_add_custom_service)
        add_row.addWidget(self._btn_add_service)
        add_row.addStretch(1)
        decl_form.addRow("", add_row)

        root.addWidget(decl_grp)

        # ── Info-Block ───────────────────────────────────────────
        info_grp = QGroupBox("Hintergrund-Information")
        info_grp.setCheckable(True)
        info_grp.setChecked(False)
        info_grp.setStyleSheet(
            f"QGroupBox {{ color: {c.TEXT_MAIN}; font-weight: bold; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; "
            f"margin-top: 8px; padding-top: 12px; }}"
            f"QGroupBox::title {{ left: 8px; padding: 0 4px; }}"
        )
        info_lyt = QVBoxLayout(info_grp)
        # einheitlicher Hintergrund-Info-Abstand (wie backup_step) —
        # Luft zwischen GroupBox-Rahmen/Titel und dem Erklaer-Text.
        info_lyt.setContentsMargins(12, 10, 12, 12)
        info_lyt.setSpacing(8)
        info_lbl = QLabel(_INFO_TEXT)
        info_lbl.setTextFormat(Qt.TextFormat.RichText)
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px; line-height: 1.4;"
        )
        info_lyt.addWidget(info_lbl)
        # deutlicher Abstand zwischen Ausfuell-Bereich und Hintergrund-Info.
        root.addSpacing(14)
        root.addWidget(info_grp)

        root.addStretch()

        # Tab-Reihenfolge (F4): Detection-Schalter -> Domain-Feld.
        QWidget.setTabOrder(self._chk_detection, self._edt_domain)

    # ------------------------------------------------------------------
    # Slots / Helpers
    # ------------------------------------------------------------------

    def _on_detection_toggled(self, _state) -> None:  # noqa: ANN001
        if not self._chk_detection.isChecked():
            self._detected = []
            self._refresh_provider_list()
            return
        self._run_scan()

    def _on_domain_changed(self) -> None:
        if self._chk_detection.isChecked():
            self._run_scan()

    def _run_scan(self) -> None:
        report = self._scanner.scan(
            enabled=True,
            domain=self._edt_domain.text().strip(),
        )
        self._detected = report.detected
        self._scan_errors = list(report.errors)
        self._refresh_provider_list(scan_errors=self._scan_errors)

    def _refresh_provider_list(self, scan_errors: list[str] | None = None) -> None:
        c = theme.get()
        # Vorherige Eintraege entfernen
        while self._provider_container.count():
            item = self._provider_container.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()

        if not self._chk_detection.isChecked():
            self._provider_list_label.setText(
                "Detection deaktiviert — Fragebogen unten ausfuellen."
            )
            self._provider_list_label.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; padding-left: 4px;"
            )
            return

        if not self._detected and not scan_errors:
            self._provider_list_label.setText(
                "Detection aktiv — Domain eingeben oder warten bis Software-Scan laeuft."
            )
            self._provider_list_label.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; padding-left: 4px;"
            )
            return

        if scan_errors:
            # Scan-Fehlertexte sind untrusted (DNS-/Netz-Antworten) —
            # vor dem RichText-Rendern escapen/, R22).
            err_lbl = QLabel(
                " • " + "<br> • ".join(escape_html(e) for e in scan_errors)
            )
            err_lbl.setTextFormat(Qt.TextFormat.RichText)
            err_lbl.setWordWrap(True)
            err_lbl.setStyleSheet(
                f"color: {theme.SEVERITY_SIGNAL_HIGH}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
            self._provider_container.addWidget(err_lbl)

        for p in self._detected:
            row = QHBoxLayout()
            row.setSpacing(6)
            badge = QLabel(f" {_STATUS_LABEL.get(p.status, p.status)} ")
            badge.setStyleSheet(
                f"background-color: {_status_color(p.status)};"
                f" color: #1a1a1a; font-weight: bold;"
                f" border-radius: 6px; padding: 1px 6px; font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
            row.addWidget(badge)
            # Provider-Daten stammen aus DNS/SPF/Software-Scan (untrusted) —
            # vor dem RichText-Rendern escapen/, R22).
            name_lbl = QLabel(
                f"<b>{escape_html(p.name)}</b> — via {escape_html(p.via)}: "
                f"<i>{escape_html(p.evidence)}</i>"
            )
            name_lbl.setTextFormat(Qt.TextFormat.RichText)
            name_lbl.setStyleSheet(f"color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px;")
            name_lbl.setWordWrap(True)
            row.addWidget(name_lbl, stretch=1)
            host = QWidget()
            host.setLayout(row)
            self._provider_container.addWidget(host)

        self._provider_list_label.setText(
            f"{len(self._detected)} Provider erkannt."
        )
        self._provider_list_label.setStyleSheet(
            f"color: {theme.SEVERITY_SIGNAL_OK}; font-size: {theme.FONT_SIZE_CAPTION}px; "
            f"padding-left: 4px;"
        )

    def _add_custom_service(self, name: str, *, checked: bool) -> QCheckBox:
        """Legt eine Checkbox fuer einen eigenen Dienst an (idempotent).

        Wird vom "+ Hinzufuegen"-Button UND von:meth:`set_data` (Reload eines
        zuvor erfassten Custom-Dienstes) genutzt. Existiert der Name schon, wird
        nur der Haken gesetzt — keine Dublette.

        Args:
            name: Anzeigename des Dienstes.
            checked: Ob die Checkbox angehakt sein soll.

        Returns:
            Die (neue oder vorhandene) Checkbox.
        """
        existing = self._declaration_combos.get(name)
        if existing is not None:
            existing.setChecked(checked)
            return existing
        chk = QCheckBox(name)
        chk.setStyleSheet(f"color: {theme.get().TEXT_MAIN};")
        chk.setChecked(checked)
        # Vor der Eingabezeile einfuegen, damit das Eingabefeld unten bleibt.
        self._decl_form.insertRow(self._decl_form.rowCount() - 1, "", chk)
        self._declaration_combos[name] = chk
        return chk

    def _on_add_custom_service(self) -> None:
        """Uebernimmt den eingetippten Dienstnamen als angehakte Checkbox."""
        name = self._edt_custom_service.text().strip()
        if not name:
            return
        self._add_custom_service(name, checked=True)
        self._edt_custom_service.clear()

    def _collect_declared(self) -> list[DetectedProvider]:
        declared: list[DetectedProvider] = []
        for name, chk in self._declaration_combos.items():
            if not chk.isChecked():
                continue
            # Aus dem Catalog den Eintrag holen
            provider = find_by_keyword(name)
            if provider is None:
                # Auch nicht gefundene werden mit Fallback erfasst —
                # wir koennen dann zumindest den Status nicht
                # ermitteln und werten konservativ als "cloud_act".
                declared.append(
                    DetectedProvider(
                        name=name,
                        status="cloud_act",
                        category="saas_other",
                        via="self_declared",
                        evidence="",
                        original_label=name,
                    )
                )
                continue
            declared.append(
                DetectedProvider(
                    name=provider.name,
                    status=provider.status,
                    category=provider.category,
                    via="self_declared",
                    evidence="",
                    legal_entity_country=provider.legal_entity_country,
                    parent_country=provider.parent_country,
                    residual_risk_note=provider.residual_risk_note,
                    original_label=name,
                )
            )
        return declared


__all__ = ["SovereigntyStep", "all_providers"]
