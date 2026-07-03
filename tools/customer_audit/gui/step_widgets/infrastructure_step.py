"""
infrastructure_step — Schritt 2: IT-Infrastruktur.

Erfasst Betriebssysteme, AV, Firewall, Verschlüsselung, VPN, Remote-Access.

Schichtzugehörigkeit: gui/ — nur UI-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.customer_audit.domain.entities import (
    BETRIEBSSYSTEME_OPTIONEN,
    MAX_TEXT_LENGTH,
    REMOTE_ACCESS_OPTIONEN,
    STATUS_OPTIONEN,
    VERSCHLUESSELUNG_OPTIONEN,
    InfrastructureData,
    sanitize_text,
)
from tools.customer_audit.gui.step_widgets import field_styles
from tools.customer_audit.gui.step_widgets.prefill_helpers import (
    fmt_iso_date,
    match_os_option,
    origin_tooltip,
)

if TYPE_CHECKING:
    from core.scan_prefill.models import AuditPrefill


class InfrastructureStep(QWidget):
    """Wizard-Schritt 2: IT-Infrastruktur.

    Attributes:
        _cb_betriebssysteme: Checkboxen für Betriebssysteme.
        _cb_verschluesselung: Checkboxen für Verschlüsselung.
        _cb_remote_access: Checkboxen für Remote-Access-Tools.
    """

    #: Emittiert (mit ``self``), wenn der Nutzer die gemessene Vorbefuellung
    #: anfordert (Checkbox "Gemessene Werte uebernehmen", nur SELF). Der Wizard
    #: erhebt dann den ScanDataPort-Snapshot im Worker und ruft
    #::meth:`apply_prefill` Phase 3).
    prefill_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert den Schritt.

        Args:
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._cb_betriebssysteme: dict[str, QCheckBox] = {}
        self._cb_verschluesselung: dict[str, QCheckBox] = {}
        self._cb_remote_access: dict[str, QCheckBox] = {}
        # Phase 3: vom Prefill gesperrte Widgets (fuer Override/Reset).
        self._measured_widgets: list[QWidget] = []
        # SELF-only-Gate: im CUSTOMER-Modus False -> kein Prefill
        # (fail-closed gegen Mid-Scan-Mode-Wechsel + verspaetete Worker-Callbacks).
        self._prefill_available = True
        self._build_ui()

    def _build_ui(self) -> None:
        """Baut das Formular-Layout auf."""
        c = theme.get()

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Scrollbar für viele Felder
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent; border: none;")

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(0, 0, 8, 0)
        inner_layout.setSpacing(12)

        hdr = QLabel("IT-Infrastruktur")
        hdr.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway;"
            " font-weight: 700; font-size: 14px;"
        )
        inner_layout.addWidget(hdr)

        # --- Phase 3: gemessene Vorbefuellung (nur SELF, Muster B) ---
        # Explizite Opt-in-Checkbox (kein verstecktes Auto-Befuellen). Der Wizard
        # erhebt den Mess-Snapshot im Hintergrund-Thread und ruft apply_prefill.
        self._chk_prefill = QCheckBox(
            "Gemessene Werte automatisch uebernehmen "
            "(Firewall, RDP, Verschluesselung, OS/Patch)"
        )
        self._chk_prefill.setStyleSheet(
            f"QCheckBox {{ color: {c.TEXT_MAIN}; font-size: 13px; }}"
        )
        self._chk_prefill.stateChanged.connect(self._on_prefill_toggled)
        inner_layout.addWidget(self._chk_prefill)

        self._lbl_prefill = QLabel("")
        # Herkunfts-/Mess-Text — PlainText (nie Auto-RichText R22).
        self._lbl_prefill.setTextFormat(Qt.TextFormat.PlainText)
        self._lbl_prefill.setStyleSheet(field_styles.origin_badge_style())
        self._lbl_prefill.setWordWrap(True)
        self._lbl_prefill.hide()
        inner_layout.addWidget(self._lbl_prefill)

        # geteilte Feld-Styles (einheitliche Fokus-Hervorhebung +
        # feste Dropdown-Breite) statt pro-Step dupliziertem QSS.
        _input_style = field_styles.input_style()
        _combo_style = field_styles.combo_style()
        _lbl_style = f"color: {c.TEXT_MAIN}; font-size: 13px;"
        _group_style = (
            f"QGroupBox {{ color: {c.TEXT_MAIN}; font-family: Inter; font-size: 13px;"
            f" font-weight: 600; border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" margin-top: 8px; padding-top: 8px; }}"
            f"QGroupBox::title {{ subcontrol-origin: margin; left: 8px; }}"
        )
        _cb_style = f"QCheckBox {{ color: {c.TEXT_MAIN}; font-size: 13px; }}"

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(
            Qt.AlignmentFlag.AlignRight
        )

        # --- Betriebssysteme (Mehrfachauswahl) ---
        grp_os = QGroupBox("Betriebssysteme")
        grp_os.setStyleSheet(_group_style)
        grp_os_layout = QVBoxLayout(grp_os)
        grp_os_layout.setSpacing(4)
        for os_name in BETRIEBSSYSTEME_OPTIONEN:
            cb = QCheckBox(os_name)
            cb.setStyleSheet(_cb_style)
            grp_os_layout.addWidget(cb)
            self._cb_betriebssysteme[os_name] = cb
        inner_layout.addWidget(grp_os)

        # OS Patch-Stand
        self._input_patch_stand = QLineEdit()
        self._input_patch_stand.setPlaceholderText("z.B. Windows 11 23H2, automatisch")
        self._input_patch_stand.setMaxLength(MAX_TEXT_LENGTH)
        self._input_patch_stand.setStyleSheet(_input_style)
        form.addRow(
            self._make_label("OS Patch-Stand", _lbl_style), self._input_patch_stand
        )

        # --- Antivirus ---
        self._input_av_name = QLineEdit()
        self._input_av_name.setPlaceholderText("z.B. Windows Defender, ESET")
        self._input_av_name.setMaxLength(MAX_TEXT_LENGTH)
        self._input_av_name.setStyleSheet(_input_style)
        form.addRow(self._make_label("Antivirus", _lbl_style), self._input_av_name)

        self._combo_av_status = QComboBox()
        self._combo_av_status.addItems(STATUS_OPTIONEN)
        self._combo_av_status.setStyleSheet(_combo_style)
        form.addRow(self._make_label("AV-Status", _lbl_style), self._combo_av_status)

        # --- Firewall ---
        self._input_fw_name = QLineEdit()
        self._input_fw_name.setPlaceholderText("z.B. Windows Firewall, pfSense")
        self._input_fw_name.setMaxLength(MAX_TEXT_LENGTH)
        self._input_fw_name.setStyleSheet(_input_style)
        form.addRow(self._make_label("Firewall", _lbl_style), self._input_fw_name)

        self._combo_fw_status = QComboBox()
        self._combo_fw_status.addItems(STATUS_OPTIONEN)
        self._combo_fw_status.setStyleSheet(_combo_style)
        form.addRow(self._make_label("FW-Status", _lbl_style), self._combo_fw_status)

        inner_layout.addLayout(form)

        # --- Verschlüsselung (Mehrfachauswahl) ---
        grp_enc = QGroupBox("Verschlüsselung")
        grp_enc.setStyleSheet(_group_style)
        grp_enc_layout = QVBoxLayout(grp_enc)
        grp_enc_layout.setSpacing(4)
        for enc in VERSCHLUESSELUNG_OPTIONEN:
            cb = QCheckBox(enc)
            cb.setStyleSheet(_cb_style)
            grp_enc_layout.addWidget(cb)
            self._cb_verschluesselung[enc] = cb
        inner_layout.addWidget(grp_enc)

        form2 = QFormLayout()
        form2.setSpacing(8)
        form2.setLabelAlignment(
            Qt.AlignmentFlag.AlignRight
        )

        # VPN
        self._input_vpn = QLineEdit()
        self._input_vpn.setPlaceholderText("z.B. OpenVPN, WireGuard, Keine")
        self._input_vpn.setMaxLength(MAX_TEXT_LENGTH)
        self._input_vpn.setStyleSheet(_input_style)
        form2.addRow(self._make_label("VPN-Lösung", _lbl_style), self._input_vpn)

        # Browser
        self._input_browser = QLineEdit()
        self._input_browser.setPlaceholderText("z.B. Chrome 122, Firefox 124")
        self._input_browser.setMaxLength(MAX_TEXT_LENGTH)
        self._input_browser.setStyleSheet(_input_style)
        form2.addRow(self._make_label("Browser", _lbl_style), self._input_browser)

        # Server-Infrastruktur
        self._input_server = QLineEdit()
        self._input_server.setPlaceholderText("z.B. On-Premise, Cloud (Azure), Hybrid")
        self._input_server.setMaxLength(MAX_TEXT_LENGTH)
        self._input_server.setStyleSheet(_input_style)
        form2.addRow(self._make_label("Server", _lbl_style), self._input_server)

        inner_layout.addLayout(form2)

        # --- Remote-Access-Tools (Mehrfachauswahl) ---
        grp_ra = QGroupBox("Remote-Access-Tools")
        grp_ra.setStyleSheet(_group_style)
        grp_ra_layout = QVBoxLayout(grp_ra)
        grp_ra_layout.setSpacing(4)
        for tool in REMOTE_ACCESS_OPTIONEN:
            cb = QCheckBox(tool)
            cb.setStyleSheet(_cb_style)
            grp_ra_layout.addWidget(cb)
            self._cb_remote_access[tool] = cb
        inner_layout.addWidget(grp_ra)

        inner_layout.addStretch()
        scroll.setWidget(inner)
        root.addWidget(scroll)

        # Tab-Reihenfolge (F4) — Text-/Dropdown-Felder in logischer Folge.
        for prev, nxt in (
            (self._input_patch_stand, self._input_av_name),
            (self._input_av_name, self._combo_av_status),
            (self._combo_av_status, self._input_fw_name),
            (self._input_fw_name, self._combo_fw_status),
            (self._combo_fw_status, self._input_vpn),
            (self._input_vpn, self._input_browser),
            (self._input_browser, self._input_server),
        ):
            QWidget.setTabOrder(prev, nxt)

    @staticmethod
    def _make_label(text: str, style: str) -> QLabel:
        """Erstellt ein Formular-Label.

        Args:
            text: Label-Text.
            style: QSS-Stylesheet.

        Returns:
            Formatiertes QLabel.
        """
        lbl = QLabel(text)
        lbl.setStyleSheet(style)
        return lbl

    def _checked_items(self, checkboxes: dict[str, QCheckBox]) -> list[str]:
        """Gibt alle aktivierten Checkbox-Werte zurück.

        Args:
            checkboxes: Dict von Label → QCheckBox.

        Returns:
            Liste der ausgewählten Optionen.
        """
        return [name for name, cb in checkboxes.items() if cb.isChecked()]

    def is_valid(self) -> bool:
        """Schritt ist immer gültig (keine Pflichtfelder).

        Returns:
            True.
        """
        return True

    def get_data(self) -> InfrastructureData:
        """Gibt die eingegebenen Infrastruktur-Daten zurück.

        Returns:
            InfrastructureData mit den Formularwerten.
        """
        return InfrastructureData(
            betriebssysteme=self._checked_items(self._cb_betriebssysteme),
            os_patch_stand=sanitize_text(self._input_patch_stand.text().strip()),
            antivirus_name=sanitize_text(self._input_av_name.text().strip()),
            antivirus_status=self._combo_av_status.currentText(),
            firewall_name=sanitize_text(self._input_fw_name.text().strip()),
            firewall_status=self._combo_fw_status.currentText(),
            verschluesselung=self._checked_items(self._cb_verschluesselung),
            vpn_loesung=sanitize_text(self._input_vpn.text().strip()),
            browser=sanitize_text(self._input_browser.text().strip()),
            server_infrastruktur=sanitize_text(self._input_server.text().strip()),
            remote_access_tools=self._checked_items(self._cb_remote_access),
        )

    def set_data(self, data: InfrastructureData) -> None:
        """Befüllt das Formular mit vorhandenen Daten.

        Args:
            data: Vorhandene InfrastructureData.
        """
        for name, cb in self._cb_betriebssysteme.items():
            cb.setChecked(name in data.betriebssysteme)
        self._input_patch_stand.setText(data.os_patch_stand)
        self._input_av_name.setText(data.antivirus_name)
        idx = self._combo_av_status.findText(data.antivirus_status)
        if idx >= 0:
            self._combo_av_status.setCurrentIndex(idx)
        self._input_fw_name.setText(data.firewall_name)
        idx = self._combo_fw_status.findText(data.firewall_status)
        if idx >= 0:
            self._combo_fw_status.setCurrentIndex(idx)
        for name, cb in self._cb_verschluesselung.items():
            cb.setChecked(name in data.verschluesselung)
        self._input_vpn.setText(data.vpn_loesung)
        self._input_browser.setText(data.browser)
        self._input_server.setText(data.server_infrastruktur)
        for name, cb in self._cb_remote_access.items():
            cb.setChecked(name in data.remote_access_tools)

    # ------------------------------------------------------------------
    # Phase 3 — gemessene Vorbefuellung (nur SELF)
    # ------------------------------------------------------------------

    def _on_prefill_toggled(self, _state) -> None:  # noqa: ANN001
        """Checkbox-Handler: Messung anfordern (an) bzw. Sperre aufheben (aus)."""
        if self._chk_prefill.isChecked():
            self.prefill_requested.emit(self)
        else:
            self._clear_measured()

    def set_prefill_available(self, available: bool) -> None:
        """Gibt die gemessene Vorbefuellung nur im Selbst-Audit frei.

        Spiegelt:meth:`BackupStep.set_detection_available`: im CUSTOMER-Modus
        (``available=False``) wird die Checkbox deaktiviert, abgehakt und jede
        bereits uebernommene Messung zurueckgesetzt — ein Fremd-Audit darf keine
        Eigenscan-Daten des Beraterrechners tragen (fail-closed GUI-Sperre; die
        autoritative Sperre sitzt in der Use-Case-Assertion).

        Args:
            available: ``True`` (SELF) gibt frei; ``False`` (CUSTOMER) sperrt +
                setzt bereits uebernommene Mess-Werte HART zurueck.
        """
        self._prefill_available = available
        if not available:
            # CUSTOMER: gemessene Eigenscan-Werte HART zuruecksetzen (nicht nur
            # entsperren) — sie duerfen nicht in ein Fremd-Audit gelangen. ERST
            # zuruecksetzen (solange _measured_widgets befuellt ist), DANN abhaken;
            # setChecked(False) loest sonst _on_prefill_toggled -> _clear_measured
            # OHNE Reset aus und wuerde die Liste vorzeitig leeren.
            self._clear_measured(reset_values=True)
            self._chk_prefill.setChecked(False)
        self._chk_prefill.setEnabled(available)
        self._chk_prefill.setToolTip(
            ""
            if available
            else "Im Kunden-Audit nicht verfuegbar — die Messung laeuft auf dem "
            "Beraterrechner, nicht beim Mandanten."
        )

    def set_prefill_loading(self, loading: bool) -> None:
        """Zeigt waehrend des Hintergrund-Scans einen Lade-Hinweis an.

        Args:
            loading: ``True`` blendet "Messung laeuft …" ein und sperrt die
                Checkbox; ``False`` gibt die Checkbox wieder frei.
        """
        if loading:
            self._chk_prefill.setEnabled(False)
            self._lbl_prefill.setText("Messung laeuft … (Hardening-Scan)")
            self._lbl_prefill.show()
        else:
            # Nur freigeben, wenn nicht durch den CUSTOMER-Gate gesperrt
            # (Mode-Wechsel mid-scan fail-closed).
            self._chk_prefill.setEnabled(self._prefill_available)

    def notify_prefill_failed(self, reason: str) -> None:
        """Meldet einen fehlgeschlagenen/nicht verfuegbaren Scan (fail-soft).

        Args:
            reason: Kurzer Grund (z. B. Exception-Klassenname).
        """
        self._chk_prefill.setChecked(False)
        self._chk_prefill.setEnabled(self._prefill_available)
        self._lbl_prefill.setText(
            f"Messung nicht moeglich ({reason}) — bitte manuell ausfuellen."
        )
        self._lbl_prefill.show()

    def apply_prefill(self, prefill: AuditPrefill) -> None:
        """Uebernimmt gemessene Werte read-only + zeigt den Herkunfts-Badge.

        Nur messbare Felder werden gesetzt + gesperrt; nicht messbare bleiben
        unveraendert editierbar. Zum Aendern entfernt der Nutzer den
        Haken (``_on_prefill_toggled`` →:meth:`_clear_measured`, „ueberschreibbar").

        Fail-closed: ist die Vorbefuellung gesperrt (CUSTOMER, z. B. verspaeteter
        Worker-Callback nach Mode-Wechsel mid-scan), passiert NICHTS.

        Args:
            prefill: Der gemessene:class:`AuditPrefill`-Snapshot.
        """
        if not self._prefill_available:
            return
        self._clear_measured()
        date = fmt_iso_date(prefill.generated_at)
        applied: list[str] = []

        fw = prefill.firewall_active
        if fw is not None:
            val = "aktiv" if fw.value else "inaktiv"
            self._set_combo_measured(self._combo_fw_status, val, fw)
            applied.append(f"Firewall {val}")

        os_field = prefill.os_name
        if os_field is not None and isinstance(os_field.value, str):
            option = match_os_option(os_field.value)
            if option is not None:
                self._set_group_cb_measured(
                    self._cb_betriebssysteme, option, True, os_field
                )
                applied.append(option)

        patch = prefill.patch_ok
        if patch is not None:
            txt = (
                "Windows-Update funktionsfaehig"
                if patch.value
                else "Windows-Update nicht aktuell"
            )
            self._set_line_measured(self._input_patch_stand, txt, patch)
            applied.append("Patch " + ("ok" if patch.value else "pruefen"))

        enc = prefill.disk_encryption_active
        if enc is not None and enc.value:
            # Nur ergaenzen wenn BitLocker positiv aktiv gemessen wurde —
            # „BitLocker aus" sagt nichts ueber andere Verschluesselung
            # (VeraCrypt/FileVault) aus und darf eine manuelle Eingabe nicht
            # ueberschreiben (Spec: nur ergaenzen wenn truthy).
            self._set_group_cb_measured(self._cb_verschluesselung, "BitLocker", True, enc)
            applied.append("BitLocker aktiv")

        rdp = prefill.remote_access_rdp
        if rdp is not None and rdp.value:
            # Nur ergaenzen wenn RDP positiv erkannt (exposed/in Nutzung) —
            # „kein RDP-Listener" beweist keine Nicht-Nutzung und ueberschreibt
            # keine manuelle Eingabe (Spec: nur ergaenzen wenn truthy).
            self._set_group_cb_measured(self._cb_remote_access, "RDP", True, rdp)
            applied.append("RDP in Nutzung")

        if applied:
            self._lbl_prefill.setText(
                f"Gemessen am {date}: "
                + " · ".join(applied)
                + ". Zum Aendern den Haken entfernen."
            )
        else:
            self._chk_prefill.setChecked(False)
            self._lbl_prefill.setText(
                "Keine Werte messbar (z.B. kein Windows / fehlende Rechte)."
            )
        self._lbl_prefill.show()

    def _set_combo_measured(self, combo: QComboBox, value: str, field) -> None:  # noqa: ANN001
        """Setzt eine QComboBox auf den gemessenen Wert + sperrt sie."""
        idx = combo.findText(value)
        if idx >= 0:
            combo.setCurrentIndex(idx)
        combo.setEnabled(False)
        combo.setToolTip(origin_tooltip(field))
        self._measured_widgets.append(combo)

    def _set_line_measured(self, line: QLineEdit, text: str, field) -> None:  # noqa: ANN001
        """Setzt ein QLineEdit auf den gemessenen Text + macht es read-only."""
        line.setText(text)
        line.setReadOnly(True)
        line.setToolTip(origin_tooltip(field))
        self._measured_widgets.append(line)

    def _set_group_cb_measured(
        self,
        group: dict[str, QCheckBox],
        key: str,
        checked: bool,
        field,  # noqa: ANN001
    ) -> None:
        """Setzt eine Gruppen-Checkbox auf den gemessenen Stand + sperrt nur sie."""
        cb = group.get(key)
        if cb is None:
            return
        cb.setChecked(checked)
        cb.setEnabled(False)
        cb.setToolTip(origin_tooltip(field))
        self._measured_widgets.append(cb)

    def _clear_measured(self, reset_values: bool = False) -> None:
        """Hebt alle vom Prefill gesperrten Widgets wieder auf (Override/Reset).

        Args:
            reset_values: ``False`` (Override durch Haken-Entfernen im SELF-Modus)
                behaelt die gemessenen Werte (read-only → editierbar,
                „ueberschreibbar"). ``True`` (CUSTOMER-Gate) setzt die
                gemessenen Felder HART auf ihren neutralen Default zurueck —
                Eigenscan-Werte duerfen nicht in ein Fremd-Audit gelangen
                (fail-closed).
        """
        for widget in self._measured_widgets:
            if reset_values:
                if widget is self._combo_fw_status:
                    widget.setCurrentText("unbekannt")
                elif widget is self._input_patch_stand:
                    widget.setText("")
                elif isinstance(widget, QCheckBox):
                    widget.setChecked(False)
            widget.setEnabled(True)
            if isinstance(widget, QLineEdit):
                widget.setReadOnly(False)
            widget.setToolTip("")
        self._measured_widgets = []
        self._lbl_prefill.hide()
        self._lbl_prefill.setText("")
