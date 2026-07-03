"""
network_step — Schritt 4: Netzwerksicherheit.

Erfasst Segmentierung, WLAN, offene Ports, IDS/IPS, letzter Pentest.

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
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.customer_audit.domain.entities import (
    JA_NEIN_EINFACH,
    JA_NEIN_OPTIONEN,
    WLAN_OPTIONEN,
    NetworkData,
    sanitize_text,
)
from tools.customer_audit.gui.step_widgets import field_styles
from tools.customer_audit.gui.step_widgets.prefill_helpers import (
    fmt_iso_date,
    origin_tooltip,
)

if TYPE_CHECKING:
    from core.scan_prefill.models import AuditPrefill


class NetworkStep(QWidget):
    """Wizard-Schritt 4: Netzwerksicherheit."""

    #: Emittiert (mit ``self``), wenn der Nutzer den gemessenen Netzwerk-Scan
    #: uebernehmen will (nur SELF Phase 3).
    prefill_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert den Schritt.

        Args:
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        # Phase 3: vom Prefill gesperrte Widgets (fuer Override/Reset).
        self._measured_widgets: list[QWidget] = []
        # SELF-only-Gate: im CUSTOMER-Modus False -> kein Prefill.
        self._prefill_available = True
        self._build_ui()

    def _build_ui(self) -> None:
        """Baut das Formular-Layout auf."""
        c = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        hdr = QLabel("Netzwerksicherheit")
        hdr.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway;"
            " font-weight: 700; font-size: 14px;"
        )
        root.addWidget(hdr)

        # --- Phase 3: gemessene Vorbefuellung (nur SELF, Muster B) ---
        self._chk_prefill = QCheckBox(
            "Gemessenen Netzwerk-Scan uebernehmen (offene Ports erfasst)"
        )
        self._chk_prefill.setStyleSheet(
            f"QCheckBox {{ color: {c.TEXT_MAIN}; font-size: 13px; }}"
        )
        self._chk_prefill.stateChanged.connect(self._on_prefill_toggled)
        root.addWidget(self._chk_prefill)

        self._lbl_prefill = QLabel("")
        # Herkunfts-/Mess-Text — PlainText (nie Auto-RichText R22).
        self._lbl_prefill.setTextFormat(Qt.TextFormat.PlainText)
        self._lbl_prefill.setStyleSheet(field_styles.origin_badge_style())
        self._lbl_prefill.setWordWrap(True)
        self._lbl_prefill.hide()
        root.addWidget(self._lbl_prefill)

        # geteilte Feld-Styles (einheitliche Fokus-Hervorhebung +
        # feste Dropdown-Breite) statt pro-Step dupliziertem QSS.
        _combo_style = field_styles.combo_style()
        _input_style = field_styles.input_style()
        _lbl_style = f"color: {c.TEXT_MAIN}; font-size: 13px;"

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(
            Qt.AlignmentFlag.AlignRight
        )

        # Netzwerksegmentierung
        self._combo_segmentierung = QComboBox()
        self._combo_segmentierung.addItems(JA_NEIN_OPTIONEN)
        self._combo_segmentierung.setCurrentText("Nein")
        self._combo_segmentierung.setStyleSheet(_combo_style)
        form.addRow(
            self._make_label("Netzwerksegmentierung", _lbl_style),
            self._combo_segmentierung,
        )

        # WLAN-Sicherheit
        self._combo_wlan = QComboBox()
        self._combo_wlan.addItems(WLAN_OPTIONEN)
        self._combo_wlan.setCurrentText("Unbekannt")
        self._combo_wlan.setStyleSheet(_combo_style)
        form.addRow(self._make_label("WLAN-Sicherheit", _lbl_style), self._combo_wlan)

        # Offene Ports bekannt
        self._combo_ports = QComboBox()
        self._combo_ports.addItems(JA_NEIN_EINFACH)
        self._combo_ports.setCurrentText("Nein")
        self._combo_ports.setStyleSheet(_combo_style)
        form.addRow(
            self._make_label("Offene Ports bekannt", _lbl_style), self._combo_ports
        )

        # IDS/IPS vorhanden
        self._combo_ids = QComboBox()
        self._combo_ids.addItems(JA_NEIN_EINFACH)
        self._combo_ids.setCurrentText("Nein")
        self._combo_ids.setStyleSheet(_combo_style)
        form.addRow(self._make_label("IDS/IPS vorhanden", _lbl_style), self._combo_ids)

        # Letzter Pentest
        self._input_pentest = QLineEdit()
        self._input_pentest.setPlaceholderText("z.B. 2023, Nie, Unbekannt")
        self._input_pentest.setMaxLength(50)
        self._input_pentest.setStyleSheet(_input_style)
        form.addRow(
            self._make_label("Letzter Pentest", _lbl_style), self._input_pentest
        )

        root.addLayout(form)
        root.addStretch()

        # Tab-Reihenfolge (F4) — logische Feld-Folge explizit setzen.
        for prev, nxt in (
            (self._combo_segmentierung, self._combo_wlan),
            (self._combo_wlan, self._combo_ports),
            (self._combo_ports, self._combo_ids),
            (self._combo_ids, self._input_pentest),
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

    def is_valid(self) -> bool:
        """Schritt ist immer gültig.

        Returns:
            True.
        """
        return True

    def get_data(self) -> NetworkData:
        """Gibt die eingegebenen Netzwerk-Daten zurück.

        Returns:
            NetworkData mit den Formularwerten.
        """
        return NetworkData(
            netzwerksegmentierung=self._combo_segmentierung.currentText(),
            wlan_sicherheit=self._combo_wlan.currentText(),
            offene_ports_bekannt=self._combo_ports.currentText(),
            ids_ips_vorhanden=self._combo_ids.currentText(),
            letzter_pentest=sanitize_text(self._input_pentest.text().strip())
            or "Unbekannt",
        )

    def set_data(self, data: NetworkData) -> None:
        """Befüllt das Formular mit vorhandenen Daten.

        Args:
            data: Vorhandene NetworkData.
        """
        _combos = [
            (self._combo_segmentierung, data.netzwerksegmentierung),
            (self._combo_wlan, data.wlan_sicherheit),
            (self._combo_ports, data.offene_ports_bekannt),
            (self._combo_ids, data.ids_ips_vorhanden),
        ]
        for combo, value in _combos:
            idx = combo.findText(value)
            if idx >= 0:
                combo.setCurrentIndex(idx)
        pentest = data.letzter_pentest
        self._input_pentest.setText("" if pentest == "Unbekannt" else pentest)

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

        Spiegelt:meth:`BackupStep.set_detection_available` (fail-closed GUI-
        Sperre im CUSTOMER-Modus; autoritativ via Use-Case-Assertion).

        Args:
            available: ``True`` (SELF) gibt frei; ``False`` (CUSTOMER) sperrt +
                setzt einen bereits uebernommenen Mess-Wert HART zurueck.
        """
        self._prefill_available = available
        if not available:
            # CUSTOMER: gemessenen Wert HART zuruecksetzen (nicht nur entsperren) —
            # kein Eigenscan-Wert in ein Fremd-Audit, fail-closed). ERST
            # zuruecksetzen, DANN abhaken (setChecked(False) wuerde sonst via
            # _on_prefill_toggled -> _clear_measured ohne Reset vorzeitig leeren).
            self._clear_measured(reset_values=True)
            self._chk_prefill.setChecked(False)
        self._chk_prefill.setEnabled(available)
        self._chk_prefill.setToolTip(
            ""
            if available
            else "Im Kunden-Audit nicht verfuegbar — der Netzwerk-Scan laeuft "
            "auf dem Beraterrechner, nicht beim Mandanten."
        )

    def set_prefill_loading(self, loading: bool) -> None:
        """Zeigt waehrend des Hintergrund-Scans einen Lade-Hinweis an."""
        if loading:
            self._chk_prefill.setEnabled(False)
            self._lbl_prefill.setText("Messung laeuft …")
            self._lbl_prefill.show()
        else:
            # Nur freigeben, wenn nicht durch den CUSTOMER-Gate gesperrt.
            self._chk_prefill.setEnabled(self._prefill_available)

    def notify_prefill_failed(self, reason: str) -> None:
        """Meldet einen fehlgeschlagenen/nicht verfuegbaren Scan (fail-soft)."""
        self._chk_prefill.setChecked(False)
        self._chk_prefill.setEnabled(self._prefill_available)
        self._lbl_prefill.setText(
            f"Messung nicht moeglich ({reason}) — bitte manuell ausfuellen."
        )
        self._lbl_prefill.show()

    def apply_prefill(self, prefill: AuditPrefill) -> None:
        """Uebernimmt die gemessene Netzwerk-Scan-Praesenz read-only + Badge.

        ``open_ports_scanned`` (mind. ein Netzwerk-Scan liegt vor) → setzt
        ``Offene Ports bekannt`` auf „Ja" + sperrt das Feld. Kein Scan → Hinweis.
        Zum Aendern den Haken entfernen (``_clear_measured``, „ueberschreibbar").

        Fail-closed: ist die Vorbefuellung gesperrt (CUSTOMER), passiert NICHTS.

        Args:
            prefill: Der gemessene:class:`AuditPrefill`-Snapshot.
        """
        if not self._prefill_available:
            return
        self._clear_measured()
        field = prefill.open_ports_scanned
        if field is None or not field.value:
            self._chk_prefill.setChecked(False)
            self._lbl_prefill.setText(
                "Kein Netzwerk-Scan vorhanden — bitte manuell ausfuellen "
                "(Netzwerk-Scanner ausfuehren)."
            )
            self._lbl_prefill.show()
            return
        idx = self._combo_ports.findText("Ja")
        if idx >= 0:
            self._combo_ports.setCurrentIndex(idx)
        self._combo_ports.setEnabled(False)
        self._combo_ports.setToolTip(origin_tooltip(field))
        self._measured_widgets.append(self._combo_ports)
        self._lbl_prefill.setText(
            f"Gemessen am {fmt_iso_date(prefill.generated_at)}: offene Ports "
            "erfasst (Netzwerk-Scan vorhanden). Zum Aendern den Haken entfernen."
        )
        self._lbl_prefill.show()

    def _clear_measured(self, reset_values: bool = False) -> None:
        """Hebt die vom Prefill gesperrten Widgets wieder auf (Override/Reset).

        Args:
            reset_values: ``False`` (Override im SELF-Modus) behaelt den Wert;
                ``True`` (CUSTOMER-Gate) setzt ``Offene Ports bekannt`` HART auf
                den Default „Nein" zurueck — kein Eigenscan-Wert in ein Fremd-Audit
, fail-closed).
        """
        for widget in self._measured_widgets:
            if reset_values and widget is self._combo_ports:
                widget.setCurrentText("Nein")
            widget.setEnabled(True)
            widget.setToolTip("")
        self._measured_widgets = []
        self._lbl_prefill.hide()
        self._lbl_prefill.setText("")
