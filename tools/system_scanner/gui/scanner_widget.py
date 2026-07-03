"""
scanner_widget — PySide6 Widget für den lokalen Software-Scanner.

Zeigt einen "Scan starten"-Button, Fortschrittsbalken während des Scans
und nach Abschluss ein Übersichts-Dashboard mit OS-, Antivirus-,
Firewall-, Verschlüsselungs- und Browser-Status.

Der Scan läuft in einem QThread — kein UI-Freeze.

Schichtzugehörigkeit: gui/ — keine Business-Logik.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QThread, Signal, Slot
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog
from core.export import export_actions
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.system_scanner.application.bitlocker_compliance import (
    BitLockerComplianceLevel,
    BitLockerComplianceService,
)
from tools.system_scanner.application.manual_entry_service import (
    ManualEntryService,
)
from tools.system_scanner.application.scan_history_use_case import ScanHistoryUseCase
from tools.system_scanner.application.scan_use_case import ScanUseCase
from tools.system_scanner.application.system_compliance_service import (
    LicenseStatus,
    SystemComplianceService,
)
from tools.system_scanner.application.system_exporter import SystemExporter
from tools.system_scanner.domain.entities import (
    ManualScannerEntry,
    ScanResult,
    SecurityComponent,
)
from tools.system_scanner.domain.enums import ComponentStatus, ComponentType
from tools.system_scanner.gui.manual_entry_dialog import ManualEntryDialog

log = get_logger(__name__)

# Kategorien die "Manuell hinzufügen" unterstützen.
_MANUAL_CATEGORIES: tuple[ComponentType, ...] = (
    ComponentType.ANTIVIRUS,
    ComponentType.FIREWALL,
    ComponentType.ENCRYPTION,
)

# ---------------------------------------------------------------------------
# Status-Farben (Ampel) — aus theme.py
# ---------------------------------------------------------------------------


def _status_color(status: ComponentStatus) -> str:
    """Gibt die Ampel-Farbe für einen Status zurück.

    Args:
        status: ComponentStatus.

    Returns:
        Hex-Farbstring aus dem aktiven Theme.
    """
    if status == ComponentStatus.ACTIVE:
        return theme.SUCCESS
    if status == ComponentStatus.INACTIVE:
        return theme.ERROR
    if status == ComponentStatus.OUTDATED:
        return theme.WARNING
    if status == ComponentStatus.RISK:
        return theme.WARNING
    return theme.TEXT_DIM


def _status_icon(status: ComponentStatus) -> str:
    """Gibt das Material-Symbol für einen Status zurück.

    Args:
        status: ComponentStatus.

    Returns:
        Material Symbol Name.
    """
    if status == ComponentStatus.ACTIVE:
        return "check_circle"
    if status == ComponentStatus.INACTIVE:
        return "cancel"
    if status == ComponentStatus.OUTDATED:
        return "update"
    if status == ComponentStatus.RISK:
        return "warning"
    return "help"


def _component_type_icon(ctype: ComponentType) -> str:
    """Gibt das Material-Symbol für einen Komponenten-Typ zurück.

    Args:
        ctype: ComponentType.

    Returns:
        Material Symbol Name.
    """
    icons = {
        ComponentType.ANTIVIRUS: "security",
        ComponentType.FIREWALL: "shield",
        ComponentType.ENCRYPTION: "lock",
        ComponentType.BROWSER: "public",
        ComponentType.OS_UPDATE: "system_update",
        ComponentType.VPN: "vpn_key",
        ComponentType.PASSWORD_MANAGER: "password",
        ComponentType.REMOTE_ACCESS: "screen_share",
    }
    return icons.get(ctype, "device_unknown")


# ---------------------------------------------------------------------------
# QThread Worker
# ---------------------------------------------------------------------------


class _ScanWorker(QThread):
    """Führt den System-Scan in einem separaten Thread durch.

    Signals:
        scan_finished: Emittiert das ScanResult nach Abschluss.
        scan_error: Emittiert eine Fehlermeldung bei Ausnahmen.
        progress: Emittiert Fortschrittsschritte (0–100).
    """

    scan_finished: Signal = Signal(object)
    scan_error: Signal = Signal(str)
    progress: Signal = Signal(int)

    def __init__(self, use_case: ScanUseCase, parent: QWidget | None = None) -> None:
        """Initialisiert den Worker.

        Args:
            use_case: Scan-Use-Case-Instanz.
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._use_case = use_case

    def run(self) -> None:
        """Führt den Scan aus (in QThread)."""
        try:
            self.progress.emit(10)
            result = self._use_case.execute()
            self.progress.emit(100)
            self.scan_finished.emit(result)
        except RuntimeError as exc:
            self.scan_error.emit(str(exc))
        except Exception as exc:  # noqa: BLE001 -- Worker-Thread: jeder unbekannte Fehler muss in scan_error landen statt Thread sterben zu lassen
            self.scan_error.emit(f"Unbekannter Fehler: {exc}")


# ---------------------------------------------------------------------------
# Status-Karte für eine Sicherheitskomponente
# ---------------------------------------------------------------------------


class _ComponentCard(QFrame):
    """Karte für eine Sicherheitskomponente mit Ampel-Status.

    Zeigt Icon, Name, Status-Farbe und optionale Detailinformation.
    Bei manuellen Einträgen (``is_manual=True``) wird zusätzlich ein
    ``(manuell)``-Label und Edit/Delete-Buttons eingeblendet.
    """

    def __init__(
        self,
        component: SecurityComponent,
        is_manual: bool = False,
        on_edit: Callable[[], None] | None = None,
        on_delete: Callable[[], None] | None = None,
        parent: QWidget | None = None,
        neutral_reason: str | None = None,
    ) -> None:
        """Initialisiert die Karte.

        Args:
            component: Zu darstellende Sicherheitskomponente.
            is_manual: True wenn Eintrag manuell erfasst — blendet
                ``(manuell)``-Label und Edit/Delete ein.
            on_edit: Callback bei Klick auf Edit-Icon (nur bei manuell).
            on_delete: Callback bei Klick auf Delete-Icon (nur bei manuell).
            parent: Optionales Eltern-Widget.
            neutral_reason: — wenn gesetzt, wird die Karte NEUTRAL (statt
                rot) gezeigt + dieser Erklaerungstext eingeblendet. Genutzt fuer
                eine inaktive eingebaute Schutzsoftware (Windows Defender), die
                NUR deshalb inaktiv ist, weil ein anderes AV aktiv ist — das ist
                kein Befund, sondern Windows-Normalverhalten.
        """
        super().__init__(parent)
        self._build(
            component,
            is_manual=is_manual,
            on_edit=on_edit,
            on_delete=on_delete,
            neutral_reason=neutral_reason,
        )

    def _build(
        self,
        comp: SecurityComponent,
        is_manual: bool,
        on_edit: Callable[[], None] | None,
        on_delete: Callable[[], None] | None,
        neutral_reason: str | None = None,
    ) -> None:
        """Baut das Layout auf."""
        self.setObjectName("ComponentCard")
        # Mess-Neutralitaet — ein inaktiver eingebauter Schutz, der von
        # einer aktiven Drittsoftware abgeloest wird, ist kein roter Befund.
        color = (
            theme.SEVERITY_SIGNAL_INFO
            if neutral_reason
            else _status_color(comp.status)
        )
        self.setStyleSheet(
            f"""
            QFrame#ComponentCard {{
                background: {theme.CARD_BG};
                border: 1px solid {theme.BORDER};
                border-left: 4px solid {color};
                border-radius: 6px;
                padding: 4px;
            }}
            QPushButton#card_icon_btn {{
                background: transparent;
                border: none;
                padding: 4px;
            }}
            QPushButton#card_icon_btn:hover {{
                background: {theme.BG_INPUT};
                border-radius: 4px;
            }}
            """
        )

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(12)

        # Status-Dot
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {color}; font-size: 18px;")
        dot.setFixedWidth(20)
        layout.addWidget(dot)

        # Name + Detail
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)

        name_label = QLabel(comp.name)
        name_label.setStyleSheet(
            f"color: {theme.TEXT_MAIN}; font-family: Raleway; font-weight: 600;"
            " font-size: 13px;"
        )
        text_layout.addWidget(name_label)

        if is_manual:
            manual_label = QLabel("(manuell)")
            manual_label.setStyleSheet(
                f"color: {theme.TEXT_DIM}; font-family: Raleway; font-size: 11px;"
                " font-style: italic;"
            )
            text_layout.addWidget(manual_label)

        if comp.version:
            version_label = QLabel(comp.version)
            version_label.setStyleSheet(
                f"color: {theme.TEXT_DIM}; font-family: 'JetBrains Mono';"
                " font-size: 12px;"
            )
            text_layout.addWidget(version_label)

        if comp.detail:
            detail_label = QLabel(comp.detail)
            detail_label.setStyleSheet(
                f"color: {theme.TEXT_DIM}; font-size: 12px; font-style: italic;"
            )
            detail_label.setWordWrap(True)
            text_layout.addWidget(detail_label)

        if neutral_reason:
            reason_label = QLabel(neutral_reason)
            reason_label.setStyleSheet(
                f"color: {theme.TEXT_DIM}; font-size: 12px; font-style: italic;"
            )
            reason_label.setWordWrap(True)
            text_layout.addWidget(reason_label)

        layout.addLayout(text_layout)
        layout.addStretch()

        # Status-Text
        status_text = {
            ComponentStatus.ACTIVE: "Aktiv",
            ComponentStatus.INACTIVE: "Inaktiv",
            ComponentStatus.OUTDATED: "Veraltet",
            ComponentStatus.RISK: "Risiko",
            ComponentStatus.UNKNOWN: "Unbekannt",
        }.get(comp.status, "Unbekannt")

        status_label = QLabel(status_text)
        status_label.setStyleSheet(
            f"color: {color}; font-family: Raleway; font-weight: 700; font-size: 12px;"
        )
        layout.addWidget(status_label)

        if is_manual:
            edit_btn = QPushButton()
            edit_btn.setObjectName("card_icon_btn")
            edit_btn.setIcon(get_icon(Icons.EDIT))
            edit_btn.setToolTip("Eintrag bearbeiten")
            edit_btn.setFixedSize(28, 28)
            if on_edit is not None:
                edit_btn.clicked.connect(lambda _=False: on_edit())
            layout.addWidget(edit_btn)

            delete_btn = QPushButton()
            delete_btn.setObjectName("card_icon_btn")
            delete_btn.setIcon(get_icon(Icons.DELETE))
            delete_btn.setToolTip("Eintrag löschen")
            delete_btn.setFixedSize(28, 28)
            if on_delete is not None:
                delete_btn.clicked.connect(lambda _=False: on_delete())
            layout.addWidget(delete_btn)


# ---------------------------------------------------------------------------
# Hauptwidget
# ---------------------------------------------------------------------------


class SystemScannerWidget(QWidget):
    """Haupt-Widget des System-Scanners.

    Zeigt den "Scan starten"-Button, Fortschrittsbalken und nach
    Abschluss ein Dashboard mit allen Sicherheitskomponenten.
    """

    def __init__(
        self,
        scan_use_case: ScanUseCase,
        history_use_case: ScanHistoryUseCase,
        manual_entry_service: ManualEntryService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Widget.

        Args:
            scan_use_case: Use Case für den Scan-Vorgang.
            history_use_case: Use Case für den Scan-Verlauf.
            manual_entry_service: Service fuer manuell erfasste Eintraege
                (Antivirus/Firewall/Verschluesselung). Wird gelazy erzeugt
                wenn ``None``. (RUN2-GUI): Widget arbeitet ueber
                den Application-Layer-Service statt direkt gegen das
                Repository.
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._scan_use_case = scan_use_case
        self._history_use_case = history_use_case
        self._manual_service = manual_entry_service or ManualEntryService()
        self._worker: _ScanWorker | None = None
        self._last_result: ScanResult | None = None
        self._exporter = SystemExporter()
        self._build_ui()
        self._load_last_result()

    def _build_ui(self) -> None:
        """Baut das Haupt-Layout auf."""
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(16)

        # Header
        header_layout = QHBoxLayout()
        title = QLabel("System-Scanner")
        title.setStyleSheet(
            f"color: {theme.TEXT_MAIN}; font-family: Raleway;"
            " font-weight: 700; font-size: 20px;"
        )
        header_layout.addWidget(title)
        header_layout.addStretch()

        # Export-Buttons (initial versteckt bis Scan abgeschlossen)
        self._btn_json = QPushButton("JSON")
        self._btn_json.setIcon(get_icon(Icons.DATA_OBJECT))
        self._btn_json.setToolTip("Als JSON exportieren")
        self._btn_json.setStyleSheet(self._secondary_button_style())
        self._btn_json.clicked.connect(self._on_export_json)
        self._btn_json.setVisible(False)
        header_layout.addWidget(self._btn_json)

        self._btn_xlsx = QPushButton("Excel")
        self._btn_xlsx.setIcon(get_icon(Icons.TABLE_VIEW))
        self._btn_xlsx.setToolTip("Als Excel-Datei exportieren")
        self._btn_xlsx.setStyleSheet(self._secondary_button_style())
        self._btn_xlsx.clicked.connect(self._on_export_xlsx)
        self._btn_xlsx.setVisible(False)
        header_layout.addWidget(self._btn_xlsx)

        self._btn_pdf = QPushButton("PDF")
        self._btn_pdf.setIcon(get_icon(Icons.PDF))
        self._btn_pdf.setToolTip("Als PDF-Report exportieren")
        self._btn_pdf.setStyleSheet(self._secondary_button_style())
        self._btn_pdf.clicked.connect(self._on_export_pdf)
        self._btn_pdf.setVisible(False)
        header_layout.addWidget(self._btn_pdf)

        self._scan_btn = QPushButton("Scan starten")
        self._scan_btn.setStyleSheet(self._primary_button_style())
        self._scan_btn.clicked.connect(self._start_scan)
        header_layout.addWidget(self._scan_btn)

        _tip_scan = self._help_tip("btn_scan")
        if _tip_scan:
            header_layout.addWidget(HelpButton(_tip_scan))

        root.addLayout(header_layout)

        _hc = HelpRegistry.get("system_scanner")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            self._help_panel.open_full_help.connect(self._open_help_dialog)
            root.addWidget(self._help_panel)

        # Beschreibung: outcome-orientiert — was der Scan liefert)
        desc = QLabel(
            "Erstellt einen lokalen Sicherheits-Überblick deines Systems: "
            "Status von Antivirus, Firewall, Verschlüsselung (BitLocker), "
            "Benutzerkonten und Betriebssystem-Updates — in rund 30–60 "
            "Sekunden, 100 % lokal."
        )
        desc.setStyleSheet(f"color: {theme.TEXT_DIM}; font-size: 13px;")
        desc.setWordWrap(True)
        root.addWidget(desc)

        # Fortschrittsbalken: kanonischer FinlaiProgressBar)
        self._progress = FinlaiProgressBar(total=100)
        self._progress.setVisible(False)
        root.addWidget(self._progress)

        # Status-Label
        self._status_label = QLabel("")
        self._status_label.setStyleSheet(
            f"color: {theme.TEXT_DIM}; font-size: 12px; font-style: italic;"
        )
        root.addWidget(self._status_label)

        # Trennlinie
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"color: {theme.BORDER};")
        root.addWidget(line)

        # Ergebnis-Bereich (scrollbar)
        self._result_area = QScrollArea()
        self._result_area.setWidgetResizable(True)
        self._result_area.setFrameShape(QFrame.Shape.NoFrame)
        self._result_area.setStyleSheet("background: transparent;")

        self._result_widget = QWidget()
        self._result_layout = QVBoxLayout(self._result_widget)
        self._result_layout.setContentsMargins(0, 0, 0, 0)
        self._result_layout.setSpacing(8)
        self._result_layout.addStretch()

        self._result_area.setWidget(self._result_widget)
        root.addWidget(self._result_area)

    def _primary_button_style(self) -> str:
        """Gibt den Stylesheet für den primären Button zurück.

        Returns:
            QSS-String.
        """
        return (
            f"QPushButton {{"
            f"  background: {theme.ACCENT};"
            f"  color: {theme.BG_DARK};"
            f"  border: none;"
            f"  border-radius: 6px;"
            f"  padding: 8px 20px;"
            f"  font-family: Raleway;"
            f"  font-weight: 700;"
            f"  font-size: 13px;"
            f"}}"
            f"QPushButton:hover {{ background: {theme.ACCENT_DIM}; }}"
            f"QPushButton:disabled {{ background: {theme.BG_BUTTON_DISABLED};"
            f"  color: {theme.TEXT_BUTTON_DISABLED}; }}"
        )

    def _secondary_button_style(self) -> str:
        """Gibt den Stylesheet für den sekundären Button zurück.

        Returns:
            QSS-String.
        """
        return (
            f"QPushButton {{"
            f"  background: transparent;"
            f"  color: {theme.ACCENT};"
            f"  border: 1px solid {theme.ACCENT};"
            f"  border-radius: 6px;"
            f"  padding: 8px 20px;"
            f"  font-family: Raleway;"
            f"  font-weight: 600;"
            f"  font-size: 13px;"
            f"}}"
            f"QPushButton:hover {{ background: {theme.ACCENT_DARK}; color: {theme.BG_DARK}; }}"
        )

    def _load_last_result(self) -> None:
        """Lädt das letzte Scan-Ergebnis aus der Datenbank (falls vorhanden)."""
        try:
            result = self._history_use_case.get_latest()
            if result:
                self._last_result = result
                self._render_result(result)
                self._status_label.setText(
                    f"Letzter Scan: {result.timestamp.strftime('%d.%m.%Y %H:%M')}"
                )
        except (OSError, RuntimeError) as exc:
            self._status_label.setText(
                f"Letztes Ergebnis konnte nicht geladen werden: {exc}"
            )

    @Slot()
    def _start_scan(self) -> None:
        """Startet den Scan in einem QThread."""
        if self._worker and self._worker.isRunning():
            return

        self._scan_btn.setEnabled(False)
        self._btn_json.setVisible(False)
        self._btn_xlsx.setVisible(False)
        self._btn_pdf.setVisible(False)
        self._progress.setVisible(True)
        self._progress.setValue(10)
        self._status_label.setText("Scan läuft — bitte warten...")
        self._clear_result()

        self._worker = _ScanWorker(self._scan_use_case, self)
        self._worker.progress.connect(self._on_progress)
        self._worker.scan_finished.connect(self._on_scan_finished)
        self._worker.scan_error.connect(self._on_scan_error)
        self._worker.start()

    @Slot(int)
    def _on_progress(self, value: int) -> None:
        """Aktualisiert den Fortschrittsbalken.

        Args:
            value: Fortschrittswert 0–100.
        """
        self._progress.setValue(value)

    @Slot(object)
    def _on_scan_finished(self, result: ScanResult) -> None:
        """Verarbeitet das abgeschlossene Scan-Ergebnis.

        Args:
            result: Abgeschlossenes ScanResult.
        """
        self._last_result = result
        self._progress.setVisible(False)
        self._scan_btn.setEnabled(True)
        self._btn_json.setVisible(True)
        self._btn_xlsx.setVisible(True)
        self._btn_pdf.setVisible(True)
        n_components = len(result.security_components)
        duration = result.scan_duration_s
        self._status_label.setText(
            f"Scan abgeschlossen — {n_components} Komponenten erkannt ({duration:.1f}s)"
        )
        self._render_result(result)

    @Slot(str)
    def _on_scan_error(self, error_msg: str) -> None:
        """Zeigt eine Fehlermeldung bei Scan-Fehler.

        Args:
            error_msg: Fehlerbeschreibung.
        """
        self._progress.setVisible(False)
        self._scan_btn.setEnabled(True)
        self._status_label.setText(f"Scan fehlgeschlagen: {error_msg}")
        FinlaiInfoDialog(
            title="Scan fehlgeschlagen",
            message=error_msg,
            icon_name=Icons.ERROR,
            parent=self,
        ).exec()

    def _clear_result(self) -> None:
        """Löscht alle Widgets im Ergebnis-Bereich."""
        while self._result_layout.count() > 0:
            item = self._result_layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

    def _render_result(self, result: ScanResult) -> None:
        """Rendert das Scan-Ergebnis als Dashboard.

        Args:
            result: Zu darstellendes ScanResult.
        """
        self._clear_result()

        # OS-Info-Karte
        os_group = self._make_group("Betriebssystem")
        os_layout = QVBoxLayout()
        os_text = (
            f"{result.os_info.name}  |  Version: {result.os_info.version}"
            f"  |  Arch: {result.os_info.architecture}"
        )
        os_label = QLabel(os_text)
        os_label.setStyleSheet(
            f"color: {theme.TEXT_MAIN}; font-family: 'JetBrains Mono'; font-size: 13px;"
        )
        os_label.setWordWrap(True)
        os_layout.addWidget(os_label)
        os_group.setLayout(os_layout)
        self._result_layout.addWidget(os_group)

        # Iter 2f: Compliance-Banner (OS-EOL + Windows-Lizenz).
        # Wird stillschweigend uebersprungen, wenn der Service-Aufruf
        # fehlschlaegt — der Scan-Pfad darf nie crashen.
        try:
            compliance = SystemComplianceService().gather(result.os_info.name)
            self._add_compliance_banner(compliance)
        except Exception:  # noqa: BLE001 — Banner darf nie das Result blockieren
            log.exception("System-Compliance-Banner fehlgeschlagen")

        # Iter 3f: BitLocker-Recovery-Key-Audit.
        # Wird stillschweigend uebersprungen wenn die Probe nicht greift
        # (Non-Windows / kein Admin / kein BitLocker-Modul).
        try:
            bitlocker = BitLockerComplianceService().gather()
            self._add_bitlocker_banner(bitlocker)
        except Exception:  # noqa: BLE001
            log.exception("BitLocker-Banner fehlgeschlagen")

        # Sicherheitskomponenten gruppiert nach Typ
        type_order = [
            ComponentType.ANTIVIRUS,
            ComponentType.FIREWALL,
            ComponentType.ENCRYPTION,
            ComponentType.OS_UPDATE,
            ComponentType.BROWSER,
            ComponentType.VPN,
            ComponentType.PASSWORD_MANAGER,
            ComponentType.REMOTE_ACCESS,
        ]
        type_labels = {
            ComponentType.ANTIVIRUS: "Antivirus / EDR",
            ComponentType.FIREWALL: "Firewall",
            ComponentType.ENCRYPTION: "Verschlüsselung",
            ComponentType.OS_UPDATE: "Betriebssystem-Updates",
            ComponentType.BROWSER: "Browser",
            ComponentType.VPN: "VPN",
            ComponentType.PASSWORD_MANAGER: "Passwort-Manager",
            ComponentType.REMOTE_ACCESS: "Remote-Access (Risiko prüfen!)",
        }

        grouped: dict[ComponentType, list[SecurityComponent]] = {}
        for comp in result.security_components:
            grouped.setdefault(comp.type, []).append(comp)

        manual_by_category: dict[ComponentType, list[ManualScannerEntry]] = {
            ctype: self._load_manual_entries(ctype) for ctype in _MANUAL_CATEGORIES
        }

        for ctype in type_order:
            comps = grouped.get(ctype, [])
            manual_entries = manual_by_category.get(ctype, [])

            # Nicht-manuelle Kategorien: bisheriges Verhalten (leere überspringen).
            if ctype not in _MANUAL_CATEGORIES and not comps:
                continue

            group = self._make_group(type_labels.get(ctype, ctype.value))
            group_layout = QVBoxLayout()
            group_layout.setSpacing(6)

            # In der AV/EDR-Gruppe ist eine inaktive eingebaute
            # Schutzsoftware (Windows Defender) KEIN Problem, solange ein anderes
            # AV aktiv ist — Windows deaktiviert den eingebauten Schutz dann
            # automatisch. Neutral statt rot (Live-Test: Bitdefender aktiv ->
            # Defender inaktiv wirkte faelschlich wie eine Luecke).
            av_has_active = ctype == ComponentType.ANTIVIRUS and any(
                c.status == ComponentStatus.ACTIVE for c in comps
            )
            for comp in comps:
                neutral_reason = None
                if av_has_active and comp.status == ComponentStatus.INACTIVE:
                    neutral_reason = (
                        "Inaktiv, weil eine andere Schutzsoftware aktiv ist — "
                        "Windows deaktiviert den eingebauten Schutz dann "
                        "automatisch. Das ist kein Sicherheitsproblem."
                    )
                card = _ComponentCard(comp, neutral_reason=neutral_reason)
                group_layout.addWidget(card)

            for entry in manual_entries:
                sec_comp = entry.to_security_component()
                card = _ComponentCard(
                    sec_comp,
                    is_manual=True,
                    on_edit=lambda e=entry: self._on_edit_manual(e),
                    on_delete=lambda e=entry: self._on_delete_manual(e),
                )
                group_layout.addWidget(card)

            if ctype in _MANUAL_CATEGORIES and self._should_show_add_button(
                comps, manual_entries
            ):
                add_btn = QPushButton("Manuell hinzufügen")
                add_btn.setIcon(get_icon(Icons.ADD))
                add_btn.setStyleSheet(self._secondary_button_style())
                add_btn.clicked.connect(
                    lambda _=False, cat=ctype: self._on_add_manual(cat)
                )
                btn_row = QHBoxLayout()
                btn_row.addStretch()
                btn_row.addWidget(add_btn)
                _tip_manual = self._help_tip("btn_manual_add")
                if _tip_manual:
                    btn_row.addWidget(HelpButton(_tip_manual))
                group_layout.addLayout(btn_row)

            group.setLayout(group_layout)
            self._result_layout.addWidget(group)

        # Warnungen
        if result.warnings:
            warn_group = self._make_group("Hinweise / Warnungen")
            warn_layout = QVBoxLayout()
            for w in result.warnings:
                warn_label = QLabel(f"• {w}")
                warn_label.setStyleSheet(f"color: {theme.WARNING}; font-size: 12px;")
                warn_label.setWordWrap(True)
                warn_layout.addWidget(warn_label)
            warn_group.setLayout(warn_layout)
            self._result_layout.addWidget(warn_group)

        self._result_layout.addStretch()

    # ------------------------------------------------------------------
    # Manuelle Einträge
    # ------------------------------------------------------------------

    def _load_manual_entries(
        self, category: ComponentType
    ) -> list[ManualScannerEntry]:
        """Lädt manuelle Einträge einer Kategorie mit Fehler-Fallback."""
        try:
            return self._manual_service.get_all(category)
        except (OSError, RuntimeError) as exc:
            log.warning(
                "Manuelle Einträge für %s konnten nicht geladen werden: %s",
                category.value,
                exc,
            )
            return []

    @staticmethod
    def _should_show_add_button(
        comps: list[SecurityComponent],
        manual_entries: list[ManualScannerEntry],
    ) -> bool:
        """Ob der "Manuell hinzufügen"-Button in dieser Sektion erscheinen soll.

        User-Spec: sichtbar wenn Status = Unbekannt ODER Liste leer ist.
        """
        if not comps and not manual_entries:
            return True
        return any(c.status == ComponentStatus.UNKNOWN for c in comps)

    def _on_add_manual(self, category: ComponentType) -> None:
        """Öffnet den Dialog zum Anlegen eines neuen manuellen Eintrags."""
        dialog = ManualEntryDialog(category=category, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            entry = self._manual_service.add(dialog.result_entry())
        except (OSError, RuntimeError, ValueError) as exc:
            log.error("Manuellen Eintrag anlegen fehlgeschlagen: %s", exc)
            FinlaiInfoDialog(
                title="Hinzufügen fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        log.info("Manueller Eintrag angelegt: %s/%s", category.value, entry.name)
        self._rerender_last_result()

    def _on_edit_manual(self, entry: ManualScannerEntry) -> None:
        """Öffnet den Dialog zum Bearbeiten eines manuellen Eintrags."""
        dialog = ManualEntryDialog(
            category=entry.category, entry=entry, parent=self
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._manual_service.update(dialog.result_entry())
        except (OSError, RuntimeError, ValueError) as exc:
            log.error("Manuellen Eintrag aktualisieren fehlgeschlagen: %s", exc)
            FinlaiInfoDialog(
                title="Bearbeiten fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._rerender_last_result()

    def _on_delete_manual(self, entry: ManualScannerEntry) -> None:
        """Löscht einen manuellen Eintrag nach Rückfrage."""
        if entry.entry_id is None:
            return
        dlg = FinlaiConfirmDialog(
            title="Eintrag löschen?",
            message=f"Soll der Eintrag '{entry.name}' wirklich gelöscht werden?",
            confirm_text="Löschen",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._manual_service.delete(entry.entry_id)
        except (OSError, RuntimeError) as exc:
            log.error("Manuellen Eintrag löschen fehlgeschlagen: %s", exc)
            FinlaiInfoDialog(
                title="Löschen fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._rerender_last_result()

    def _rerender_last_result(self) -> None:
        """Rendert die UI neu mit dem letzten Scan + aktuellen manuellen Einträgen."""
        if self._last_result is not None:
            self._render_result(self._last_result)

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("system_scanner")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "system_scanner", parent=self.window()
        )
        dlg.show()

    def _add_compliance_banner(self, info) -> None:  # noqa: ANN001 — SystemComplianceInfo
        """Rendert OS-EOL + Lizenz-Status als Compliance-Karte.

        Iter 2f: wird nach der OS-Info-Karte
        eingeblendet. Auf Non-Windows mit unbekanntem OS erscheint nur
        ein dezenter "Compliance-Status unbekannt"-Eintrag.
        """
        group = self._make_group("Compliance-Status (ID.AM)")
        layout = QVBoxLayout()

        # OS-EOL-Zeile
        eol_color = theme.TEXT_MAIN
        if info.os_eol.is_eol:
            eol_color = theme.DANGER
        elif info.os_eol.is_expiring_soon:
            eol_color = getattr(theme, "WARNING", theme.ACCENT)
        eol_label = QLabel(f"OS-Lifecycle: {info.os_eol.headline}")
        eol_label.setStyleSheet(
            f"color: {eol_color}; font-family: 'JetBrains Mono'; "
            "font-size: 12px; padding: 2px 0;"
        )
        eol_label.setWordWrap(True)
        layout.addWidget(eol_label)

        if info.os_eol.matched_entry and info.os_eol.matched_entry.successor:
            successor_label = QLabel(
                f"Nachfolge: {info.os_eol.matched_entry.successor}"
            )
            successor_label.setStyleSheet(
                f"color: {theme.TEXT_DIM}; font-family: 'JetBrains Mono'; "
                "font-size: 11px; padding-left: 14px;"
            )
            layout.addWidget(successor_label)

        # Lizenz-Status
        lic_color = theme.TEXT_MAIN
        if info.license.status is LicenseStatus.LICENSED:
            lic_color = getattr(theme, "SUCCESS", theme.ACCENT)
        elif info.license.status in (
            LicenseStatus.NOT_APPLICABLE,
            LicenseStatus.UNKNOWN,
        ):
            # "nicht messbar" (Non-Windows ODER Probe-Timeout) wird
            # gedaempft gezeigt — kein roter Alarm fuer einen Mess-Fehlschlag.
            lic_color = theme.TEXT_DIM
        elif info.license.needs_attention:
            lic_color = theme.DANGER
        # "(Quelle: none)" weglassen — bei UNKNOWN/NOT_APPLICABLE ist das
        # verwirrend (es gibt keine echte Quelle).
        quelle = (
            f"  (Quelle: {info.license.source})"
            if info.license.source and info.license.source != "none"
            else ""
        )
        lic_label = QLabel(f"Windows-Lizenz: {info.license.message}{quelle}")
        lic_label.setStyleSheet(
            f"color: {lic_color}; font-family: 'JetBrains Mono'; "
            "font-size: 12px; padding: 2px 0;"
        )
        lic_label.setWordWrap(True)
        layout.addWidget(lic_label)

        group.setLayout(layout)
        self._result_layout.addWidget(group)

    def _add_bitlocker_banner(self, info) -> None:  # noqa: ANN001 — BitLockerComplianceInfo
        """Rendert den BitLocker-Recovery-Key-Audit als Compliance-Karte.

        Iter 3f: zeigt pro Volume die BitLocker-
        Bewertung (CRITICAL/WARNING/INFO/OK). Auf Non-Windows oder bei
        nicht-aufrufbarer Probe ein gedaempfter "nicht verfuegbar"-Hinweis.
        """
        if info.overall_level is BitLockerComplianceLevel.NOT_APPLICABLE:
            # Komplett ausblenden — auf Non-Windows hat das Banner keinen Wert.
            return

        group = self._make_group("BitLocker-Recovery-Key-Audit (PR.DS-1)")
        layout = QVBoxLayout()

        level_color = {
            BitLockerComplianceLevel.OK: getattr(theme, "SUCCESS", theme.ACCENT),
            BitLockerComplianceLevel.INFO: getattr(theme, "INFO", theme.ACCENT),
            BitLockerComplianceLevel.WARNING: getattr(
                theme, "WARNING", theme.ACCENT
            ),
            BitLockerComplianceLevel.UNKNOWN: theme.TEXT_DIM,
            BitLockerComplianceLevel.CRITICAL: theme.DANGER,
        }.get(info.overall_level, theme.TEXT_MAIN)

        headline = QLabel(info.banner_text)
        headline.setStyleSheet(
            f"color: {level_color}; font-family: 'JetBrains Mono'; "
            "font-size: 12px; padding: 2px 0;"
        )
        headline.setWordWrap(True)
        layout.addWidget(headline)

        # Detail-Zeilen pro Volume (max 5, sonst gibt's den Stream-Effekt).
        max_detail_rows = 5
        for assessment in info.assessments[:max_detail_rows]:
            row_color = {
                BitLockerComplianceLevel.OK: getattr(theme, "SUCCESS", theme.ACCENT),
                BitLockerComplianceLevel.INFO: getattr(theme, "INFO", theme.ACCENT),
                BitLockerComplianceLevel.WARNING: getattr(
                    theme, "WARNING", theme.ACCENT
                ),
                BitLockerComplianceLevel.CRITICAL: theme.DANGER,
                BitLockerComplianceLevel.UNKNOWN: theme.TEXT_DIM,
            }.get(assessment.level, theme.TEXT_DIM)
            row_label = QLabel(
                f"[{assessment.level.display_label}] {assessment.message}"
            )
            row_label.setStyleSheet(
                f"color: {row_color}; font-family: 'JetBrains Mono'; "
                "font-size: 11px; padding: 1px 0 1px 14px;"
            )
            row_label.setWordWrap(True)
            layout.addWidget(row_label)
        if len(info.assessments) > max_detail_rows:
            more = QLabel(
                f"... und {len(info.assessments) - max_detail_rows} "
                "weitere Volume(s)."
            )
            more.setStyleSheet(
                f"color: {theme.TEXT_DIM}; font-family: 'JetBrains Mono'; "
                "font-size: 11px; padding-left: 14px;"
            )
            layout.addWidget(more)

        # Quelle des Probe-Pfades (PowerShell vs. manage-bde) — Diagnose-Detail
        source_label = QLabel(f"Probe-Quelle: {info.report.source}")
        source_label.setStyleSheet(
            f"color: {theme.TEXT_DIM}; font-family: 'JetBrains Mono'; "
            "font-size: 10px; padding-left: 14px;"
        )
        layout.addWidget(source_label)

        group.setLayout(layout)
        self._result_layout.addWidget(group)

    def _make_group(self, title: str) -> QGroupBox:
        """Erstellt eine styled GroupBox.

        Args:
            title: Gruppenüberschrift.

        Returns:
            Formatierte QGroupBox.
        """
        group = QGroupBox(title)
        group.setStyleSheet(
            f"""
            QGroupBox {{
                color: {theme.ACCENT};
                font-family: Raleway;
                font-weight: 700;
                font-size: 13px;
                border: 1px solid {theme.BORDER};
                border-radius: 6px;
                margin-top: 8px;
                padding-top: 12px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 6px;
                left: 12px;
            }}
            """
        )
        return group

    def _build_export_result(self) -> ScanResult | None:
        """Baut ein ScanResult inkl. manueller Einträge für den Export.

        Manuelle Einträge werden als ``SecurityComponent`` mit
        ``detail="(manuell)"`` an die Komponentenliste angefügt, damit alle
        Exporter (JSON/Excel/PDF) sie automatisch mit rendern.

        Returns:
            Kopie des letzten ScanResults mit ergänzten manuellen Einträgen,
            oder ``None`` wenn kein Scan vorhanden ist.
        """
        if self._last_result is None:
            return None

        manual_components: list[SecurityComponent] = []
        for ctype in _MANUAL_CATEGORIES:
            for entry in self._load_manual_entries(ctype):
                comp = entry.to_security_component()
                comp.detail = "(manuell)"
                manual_components.append(comp)

        if not manual_components:
            return self._last_result

        merged = ScanResult.from_dict(self._last_result.to_dict())
        merged.security_components.extend(manual_components)
        return merged

    @Slot()
    def _on_export_json(self) -> None:
        """Exportiert das letzte Scan-Ergebnis + manuelle Einträge als JSON."""
        result = self._build_export_result()
        if result:
            export_actions.run_json_export(self._exporter, result, self)

    @Slot()
    def _on_export_xlsx(self) -> None:
        """Exportiert das letzte Scan-Ergebnis + manuelle Einträge als Excel."""
        result = self._build_export_result()
        if result:
            export_actions.run_xlsx_export(self._exporter, result, self)

    @Slot()
    def _on_export_pdf(self) -> None:
        """Exportiert das letzte Scan-Ergebnis + manuelle Einträge als PDF-Report."""
        result = self._build_export_result()
        if result:
            export_actions.run_pdf_export(self._exporter, result, self)

    def get_last_result(self) -> ScanResult | None:
        """Gibt das letzte Scan-Ergebnis zurück (für Assessment-Integration).

        Returns:
            Letztes ScanResult oder None.
        """
        return self._last_result
