"""
techstack_dialog — TechStack-Eingabedialog fuer Kundensysteme.

Sprint 6 Phase 1: Aus csaf_advisor_widget.py extrahiert.
Groesster der drei Dialog-Splits (~430 Zeilen). Komplexes Formular mit
Sektionen fuer OS, Sicherheitssoftware, Browser, Verschluesselung, VPN,
Remote-Access und Custom-Software.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Slot
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.security_scoring.domain.tech_stack.entities import TechStack

_OS_OPTIONS = ["Windows 10", "Windows 11", "Windows Server", "macOS", "Linux"]
_BROWSER_OPTIONS = ["Chrome", "Firefox", "Edge", "Safari", "Brave"]
_ENCRYPTION_OPTIONS = ["BitLocker", "FileVault", "LUKS", "VeraCrypt"]
_REMOTE_OPTIONS = ["TeamViewer", "AnyDesk", "RDP", "VNC", "SSH"]
_TOOL_STATI = ["aktiv", "inaktiv", "unbekannt"]


class TechStackDialog(QDialog):
    """Dialog zur Eingabe/Bearbeitung des Tech-Stacks eines Kundensystems.

    Zeigt Sektionen für Betriebssysteme, Sicherheitssoftware, Browser
    und weitere Software. Füllt sich bei Übergabe eines bestehenden
    TechStack-Objekts automatisch vor.

    Args:
        system_name: Anzeigename des Systems (für den Dialog-Titel).
        initial: Vorhandener TechStack (für Bearbeitung) oder None.
        parent: Eltern-Widget.
    """

    def __init__(
        self,
        system_name: str,
        initial: TechStack | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Tech-Stack: {system_name}")
        self.setMinimumSize(560, 680)
        t = theme.get()
        self.setStyleSheet(f"background-color: {t.BG_MAIN}; color: {t.TEXT_MAIN};")

        self._initial = initial
        self._build_ui()
        if initial:
            self._prefill(initial)

    def _build_ui(self) -> None:
        """Erstellt das Dialog-Layout mit Scroll-Bereich."""
        t = theme.get()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Title bar
        title_bar = QLabel("  Tech-Stack bearbeiten")
        title_bar.setStyleSheet(
            f"background: {t.BG_DARK}; color: {t.ACCENT}; font-family: Raleway;"
            " font-weight: 700; font-size: 14px; padding: 12px 16px;"
        )
        outer.addWidget(title_bar)

        # Scroll area for form
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        # Section: Betriebssysteme
        layout.addWidget(self._section_label("Betriebssysteme"))
        self._os_checks: dict[str, tuple] = {}
        os_grid = QWidget()
        os_grid_layout = QVBoxLayout(os_grid)
        os_grid_layout.setContentsMargins(0, 0, 0, 0)
        os_grid_layout.setSpacing(4)
        for os_name in _OS_OPTIONS:
            row = QHBoxLayout()
            chk = QCheckBox(os_name)
            chk.setStyleSheet(f"color: {t.TEXT_MAIN}; font-size: 13px;")
            ver = QLineEdit()
            ver.setPlaceholderText("Version (optional)")
            ver.setFixedWidth(160)
            ver.setStyleSheet(self._input_style())
            row.addWidget(chk)
            row.addStretch()
            row.addWidget(
                QLabel("Version:", styleSheet=f"color: {t.TEXT_DIM}; font-size: 13px;")
            )
            row.addWidget(ver)
            wrapper = QWidget()
            wrapper.setLayout(row)
            os_grid_layout.addWidget(wrapper)
            self._os_checks[os_name] = (chk, ver)
        layout.addWidget(os_grid)

        # Section: Sicherheitssoftware
        layout.addWidget(self._section_label("Sicherheitssoftware"))
        sec_grid = QWidget()
        sec_layout = QVBoxLayout(sec_grid)
        sec_layout.setContentsMargins(0, 0, 0, 0)
        sec_layout.setSpacing(6)

        row_av = QHBoxLayout()
        row_av.addWidget(
            QLabel(
                "Antivirus/EDR:", styleSheet=f"color: {t.TEXT_DIM}; font-size: 13px;"
            )
        )
        self._edit_antivirus = QLineEdit()
        self._edit_antivirus.setPlaceholderText("z. B. Windows Defender")
        self._edit_antivirus.setStyleSheet(self._input_style())
        row_av.addWidget(self._edit_antivirus)
        self._combo_av_status = QComboBox()
        self._combo_av_status.addItems(_TOOL_STATI)
        self._combo_av_status.setStyleSheet(self._combo_style())
        self._combo_av_status.setFixedWidth(110)
        row_av.addWidget(self._combo_av_status)
        sec_layout.addLayout(row_av)

        row_fw = QHBoxLayout()
        row_fw.addWidget(
            QLabel("Firewall:", styleSheet=f"color: {t.TEXT_DIM}; font-size: 13px;")
        )
        self._edit_firewall = QLineEdit()
        self._edit_firewall.setPlaceholderText("z. B. Windows Firewall")
        self._edit_firewall.setStyleSheet(self._input_style())
        row_fw.addWidget(self._edit_firewall)
        self._combo_fw_status = QComboBox()
        self._combo_fw_status.addItems(_TOOL_STATI)
        self._combo_fw_status.setStyleSheet(self._combo_style())
        self._combo_fw_status.setFixedWidth(110)
        row_fw.addWidget(self._combo_fw_status)
        sec_layout.addLayout(row_fw)

        layout.addWidget(sec_grid)

        # Section: Browser
        layout.addWidget(self._section_label("Browser"))
        self._browser_checks: dict[str, tuple] = {}
        for br_name in _BROWSER_OPTIONS:
            row = QHBoxLayout()
            chk = QCheckBox(br_name)
            chk.setStyleSheet(f"color: {t.TEXT_MAIN}; font-size: 13px;")
            ver = QLineEdit()
            ver.setPlaceholderText("Version (optional)")
            ver.setFixedWidth(160)
            ver.setStyleSheet(self._input_style())
            row.addWidget(chk)
            row.addStretch()
            row.addWidget(
                QLabel("Version:", styleSheet=f"color: {t.TEXT_DIM}; font-size: 13px;")
            )
            row.addWidget(ver)
            wrapper = QWidget()
            wrapper.setLayout(row)
            layout.addWidget(wrapper)
            self._browser_checks[br_name] = (chk, ver)

        # Section: Verschlüsselung
        layout.addWidget(self._section_label("Verschlüsselung"))
        self._enc_checks: dict[str, QCheckBox] = {}
        enc_row = QHBoxLayout()
        for enc in _ENCRYPTION_OPTIONS:
            chk = QCheckBox(enc)
            chk.setStyleSheet(f"color: {t.TEXT_MAIN}; font-size: 13px;")
            enc_row.addWidget(chk)
            self._enc_checks[enc] = chk
        enc_row.addStretch()
        enc_wrapper = QWidget()
        enc_wrapper.setLayout(enc_row)
        layout.addWidget(enc_wrapper)

        # Section: VPN
        layout.addWidget(self._section_label("VPN"))
        self._edit_vpn = QLineEdit()
        self._edit_vpn.setPlaceholderText("VPN-Name (leer = kein VPN)")
        self._edit_vpn.setStyleSheet(self._input_style())
        layout.addWidget(self._edit_vpn)

        # Section: Remote-Access
        layout.addWidget(self._section_label("Remote-Access"))
        self._remote_checks: dict[str, QCheckBox] = {}
        remote_row = QHBoxLayout()
        for ra in _REMOTE_OPTIONS:
            chk = QCheckBox(ra)
            chk.setStyleSheet(f"color: {t.TEXT_MAIN}; font-size: 13px;")
            remote_row.addWidget(chk)
            self._remote_checks[ra] = chk
        remote_row.addStretch()
        ra_wrapper = QWidget()
        ra_wrapper.setLayout(remote_row)
        layout.addWidget(ra_wrapper)

        # Section: Sonstige Software
        layout.addWidget(self._section_label("Sonstige Software"))
        custom_row = QHBoxLayout()
        self._edit_custom_entry = QLineEdit()
        self._edit_custom_entry.setPlaceholderText("Software-Name eingeben …")
        self._edit_custom_entry.setStyleSheet(self._input_style())
        custom_row.addWidget(self._edit_custom_entry)
        btn_add_custom = QPushButton("Hinzufügen")
        btn_add_custom.setStyleSheet(self._btn_style())
        btn_add_custom.clicked.connect(self._on_add_custom)
        custom_row.addWidget(btn_add_custom)
        layout.addLayout(custom_row)

        self._custom_list = QListWidget()
        self._custom_list.setMaximumHeight(100)
        self._custom_list.setStyleSheet(
            f"QListWidget {{ background: {t.CARD_BG}; border: 1px solid {t.BORDER};"
            f" border-radius: 4px; color: {t.TEXT_MAIN}; font-size: 13px; }}"
            f"QListWidget::item {{ padding: 3px 6px; }}"
            f"QListWidget::item:selected {{ background: {t.ACCENT}; color: {t.BG_MAIN}; }}"
        )
        layout.addWidget(self._custom_list)
        btn_remove_custom = QPushButton("Ausgewählte entfernen")
        btn_remove_custom.setStyleSheet(self._btn_style())
        btn_remove_custom.clicked.connect(self._on_remove_custom)
        layout.addWidget(btn_remove_custom)

        layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, stretch=1)

        # Buttons
        t = theme.get()
        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(16, 10, 16, 12)
        btn_row.addStretch()

        btn_cancel = QPushButton("Abbrechen")
        btn_cancel.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {t.TEXT_DIM};"
            f" border: 1px solid {t.BORDER}; border-radius: 6px;"
            f" padding: 6px 16px; font-family: Raleway; font-weight: 600; }}"
            f"QPushButton:hover {{ background: {t.CARD_BG}; color: {t.TEXT_MAIN}; }}"
        )
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)

        btn_save = QPushButton("Speichern")
        btn_save.setDefault(True)
        btn_save.setStyleSheet(
            f"QPushButton {{ background: {t.ACCENT}; color: {t.BG_DARK}; border: none;"
            f" border-radius: 6px; padding: 6px 16px;"
            f" font-family: Raleway; font-weight: 600; }}"
            f"QPushButton:hover {{ background: {t.ACCENT_DIM}; color: {t.BG_DARK}; }}"
        )
        btn_save.clicked.connect(self.accept)
        btn_row.addWidget(btn_save)

        btn_container = QWidget()
        btn_container.setLayout(btn_row)
        btn_container.setStyleSheet(
            f"background: {t.BG_DARK}; border-top: 1px solid {t.BORDER};"
        )
        outer.addWidget(btn_container)

    def _prefill(self, stack: TechStack) -> None:
        """Füllt das Formular mit einem bestehenden TechStack vor.

        Args:
            stack: Bestehender TechStack aus einem SystemProfile.
        """

        for os_entry in stack.operating_systems:
            if os_entry.name in self._os_checks:
                chk, ver = self._os_checks[os_entry.name]
                chk.setChecked(True)
                ver.setText(os_entry.version)

        if stack.antivirus.name:
            self._edit_antivirus.setText(stack.antivirus.name)
            status_val = (
                stack.antivirus.status.value
                if hasattr(stack.antivirus.status, "value")
                else str(stack.antivirus.status)
            )
            idx = self._combo_av_status.findText(status_val)
            if idx >= 0:
                self._combo_av_status.setCurrentIndex(idx)

        if stack.firewall.name:
            self._edit_firewall.setText(stack.firewall.name)
            status_val = (
                stack.firewall.status.value
                if hasattr(stack.firewall.status, "value")
                else str(stack.firewall.status)
            )
            idx = self._combo_fw_status.findText(status_val)
            if idx >= 0:
                self._combo_fw_status.setCurrentIndex(idx)

        for br_entry in stack.browsers:
            if br_entry.name in self._browser_checks:
                chk, ver = self._browser_checks[br_entry.name]
                chk.setChecked(True)
                ver.setText(br_entry.version)

        for enc in stack.encryption:
            if enc in self._enc_checks:
                self._enc_checks[enc].setChecked(True)

        if stack.vpn:
            self._edit_vpn.setText(stack.vpn)

        for ra in stack.remote_access:
            if ra in self._remote_checks:
                self._remote_checks[ra].setChecked(True)

        for sw in stack.custom_software:
            if sw:
                self._custom_list.addItem(sw)

    def get_tech_stack(self) -> TechStack:
        """Liest den Formularzustand aus und gibt einen TechStack zurück.

        Returns:
            TechStack-Objekt mit allen eingegebenen Daten.
        """
        from tools.security_scoring.domain.tech_stack.entities import (  # noqa: PLC0415
            BrowserEntry,
            OSEntry,
            SecurityTool,
            TechStack,
        )
        from tools.security_scoring.domain.tech_stack.enums import (
            ToolStatus,  # noqa: PLC0415
        )

        _status_map = {
            "aktiv": ToolStatus.AKTIV,
            "inaktiv": ToolStatus.INAKTIV,
            "unbekannt": ToolStatus.UNBEKANNT,
        }

        os_entries = [
            OSEntry(name=n, version=ver.text().strip())
            for n, (chk, ver) in self._os_checks.items()
            if chk.isChecked()
        ]

        antivirus = SecurityTool(
            name=self._edit_antivirus.text().strip(),
            status=_status_map.get(
                self._combo_av_status.currentText(), ToolStatus.UNBEKANNT
            ),
        )

        firewall = SecurityTool(
            name=self._edit_firewall.text().strip(),
            status=_status_map.get(
                self._combo_fw_status.currentText(), ToolStatus.UNBEKANNT
            ),
        )

        browsers = [
            BrowserEntry(name=n, version=ver.text().strip())
            for n, (chk, ver) in self._browser_checks.items()
            if chk.isChecked()
        ]

        encryption = [enc for enc, chk in self._enc_checks.items() if chk.isChecked()]

        vpn_text = self._edit_vpn.text().strip()

        remote_access = [
            ra for ra, chk in self._remote_checks.items() if chk.isChecked()
        ]

        custom_software = [
            self._custom_list.item(i).text()
            for i in range(self._custom_list.count())
            if self._custom_list.item(i).text().strip()
        ]

        return TechStack(
            operating_systems=os_entries,
            antivirus=antivirus,
            firewall=firewall,
            browsers=browsers,
            encryption=encryption,
            vpn=vpn_text or None,
            remote_access=remote_access,
            custom_software=custom_software,
        )

    @Slot()
    def _on_add_custom(self) -> None:
        """Fügt einen Eintrag zur Custom-Software-Liste hinzu."""
        text = self._edit_custom_entry.text().strip()
        if text:
            self._custom_list.addItem(text)
            self._edit_custom_entry.clear()

    @Slot()
    def _on_remove_custom(self) -> None:
        """Entfernt den ausgewählten Eintrag aus der Custom-Software-Liste."""
        for item in self._custom_list.selectedItems():
            self._custom_list.takeItem(self._custom_list.row(item))

    @staticmethod
    def _section_label(text: str) -> QLabel:
        t = theme.get()
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"color: {t.ACCENT}; font-family: Raleway; font-weight: 700;"
            " font-size: 13px; padding-top: 6px;"
        )
        return lbl

    @staticmethod
    def _input_style() -> str:
        t = theme.get()
        return (
            f"QLineEdit {{ background: {t.CARD_BG}; color: {t.TEXT_MAIN};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px; padding: 4px 8px;"
            f" font-size: 13px; }}"
        )

    @staticmethod
    def _combo_style() -> str:
        t = theme.get()
        return (
            f"QComboBox {{ background: {t.CARD_BG}; color: {t.TEXT_MAIN};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px; padding: 3px 6px;"
            f" font-size: 13px; }}"
        )

    @staticmethod
    def _btn_style() -> str:
        t = theme.get()
        return (
            f"QPushButton {{ background: {t.BG_BUTTON}; color: {t.TEXT_MAIN};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px;"
            f" padding: 4px 10px; font-size: 13px; }}"
            f"QPushButton:hover {{ background: {t.ACCENT}; color: {t.BG_MAIN}; }}"
        )
