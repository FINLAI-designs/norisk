"""
customer_audit_widget — Haupt-Widget für das Kunden-Audit-Tool.

Zeigt die Audit-Liste und ermöglicht das Erstellen/Öffnen von Audits.

Schichtzugehörigkeit: gui/ — nur UI-Logik + Use-Case-Aufrufe.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.logger import get_logger
from tools.customer_audit.application.nis2_incident_service import (
    Nis2IncidentService,
)
from tools.customer_audit.application.services import (
    CustomerAuditServices,
)
from tools.customer_audit.gui.customer_list_widget import CustomerListWidget
from tools.customer_audit.gui.customer_wizard import CustomerWizard

log = get_logger(__name__)


class CustomerAuditWidget(QWidget):
    """Haupt-Widget für das Kunden-Audit-Tool (Security-Audit).

    Zeigt die Audit-Liste mit Wizard-Einstieg.: Der frühere
    interne „NIS2-Vorfälle"-Tab entfällt — NIS2-Vorfälle leben jetzt als
    eigener Geschwister-Tab im Bereich „Security-Bewertung"
    (:mod:`tools.security_assessment`). Der NIS2-Hinweis-Button in der Toolbar
    bleibt (zeigt die Anzahl offener Vorfälle) und stößt über das Signal
:attr:`nis2_requested` den Sprung auf den NIS2-Geschwister-Tab an — ohne den
    Container-Key zu kennen (der Container verbindet das Signal).

    Signals:
        nis2_requested: Der Toolbar-Button bittet um den Wechsel auf den
            NIS2-Vorfälle-Tab des umgebenden „Security-Bewertung"-Containers.

    Attributes:
        _services: Use-Case-Buendel.
        _list_widget: Widget für die Listenansicht.
    """

    nis2_requested = Signal()

    def __init__(
        self,
        services: CustomerAuditServices,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Haupt-Widget.

        Args:
            services: Service-Buendel mit allen Use-Cases: GUI
                kennt das Repository nicht mehr direkt, nur den
                application-Layer).
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._services = services
        self._load_use_case = services.load
        self._build_ui()

    def _build_ui(self) -> None:
        """Baut die Audit-Ansicht (Toolbar + Hilfe + Liste).

        NIS2-Vorfälle sind kein interner Tab mehr (siehe Klassen-
        Docstring); das Widget zeigt direkt den Audits-Inhalt.
        """
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_audits_tab())

    def _build_audits_tab(self) -> QWidget:
        """Baut den „Audits"-Tab (Toolbar + Hilfe-Panel + Audit-Liste)."""
        c = theme.get()
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # --- Toolbar ---
        toolbar = QWidget()
        toolbar.setStyleSheet(
            f"background: {c.BG_DARK}; border-bottom: 1px solid {c.BORDER};"
        )
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(16, 10, 16, 10)

        lbl_title = QLabel("Security-Audit")
        lbl_title.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway;"
            " font-weight: 700; font-size: 16px; border: none;"
        )
        toolbar_layout.addWidget(lbl_title)
        toolbar_layout.addStretch()

        btn_new = QPushButton("+ Neues Audit")
        btn_new.clicked.connect(self._open_wizard)
        btn_new.setStyleSheet(
            f"QPushButton {{ background: {c.ACCENT}; color: {theme.TEXT_ON_ACCENT_DEEP};"
            f" border: none; border-radius: 4px; padding: 8px 18px;"
            f" font-family: Raleway; font-weight: 700; font-size: 13px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}cc; }}"
        )
        toolbar_layout.addWidget(btn_new)

        _tip_new = self._help_tip("btn_new")
        if _tip_new:
            toolbar_layout.addWidget(HelpButton(_tip_new))

        # Schnell-Sprung auf den NIS2-Vorfälle-Tab. Zeigt die Anzahl
        # offener Vorfälle (fail-safe — Service-Fehler liefern „–"); Klick
        # wechselt intern auf den NIS2-Tab (früher Signal nach oben).
        self._nis2_btn = QPushButton("NIS2-Vorfaelle (–)")
        self._nis2_btn.setToolTip(
            "Wechselt zum NIS2-Vorfälle-Tab (Bereich Security-Bewertung)."
        )
        self._nis2_btn.clicked.connect(self.nis2_requested.emit)
        self._nis2_btn.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {c.ACCENT};"
            f" border: 1px solid {c.ACCENT}; border-radius: 4px;"
            f" padding: 7px 14px; font-family: Raleway; font-weight: 600;"
            f" font-size: 13px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {theme.TEXT_ON_ACCENT_DEEP}; }}"
        )
        toolbar_layout.addWidget(self._nis2_btn)
        self._refresh_nis2_button()

        layout.addWidget(toolbar)

        _hc = HelpRegistry.get("customer_audit")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            self._help_panel.open_full_help.connect(self._open_help_dialog)
            layout.addWidget(self._help_panel)

        # --- Liste ---
        self._list_widget = CustomerListWidget(self._services)
        self._list_widget.open_requested.connect(self._open_existing)
        layout.addWidget(self._list_widget, stretch=1)

        return tab

    def apply_navigation(self, *, tab: str | None = None, **_kwargs) -> None:
        """Deeplink-Kompat: ``tab='nis2'`` stößt den Sprung zum
        NIS2-Geschwister-Tab des Containers an (via:attr:`nis2_requested`).

        Normalerweise fängt der Router den Deeplink bereits vorher per Alias ab
        und wählt den Container-Sub-Tab direkt (``navigate_to('customer_audit',
        tab='nis2')`` → ``security_assessment`` + Sub-Tab ``nis2``); diese
        Methode bleibt als Fallback für Direktaufrufe auf das eingebettete
        Audit-Widget.

        Args:
            tab: Ziel-Tab. ``'nis2'`` → NIS2-Vorfälle (Geschwister-Tab),
                ``'audits'`` → Audits (dieses Widget, No-op).
        """
        if tab == "nis2":
            self.nis2_requested.emit()

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("customer_audit")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "customer_audit", parent=self.window()
        )
        dlg.show()

    def _open_wizard(self) -> None:
        """Öffnet den Wizard für ein neues Audit."""
        wizard = CustomerWizard(self._services, parent=self)
        wizard.audit_saved.connect(self._on_audit_saved)
        wizard.exec()

    def _open_existing(self, audit_id: str) -> None:
        """Öffnet ein vorhandenes Audit im Editier-Modus.

        Anders als bis (read-only) wird das Audit editierbar geladen:
        Speichern erzeugt eine **neue Version** (neue audit_id, supersedes-Kette,
), das Original bleibt unverändert erhalten.

        Args:
            audit_id: UUID des zu öffnenden Audits.
        """
        if not audit_id:
            log.warning("_open_existing aufgerufen mit leerer ID — übersprungen")
            return
        result = self._load_use_case.get_by_id(audit_id)
        if result is None:
            log.warning("Audit %s nicht gefunden", audit_id)
            return

        wizard = CustomerWizard(self._services, parent=self)
        wizard.load_for_edit(result)
        wizard.audit_saved.connect(self._on_audit_saved)
        wizard.exec()

    def _on_audit_saved(self, _result) -> None:
        """Aktualisiert die Liste nach dem Speichern eines Audits."""
        self._list_widget.refresh()
        self._refresh_nis2_button()

    def _refresh_nis2_button(self) -> None:
        """Setzt die Anzahl offener NIS2-Vorfaelle im Toolbar-Button.

        Fail-safe: wenn der Service nicht initialisierbar ist (z.B. weil
        die DB noch nicht angelegt wurde), bleibt der Button bei "–".
        """
        try:
            count = len(Nis2IncidentService().list_open_incidents())
        except (RuntimeError, OSError, ImportError):
            log.debug("nis2-button: service-init failed (fallback to '–')")
            self._nis2_btn.setText("NIS2-Vorfaelle (–)")
            return
        self._nis2_btn.setText(f"NIS2-Vorfaelle ({count})")
