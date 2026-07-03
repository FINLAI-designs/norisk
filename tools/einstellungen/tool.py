"""
tool — Einstellungen-Tool für FINLAI

Zeigt dem eingeloggten Benutzer Kontoinfos und ermöglicht
das Ändern des eigenen Passworts. Admins haben zusätzlich
Zugriff auf die Benutzerverwaltung (AdminPanel).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import importlib
from datetime import datetime

from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.auth.session import Session
from core.auth.user_store import UserStore
from core.base_tool import BaseTool
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.ui_settings import UISettings
from tools.einstellungen.gui.theme_selector import ThemeSelector
from tools.einstellungen.gui.two_row_tab_bar import (
    ROW_BOTTOM,
    ROW_TOP,
    TwoRowTabBar,
)

log = get_logger(__name__)


def _lazy_tab(module: str, cls: str):
    """Factory: importiert das Tab-Modul ERST beim ersten Oeffnen (Perf).

    Die Settings-Tabs werden ohnehin lazy instanziiert (``_on_tab_changed``) —
    aber der Modul-IMPORT lief bisher beim Login (``register_from_module`` zieht
    ``einstellungen/tool.py`` und damit alle Tab-Module + transitive Deps). Diese
    Factory verschiebt den Import auf den ersten Tab-Klick.
    """

    def _factory():
        return getattr(importlib.import_module(module), cls)()

    return _factory


def _field_style() -> str:
    c = theme.get()
    return f"""
    QLineEdit {{
        background-color: {c.BG_INPUT};
        color: {c.TEXT_MAIN};
        border: 1px solid {c.BORDER};
        border-radius: 4px;
        padding: 4px 8px;
        font-family: 'Raleway';
    }}
    QLineEdit:focus {{ border-color: {c.ACCENT}; }}
"""


class EinstellungenTool(BaseTool):
    """Einstellungen-Tool — Kontoinfo und Passwortänderung für alle Benutzer.

    Zeigt Informationen zum angemeldeten Benutzer und ermöglicht das
    Ändern des eigenen Passworts. Administratoren erhalten zusätzlich
    einen Button zur Benutzerverwaltung.
    """

    name = "Einstellungen"
    icon = "settings"

    def create_widget(self, parent: QWidget | None = None) -> QWidget:
        """Erstellt und gibt das Einstellungen-Widget zurück.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
            Das vollständig initialisierte Einstellungen-Widget.
        """
        return _EinstellungenWidget(parent)


class _EinstellungenWidget(QWidget):
    """Internes Widget des Einstellungen-Tools."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._store = UserStore()
        self._ui_settings = UISettings.load()
        self._btn_admin: QPushButton | None = None
        self._build_ui()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        s = _field_style()
        for pw in (self._pw_old, self._pw_new, self._pw_new2):
            pw.setStyleSheet(s)
        c = theme.get()
        self._btn_change.setStyleSheet(
            f"QPushButton {{ background-color: {c.ACCENT}; color: {c.BG_DARK};"
            f" border: none; border-radius: 4px; font-weight: bold; }}"
            f"QPushButton:hover {{ background-color: {c.BG_SIDEBAR_HOVER}; }}"
        )
        if self._btn_admin is not None:
            self._btn_admin.setStyleSheet(
                f"QPushButton {{ background-color: {c.BG_BUTTON}; color: {c.ACCENT};"
                f" border: 1px solid {c.ACCENT}; border-radius: 4px;"
                f" font-weight: bold; font-family: 'Raleway'; }}"
                f"QPushButton:hover {{ background-color: {c.BG_SIDEBAR_HOVER}; }}"
            )

    def _build_ui(self) -> None:
        """Erstellt die gesamte Einstellungen-Oberfläche mit Tab-Struktur."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(0)

        # Überschrift
        title = QLabel("Einstellungen")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 18px; font-weight: bold;"
            f" color: {theme.get().ACCENT}; margin-bottom: 4px;"
        )
        layout.addWidget(title)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(
            f"background-color: {theme.get().ACCENT}; margin: 8px 0 20px 0;"
        )
        layout.addWidget(sep)
        layout.addSpacing(8)

        # Tab-Widget — zwei Reihen statt einer.
        # Bei zwoelf Einstellungen-Tabs reichte der horizontale Platz nicht
        # mehr aus; Qt's QTabBar bietet keine Mehrzeiligkeit, deshalb der
        # Custom-Container TwoRowTabBar mit zwei QTabBar-Widgeten + gemeinsamem
        # QStackedWidget. Beide Reihen teilen sich denselben Style.
        tabs = TwoRowTabBar()
        c = theme.get()
        tab_style = f"""
            QTabBar::tab {{
                background: {c.BG_BUTTON};
                color: {c.TEXT_MAIN};
                border: 1px solid {c.BORDER};
                border-bottom: none;
                border-radius: 4px 4px 0 0;
                padding: 6px 16px;
                font-family: 'Raleway';
                font-size: 13px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background: {c.ACCENT};
                color: {c.BG_DARK};
                font-weight: bold;
            }}
            QTabBar::tab:hover:!selected {{
                background: {c.BG_SIDEBAR_HOVER};
                color: {c.BG_DARK};
            }}
        """
        tabs.set_tab_bar_style_sheet(tab_style)

        # ── Lazy Tab Loading (Performance-Fix 2026-04-28) ────────────────
        # Vorher: alle Tabs eager instantiiert → KiEinstellungenTab.__init__
        # blockierte ~9 Sek (Ollama-HTTP-Ping + Provider-Status-Loop). Jetzt
        # wird nur der Default-Tab "Erscheinungsbild" eager gebaut, alle
        # anderen erst beim ersten Klick. Settings-Tool oeffnet < 200 ms.
        tab_appearance = self._build_appearance_tab()
        appearance_idx = tabs.add_tab(
            tab_appearance, get_icon(Icons.PALETTE), "Erscheinungsbild", row=ROW_TOP
        )

        # Lazy-Tab-Specs: (label, icon-name, factory-callable, row).
        # Erscheinungsbild ist NICHT in der Liste — bereits eager gebaut.
        # Reihen-Split, 2026-05-26, 6 + 6 balanciert):
        # ROW_TOP — Allgemein: Erscheinungsbild + Wichtige Links + Ueber FINLAI
        # + Rechtliches + KI-Verzeichnis.
        # ROW_BOTTOM — Werkzeuge: KI-Einstellungen + API-Keys + Feed-Konfiguration
        # + Patch-Monitor + Netzwerk-Collector + SBOM/AI-BOM.
        _g = "tools.einstellungen.gui"  # Modul-Praefix fuer die Lazy-Tabs
        self._lazy_tab_specs: list[tuple[str, str, callable, int]] = [
            ("Wichtige Links", Icons.LINK, _lazy_tab(f"{_g}.links_tab", "LinksTab"), ROW_TOP),
            ("Über FINLAI", Icons.INFO, self._build_about_tab, ROW_TOP),
            ("Rechtliches", Icons.GAVEL, _lazy_tab(f"{_g}.legal_tab", "LegalTab"), ROW_TOP),
            ("KI-Verzeichnis", Icons.CHAT, _lazy_tab(f"{_g}.ki_verzeichnis_tab", "KiVerzeichnisTab"), ROW_TOP),
            # ── Werkzeuge ────────────────────────────────────────────────
            ("KI-Einstellungen", Icons.SETTINGS, _lazy_tab(f"{_g}.ki_einstellungen_tab", "KiEinstellungenTab"), ROW_BOTTOM),
            ("API-Keys", Icons.SETTINGS, _lazy_tab(f"{_g}.api_keys_tab", "ApiKeysTab"), ROW_BOTTOM),
            ("Feed-Konfiguration", Icons.SETTINGS, _lazy_tab(f"{_g}.feed_settings_tab", "FeedSettingsTab"), ROW_BOTTOM),
            # Bug-Fix-Sprint C-5 (Option D ergaenzt) — Patch-Monitor-Setup.
            ("Patch-Monitor", Icons.SETTINGS, _lazy_tab(f"{_g}.patch_monitor_setup_tab", "PatchMonitorSetupTab"), ROW_BOTTOM),
            # Phase C — Netzwerk-Hintergrund-Collector (geplante Aufgabe).
            ("Netzwerk-Collector", Icons.NETWORK_MONITOR, _lazy_tab(f"{_g}.network_collector_setup_tab", "NetworkCollectorSetupTab"), ROW_BOTTOM),
            # SBOM (CycloneDX) + AI-BOM (EU AI Act / EU CRA).
            ("SBOM / AI-BOM", "inventory_2", _lazy_tab(f"{_g}.sbom_aibom_tab", "SbomAiBomTab"), ROW_BOTTOM),
        ]
        self._lazy_tab_loaded: list[bool] = [False] * len(self._lazy_tab_specs)
        # spec_idx -> global_idx im TwoRowTabBar (stabil ueber set_tab_widget).
        self._spec_to_global: list[int] = []
        for label, icon_name, _factory, row in self._lazy_tab_specs:
            stub = QWidget()
            QVBoxLayout(stub)  # leerer Container -- wird beim ersten Klick ersetzt
            global_idx = tabs.add_tab(stub, get_icon(icon_name), label, row=row)
            self._spec_to_global.append(global_idx)
        # global_idx -> spec_idx (-1 fuer eager-Tab Erscheinungsbild).
        self._global_to_spec: dict[int, int] = {
            g: s for s, g in enumerate(self._spec_to_global)
        }
        self._appearance_global_idx = appearance_idx
        self._tabs = tabs
        tabs.currentChanged.connect(self._on_tab_changed)

        layout.addWidget(tabs)

    def _on_tab_changed(self, global_idx: int) -> None:
        """Lazy-instantiiert den Tab beim ersten Wechsel.

        Der eager gebaute Erscheinungsbild-Tab und bereits geladene Tabs
        werden uebersprungen. Alle anderen Stubs werden bei der ersten
        Selektion durch das echte Widget ersetzt (via
:meth:`TwoRowTabBar.set_tab_widget`).

        Args:
            global_idx: Aktiver globaler Tab-Index nach dem Wechsel.
        """
        spec_idx = self._global_to_spec.get(global_idx, -1)
        if spec_idx < 0:
            return
        if self._lazy_tab_loaded[spec_idx]:
            return
        self._lazy_tab_loaded[spec_idx] = True
        label, icon_name, factory, _row = self._lazy_tab_specs[spec_idx]
        real_widget = factory()
        self._tabs.set_tab_widget(global_idx, real_widget, get_icon(icon_name), label)

    def _build_appearance_tab(self) -> QWidget:
        """Baut den Erscheinungsbild-Tab mit ThemeSelector und Passwortänderung."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Theme-Auswahl
        self._theme_selector = ThemeSelector()
        self._theme_selector.theme_changed.connect(self._on_theme_changed)
        layout.addWidget(self._theme_selector)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {theme.get().BORDER};")
        layout.addWidget(sep)

        layout.addWidget(self._build_module_visibility_panel())

        sep_mv = QFrame()
        sep_mv.setFrameShape(QFrame.Shape.HLine)
        sep_mv.setFixedHeight(1)
        sep_mv.setStyleSheet(f"background-color: {theme.get().BORDER};")
        layout.addWidget(sep_mv)

        layout.addWidget(self._build_password_panel())
        layout.addStretch()
        return tab

    def _build_module_visibility_panel(self) -> QWidget:
        """Baut den Bereich zur Sidebar-Modulsichtbarkeit (Profil-Gating).

        Spiegelt das reversible Override ``UISettings.profile_gating_enabled``:
        ist die Checkbox aktiv („Alle Module anzeigen"), wird das W1-Profil-Gating
        der Sidebar aufgehoben — gegen Fehlklassifikation im W1-Interview.
        """
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        header = QLabel("Modul-Sichtbarkeit")
        header.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {theme.get().ACCENT}; margin-bottom: 8px;"
        )
        layout.addWidget(header)

        self._chk_show_all_modules = QCheckBox("Alle Module anzeigen")
        # checked == Override an == Gating aus.
        self._chk_show_all_modules.setChecked(
            not self._ui_settings.profile_gating_enabled
        )
        self._chk_show_all_modules.toggled.connect(self._on_show_all_modules_toggled)
        self._chk_show_all_modules.setStyleSheet(
            f"QCheckBox {{ font-family: 'Raleway'; font-size: 13px;"
            f" color: {theme.get().TEXT_MAIN}; }}"
        )
        layout.addWidget(self._chk_show_all_modules)

        hint = QLabel(
            "Standardmäßig blendet NoRisk Module aus, die laut Ihrem Profil nicht "
            "relevant sind (z. B. API-Security ohne eigene API). Aktivieren Sie "
            "diese Option, um alle Module zu sehen. Achtung: Eine Fehleinschätzung "
            "Ihres Profils kann sonst Angriffsfläche verstecken. Die Änderung wirkt "
            "nach einem Neustart der App."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {theme.get().TEXT_DIM};"
        )
        layout.addWidget(hint)
        return panel

    def _on_show_all_modules_toggled(self, checked: bool) -> None:
        """Persistiert das reversible Profil-Gating-Override.

        Args:
            checked: True = „Alle Module anzeigen" (Gating aus).
        """
        self._ui_settings.update_profile_gating(not checked)

    def _build_about_tab(self) -> QWidget:
        """Baut den Über-FINLAI-Tab mit Benutzerkonto, Lizenz und Admin-Bereich."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        layout.addWidget(self._build_info_panel())

        # Admin-Panel Button (nur für Admins)
        if Session().is_admin():
            sep2 = QFrame()
            sep2.setFrameShape(QFrame.Shape.HLine)
            sep2.setFixedHeight(1)
            sep2.setStyleSheet(f"background-color: {theme.get().BORDER};")
            layout.addWidget(sep2)
            layout.addWidget(self._build_admin_section())

        layout.addStretch()
        return tab

    def _build_info_panel(self) -> QWidget:
        """Erstellt den Informationsbereich mit Benutzer- und Lizenzdaten."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        header = QLabel("Benutzerkonto")
        header.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {theme.get().ACCENT}; margin-bottom: 8px;"
        )
        layout.addWidget(header)

        session = Session()
        user = session.current_user

        def info_row(label: str, value: str) -> QWidget:
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(8)

            lbl = QLabel(f"{label}:")
            lbl.setFixedWidth(100)
            lbl.setStyleSheet(
                f"color: {theme.get().TEXT_DIM}; font-family: 'Raleway'; font-size: 13px;"
            )

            val = QLabel(value)
            val.setStyleSheet(
                f"color: {theme.get().TEXT_MAIN}; font-family: 'Raleway'; font-size: 13px;"
            )
            val.setWordWrap(True)

            row_layout.addWidget(lbl)
            row_layout.addWidget(val, stretch=1)
            return row

        if user:
            layout.addWidget(info_row("Angemeldet als", user.full_name))
            layout.addWidget(info_row("Benutzername", user.username))
            role_text = "Administrator" if user.role == "admin" else "Benutzer"
            layout.addWidget(info_row("Rolle", role_text))

            last_login = "—"
            if user.last_login:
                try:
                    dt = datetime.fromisoformat(user.last_login)
                    last_login = dt.strftime("%d.%m.%Y %H:%M")
                except ValueError:
                    last_login = user.last_login
            layout.addWidget(info_row("Letzter Login", last_login))

        # Single-Tenant-OSS — Lizenzinfo + "Lizenz verwalten"
        # entfernt (kein Lizenz-Status/-Tier/-Trial mehr im UI).
        layout.addStretch()
        return panel

    def _build_password_panel(self) -> QWidget:
        """Erstellt den Passwortänderungs-Bereich."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        header = QLabel("Passwort ändern")
        header.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {theme.get().ACCENT}; margin-bottom: 8px;"
        )
        layout.addWidget(header)

        layout.addWidget(QLabel("Aktuelles Passwort:"))
        self._pw_old = QLineEdit()
        self._pw_old.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_old.setFixedHeight(34)
        self._pw_old.setStyleSheet(_field_style())
        layout.addWidget(self._pw_old)

        layout.addWidget(QLabel("Neues Passwort:"))
        self._pw_new = QLineEdit()
        self._pw_new.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_new.setFixedHeight(34)
        self._pw_new.setStyleSheet(_field_style())
        self._pw_new.textChanged.connect(self._update_strength)
        layout.addWidget(self._pw_new)

        self._lbl_strength = QLabel("")
        self._lbl_strength.setStyleSheet("font-size: 13px;")
        layout.addWidget(self._lbl_strength)

        layout.addWidget(QLabel("Neues Passwort wiederholen:"))
        self._pw_new2 = QLineEdit()
        self._pw_new2.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_new2.setFixedHeight(34)
        self._pw_new2.setStyleSheet(_field_style())
        layout.addWidget(self._pw_new2)

        self._lbl_pw_msg = QLabel("")
        self._lbl_pw_msg.setStyleSheet(f"font-size: 13px; color: {theme.get().ERROR};")
        self._lbl_pw_msg.setWordWrap(True)
        layout.addWidget(self._lbl_pw_msg)

        layout.addSpacing(8)
        self._btn_change = QPushButton("Passwort ändern")
        self._btn_change.setIcon(get_icon(Icons.SAVE))
        self._btn_change.setFixedHeight(36)
        c = theme.get()
        self._btn_change.setStyleSheet(
            f"QPushButton {{ background-color: {c.ACCENT}; color: {c.BG_DARK};"
            f" border: none; border-radius: 4px; font-weight: bold; }}"
            f"QPushButton:hover {{ background-color: {c.BG_SIDEBAR_HOVER}; }}"
        )
        self._btn_change.clicked.connect(self._change_password)
        layout.addWidget(self._btn_change)

        layout.addStretch()
        return panel

    def _build_admin_section(self) -> QWidget:
        """Erstellt den Admin-Bereich mit dem Benutzerverwaltungs-Button."""
        section = QWidget()
        layout = QHBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)

        lbl = QLabel("Administratorfunktionen:")
        lbl.setStyleSheet(
            f"color: {theme.get().ACCENT}; font-family: 'Raleway'; font-size: 13px;"
        )
        layout.addWidget(lbl)
        layout.addSpacing(16)

        self._btn_admin = QPushButton("Benutzerverwaltung")
        self._btn_admin.setIcon(get_icon(Icons.ADMIN_PANEL))
        self._btn_admin.setFixedHeight(38)
        self._btn_admin.setFixedWidth(200)
        c = theme.get()
        self._btn_admin.setStyleSheet(
            f"QPushButton {{ background-color: {c.BG_BUTTON}; color: {c.ACCENT};"
            f" border: 1px solid {c.ACCENT}; border-radius: 4px;"
            f" font-weight: bold; font-family: 'Raleway'; }}"
            f"QPushButton:hover {{ background-color: {c.BG_SIDEBAR_HOVER}; }}"
        )
        self._btn_admin.clicked.connect(self._open_admin_panel)
        layout.addWidget(self._btn_admin)
        layout.addStretch()
        return section

    # ------------------------------------------------------------------
    def _on_theme_changed(self, mode: str) -> None:
        """Speichert die Theme-Auswahl und wendet sie live an.

        Sprint 3: Statt `MainWindow.apply_theme` via `hasattr`-Workaround
        (Audit S2-6) wird `theme.apply(app, mode)` direkt aufgerufen. Der
        bestehende Listener-Mechanismus (`theme.register_listener` in
        MainWindow.__init__) triggert dann `MainWindow.apply_theme`
        automatisch und emittiert `global_signals.theme_changed` für
        weitere Subscriber.
        """
        from PySide6.QtWidgets import QApplication  # noqa: PLC0415

        self._ui_settings.theme = mode
        self._ui_settings.save()
        app = QApplication.instance()
        if app is not None:
            theme.apply(app, mode)

    # ------------------------------------------------------------------
    def _update_strength(self, pw: str) -> None:
        """Zeigt die Passwort-Stärke an."""
        score = sum(
            [
                len(pw) >= 8,
                len(pw) >= 12,
                any(c.isupper() for c in pw),
                any(c.isdigit() for c in pw),
                any(c in "!@#$%^&*()_+-=" for c in pw),
            ]
        )
        if not pw:
            self._lbl_strength.setText("")
        elif score <= 2:
            self._lbl_strength.setText("Stärke: ● Schwach")
            self._lbl_strength.setStyleSheet(
                f"color: {theme.get().ERROR}; font-size: 13px;"
            )
        elif score <= 3:
            self._lbl_strength.setText("Stärke: ●● Mittel")
            self._lbl_strength.setStyleSheet(
                f"color: {theme.get().WARNING}; font-size: 13px;"
            )
        else:
            self._lbl_strength.setText("Stärke: ●●● Stark")
            self._lbl_strength.setStyleSheet(
                f"color: {theme.get().SUCCESS}; font-size: 13px;"
            )

    def _change_password(self) -> None:
        """Führt die Passwortänderung für den aktuell eingeloggten Benutzer durch."""
        old_pw = self._pw_old.text()
        new_pw = self._pw_new.text()
        new_pw2 = self._pw_new2.text()
        user = Session().current_user

        if not user:
            return

        if not old_pw or not new_pw or not new_pw2:
            self._lbl_pw_msg.setStyleSheet(
                f"color: {theme.get().ERROR}; font-size: 13px;"
            )
            self._lbl_pw_msg.setText("Alle Felder müssen ausgefüllt sein.")
            return

        if new_pw != new_pw2:
            self._lbl_pw_msg.setStyleSheet(
                f"color: {theme.get().ERROR}; font-size: 13px;"
            )
            self._lbl_pw_msg.setText("Die neuen Passwörter stimmen nicht überein.")
            return

        if len(new_pw) < 6:
            self._lbl_pw_msg.setStyleSheet(
                f"color: {theme.get().ERROR}; font-size: 13px;"
            )
            self._lbl_pw_msg.setText("Das Passwort muss mindestens 6 Zeichen haben.")
            return

        if self._store.change_password(user.username, old_pw, new_pw):
            self._lbl_pw_msg.setStyleSheet(
                f"color: {theme.get().SUCCESS}; font-size: 13px;"
            )
            self._lbl_pw_msg.setText("Passwort erfolgreich geändert.")
            self._pw_old.clear()
            self._pw_new.clear()
            self._pw_new2.clear()
            self._lbl_strength.setText("")
            from core.audit_log import AuditLogger

            AuditLogger().log_action("PASSWORD_CHANGED", {"username": user.username})  # noqa
        else:
            self._lbl_pw_msg.setStyleSheet(
                f"color: {theme.get().ERROR}; font-size: 13px;"
            )
            self._lbl_pw_msg.setText("Das aktuelle Passwort ist falsch.")

    def _open_admin_panel(self) -> None:
        """Öffnet den Benutzerverwaltungs-Dialog (nur für Admins)."""
        if not Session().is_admin():
            return
        from core.auth.admin_panel import AdminPanel

        # Tool-Namen aus der Registry ermitteln
        try:
            tool_names = self._get_available_tool_names()
        except (ImportError, OSError, AttributeError):
            tool_names = []
        panel = AdminPanel(tool_names, self)
        panel.exec()

    def _get_available_tool_names(self) -> list[str]:
        """Gibt die Tool-Namen der aktiven App zurück.

        Nutzt die aktive AppConfig um nur die Tools der laufenden App
        zu importieren. Importiert die Tool-Klassen dynamisch und liest
        deren ``name``-Attribut.

        Returns:
            Alphabetisch sortierte Liste der Tool-Namen der aktiven App.
        """
        import importlib  # noqa: PLC0415

        from apps.app_config import get_active_config  # noqa: PLC0415

        cfg = get_active_config()
        if cfg is None:
            return []

        tool_names: list[str] = []
        for module_path in cfg.tool_modules:
            try:
                mod = importlib.import_module(module_path)
                # Tool-Klasse ist die erste BaseTool-Subklasse im Modul
                for attr in vars(mod).values():
                    if (
                        isinstance(attr, type)
                        and hasattr(attr, "name")
                        and attr.name not in ("", "Home", "Einstellungen")
                    ):
                        tool_names.append(attr.name)
                        break
            except (ImportError, AttributeError, TypeError):
                # NICHT still schlucken: ein hier verschluckter Importfehler
                # entfernt ein Tool unbemerkt aus dem Rechte-Picker. Wird es
                # dann beim Anlegen eines Benutzers nicht angehakt, fehlt es in
                # dessen allowed_tools und der Sidebar-Eintrag wirkt „tot".
                log.exception(
                    "Tool-Name für Rechte-Picker nicht ermittelbar: %s",
                    module_path,
                )

        return sorted(set(tool_names))
