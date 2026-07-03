"""app_config — Zentrale Konfiguration für die drei FINLAI-Apps.

Jede AppConfig definiert welche Tools registriert werden und wie die
Sidebar-Gruppen aufgebaut sind. Kein Code wird bewegt — alle Tools
bleiben in tools/. Nur die Einstiegspunkte und diese Konfiguration
steuern den App-Inhalt.

Sidebar-Gruppen-Format
-----------------------
Jede Gruppe ist ein dict mit den Schlüsseln:
  key (str): Interner Gruppen-Schlüssel (entspricht _GroupWidget-key).
  name (str): Anzeigename.
  icon (str): Emoji-Icon.
  tool_keys (list[str]): Nav-Item-Schlüssel der enthaltenen Tools.
                          Entspricht den SidebarItem.key-Werten in sidebar.py.

Tool-Modules-Format
--------------------
Python-Modulpfade zu den tool.py-Dateien. Werden per importlib dynamisch
geladen und in der ToolRegistry registriert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.version import __version__ as _APP_VERSION


@dataclass
class AppConfig:
    """Konfiguration einer App-Instanz.

    Attributes:
        app_id: Maschinenlesbarer Bezeichner (``"finlai"``, ``"norisk"``,
                        ``"automate"``).
        app_name: Anzeigename der App.
        app_slogan: Kurz-Slogan für Splash und Titelleiste.
        window_title: Vollständiger Fenstertitel.
        icon_path: Relativer Pfad zum App-Icon (ab Projektroot).
        accent_color: CI-Akzentfarbe als Hex-String (``"#rrggbb"``).
        tool_modules: Geordnete Liste der Modulpfade aller Tools
                        (Reihenfolge = Sidebar-Reihenfolge).
        sidebar_groups: Sidebar-Gruppen-Konfiguration (siehe Modulkopf).
        splash_text: Optionaler Text im Splash-Screen.
        version: App-Version (SemVer). Default: ``core.version.__version__``.
        update_url: Optionale Override-URL für den Update-Check.
                        Leer = es gilt ``UPDATE_BASE_URL`` aus den Settings
                        (Umgebungsvariable ``FINLAI_UPDATE_BASE_URL``); ist auch
                        die leer (Open-Source-Default), wird der Auto-Update-Check
                        übersprungen — kein Phone-Home. Kommerzielle bzw.
                        White-Label-Builds mit eigenem Server setzen hier ihre
                        vollständige ``latest.json``-URL ein.
    """

    app_id: str
    app_name: str
    app_slogan: str
    window_title: str
    icon_path: str
    accent_color: str
    tool_modules: list[str] = field(default_factory=list)
    sidebar_groups: list[dict] = field(default_factory=list)
    splash_text: str = ""
    version: str = _APP_VERSION
    update_url: str = ""
    display_name: str = ""


# ---------------------------------------------------------------------------
# NoRisk by FINLAI — Cybersecurity
# ---------------------------------------------------------------------------

NORISK_CONFIG = AppConfig(
    app_id="norisk",
    app_name="NoRisk by FINLAI",
    display_name="NoRisk",
    app_slogan="",
    window_title="NORISK BY FINLAI",
    icon_path="resources/icons/norisk.ico",
    accent_color="#51dacf",
    tool_modules=[
        # tools.mainpage dient NICHT mehr als eigenes Dock (das Cockpit/
        # „Übersicht" IST die EINE Landing-Seite Vision B 3c).
        # Der Eintrag BLEIBT aber registriert: das Cockpit komponiert mainpage-
        # Widgets (KiTodoSection/TaskSnippet/Quickstart/Activity/Phishing) und
        # nutzt dessen Services (Task/Journal/Quickstart). NICHT entfernen.
        "tools.mainpage.tool",  # Index 0 — Service-/Widget-Lieferant fuers Cockpit
        "tools.norisk_dashboard.tool",
        "tools.cyber_dashboard.tool",
        "tools.system_scanner.tool",
        "tools.system_tuner.tool",  # "System optimieren" — Datenschutz/Telemetrie
        "tools.security_scoring.tool",
        "tools.techstack.tool",
        "tools.network_scanner.tool",
        # network_monitor bleibt REGISTRIERT (PyInstaller-Spec + crashsicheres
        # navigate_to('network_monitor') aus Help-Links), erscheint aber NICHT
        # mehr als Standalone-Sidebar-Eintrag (Triage P1) — der Monitor lebt als
        # eingebetteter Live-Tab im network_scanner.
        "tools.network_monitor.tool",
        "tools.api_security.tool",
        "tools.cert_monitor.tool",
        "tools.password_checker.tool",
        # customer_audit/nis2_incidents/security_scoring/awareness_tracker
        # bleiben registriert (Factory-Import + PyInstaller-Spec), sind aber kein
        # eigener Sidebar-Eintrag/Dock mehr — sie sind die vier Sub-Tabs des
        # Containers tools.security_assessment (Bereich „Bewerten" =
        # „Security-Bewertung"). techstack (oben) lebt jetzt als Tab im
        # Advisory-Monitor (csaf_advisor), ebenfalls ohne eigenen Sidebar-Eintrag.
        "tools.customer_audit.tool",
        "tools.nis2_incidents.tool",
        "tools.awareness_tracker.tool",
        "tools.security_assessment.tool",  # Bewerten-Container (4 Tabs)
        "tools.dependency_auditor.tool",
        "tools.csaf_advisor.tool",
        "tools.patch_monitor.tool",
        "tools.supply_chain_monitor.tool",
        "tools.file_scanner.tool",  # 3b: verschmilzt email/pdf/document
        # tools.ki_integration entfernt — der vereinte FINLAI-Assistent
        # lebt als Reiter im Handbuch-Dialog (Maskottchen + F1), kein Sidebar-Tool.
        "tools.einstellungen.tool",  # Immer letzter Eintrag
    ],
    sidebar_groups=[
        # (2026-06-06, Phase 3): Workflow-orientierte 6-Bereiche-IA
        # entlang der Nutzerreise (Refactoring-Plan §4). Vorher 7 flache
        # Gruppen Variante A). Die ``key``-Werte muessen mit
        # ``core.sidebar_config.ALL_NORISK_GROUP_CONFIGS`` uebereinstimmen;
        # die ``tool_keys`` sind der Sichtbarkeits-Filter (Schnittmenge mit
        # den dortigen Items). ``icon`` ist hier fuer statische Gruppen
        # ungenutzt (Icon kommt aus sidebar_config), aber R2-konform gesetzt.
        {
            "key": "cockpit",
            "name": "Cockpit",
            "icon": "dashboard",
            "tool_keys": [
                # 3c 1b Vision B): EIN Cockpit-Eintrag. Das
                # frühere zweite Item „Mein Status" (norisk:dashboard) ist mit
                # der Landing-Seite verschmolzen — das Cockpit IST das
                # Welcome-Dock (DockMixin._build_home). ``home`` allein.
                "home",
            ],
        },
        {
            "key": "lage",
            "name": "Lage",
            "icon": "warning",
            "tool_keys": [
                "cyber_dashboard",
                "csaf_advisor",
            ],
        },
        # Reihenfolge + Namen + Item-Zuordnung umgebaut. Die
        # internen Gruppen-Keys (bewerten/ueberwachen/pruefen) bleiben stabil und
        # muessen weiter zu sidebar_config.ALL_NORISK_GROUP_CONFIGS passen; nur die
        # Anzeigenamen, die Reihenfolge und die tool_keys aendern sich.
        {
            "key": "bewerten",
            "name": "Sicherheit & Audit",
            "icon": "assignment",
            # Container „Security-Bewertung" (Audit/Score/Awareness/NIS2
            # als Sub-Tabs).: + „System Optimierung" (system_tuner).
            "tool_keys": [
                "security_assessment",
                "system_tuner",
            ],
        },
        {
            "key": "ueberwachen",
            "name": "Überwachung",
            "icon": "monitor_heart",
            # password_checker dazu; cert_monitor nach „Scanner" gewandert.
            "tool_keys": [
                "patch_monitor",
                "password_checker",
                "supply_chain_monitor",
            ],
        },
        {
            "key": "pruefen",
            "name": "Scanner",
            "icon": "radar",
            # „Prüfen" → „Scanner". system_tuner/password_checker raus,
            # cert_monitor (Zertifikats-Scan) rein.
            "tool_keys": [
                "system_scanner",
                "network_scanner",
                "cert_monitor",
                "api_security",
                "file_scanner",
                "dependency_auditor",
            ],
        },
        # Bereich „Assistenz" (ki:ollama) entfernt (6 → 5 Bereiche).
        {
            "key": "links",
            "name": "Wichtige Links",
            "icon": "link",
            "tool_keys": [],
        },
    ],
)

# ---------------------------------------------------------------------------
# Registry aller App-Konfigurationen (NoRisk-Repo: nur eine App)
# ---------------------------------------------------------------------------

ALL_CONFIGS: dict[str, AppConfig] = {
    "norisk": NORISK_CONFIG,
}

# ---------------------------------------------------------------------------
# Aktive App — wird beim Start von launch_app gesetzt
# ---------------------------------------------------------------------------

_active_config: AppConfig | None = None


def set_active_app(config: AppConfig) -> None:
    """Setzt die aktive App-Konfiguration (wird beim Start aufgerufen).

    Args:
        config: Die gestartete AppConfig-Instanz.
    """
    global _active_config
    _active_config = config


def get_active_config() -> AppConfig | None:
    """Gibt die aktive App-Konfiguration zurück.

    Returns:
        Aktive AppConfig oder None wenn noch nicht gesetzt.
    """
    return _active_config
