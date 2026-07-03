"""
sidebar_config — Deklarative Sidebar-Konfiguration für NoRisk.

Sprint 5 Phase 1: Trennt die *Struktur* der Sidebar-Items
(Label, Icon-Name, Tooltip, License-Feature) vom *Rendering* in
:mod:`core.sidebar`. Refactor-Ziel des Audit-Befunds S1-3 / CC-4:
22 ``_build_*_group``-Methoden → 1 generischer Builder
(:meth:`SidebarWidget._build_group_from_config`) plus deklarative
Config je Gruppe.

Diese Datei ist bewusst **PySide6-frei** — Dataclasses + String-Icon-
Namen, keine ``QIcon``-Objekte. Die Auflösung Icon-Name → ``QIcon``
passiert im Builder via:func:`core.icons.get_sidebar_icon`.

Reorganisation 2026-06-06, Phase 3 — Workflow-orientierte App):
Frueher 7 flache Gruppen Variante A). Heute **6 Bereiche** entlang
der Nutzerreise „wo stehe ich" → „was tun" (Refactoring-Plan §4):

    Cockpit adaptiver Sicherheitsstatus (Mein Status)
    Lage Bedrohungslage + Advisory-Monitor
    Prüfen on-demand-Scans (System/Netzwerk/Datei/Passwort, opt. API/Dependency)
    Überwachen kontinuierliche Beobachtung (Patch/Netzwerk/Supply-Chain, opt. Zert.)
    Bewerten Security-Bewertung (Audit/Score/Awareness/NIS2 als Tabs)
    Assistenz Security-Chat (Handbuch-Assistent lebt im KI-Verzeichnis)

Optionale, profil-gegatete Module (api_security, dependency_auditor,
cert_monitor) sind hier regulär gelistet; das sichtbare Profil-Gating
(Dimmen/Ausblenden) folgt in Phase 3d (Profil-Entity aus W1).
Vision B ist umgesetzt (Phase 3c): Es gibt EINEN Cockpit-Eintrag
(key=``home``); ``home`` und ``norisk:dashboard`` zeigen dasselbe
verschmolzene Cockpit (Welcome-Page + „Mein Status" zusammengeführt).
``cyber_dashboard`` ist zu „Bedrohungslage" umbenannt; ``nis2_incidents``
ist ein Tab im Security-Audit, ``einstellungen`` lebt fix in der
Bottom-Leiste.

Author: Patrick Riederich
Version: 3.0
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.security_subject.w1_profil import (
    GATING_KEY_API,
    GATING_KEY_ENTWICKLER,
    GATING_KEY_WEBSITE,
)


@dataclass
class SidebarItemConfig:
    """Deklarative Config für einen einzelnen Sidebar-Eintrag.

    Wird zur Laufzeit vom generischen Builder in ein
:class:`core.sidebar._NavItemWidget` umgesetzt.

    Attributes:
        key: Eindeutiger Navigationsschlüssel (z. B. ``"cyber_dashboard"``,
            ``"norisk:dashboard"``).
        label: Anzeigetext.
        icon: Material-Symbol-Name als String (z. B. ``"shield"`` oder
            ``Icons.DASHBOARD``). Kein ``QIcon``-Objekt — die Auflösung
            macht der Builder.
        tooltip: Tooltip-Text. Wenn leer, fällt der Builder auf ``label``
            zurück.
        license_feature: Optionaler Feature-Key aus
:mod:`core.license_features`. Wenn gesetzt, wendet der Builder
            ``_apply_license_lock(w, feature_key)`` auf das Widget an.
        profile_gating_key: Optionaler W1-Profil-Flag-Schlüssel aus
:mod:`core.security_subject.w1_profil` (z. B. ``GATING_KEY_API``).
            Wenn gesetzt UND das Flag am eigenen Subjekt explizit ``0`` ist
            (Eigenschaft fehlt), graut der Builder das Item profilbedingt aus
 Phase 3d). ``None``/``1`` → keine Wirkung. Reversibel über
            ``UISettings.profile_gating_enabled``.
    """

    key: str
    label: str
    icon: str
    tooltip: str = ""
    license_feature: str = ""
    profile_gating_key: str = ""


@dataclass
class SidebarGroupConfig:
    """Deklarative Config für eine ganze Sidebar-Gruppe.

    Attributes:
        key: Gruppen-Key, muss zu ``AppConfig.sidebar_groups[i]["key"]``
            passen damit der ``tool_keys``-Filter greift.
        label: Anzeigename der Gruppe (z. B. ``"Cockpit"``).
        icon: Material-Symbol-Name als String.
        items: Liste der Items in Anzeige-Reihenfolge.
        expanded: True → Gruppe ist beim ersten Render aufgeklappt.
    """

    key: str
    label: str
    icon: str
    items: list[SidebarItemConfig] = field(default_factory=list)
    expanded: bool = False


# ---------------------------------------------------------------------------
# Konkrete Group-Configs für NoRisk (6 Bereiche — Phase 3)
# ---------------------------------------------------------------------------
# WICHTIG: Der ``key`` jeder Gruppe muss identisch in
# ``apps.app_config.NORISK_CONFIG.sidebar_groups`` auftauchen — sonst wird
# die Gruppe in ``core.sidebar._build_nav`` herausgefiltert. Jeder Item-Key
# muss zudem ein gültiger ``nav_key`` aus ``MainWindow._NAV_TOOL_MAP`` sein
# (Ausnahme: ``ki:ollama`` ist ein Standalone-Dock in ``dock_mixin``).

# Bereich 1 — COCKPIT: adaptiver Sicherheitsstatus + Landing-Seite.
# 3c 1b Vision B): Welcome-Page und „Mein Status" sind
# verschmolzen — EIN Cockpit-Eintrag. Der frühere zweite Eintrag
# („Mein Status"/``norisk:dashboard``) entfällt; das Cockpit IST jetzt das
# Welcome-Dock und beide Keys (``home``/``norisk:dashboard``) zeigen dasselbe
# Dock (NavigationMixin). Bewusst OHNE license_feature: die Landing-Seite muss
# immer erreichbar sein (das norisk_dashboard-Tool-Gating greift separat).
COCKPIT_GROUP_CONFIG = SidebarGroupConfig(
    key="cockpit",
    label="Cockpit",
    icon="dashboard",
    expanded=True,
    items=[
        SidebarItemConfig(
            key="home",
            label="Cockpit",
            icon="dashboard",
            tooltip="Cockpit — Startseite mit adaptivem Sicherheitsüberblick "
            "und Aufgaben",
        ),
    ],
)

# Bereich 2 — LAGE: tagesaktuelles Bedrohungsbild.
LAGE_GROUP_CONFIG = SidebarGroupConfig(
    key="lage",
    label="Lage",
    icon="warning",
    items=[
        SidebarItemConfig(
            key="cyber_dashboard",
            label="Bedrohungslage",
            icon="dashboard",
            tooltip="Bedrohungslage — tagesaktuelles Lagebild mit CVE/CSAF + Phishing",
            license_feature="cyber_dashboard",
        ),
        SidebarItemConfig(
            key="csaf_advisor",
            label="Advisory-Monitor",
            icon="security_update_warning",
            tooltip="Advisory-Monitor — BSI/Hersteller-CSAF-Advisories",
            license_feature="csaf_advisor",
        ),
    ],
)

# Bereich 5 — SCANNER (Anzeigename; key bleibt ``pruefen`` zur Kompatibilität).
# „Prüfen" → „Scanner" umbenannt + neu sortiert. system_tuner
# ist nach „Sicherheit & Audit" gewandert, password_checker nach „Überwachung";
# cert_monitor ist aus „Überwachung" hierher gezogen (Zertifikats-Scan).
# cert_monitor/api_security/dependency_auditor sind profil-optional.
PRUEFEN_GROUP_CONFIG = SidebarGroupConfig(
    key="pruefen",
    label="Scanner",
    icon="radar",
    items=[
        SidebarItemConfig(
            key="system_scanner",
            label="System-Scan",
            icon="radar",
            tooltip="Lokalen System-Scan durchführen",
            license_feature="system_scanner",
        ),
        SidebarItemConfig(
            key="network_scanner",
            label="Netzwerk-Scan",
            icon="wifi_find",
            tooltip="Netzwerk-Scan — Hosts, Ports, Services im LAN",
            license_feature="network_scanner",
        ),
        SidebarItemConfig(
            key="cert_monitor",
            label="Zertifikats-Scan",
            icon="verified_user",
            tooltip="SSL/TLS-Zertifikats-Scan — Ablauf und Schwächen "
            "(nur mit eigener Website)",
            license_feature="cert_monitor",
            profile_gating_key=GATING_KEY_WEBSITE,
        ),
        SidebarItemConfig(
            key="api_security",
            label="API-Scan",
            icon="api",
            tooltip="API-Scan — REST-APIs auf OWASP-Mängel testen "
            "(nur mit eigener API)",
            license_feature="api_security",
            profile_gating_key=GATING_KEY_API,
        ),
        # (Phase 3b): Datei-Scanner-Merge — E-Mail-Anhang + PDF-Risiko +
        # Dokument (Office) in EINEM Eintrag mit Sub-Tabs. Container immer
        # sichtbar (license_feature=""); die Sub-Tabs werden im Widget pro
        # Lizenz-Feature freigeschaltet (email_attachment_scanner /
        # pdf_risk_scanner / document_scanner).
        SidebarItemConfig(
            key="file_scanner",
            label="Datei-Scan",
            icon="description",
            tooltip="Datei-Scan — E-Mail-Anhänge, PDFs und Office-Dokumente prüfen",
            license_feature="",
        ),
        SidebarItemConfig(
            key="dependency_auditor",
            label="Dependency-Scan",
            icon="inventory_2",
            tooltip="Dependency-Scan — Python-Pakete gegen PyPI-Sicherheitswarner "
            "(nur bei eigener Entwicklung)",
            license_feature="dependency_auditor",
            profile_gating_key=GATING_KEY_ENTWICKLER,
        ),
    ],
)

# Bereich 4 — ÜBERWACHUNG (Anzeigename; key bleibt ``ueberwachen``): kontinuierliche
# Beobachtung.: password_checker aus „Scanner" hierher dazu; cert_monitor ist
# nach „Scanner" (Zertifikats-Scan) gewandert.
UEBERWACHEN_GROUP_CONFIG = SidebarGroupConfig(
    key="ueberwachen",
    label="Überwachung",
    icon="monitor_heart",
    items=[
        SidebarItemConfig(
            key="patch_monitor",
            label="Patchmonitor",
            icon="system_update_alt",
            tooltip="Patchmonitor — installierte Software, Updates und Lifecycle (EOL)",
            license_feature="",  # immer aktiv
        ),
        SidebarItemConfig(
            key="password_checker",
            label="Passwort-Checker",
            icon="password",
            tooltip="Passwort-Stärke (offline) und Leak-Check gegen bekannte Datenlecks",
            license_feature="password_checker",
        ),
        SidebarItemConfig(
            key="supply_chain_monitor",
            label="Supply-Chain-Monitor",
            icon="hub",
            tooltip="Supply-Chain-Monitor — Vendor- und AVV-Inventar (NIS2 Art. 21(2)(d))",
            license_feature="supply_chain_monitor",
        ),
    ],
)

# Bereich 3 — SICHERHEIT & AUDIT (Anzeigename; key bleibt ``bewerten``).
# Container „Security-Bewertung" (Audit/Score/Awareness/NIS2 als Sub-Tabs;
# Deeplinks via Router-Alias).: „System Optimierung" (system_tuner) aus
# „Scanner" hierher dazu.
BEWERTEN_GROUP_CONFIG = SidebarGroupConfig(
    key="bewerten",
    label="Sicherheit & Audit",
    icon="assignment",
    items=[
        SidebarItemConfig(
            key="security_assessment",
            label="Security-Bewertung",
            icon="assignment",
            tooltip="Security-Bewertung — Audit, Score, Awareness und "
            "NIS2-Vorfälle in einem Bereich",
            # Container immer sichtbar; die Sub-Tabs tragen ihr bisheriges
            # Lizenz-Feature (seit/Single-Tenant inert) — kein neues
            # License-Server-Feature.
            license_feature="",
        ),
        SidebarItemConfig(
            key="system_tuner",
            label="System Optimierung",
            icon="tune",
            tooltip="System Optimierung — Datenschutz & Telemetrie prüfen und optimieren",
            license_feature="system_tuner",
        ),
    ],
)

# Der frühere Bereich „Assistenz" (Security-Chat,
# ``ki:ollama``) wurde entfernt (6 → 5 Bereiche). Der vereinte FINLAI-Assistent
# (Bedienung + IT-Sicherheit) lebt jetzt als Reiter im Handbuch-Dialog und ist
# über das Maskottchen + F1 erreichbar — kein eigenes Sidebar-Tool mehr.
# „Einstellungen" lebt fix in der Bottom-Leiste (core.sidebar._build_bottom).

# ---------------------------------------------------------------------------
# Zentrale Reihenfolge der statischen NoRisk-Sidebar-Gruppen
# ---------------------------------------------------------------------------
# Die "links"-Gruppe + Coming-Soon-Gruppen kommen NICHT in diese Liste —
# Links ist dynamisch (LinksRepository + Live-Rebuild), Coming-Soon kommt
# direkt aus AppConfig.sidebar_groups. Beide bleiben Sonderfaelle in
# core/sidebar._build_nav.
#
# Die Reihenfolge hier bestimmt die Anzeigereihenfolge im Default-Modus
# (ohne explizite AppConfig.sidebar_groups). Im Config-driven Modus
# kommt die Reihenfolge aus AppConfig — und muss zu dieser Liste passen.
# Reihenfolge cockpit · lage · „Sicherheit & Audit" (bewerten) ·
# „Überwachung" (ueberwachen) · „Scanner" (pruefen). Die internen Gruppen-Keys
# bleiben stabil (nur Anzeigenamen + Reihenfolge + Item-Zuordnung geaendert).
ALL_NORISK_GROUP_CONFIGS: list[SidebarGroupConfig] = [
    COCKPIT_GROUP_CONFIG,
    LAGE_GROUP_CONFIG,
    BEWERTEN_GROUP_CONFIG,
    UEBERWACHEN_GROUP_CONFIG,
    PRUEFEN_GROUP_CONFIG,
]
