"""workflow_definition — Die statische Workflow-Checkliste, Patrick 2026-07-02).

Die konkrete Reihenfolge der Tool-Nutzung als Code-Konstante (Produkt-Content,
weiterentwickelbar OHNE DB-Migration — nur der Fortschritt liegt in der DB).
Zwei Auspraegungen: eigenes System (14 Schritte, inkl. technischer Scans) und
Kundensystem (6 Schritte, kein technisches Scannen — nur Fragebogen-Audit +
NIS2 + Lieferkette + Report; ``SubjectKind.KUNDE``-Vertrag).

Die drei Scan-Schritte Zertifikat/API/Dependency tragen ihr W1-Profil-Gating
(dieselben Schluessel wie die Sidebar) — der Service blendet sie aus, wenn das
Profil-Flag am eigenen Subjekt ``0`` ist.

Schicht: ``domain/`` — nav_keys sind nur Strings (keine Tool-Importkante); die
Gating-Konstanten kommen aus ``core.security_subject``.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.security_subject.w1_profil import (
    GATING_KEY_API,
    GATING_KEY_ENTWICKLER,
    GATING_KEY_WEBSITE,
)
from tools.norisk_dashboard.domain.workflow_models import (
    APPLIES_BOTH,
    APPLIES_KUNDE,
    APPLIES_SELF,
    WorkflowStepDef,
)

# Phasen-Ueberschriften (Anzeige-Gruppen im Pfad).
_P_SCAN = "1. Prüfen & Scannen"
_P_BEWERTEN = "2. Bewerten"
_P_NACHWEISEN = "3. Nachweisen"
_P_UEBERWACHEN = "4. Überwachen"
_P_BERICHT = "5. Bericht"

_PK_ERFASSEN = "1. Kunde erfassen"
_PK_BEWERTEN = "2. Bewerten"
_PK_NACHWEISEN = "3. Nachweisen"
_PK_BERICHT = "4. Bericht"


#: Die komplette Checkliste (eigenes System + Kunde). Reihenfolge = ``order``.
WORKFLOW_STEPS: tuple[WorkflowStepDef, ...] = (
    # ---- Eigenes System (SELF) -------------------------------------------
    WorkflowStepDef(
        step_key="self_scan_system",
        phase=_P_SCAN,
        titel="System-Scan durchführen",
        beschreibung="Prüft Virenschutz, Firewall und Verschlüsselung Ihres "
        "Rechners — die Rohdaten für den Security-Score.",
        nav_key="system_scanner",
        applies_to=APPLIES_SELF,
        order=1,
    ),
    WorkflowStepDef(
        step_key="self_scan_network",
        phase=_P_SCAN,
        titel="Netzwerk-Scan durchführen",
        beschreibung="Findet Geräte und offene Zugänge in Ihrem Netzwerk.",
        nav_key="network_scanner",
        applies_to=APPLIES_SELF,
        order=2,
    ),
    WorkflowStepDef(
        step_key="self_scan_cert",
        phase=_P_SCAN,
        titel="Zertifikats-Scan",
        beschreibung="Prüft die SSL/TLS-Zertifikate Ihrer Webseiten auf Ablauf "
        "und Schwächen.",
        nav_key="cert_monitor",
        applies_to=APPLIES_SELF,
        gating_key=GATING_KEY_WEBSITE,
        order=3,
    ),
    WorkflowStepDef(
        step_key="self_scan_api",
        phase=_P_SCAN,
        titel="API-Scan",
        beschreibung="Prüft eine eigene Web-Schnittstelle gegen die häufigsten "
        "Schwachstellen.",
        nav_key="api_security",
        applies_to=APPLIES_SELF,
        gating_key=GATING_KEY_API,
        order=4,
    ),
    WorkflowStepDef(
        step_key="self_scan_dependency",
        phase=_P_SCAN,
        titel="Dependency-Scan",
        beschreibung="Prüft die Fremdbausteine Ihrer eigenen Software auf bekannte "
        "Lücken.",
        nav_key="dependency_auditor",
        applies_to=APPLIES_SELF,
        gating_key=GATING_KEY_ENTWICKLER,
        order=5,
    ),
    WorkflowStepDef(
        step_key="self_scan_files",
        phase=_P_SCAN,
        titel="Datei-Scan",
        beschreibung="Prüft verdächtige E-Mail-Anhänge, PDFs und Office-Dateien "
        "vor dem Öffnen.",
        nav_key="file_scanner",
        applies_to=APPLIES_SELF,
        order=6,
    ),
    WorkflowStepDef(
        step_key="self_check_passwords",
        phase=_P_SCAN,
        titel="Passwörter prüfen",
        beschreibung="Bewertet Passwort-Stärke und gleicht gegen bekannte "
        "Datenlecks ab.",
        nav_key="password_checker",
        applies_to=APPLIES_SELF,
        order=7,
    ),
    WorkflowStepDef(
        step_key="self_compute_score",
        phase=_P_BEWERTEN,
        titel="Security-Score berechnen",
        beschreibung="Erst NACH den Scans — der gemessene Score ist nur mit "
        "frischen Scan-Daten aussagekräftig.",
        nav_key="security_scoring",
        applies_to=APPLIES_SELF,
        order=8,
    ),
    WorkflowStepDef(
        step_key="self_run_audit",
        phase=_P_BEWERTEN,
        titel="Security-Audit ausfüllen",
        beschreibung="Der geführte Fragebogen ergänzt, was sich nicht messen "
        "lässt, und liefert die Risikomatrix.",
        nav_key="customer_audit",
        applies_to=APPLIES_SELF,
        order=9,
    ),
    WorkflowStepDef(
        step_key="self_track_awareness",
        phase=_P_NACHWEISEN,
        titel="Schulungen erfassen (Awareness)",
        beschreibung="Dokumentiert Mitarbeiter-Schulungen und Phishing-Übungen.",
        nav_key="awareness_tracker",
        applies_to=APPLIES_SELF,
        order=10,
    ),
    WorkflowStepDef(
        step_key="self_nis2_incidents",
        phase=_P_NACHWEISEN,
        titel="NIS2-Vorfälle pflegen",
        beschreibung="Hält die Meldekette für erhebliche Vorfälle bereit.",
        nav_key="nis2_incidents",
        applies_to=APPLIES_SELF,
        order=11,
    ),
    WorkflowStepDef(
        step_key="self_patch_monitor",
        phase=_P_UEBERWACHEN,
        titel="Patchmonitor prüfen",
        beschreibung="Zeigt fehlende Software-Updates und Auslaufsoftware.",
        nav_key="patch_monitor",
        applies_to=APPLIES_SELF,
        order=12,
    ),
    WorkflowStepDef(
        step_key="self_supply_chain",
        phase=_P_UEBERWACHEN,
        titel="Lieferkette & AVV pflegen",
        beschreibung="Verwaltet Dienstleister und Auftragsverarbeitungsverträge "
        "(NIS2 Art. 21).",
        nav_key="supply_chain_monitor",
        applies_to=APPLIES_SELF,
        order=13,
    ),
    WorkflowStepDef(
        step_key="self_export_report",
        phase=_P_BERICHT,
        titel="PDF-Report exportieren",
        beschreibung="Fasst Score, Audit und offene Themen zusammen — als letzter "
        "Schritt, wenn die Daten frisch sind.",
        nav_key="home",
        applies_to=APPLIES_SELF,
        order=14,
    ),
    # ---- Kundensystem (KUNDE) — kein technisches Scannen -----------------
    WorkflowStepDef(
        step_key="kunde_anlegen",
        phase=_PK_ERFASSEN,
        titel="Kunde erfassen",
        beschreibung="Legen Sie den Kunden an oder wählen Sie ihn oben als "
        "Subjekt aus — die Grundlage für alle weiteren Schritte.",
        nav_key="customer_audit",
        applies_to=APPLIES_KUNDE,
        order=1,
    ),
    WorkflowStepDef(
        step_key="kunde_audit",
        phase=_PK_BEWERTEN,
        titel="Security-Audit (Fragebogen)",
        beschreibung="Bewertet die IT-Sicherheit des Kunden per geführtem "
        "Fragebogen — ersetzt das technische Scoring.",
        nav_key="customer_audit",
        applies_to=APPLIES_KUNDE,
        order=2,
    ),
    WorkflowStepDef(
        step_key="kunde_nis2_betroffenheit",
        phase=_PK_BEWERTEN,
        titel="NIS2-Betroffenheit prüfen",
        beschreibung="Klärt im Fragebogen, ob und wie der Kunde meldepflichtig "
        "ist.",
        nav_key="customer_audit",
        applies_to=APPLIES_KUNDE,
        order=3,
    ),
    WorkflowStepDef(
        step_key="kunde_supply_chain",
        phase=_PK_NACHWEISEN,
        titel="Lieferkette & AVV erfassen",
        beschreibung="Erfasst die Dienstleister und AVV-Verträge des Kunden.",
        nav_key="supply_chain_monitor",
        applies_to=APPLIES_KUNDE,
        order=4,
    ),
    WorkflowStepDef(
        step_key="kunde_nis2_vorfaelle",
        phase=_PK_NACHWEISEN,
        titel="NIS2-Vorfälle pflegen",
        beschreibung="Führt bei Bedarf die Vorfall-Meldekette für den Kunden.",
        nav_key="nis2_incidents",
        applies_to=APPLIES_KUNDE,
        order=5,
    ),
    WorkflowStepDef(
        step_key="kunde_report",
        phase=_PK_BERICHT,
        titel="Audit-Report als PDF",
        beschreibung="Exportiert den prüffähigen Audit-Bericht für den Kunden.",
        nav_key="customer_audit",
        applies_to=APPLIES_KUNDE,
        order=6,
    ),
)


def steps_for_kind(kind: str) -> tuple[WorkflowStepDef, ...]:
    """Alle Schritte fuer eine Subjekt-Art (``"self"`` oder ``"kunde"``).

    Schritte mit ``applies_to == APPLIES_BOTH`` gelten fuer beide. Das
    W1-Profil-Gating (``gating_key``) wird hier NICHT angewandt — das ist Sache
    des Service, der das konkrete Subjekt kennt.

    Args:
        kind: ``"self"`` (eigenes System) oder ``"kunde"``.

    Returns:
        Nach ``order`` sortierte Schritt-Definitionen.
    """
    matched = [
        s for s in WORKFLOW_STEPS if s.applies_to in (kind, APPLIES_BOTH)
    ]
    return tuple(sorted(matched, key=lambda s: s.order))


def step_by_key(step_key: str) -> WorkflowStepDef | None:
    """Findet eine Schritt-Definition ueber ihren stabilen ``step_key``."""
    for step in WORKFLOW_STEPS:
        if step.step_key == step_key:
            return step
    return None


__all__ = ["WORKFLOW_STEPS", "step_by_key", "steps_for_kind"]
