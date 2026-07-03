"""
recommendation_engine — Regelbasierte Handlungsempfehlungen.

Generiert priorisierte Handlungsempfehlungen basierend auf den
Kunden-Assessment-Daten. Reine Domänen-Logik ohne Seiteneffekte.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.customer_audit.domain.entities import (
    BackupAuditResult,
    IncidentResponsePlan,
    InfrastructureData,
    NetworkData,
    OrganizationalData,
    SovereigntyAuditResult,
)
from tools.customer_audit.domain.risk_entities import (
    DEFAULT_RISK_CATALOG_BY_KEY,
    RiskAssessment,
    RiskLevel,
)

# ---------------------------------------------------------------------------
# Empfehlungs-Prioritäten
# ---------------------------------------------------------------------------

PRIO_KRITISCH = "Kritisch"
PRIO_HOCH = "Hoch"
PRIO_MITTEL = "Mittel"
PRIO_NIEDRIG = "Niedrig"


@dataclass(frozen=True)
class Recommendation:
    """Eine einzelne Handlungsempfehlung.

    Attributes:
        priority: Priorität (Kritisch/Hoch/Mittel/Niedrig).
        category: Betroffene Kategorie.
        title: Kurztitel der Maßnahme.
        description: Ausführlichere Beschreibung.
    """

    priority: str
    category: str
    title: str
    description: str

    def to_string(self) -> str:
        """Erzeugt eine lesbare Textdarstellung.

        Returns:
            Formatierter String.
        """
        return f"[{self.priority}] {self.category}: {self.title} — {self.description}"


# ---------------------------------------------------------------------------
# Regel-Funktionen
# ---------------------------------------------------------------------------


def _infra_recommendations(data: InfrastructureData) -> list[Recommendation]:
    """Generiert Infrastruktur-Empfehlungen.

    Args:
        data: InfrastructureData des Kunden.

    Returns:
        Liste von Empfehlungen.
    """
    recs: list[Recommendation] = []

    if data.antivirus_status == "inaktiv":
        recs.append(
            Recommendation(
                priority=PRIO_KRITISCH,
                category="IT-Infrastruktur",
                title="Antivirus aktivieren",
                description=(
                    f"Die Antivirus-Lösung '{data.antivirus_name or 'unbekannt'}'"
                    " ist inaktiv. Sofort aktivieren und auf aktuellen Stand bringen."
                ),
            )
        )
    elif data.antivirus_status == "unbekannt":
        recs.append(
            Recommendation(
                priority=PRIO_HOCH,
                category="IT-Infrastruktur",
                title="Antivirus-Status klären",
                description="Antivirus-Status ist unbekannt. Überprüfen und dokumentieren.",
            )
        )

    if data.firewall_status == "inaktiv":
        recs.append(
            Recommendation(
                priority=PRIO_KRITISCH,
                category="IT-Infrastruktur",
                title="Firewall aktivieren",
                description=(
                    f"Die Firewall '{data.firewall_name or 'unbekannt'}' ist inaktiv."
                    " Sofort aktivieren."
                ),
            )
        )
    elif data.firewall_status == "unbekannt":
        recs.append(
            Recommendation(
                priority=PRIO_HOCH,
                category="IT-Infrastruktur",
                title="Firewall-Status klären",
                description="Firewall-Status ist unbekannt. Überprüfen und dokumentieren.",
            )
        )

    # Verschlüsselung
    if not data.verschluesselung or data.verschluesselung == ["Keine"]:
        recs.append(
            Recommendation(
                priority=PRIO_KRITISCH,
                category="IT-Infrastruktur",
                title="Festplattenverschlüsselung einführen",
                description=(
                    "Keine Festplattenverschlüsselung vorhanden."
                    " BitLocker (Windows), FileVault (macOS) oder LUKS (Linux)"
                    " aktivieren."
                ),
            )
        )
    elif "Unbekannt" in data.verschluesselung:
        recs.append(
            Recommendation(
                priority=PRIO_MITTEL,
                category="IT-Infrastruktur",
                title="Verschlüsselungs-Status dokumentieren",
                description="Verschlüsselungsstatus ist unbekannt. Inventar erstellen.",
            )
        )

    # Remote-Access-Tools
    risky = [t for t in data.remote_access_tools if t in {"TeamViewer", "AnyDesk"}]
    if risky:
        recs.append(
            Recommendation(
                priority=PRIO_HOCH,
                category="IT-Infrastruktur",
                title="Remote-Access-Tools absichern",
                description=(
                    f"Folgende Tools mit erhöhtem Risiko gefunden: {', '.join(risky)}."
                    " Zugang beschränken, 2FA aktivieren, regelmäßig auditieren."
                ),
            )
        )

    return recs


def _org_recommendations(data: OrganizationalData) -> list[Recommendation]:
    """Generiert organisatorische Empfehlungen.

    Args:
        data: OrganizationalData des Kunden.

    Returns:
        Liste von Empfehlungen.
    """
    recs: list[Recommendation] = []

    checks = [
        (
            data.zugangskontrollen,
            PRIO_HOCH,
            "Zugangskontrollen",
            "Zugangskontrollkonzept einführen",
            "Benutzerkonten, Rollen und Berechtigungen nach Least-Privilege-Prinzip verwalten.",
        ),
        (
            data.backup_strategie,
            PRIO_KRITISCH,
            "Backup-Strategie",
            "Backup-Strategie implementieren",
            "3-2-1-Regel: 3 Kopien, 2 verschiedene Medien, 1 off-site. Wiederherstellung testen.",
        ),
        (
            data.update_management,
            PRIO_HOCH,
            "Update-Management",
            "Update-Management einrichten",
            "Regelmäßige Updates für OS, Software und Firmware. Patch-Zyklen definieren.",
        ),
        (
            data.mitarbeitersensibilisierung,
            PRIO_MITTEL,
            "Mitarbeitersensibilisierung",
            "Security-Awareness-Schulungen durchführen",
            "Jährliche Schulungen zu Phishing, Social Engineering und Datenschutz.",
        ),
        (
            data.incident_response_plan,
            PRIO_HOCH,
            "Incident-Response",
            "Incident-Response-Plan erstellen",
            "Klare Prozesse für Sicherheitsvorfälle definieren, testen und dokumentieren.",
        ),
        (
            data.dsgvo_konformitaet,
            PRIO_HOCH,
            "DSGVO",
            "DSGVO-Konformität herstellen",
            "Datenschutz-Folgenabschätzung, Verzeichnis von Verarbeitungstätigkeiten.",
        ),
        (
            data.avv_key_separate_storage,
            PRIO_HOCH,
            "Encryption-Audit",
            "Verschluesselungs-Schluessel getrennt verwahren",
            "AVV-/BitLocker-/Backup-Schluessel physisch + logisch getrennt "
            "vom jeweiligen Speicher-Medium verwahren. Ein einzelner "
            "Schluessel-Kompromiss darf nicht alle Schutzebenen auf "
            "einmal aushebeln (NoRisk-Audit-Paket-3 §6.3).",
        ),
    ]

    for value, prio, category, title, desc in checks:
        if value == "Nein":
            recs.append(
                Recommendation(
                    priority=prio,
                    category="Organisatorische Sicherheit",
                    title=title,
                    description=desc,
                )
            )
        elif value == "Teilweise":
            recs.append(
                Recommendation(
                    priority=PRIO_MITTEL,
                    category="Organisatorische Sicherheit",
                    title=f"{title} vervollständigen",
                    description=f"{category} ist nur teilweise vorhanden. Ausbauen und dokumentieren.",
                )
            )

    return recs


def _network_recommendations(data: NetworkData) -> list[Recommendation]:
    """Generiert Netzwerk-Empfehlungen.

    Args:
        data: NetworkData des Kunden.

    Returns:
        Liste von Empfehlungen.
    """
    recs: list[Recommendation] = []

    if data.netzwerksegmentierung == "Nein":
        recs.append(
            Recommendation(
                priority=PRIO_HOCH,
                category="Netzwerksicherheit",
                title="Netzwerksegmentierung einführen",
                description=(
                    "Kritische Systeme in separate Netzsegmente (VLANs) trennen."
                    " Least-Privilege für Netzwerk-Kommunikation."
                ),
            )
        )

    if data.wlan_sicherheit in ("WEP", "Offen"):
        recs.append(
            Recommendation(
                priority=PRIO_KRITISCH,
                category="Netzwerksicherheit",
                title="WLAN-Sicherheit sofort verbessern",
                description=(
                    f"WLAN verwendet {data.wlan_sicherheit} — kritisch unsicher."
                    " Auf WPA3 oder mindestens WPA2 umstellen."
                ),
            )
        )
    elif data.wlan_sicherheit == "WPA2":
        recs.append(
            Recommendation(
                priority=PRIO_NIEDRIG,
                category="Netzwerksicherheit",
                title="WLAN auf WPA3 upgraden",
                description="WPA2 ist akzeptabel, WPA3 bietet besseren Schutz.",
            )
        )

    if data.ids_ips_vorhanden == "Nein":
        recs.append(
            Recommendation(
                priority=PRIO_MITTEL,
                category="Netzwerksicherheit",
                title="IDS/IPS einführen",
                description=(
                    "Intrusion Detection/Prevention System fehlt."
                    " Implementierung prüfen für frühzeitige Angriffserkennung."
                ),
            )
        )

    pt = data.letzter_pentest.lower().strip()
    if pt in ("nie", ""):
        recs.append(
            Recommendation(
                priority=PRIO_HOCH,
                category="Netzwerksicherheit",
                title="Penetrationstest durchführen",
                description=(
                    "Noch kein Penetrationstest durchgeführt."
                    " Jährlicher Pentest durch qualifizierte externe Fachkraft empfohlen."
                ),
            )
        )

    return recs


# ---------------------------------------------------------------------------
# Haupt-Funktion
# ---------------------------------------------------------------------------

_PRIORITY_ORDER = {PRIO_KRITISCH: 0, PRIO_HOCH: 1, PRIO_MITTEL: 2, PRIO_NIEDRIG: 3}


def _backup_recommendations(audit: BackupAuditResult | None) -> list[Recommendation]:
    """Empfehlungen aus dem Backup-Audit-Review-Followup)."""
    if audit is None or not audit.info_block_shown:
        return []
    recs: list[Recommendation] = []
    rule = audit.rule_3_2_1_1_0 or {}
    if not rule.get("3_copies"):
        recs.append(Recommendation(
            priority=PRIO_KRITISCH,
            category="Backup",
            title="3-Kopien-Regel erfuellen",
            description=(
                "Drei unabhaengige Backup-Kopien fehlen. Mindestens "
                "eine Produktion + zwei Sicherungen einrichten."
            ),
        ))
    if not rule.get("1_offsite"):
        recs.append(Recommendation(
            priority=PRIO_KRITISCH,
            category="Backup",
            title="Offsite-Backup einrichten",
            description=(
                "Kein Offsite-Backup. Eine Kopie ausser Haus (Cloud, "
                "verschluesselt; oder Wechselmedium an anderem Standort) "
                "ist Pflicht gegen Standort-Schaden (Feuer/Diebstahl/"
                "Ransomware)."
            ),
        ))
    if not rule.get("1_immutable"):
        recs.append(Recommendation(
            priority=PRIO_HOCH,
            category="Backup",
            title="Immutable Backup-Schicht einbauen",
            description=(
                "WORM/Object-Lock oder Air-Gap fehlt. Ohne immutable "
                "Schicht kann Ransomware auch die Backups verschluesseln."
            ),
        ))
    if not rule.get("0_restore_tested"):
        recs.append(Recommendation(
            priority=PRIO_HOCH,
            category="Backup",
            title="Restore-Test durchfuehren",
            description=(
                "Kein dokumentierter Restore-Test. Mindestens jaehrlich "
                "einen Komplett-Restore probieren — unverifizierte "
                "Backups sind keine Backups."
            ),
        ))
    if not audit.encryption_enabled:
        recs.append(Recommendation(
            priority=PRIO_HOCH,
            category="Backup",
            title="Backup-Verschluesselung aktivieren",
            description=(
                "Unverschluesselte Backups sind ein DSGVO-Risiko bei "
                "Diebstahl/Datenpanne — AES-256 mit getrenntem Key-"
                "Storage aktivieren."
            ),
        ))
    return recs


def _sovereignty_recommendations(
    audit: SovereigntyAuditResult | None,
) -> list[Recommendation]:
    """Empfehlungen aus dem Datensouveraenitaets-Audit."""
    if audit is None or not audit.info_block_shown:
        return []
    recs: list[Recommendation] = []
    providers = list(audit.detected) + list(audit.declared)
    cloud_act = [p for p in providers if p.status == "cloud_act"]
    eu_boundary = [p for p in providers if p.status == "eu_boundary"]
    if cloud_act:
        names = ", ".join({p.name for p in cloud_act})
        recs.append(Recommendation(
            priority=PRIO_KRITISCH,
            category="Datensouveraenitaet",
            title="CLOUD-Act-Provider pruefen",
            description=(
                f"Mandantendaten liegen bei US-Provider(n): {names}. "
                "§43e BRAO / §9 RAO + Schrems II verlangen technische "
                "Zusatzmassnahmen (BYOK/E2EE) oder Wechsel zu EU-"
                "souveraener Alternative."
            ),
        ))
    if eu_boundary:
        names = ", ".join({p.name for p in eu_boundary})
        recs.append(Recommendation(
            priority=PRIO_HOCH,
            category="Datensouveraenitaet",
            title="EU-Boundary kritisch begleiten",
            description=(
                f"Provider mit EU-Boundary: {names}. Restrisiko durch "
                "Mutterkonzern bleibt; BYOK aktivieren wo verfuegbar."
            ),
        ))
    return recs


def _ir_recommendations(plan: IncidentResponsePlan | None) -> list[Recommendation]:
    """Empfehlungen aus dem Incident-Response-Plan."""
    if plan is None or not plan.info_block_shown:
        return []
    recs: list[Recommendation] = []
    if not plan.coordinator_name:
        recs.append(Recommendation(
            priority=PRIO_KRITISCH,
            category="Incident-Response",
            title="IR-Koordinator benennen",
            description=(
                "Kein Verantwortlicher fuer Sicherheitsvorfaelle. "
                "Eine Person mit Stellvertreter benennen — Name, Rolle, "
                "24/7-Kontakt im Plan dokumentieren."
            ),
        ))
    if len(plan.escalation_chain) < 3:
        recs.append(Recommendation(
            priority=PRIO_HOCH,
            category="Incident-Response",
            title="Eskalationskette vollstaendig hinterlegen",
            description=(
                "Mindestens 3 Stellen (Geschaeftsfuehrung, DSB, "
                "Datenschutzbehoerde) muessen im Plan stehen — "
                "DSGVO Art. 33: 72-Stunden-Meldepflicht."
            ),
        ))
    if not plan.forensic_vendor:
        recs.append(Recommendation(
            priority=PRIO_HOCH,
            category="Incident-Response",
            title="Forensik-Vendor vor-vertraglich anbinden",
            description=(
                "Im Ernstfall ist keine Zeit fuer Vendor-Auswahl. "
                "Rahmenvertrag (Retainer) mit forensischem Dienstleister "
                "abschliessen — Reaktionszeit < 4 h vereinbaren."
            ),
        ))
    if not plan.last_drill_date:
        recs.append(Recommendation(
            priority=PRIO_MITTEL,
            category="Incident-Response",
            title="Tabletop-Uebung jaehrlich",
            description=(
                "Noch nie eine Notfall-Uebung durchgefuehrt. Jaehrliche "
                "Tabletop-Uebung deckt Luecken im Plan auf, bevor sie "
                "im Ernstfall wehtun."
            ),
        ))
    return recs


# ---------------------------------------------------------------------------
# Iter 2e-ii — Risiko-Bewertung-Empfehlungen
# ---------------------------------------------------------------------------


# Mapping vom Tool-Key (im Catalog) zum human-readable Namen, der in die
# Empfehlungs-Beschreibung eingebaut wird. Falls ein Key nicht hier steht,
# nutzen wir den Key selbst (Title-Case).
_TOOL_DISPLAY_NAMES: dict[str, str] = {
    "patch_monitor": "Patch-Monitor",
    "csaf_advisor": "Advisory-Monitor",
    "system_scanner": "System-Scanner",
    "email_scanner": "E-Mail-Anhang-Scanner",
    "document_scanner": "Dokument-Scanner",
    "password_checker": "Passwort-Checker",  # noqa: S105 # nosec B105 — Tool-Display-Name
    "supply_chain_monitor": "Supply-Chain-Monitor",
}


def _tool_display(key: str) -> str:
    if key in _TOOL_DISPLAY_NAMES:
        return _TOOL_DISPLAY_NAMES[key]
    return key.replace("_", " ").title()


# Risk-Level → Recommendation-Prioritaet. Akzeptierte Risiken und GERING
# werden vom Caller herausgefiltert.
_RISK_LEVEL_TO_PRIO: dict[RiskLevel, str] = {
    RiskLevel.SEHR_HOCH: PRIO_KRITISCH,
    RiskLevel.HOCH: PRIO_HOCH,
    RiskLevel.MITTEL: PRIO_MITTEL,
    RiskLevel.GERING: PRIO_NIEDRIG,
}


def _risk_recommendations(
    risk_assessments: list[RiskAssessment] | None,
) -> list[Recommendation]:
    """Erzeugt Empfehlungen aus den BSI-200-3-Risiko-Bewertungen (Iter 2e-ii).

    Regeln:
    - ``GERING``-Risiken werden uebersprungen (keine Aktion noetig).
    - ``is_accepted=True``-Risiken werden uebersprungen (User hat
      bewusst entschieden, das Risiko zu tragen).
    - Sonst: ``RiskLevel`` → ``Recommendation.priority``. Wenn der
      Catalog-Eintrag ``recommended_tools`` hat, werden sie in die
      Beschreibung eingebaut ("via Patch-Monitor +..."). Custom-
      Risiken haben keine Tool-Empfehlung — der User selbst weiss,
      wo das Risiko mitigiert werden soll.

    Args:
        risk_assessments: Liste der per-Audit-Risiko-Bewertungen, oder
            ``None`` (Audits vor Iter 2e haben keine Liste).

    Returns:
        Empfehlungen pro actionable Risiko.
    """
    if not risk_assessments:
        return []
    recs: list[Recommendation] = []
    for assessment in risk_assessments:
        if assessment.is_accepted:
            continue
        if assessment.level is RiskLevel.GERING:
            continue
        priority = _RISK_LEVEL_TO_PRIO[assessment.level]
        title = assessment.display_title(DEFAULT_RISK_CATALOG_BY_KEY)
        # Tool-Empfehlung aus dem Catalog ziehen.
        tools: tuple[str, ...] = ()
        if not assessment.is_custom:
            entry = DEFAULT_RISK_CATALOG_BY_KEY.get(assessment.catalog_key)
            if entry is not None:
                tools = entry.recommended_tools
        if tools:
            tool_list = ", ".join(_tool_display(t) for t in tools)
            description = (
                f"Risiko-Level '{assessment.level.label}' (Eintritt: "
                f"{assessment.probability.label}, Schaden: "
                f"{assessment.impact.label}). Empfohlene Tools: {tool_list}."
            )
        else:
            description = (
                f"Risiko-Level '{assessment.level.label}' (Eintritt: "
                f"{assessment.probability.label}, Schaden: "
                f"{assessment.impact.label}). Massnahmen pruefen und "
                "im naechsten Audit-Zyklus mitigieren."
            )
        recs.append(
            Recommendation(
                priority=priority,
                category="Risiko-Bewertung",
                title=title,
                description=description,
            )
        )
    return recs


def generate_recommendations(
    infrastructure: InfrastructureData,
    organizational: OrganizationalData,
    network: NetworkData,
    *,
    backup: BackupAuditResult | None = None,
    sovereignty: SovereigntyAuditResult | None = None,
    incident_response: IncidentResponsePlan | None = None,
    risk_assessments: list[RiskAssessment] | None = None,
) -> list[Recommendation]:
    """Generiert alle Handlungsempfehlungen, priorisiert nach Schwere.

    Args:
        infrastructure: Infrastruktur-Daten.
        organizational: Organisatorische Daten.
        network: Netzwerk-Daten.
        backup: Backup-Audit, optional.
        sovereignty: Datensouveraenitaets-Audit, optional.
        incident_response: IR-Plan, optional.
        risk_assessments: BSI-200-3-Risiko-Liste-ii), optional.

    Returns:
        Priorisierte Liste von Empfehlungen (Kritisch zuerst).
    """
    all_recs: list[Recommendation] = []
    all_recs.extend(_infra_recommendations(infrastructure))
    all_recs.extend(_org_recommendations(organizational))
    all_recs.extend(_network_recommendations(network))
    all_recs.extend(_backup_recommendations(backup))
    all_recs.extend(_sovereignty_recommendations(sovereignty))
    all_recs.extend(_ir_recommendations(incident_response))
    all_recs.extend(_risk_recommendations(risk_assessments))

    return sorted(
        all_recs,
        key=lambda r: _PRIORITY_ORDER.get(r.priority, 99),
    )


def recommendations_as_strings(
    infrastructure: InfrastructureData,
    organizational: OrganizationalData,
    network: NetworkData,
    *,
    backup: BackupAuditResult | None = None,
    sovereignty: SovereigntyAuditResult | None = None,
    incident_response: IncidentResponsePlan | None = None,
    risk_assessments: list[RiskAssessment] | None = None,
) -> list[str]:
    """Generiert Empfehlungen als Textliste (inkl. neuer Sub-Audits).

    Args:
        infrastructure: Infrastruktur-Daten.
        organizational: Organisatorische Daten.
        network: Netzwerk-Daten.
        backup: Backup-Audit, optional.
        sovereignty: Datensouveraenitaets-Audit, optional.
        incident_response: IR-Plan, optional.
        risk_assessments: BSI-200-3-Risiko-Liste-ii), optional.

    Returns:
        Textliste der Empfehlungen.
    """
    recs = generate_recommendations(
        infrastructure,
        organizational,
        network,
        backup=backup,
        sovereignty=sovereignty,
        incident_response=incident_response,
        risk_assessments=risk_assessments,
    )
    return [r.to_string() for r in recs]
