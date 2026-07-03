"""
entities — Domain-Entities für das Kunden-Assessment.

Reine Datenklassen ohne externe Abhängigkeiten.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Audit-Mode
# ---------------------------------------------------------------------------


class AuditMode(Enum):
    """Welche Sicht das Audit einnimmt.

    SELF — Eigene Kanzlei wird auditiert. Auto-Detection (DNS-MX,
        Software-Scan, Backup-Detector) ist aktiv und ergaenzt den
        Fragebogen.
    CUSTOMER — Externer Kunde / Mandant wird auditiert. Nur
        Fragebogen, kein Scanner-Zugriff (laeuft ja nicht auf dem
        Kunden-Rechner).
    """

    SELF = "self"
    CUSTOMER = "customer"


# ---------------------------------------------------------------------------
# Konstanten für Eingabe-Optionen
# ---------------------------------------------------------------------------

BRANCHEN: list[str] = [
    "IT",
    "Finanzen",
    "Gesundheit",
    "Produktion",
    "Handel",
    "Bildung",
    "Öffentlicher Dienst",
    "Sonstige",
]

UNTERNEHMENSGROESSEN: list[str] = ["1-10", "11-50", "51-250", "251-1000", "1000+"]

BETRIEBSSYSTEME_OPTIONEN: list[str] = [
    "Windows 10",
    "Windows 11",
    "Windows Server",
    "macOS",
    "Linux",
    "Sonstige",
]

VERSCHLUESSELUNG_OPTIONEN: list[str] = [
    "BitLocker",
    "FileVault",
    "LUKS",
    "VeraCrypt",
    "Keine",
    "Unbekannt",
]

REMOTE_ACCESS_OPTIONEN: list[str] = [
    "TeamViewer",
    "AnyDesk",
    "RDP",
    "VNC",
    "SSH",
    "Keine",
]

STATUS_OPTIONEN: list[str] = ["aktiv", "inaktiv", "unbekannt"]

JA_NEIN_OPTIONEN: list[str] = ["Ja", "Nein", "Teilweise"]

JA_NEIN_EINFACH: list[str] = ["Ja", "Nein"]

WLAN_OPTIONEN: list[str] = ["WPA3", "WPA2", "WEP", "Offen", "Unbekannt"]

# Freitext-Maximallänge (Sicherheits-Limit)
MAX_TEXT_LENGTH = 500


def sanitize_text(value: str) -> str:
    """Begrenzt einen Freitext-Wert beim Persistieren (Input-Begrenzung).

 / (escape-at-render): Diese Funktion escaped KEIN HTML
    mehr — gespeichert wird Klartext. Output-Encoding passiert
    kontext-spezifisch an jeder markup-interpretierenden Render-/Export-
    Stelle (``core.escape.escape_html``). Hier verbleiben nur die
    Input-Concerns: Längenkappung und Entfernen von Steuerzeichen.

    Args:
        value: Zu begrenzender Text.

    Returns:
        Gekappter Text ohne Steuerzeichen (Zeilenumbruch/Tab bleiben).
    """
    cleaned = "".join(
        ch for ch in value if ch in "\n\t" or not (ord(ch) < 32 or ord(ch) == 127)
    )
    return cleaned[:MAX_TEXT_LENGTH]


def unescape_text(value: str) -> str:
    """Macht das frühere Persist-HTML-Escaping rückgängig.

    NUR noch für die einmalige Daten-Migration ``t315_escape_at_render_v1``
    (Repository) in Gebrauch — Bestandsdaten wurden bis escaped
    persistiert. Im Produktiv-Pfad NICHT mehr verwenden; der
    Edit-Unescape ist entfallen, weil die DB Klartext enthält).
    Die Ersetzungen laufen in **umgekehrter** Reihenfolge zum früheren
    Escape — ``&amp;`` zuletzt, sonst würde ``&amp;lt;`` fälschlich zu
    ``<`` statt ``&lt;``.

    Args:
        value: Mit dem Alt-Verhalten escapter Text.

    Returns:
        Der ursprüngliche Klartext.
    """
    from core.escape import unescape_legacy_html  # noqa: PLC0415

    return unescape_legacy_html(value)


# ---------------------------------------------------------------------------
# Daten-Entities
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CustomerData:
    """Kundenstammdaten.

    Attributes:
        firmenname: Name des Unternehmens (Pflichtfeld).
        ansprechpartner_name: Name des Ansprechpartners.
        ansprechpartner_email: E-Mail des Ansprechpartners.
        ansprechpartner_telefon: Telefonnummer.
        branche: Branche (aus BRANCHEN).
        unternehmensgroesse: Größenklasse (aus UNTERNEHMENSGROESSEN).
        erstellungsdatum: ISO-Datum der Erstellung.
    """

    firmenname: str
    ansprechpartner_name: str = ""
    ansprechpartner_email: str = ""
    ansprechpartner_telefon: str = ""
    branche: str = "Sonstige"
    unternehmensgroesse: str = "1-10"
    erstellungsdatum: str = ""
    # Privatperson / Kleinstbetrieb: enterprise-typische Anforderungen
    # (Zugangskontrollen, Netzwerksegmentierung, IDS/IPS, Pentest) werden im
    # Score als "nicht zutreffend" behandelt — sie fallen aus dem Nenner statt
    # als 0 zu werten, sodass ihr Fehlen den Score nicht drueckt.
    ist_privatperson: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert die Entity.

        Returns:
            JSON-serialisierbares Dict.
        """
        return {
            "firmenname": self.firmenname,
            "ansprechpartner_name": self.ansprechpartner_name,
            "ansprechpartner_email": self.ansprechpartner_email,
            "ansprechpartner_telefon": self.ansprechpartner_telefon,
            "branche": self.branche,
            "unternehmensgroesse": self.unternehmensgroesse,
            "erstellungsdatum": self.erstellungsdatum,
            "ist_privatperson": self.ist_privatperson,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CustomerData:
        """Deserialisiert ein Dict.

        Args:
            d: Dict-Repräsentation.

        Returns:
            CustomerData-Instanz.
        """
        return cls(
            firmenname=d.get("firmenname", ""),
            ansprechpartner_name=d.get("ansprechpartner_name", ""),
            ansprechpartner_email=d.get("ansprechpartner_email", ""),
            ansprechpartner_telefon=d.get("ansprechpartner_telefon", ""),
            branche=d.get("branche", "Sonstige"),
            unternehmensgroesse=d.get("unternehmensgroesse", "1-10"),
            erstellungsdatum=d.get("erstellungsdatum", ""),
            ist_privatperson=bool(d.get("ist_privatperson", False)),
        )


@dataclass(frozen=True)
class InfrastructureData:
    """IT-Infrastruktur-Daten des Kunden.

    Attributes:
        betriebssysteme: Liste eingesetzter OS (aus BETRIEBSSYSTEME_OPTIONEN).
        os_patch_stand: Freitext zu Versionen/Patch-Stand.
        antivirus_name: Name der Antivirus-Lösung.
        antivirus_status: Status (aus STATUS_OPTIONEN).
        firewall_name: Name der Firewall.
        firewall_status: Status (aus STATUS_OPTIONEN).
        verschluesselung: Liste eingesetzter Verschlüsselung.
        vpn_loesung: Freitext VPN-Lösung.
        browser: Freitext Browser + Versionen.
        server_infrastruktur: Freitext (On-Premise/Cloud/Hybrid).
        remote_access_tools: Liste eingesetzter Remote-Access-Tools.
    """

    betriebssysteme: list[str] = field(default_factory=list)
    os_patch_stand: str = ""
    antivirus_name: str = ""
    antivirus_status: str = "unbekannt"
    firewall_name: str = ""
    firewall_status: str = "unbekannt"
    verschluesselung: list[str] = field(default_factory=list)
    vpn_loesung: str = ""
    browser: str = ""
    server_infrastruktur: str = ""
    remote_access_tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert die Entity.

        Returns:
            JSON-serialisierbares Dict.
        """
        return {
            "betriebssysteme": self.betriebssysteme,
            "os_patch_stand": self.os_patch_stand,
            "antivirus_name": self.antivirus_name,
            "antivirus_status": self.antivirus_status,
            "firewall_name": self.firewall_name,
            "firewall_status": self.firewall_status,
            "verschluesselung": self.verschluesselung,
            "vpn_loesung": self.vpn_loesung,
            "browser": self.browser,
            "server_infrastruktur": self.server_infrastruktur,
            "remote_access_tools": self.remote_access_tools,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InfrastructureData:
        """Deserialisiert ein Dict.

        Args:
            d: Dict-Repräsentation.

        Returns:
            InfrastructureData-Instanz.
        """
        return cls(
            betriebssysteme=d.get("betriebssysteme", []),
            os_patch_stand=d.get("os_patch_stand", ""),
            antivirus_name=d.get("antivirus_name", ""),
            antivirus_status=d.get("antivirus_status", "unbekannt"),
            firewall_name=d.get("firewall_name", ""),
            firewall_status=d.get("firewall_status", "unbekannt"),
            verschluesselung=d.get("verschluesselung", []),
            vpn_loesung=d.get("vpn_loesung", ""),
            browser=d.get("browser", ""),
            server_infrastruktur=d.get("server_infrastruktur", ""),
            remote_access_tools=d.get("remote_access_tools", []),
        )


@dataclass(frozen=True)
class OrganizationalData:
    """Organisatorische Sicherheits-Daten.

    Jede Kategorie: "Ja" / "Nein" / "Teilweise".

    Attributes:
        zugangskontrollen: Zugangskontrollen vorhanden?
        backup_strategie: Backup-Strategie vorhanden?
        update_management: Update-Management vorhanden?
        mitarbeitersensibilisierung: Mitarbeitersensibilisierung vorhanden?
        incident_response_plan: Incident-Response-Plan vorhanden?
        dsgvo_konformitaet: DSGVO-Konformität gewährleistet?
        avv_key_separate_storage: AVV-/Crypto-Schluessel getrennt von
                                     Backup-Speicher verwahrt? (3f-ii,
                                     ii Encryption-Audit, NoRisk-
                                     Audit-Paket-3 §6.3).
    """

    zugangskontrollen: str = "Nein"
    backup_strategie: str = "Nein"
    update_management: str = "Nein"
    mitarbeitersensibilisierung: str = "Nein"
    incident_response_plan: str = "Nein"
    dsgvo_konformitaet: str = "Nein"
    avv_key_separate_storage: str = "Nein"

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert die Entity.

        Returns:
            JSON-serialisierbares Dict.
        """
        return {
            "zugangskontrollen": self.zugangskontrollen,
            "backup_strategie": self.backup_strategie,
            "update_management": self.update_management,
            "mitarbeitersensibilisierung": self.mitarbeitersensibilisierung,
            "incident_response_plan": self.incident_response_plan,
            "dsgvo_konformitaet": self.dsgvo_konformitaet,
            "avv_key_separate_storage": self.avv_key_separate_storage,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> OrganizationalData:
        """Deserialisiert ein Dict.

        Args:
            d: Dict-Repräsentation.

        Returns:
            OrganizationalData-Instanz.
        """
        return cls(
            zugangskontrollen=d.get("zugangskontrollen", "Nein"),
            backup_strategie=d.get("backup_strategie", "Nein"),
            update_management=d.get("update_management", "Nein"),
            mitarbeitersensibilisierung=d.get("mitarbeitersensibilisierung", "Nein"),
            incident_response_plan=d.get("incident_response_plan", "Nein"),
            dsgvo_konformitaet=d.get("dsgvo_konformitaet", "Nein"),
            avv_key_separate_storage=d.get("avv_key_separate_storage", "Nein"),
        )


@dataclass(frozen=True)
class PhishingData:
    """E-Mail-/Phishing-Sicherheits-Daten des Kunden.

    Speist den Phishing-Risikowert in der BSI-200-3-Matrix
    (:func:`tools.customer_audit.domain.risk_derivation.derive_risk_seeds`),
    statt ihn als statischen Default stehen zu lassen. Jede Kategorie:
    "Ja" / "Nein" / "Teilweise" (analog:class:`OrganizationalData`);
    "Nicht zutreffend" / "Unbekannt" werden bei der Ableitung neutral
    behandelt (kein Auf-/Abschlag).

    Attributes:
        mfa_aktiv: MFA für kritische Zugänge (Mail, VPN, Admin)?
        phishing_schulung_aktuell: Phishing-Awareness-Schulung < 12 Monate?
        mail_spoofing_schutz: SPF/DKIM/DMARC für die eigene Domain aktiv?
        mail_filter_aktiv: Spam-/Phishing-Mailfilter im Einsatz?
    """

    mfa_aktiv: str = "Nein"
    phishing_schulung_aktuell: str = "Nein"
    mail_spoofing_schutz: str = "Nein"
    mail_filter_aktiv: str = "Nein"

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert die Entity.

        Returns:
            JSON-serialisierbares Dict.
        """
        return {
            "mfa_aktiv": self.mfa_aktiv,
            "phishing_schulung_aktuell": self.phishing_schulung_aktuell,
            "mail_spoofing_schutz": self.mail_spoofing_schutz,
            "mail_filter_aktiv": self.mail_filter_aktiv,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PhishingData:
        """Deserialisiert ein Dict.

        Args:
            d: Dict-Repräsentation.

        Returns:
            PhishingData-Instanz.
        """
        return cls(
            mfa_aktiv=d.get("mfa_aktiv", "Nein"),
            phishing_schulung_aktuell=d.get("phishing_schulung_aktuell", "Nein"),
            mail_spoofing_schutz=d.get("mail_spoofing_schutz", "Nein"),
            mail_filter_aktiv=d.get("mail_filter_aktiv", "Nein"),
        )


@dataclass(frozen=True)
class NetworkData:
    """Netzwerksicherheits-Daten des Kunden.

    Attributes:
        netzwerksegmentierung: Ja/Nein/Teilweise.
        wlan_sicherheit: WPA3/WPA2/WEP/Offen/Unbekannt.
        offene_ports_bekannt: Ja/Nein.
        ids_ips_vorhanden: Ja/Nein.
        letzter_pentest: Datum oder "Nie"/"Unbekannt".
    """

    netzwerksegmentierung: str = "Nein"
    wlan_sicherheit: str = "Unbekannt"
    offene_ports_bekannt: str = "Nein"
    ids_ips_vorhanden: str = "Nein"
    letzter_pentest: str = "Unbekannt"

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert die Entity.

        Returns:
            JSON-serialisierbares Dict.
        """
        return {
            "netzwerksegmentierung": self.netzwerksegmentierung,
            "wlan_sicherheit": self.wlan_sicherheit,
            "offene_ports_bekannt": self.offene_ports_bekannt,
            "ids_ips_vorhanden": self.ids_ips_vorhanden,
            "letzter_pentest": self.letzter_pentest,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> NetworkData:
        """Deserialisiert ein Dict.

        Args:
            d: Dict-Repräsentation.

        Returns:
            NetworkData-Instanz.
        """
        return cls(
            netzwerksegmentierung=d.get("netzwerksegmentierung", "Nein"),
            wlan_sicherheit=d.get("wlan_sicherheit", "Unbekannt"),
            offene_ports_bekannt=d.get("offene_ports_bekannt", "Nein"),
            ids_ips_vorhanden=d.get("ids_ips_vorhanden", "Nein"),
            letzter_pentest=d.get("letzter_pentest", "Unbekannt"),
        )


@dataclass(frozen=True)
class CategoryScore:
    """Score einer einzelnen Bewertungskategorie.

    Attributes:
        name: Kategoriename.
        score: Score 0–100.
        label: Risikostufe (Niedrig/Mittel/Hoch/Kritisch).
    """

    name: str
    score: float
    label: str

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert die Entity.

        Returns:
            JSON-serialisierbares Dict.
        """
        return {"name": self.name, "score": self.score, "label": self.label}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CategoryScore:
        """Deserialisiert ein Dict.

        Args:
            d: Dict-Repräsentation.

        Returns:
            CategoryScore-Instanz.
        """
        return cls(
            name=d.get("name", ""),
            score=d.get("score", 0.0),
            label=d.get("label", "Kritisch"),
        )


# ---------------------------------------------------------------------------
# Backup-Audit
# ---------------------------------------------------------------------------

#: Bekannte Backup-Software-Familien fuer die optionale Auto-Detection.
#: Wird beim Detector in Windows-Registry-Eintraege uebersetzt.
BEKANNTE_BACKUP_TOOLS: list[str] = [
    "Veeam Agent",
    "Acronis Cyber Protect",
    "Macrium Reflect",
    "Windows Backup",
    "AOMEI Backupper",
    "EaseUS Todo Backup",
    "Backblaze",
    "Synology Active Backup",
    "QNAP HBS",
    "Duplicati",
    "Restic",
    "Veeam Backup & Replication",
]


@dataclass(frozen=True)
class BackupAuditResult:
    """Ergebnis der Backup-Auditierung (3-2-1-1-0 + optional Detection).

    Patrick-Direktive 2026-05-15: ``detection_enabled`` ist optionaler
    Switch, weil nicht jeder Anwender Backup-Software installiert hat
    oder die Detektion ueberhaupt zulassen will.
    """

    detection_enabled: bool = False
    detected_tools: list[str] = field(default_factory=list)
    last_successful_runs: dict[str, str] = field(default_factory=dict)
    rule_3_2_1_1_0: dict[str, bool] = field(default_factory=dict)
    rpo_hours: int | None = None
    rto_hours: int | None = None
    encryption_enabled: bool = False
    key_separately_stored: bool = False
    konzept_pdf_uploaded: bool = False
    last_restore_test: str = ""
    score: int = 0
    info_block_shown: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_enabled": self.detection_enabled,
            "detected_tools": list(self.detected_tools),
            "last_successful_runs": dict(self.last_successful_runs),
            "rule_3_2_1_1_0": dict(self.rule_3_2_1_1_0),
            "rpo_hours": self.rpo_hours,
            "rto_hours": self.rto_hours,
            "encryption_enabled": self.encryption_enabled,
            "key_separately_stored": self.key_separately_stored,
            "konzept_pdf_uploaded": self.konzept_pdf_uploaded,
            "last_restore_test": self.last_restore_test,
            "score": self.score,
            "info_block_shown": self.info_block_shown,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BackupAuditResult:
        return cls(
            detection_enabled=bool(d.get("detection_enabled", False)),
            detected_tools=list(d.get("detected_tools", [])),
            last_successful_runs=dict(d.get("last_successful_runs", {})),
            rule_3_2_1_1_0=dict(d.get("rule_3_2_1_1_0", {})),
            rpo_hours=d.get("rpo_hours"),
            rto_hours=d.get("rto_hours"),
            encryption_enabled=bool(d.get("encryption_enabled", False)),
            key_separately_stored=bool(d.get("key_separately_stored", False)),
            konzept_pdf_uploaded=bool(d.get("konzept_pdf_uploaded", False)),
            last_restore_test=d.get("last_restore_test", ""),
            score=int(d.get("score", 0)),
            info_block_shown=bool(d.get("info_block_shown", False)),
        )


def compute_backup_score(
    audit: BackupAuditResult, *, apply_detection_cap: bool = True
) -> int:
    """Score-Logik nach Konzept §4.1 (max 15).

    Ohne Detection: Cap auf 50 % (Selbst-Auskunft ist weniger belastbar
    als Detection-Befund). Patrick-Direktive: Detection-OFF darf nicht
    null Punkte geben — sonst wird der Switch als "Strafe" empfunden.

    Args:
        audit: Backup-Audit-Eintrag.
        apply_detection_cap: ``True`` (Default) für den Gesamt-Score — Selbst-
            Auskunft ohne Detection wird auf 50 % gedeckelt. ``False`` für die
            Risiko-Matrix-Ableitung (:func:`risk_derivation.derive_risk_seeds`):
            dort soll die DEKLARIERTE Setup-Qualität zählen, sonst erreicht ein
            perfekt angehaktes (aber nur selbst-deklariertes) 3-2-1-1-0-Backup
            nie "stark" und das Backup-Risiko bliebe trotz allem hoch.
    """
    rule = audit.rule_3_2_1_1_0
    rule_keys = ("3_copies", "2_media", "1_offsite", "1_immutable", "0_restore_tested")
    rule_filled = sum(1 for k in rule_keys if rule.get(k, False))
    rule_score = (rule_filled / len(rule_keys)) * 8  # 0..8

    rpo_rto_score = 2 if (audit.rpo_hours is not None and audit.rto_hours is not None) else 0

    encryption_score = 0
    if audit.encryption_enabled:
        encryption_score += 1
        if audit.key_separately_stored:
            encryption_score += 1

    konzept_score = 1 if audit.konzept_pdf_uploaded else 0

    test_score = 0
    if audit.last_restore_test:
        try:
            d = datetime.fromisoformat(audit.last_restore_test)
            if d.tzinfo is None:
                d = d.replace(tzinfo=UTC)
            age_days = (datetime.now(UTC) - d).days
            if 0 <= age_days <= 365:
                test_score = 2
            elif age_days <= 730:
                test_score = 1
        except (ValueError, TypeError):
            test_score = 0

    raw = rule_score + rpo_rto_score + encryption_score + konzept_score + test_score
    raw = min(15, int(round(raw)))

    if apply_detection_cap and not audit.detection_enabled and not audit.detected_tools:
        raw = int(raw * 0.5)
    return max(0, raw)


# ---------------------------------------------------------------------------
# Datensouveraenitaets-Audit
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectedProvider:
    """Ein einzelner durch den Scanner erkannter Provider."""

    name: str
    status: str  # "eu_sovereign" | "eu_boundary" | "cloud_act"
    category: str
    via: str  # "dns_mx" | "spf" | "software" | "self_declared"
    evidence: str  # konkreter Match-Wert (Hostname / Software-Name)
    legal_entity_country: str = ""
    parent_country: str = ""
    residual_risk_note: str = ""
    original_label: str = ""  # Original-Checkbox-Label bei Selbst-Deklaration

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "category": self.category,
            "via": self.via,
            "evidence": self.evidence,
            "legal_entity_country": self.legal_entity_country,
            "parent_country": self.parent_country,
            "residual_risk_note": self.residual_risk_note,
            "original_label": self.original_label,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DetectedProvider:
        return cls(
            name=d.get("name", ""),
            status=d.get("status", "cloud_act"),
            category=d.get("category", "saas_other"),
            via=d.get("via", "self_declared"),
            evidence=d.get("evidence", ""),
            legal_entity_country=d.get("legal_entity_country", ""),
            parent_country=d.get("parent_country", ""),
            residual_risk_note=d.get("residual_risk_note", ""),
            original_label=d.get("original_label", ""),
        )


@dataclass(frozen=True)
class SovereigntyAuditResult:
    """Ergebnis der Datensouveraenitaets-Pruefung.

    Patrick-Direktive 2026-05-15: DNS + MX + Software-Scan + Fragebogen,
    KEIN Browser-History.

    Attributes:
        detection_enabled: User-Flag — automatische Detection (DNS-MX +
            Software-Scan) aktiviert? Wie beim Backup-Audit: Cap auf
            50 % wenn ohne Detection.
        domain: Eingegebene Kanzlei-Domain (z. B.
            ``"kanzlei-mueller.at"``).
        detected: Auto-erkannte Provider via DNS/MX/SPF/Software.
        declared: Selbst-deklarierte Provider aus dem
            Fragebogen.
        scan_errors: Liste menschlesbarer Fehlermeldungen aus dem
            Scan (z. B. "DNS-Lookup fehlgeschlagen — domain nicht
            aufloesbar"). Werden im Report transparent gezeigt.
        rechtshinweise: Liste von Berufsrechts-/Compliance-Warnungen
            (z. B. M365 + Anwaltskanzlei ohne BYOK -> §43e BRAO).
        score: Auswertung (-50.. +10). Schwellen:
            ``> 0``: gruen, ``-1.. -20``: gelb, ``< -20``: rot.
        info_block_shown: Wurde der Hintergrund-Info-Block angezeigt?
    """

    detection_enabled: bool = False
    domain: str = ""
    detected: list[DetectedProvider] = field(default_factory=list)
    declared: list[DetectedProvider] = field(default_factory=list)
    scan_errors: list[str] = field(default_factory=list)
    rechtshinweise: list[str] = field(default_factory=list)
    score: int = 0
    info_block_shown: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_enabled": self.detection_enabled,
            "domain": self.domain,
            "detected": [p.to_dict() for p in self.detected],
            "declared": [p.to_dict() for p in self.declared],
            "scan_errors": list(self.scan_errors),
            "rechtshinweise": list(self.rechtshinweise),
            "score": self.score,
            "info_block_shown": self.info_block_shown,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SovereigntyAuditResult:
        return cls(
            detection_enabled=bool(d.get("detection_enabled", False)),
            domain=d.get("domain", ""),
            detected=[
                DetectedProvider.from_dict(x) for x in d.get("detected", [])
            ],
            declared=[
                DetectedProvider.from_dict(x) for x in d.get("declared", [])
            ],
            scan_errors=list(d.get("scan_errors", [])),
            rechtshinweise=list(d.get("rechtshinweise", [])),
            score=int(d.get("score", 0)),
            info_block_shown=bool(d.get("info_block_shown", False)),
        )


#: Punkte je Status. Schwelle ``status``:
_SOVEREIGNTY_STATUS_POINTS: dict[str, int] = {
    "cloud_act": -10,
    "eu_boundary": -5,
    "eu_sovereign": 0,
    "self_hosted": 5,
}


def compute_sovereignty_score(audit: SovereigntyAuditResult) -> int:
    """Score-Berechnung gemaess Konzept §4.2.

    Logik:
        - Detected + Declared kombiniert, doppelte Provider per
          ``name`` deduplizieren (Detection ueberschreibt Declaration).
        - Pro Provider werden die Status-Punkte addiert.
        - Ohne aktive Detection (kein Scanner-Befund) werden positive
          Boni halbiert (Selbst-Auskunft schwaecher), Penalties bleiben
          unangetastet — sonst wuerde Detection-OFF einen schlechten
          Provider belohnen.
        - Bonus +5 pro ``self_hosted``-Status (nur ueber Declaration
          erfassbar — Scanner kann es nicht zuverlaessig erkennen).

    Returns:
        Int zwischen -50 und +10 (cap'd).
    """
    by_name: dict[str, DetectedProvider] = {}
    for p in audit.detected:
        by_name[p.name] = p
    for p in audit.declared:
        if p.name not in by_name:
            by_name[p.name] = p

    raw = 0
    for p in by_name.values():
        raw += _SOVEREIGNTY_STATUS_POINTS.get(p.status, 0)
    if not audit.detection_enabled and not audit.detected and raw > 0:
        # Nur Boni werden halbiert, nicht Penalties.
        raw = int(raw * 0.5)
    return max(-50, min(10, raw))


# ---------------------------------------------------------------------------
# Incident-Response-Plan
# ---------------------------------------------------------------------------


#: Pflicht-Meldekanaele bei einem Sicherheitsvorfall — werden im
#: PDF-/Markdown-Plan als Checkliste gerendert.
MELDEKANAELE: list[str] = [
    "Geschaeftsfuehrung / Kanzlei-Inhaber",
    "Datenschutzbeauftragter (intern oder extern)",
    "IT-Dienstleister / MSP",
    "Datenschutzbehoerde (DSGVO Art. 33: 72 h)",
    "Mandanten (DSGVO Art. 34, falls hohes Risiko)",
    "BSI/CERT (NIS2 Art. 23: 24 h, wenn pflichtig)",
    "Rechtsanwaltskammer (Berufsrechtspflicht)",
    "Polizei / Cybercrime-Stelle",
    "Cyber-Versicherung",
]

#: Phasen-Vorlage nach BSI DER.2.1 + NIST CSF 2.0 RS/RC. Wird als
#: nummerierte Checkliste in den Plan eingebaut.
IR_PHASEN: list[str] = [
    "Vorbereitung (Plan vorhanden, Kontakte aktuell, Logs aktiviert)",
    "Erkennung (Wie wurde der Vorfall bemerkt? Welche Logs ausgewertet?)",
    "Ersteinschaetzung (Umfang, betroffene Systeme, Kritikalitaet)",
    "Eindaemmung (Isolation, Account-Sperre, Netzwerk-Trennung)",
    "Wiederherstellung (aus Backup, Verifikation, Rueck-Inbetriebnahme)",
    "Nachbereitung (Root-Cause, Lessons Learned, Plan-Update)",
]


@dataclass(frozen=True)
class IncidentResponsePlan:
    """Fragebogen-Eingaben zum Incident-Response-Plan.

    Der Plan wird beim Audit erfasst und beim Export zu PDF/Markdown
    als Notfallhandbuch gerendert. Patrick-Direktive 2026-05-15:
    Fragebogen-gefuehrt + Meldepflicht-Vorlagen (DSGVO 72h, NIS2 24h,
    RAK-Meldung).

    Attributes:
        coordinator_name: Wer koordiniert im Ernstfall?
        coordinator_contact: Telefon/E-Mail des Koordinators.
        escalation_chain: Liste der zu benachrichtigenden Stellen
            (subset aus:data:`MELDEKANAELE`).
        critical_systems: Frei-Text: welche Systeme sind kritisch?
            (Kanzleisoftware, Mail, beA, Telefonie,...)
        backup_location_ref: Verweis auf den Backup-Audit-Eintrag —
            wo liegen die Backups, wer hat Zugriff?
        forensic_vendor: Externer Forensik-Dienstleister vorab
            kontraktiert?
        forensic_vendor_contact: Kontakt-Daten des Forensik-Anbieters.
        cyber_insurance: Cyber-Versicherung vorhanden?
        cyber_insurance_policy: Policen-Nummer / Anbieter (frei-Text).
        last_drill_date: ISO-Datum letzte Notfall-Uebung (None
            wenn nie geuebt).
        drill_findings: Frei-Text — was wurde bei der Uebung
            gelernt?
        plan_pdf_exported: Wurde der Plan als PDF/MD exportiert?
        score: Auswertung 0..15.
        info_block_shown: Wurde der Hintergrund-Info-Block angezeigt?
    """

    coordinator_name: str = ""
    coordinator_contact: str = ""
    escalation_chain: list[str] = field(default_factory=list)
    critical_systems: str = ""
    backup_location_ref: str = ""
    forensic_vendor: str = ""
    forensic_vendor_contact: str = ""
    cyber_insurance: bool = False
    cyber_insurance_policy: str = ""
    last_drill_date: str = ""
    drill_findings: str = ""
    plan_pdf_exported: bool = False
    score: int = 0
    info_block_shown: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "coordinator_name": self.coordinator_name,
            "coordinator_contact": self.coordinator_contact,
            "escalation_chain": list(self.escalation_chain),
            "critical_systems": self.critical_systems,
            "backup_location_ref": self.backup_location_ref,
            "forensic_vendor": self.forensic_vendor,
            "forensic_vendor_contact": self.forensic_vendor_contact,
            "cyber_insurance": self.cyber_insurance,
            "cyber_insurance_policy": self.cyber_insurance_policy,
            "last_drill_date": self.last_drill_date,
            "drill_findings": self.drill_findings,
            "plan_pdf_exported": self.plan_pdf_exported,
            "score": self.score,
            "info_block_shown": self.info_block_shown,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> IncidentResponsePlan:
        return cls(
            coordinator_name=d.get("coordinator_name", ""),
            coordinator_contact=d.get("coordinator_contact", ""),
            escalation_chain=list(d.get("escalation_chain", [])),
            critical_systems=d.get("critical_systems", ""),
            backup_location_ref=d.get("backup_location_ref", ""),
            forensic_vendor=d.get("forensic_vendor", ""),
            forensic_vendor_contact=d.get("forensic_vendor_contact", ""),
            cyber_insurance=bool(d.get("cyber_insurance", False)),
            cyber_insurance_policy=d.get("cyber_insurance_policy", ""),
            last_drill_date=d.get("last_drill_date", ""),
            drill_findings=d.get("drill_findings", ""),
            plan_pdf_exported=bool(d.get("plan_pdf_exported", False)),
            score=int(d.get("score", 0)),
            info_block_shown=bool(d.get("info_block_shown", False)),
        )


#: Maximalpunkte des IR-Plan-Scores (voll bzw. fuer Privatpersonen/Kleinstbetriebe,
#: bei denen Eskalationskette + Forensik-Vendor als enterprise-only entfallen).
IR_SCORE_MAX: int = 15
IR_SCORE_MAX_PRIVAT: int = 10  # 15 - 3 (Eskalationskette) - 2 (Forensik-Vendor)


def compute_ir_score(plan: IncidentResponsePlan, *, ist_privatperson: bool = False) -> int:
    """Score-Berechnung fuer den IR-Plan (max 15, bzw. 10 fuer Privatpersonen).

    Aufschluesselung:
        Koordinator + Kontakt: 3
        Eskalationskette >= 3: 3 (enterprise-only → entfaellt bei Privat)
        Kritische Systeme definiert: 2
        Backup-Location ref: 1
        Forensik-Vendor kontraktiert: 2 (enterprise-only → entfaellt bei Privat)
        Cyber-Versicherung: 1
        Last drill <= 12 Monate: 3
        Plan PDF exportiert: (Kein direkter Score-Slot, aber
                                     gilt als Confirmation dass der
                                     Plan in PDF-Form vorliegt)

    Args:
        plan: Der IR-Plan-Eintrag.
        ist_privatperson: Wenn ``True``, fallen Eskalationskette (>=3 Kanaele)
            und Forensik-Vendor aus der Wertung — bei Einzelpersonen/Kleinst-
            betrieben sind das keine sinnvollen Anforderungen. Das Maximum sinkt
            entsprechend auf:data:`IR_SCORE_MAX_PRIVAT` (
            ``calculate_ir_plan_score``).
    """
    s = 0
    if plan.coordinator_name and plan.coordinator_contact:
        s += 3
    if not ist_privatperson and len(plan.escalation_chain) >= 3:
        s += 3
    if plan.critical_systems.strip():
        s += 2
    if plan.backup_location_ref.strip():
        s += 1
    if not ist_privatperson and plan.forensic_vendor.strip():
        s += 2
    if plan.cyber_insurance:
        s += 1
    if plan.last_drill_date:
        try:
            d = datetime.fromisoformat(plan.last_drill_date)
            if d.tzinfo is None:
                d = d.replace(tzinfo=UTC)
            age_days = (datetime.now(UTC) - d).days
            if 0 <= age_days <= 365:
                s += 3
            elif age_days <= 730:
                s += 2
        except (ValueError, TypeError):
            pass
    cap = IR_SCORE_MAX_PRIVAT if ist_privatperson else IR_SCORE_MAX
    return min(cap, s)


@dataclass(frozen=True)
class CustomerAuditResult:
    """Vollständiges Kunden-Audit-Ergebnis.

    Attributes:
        audit_id: UUID.
        audit_mode: ``AuditMode.SELF`` oder ``AuditMode.CUSTOMER``
            (Default ``CUSTOMER`` fuer Backwards-Compat).
        customer_data: Kundenstammdaten.
        infrastructure_data: IT-Infrastruktur.
        organizational_data: Organisatorische Sicherheit.
        network_data: Netzwerksicherheit.
        backup_audit: Backup-Auditierung.
        category_scores: Scores je Kategorie.
        overall_score: Gewichteter Gesamtscore 0–100.
        risk_level: Risikostufe (Kritisch/Hoch/Mittel/Niedrig).
        recommendations: Handlungsempfehlungen.
        created_at: Erstellungszeitpunkt (ISO-String).
        subject_id: UUID des verknüpften kanonischen Subjekts. Leer für Audits vor der Subjekt-Konsolidierung
            bzw. wenn kein SubjectStore verfügbar war (fail-soft).
    """

    audit_id: str
    customer_data: CustomerData
    infrastructure_data: InfrastructureData
    organizational_data: OrganizationalData
    network_data: NetworkData
    audit_mode: AuditMode = AuditMode.CUSTOMER
    backup_audit: BackupAuditResult = field(default_factory=BackupAuditResult)
    sovereignty_audit: SovereigntyAuditResult = field(
        default_factory=SovereigntyAuditResult
    )
    incident_response_plan: IncidentResponsePlan = field(
        default_factory=IncidentResponsePlan
    )
    phishing_data: PhishingData = field(default_factory=PhishingData)
    category_scores: list[CategoryScore] = field(default_factory=list)
    overall_score: float = 0.0
    risk_level: str = "Kritisch"
    recommendations: list[str] = field(default_factory=list)
    created_at: str = ""
    subject_id: str = ""
    version: int = 1
    supersedes_audit_id: str = ""
    root_audit_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert das Ergebnis vollständig (JSON-exportierbar)."""
        return {
            "audit_id": self.audit_id,
            "audit_mode": self.audit_mode.value,
            "subject_id": self.subject_id,
            "customer_data": self.customer_data.to_dict(),
            "infrastructure_data": self.infrastructure_data.to_dict(),
            "organizational_data": self.organizational_data.to_dict(),
            "network_data": self.network_data.to_dict(),
            "backup_audit": self.backup_audit.to_dict(),
            "sovereignty_audit": self.sovereignty_audit.to_dict(),
            "incident_response_plan": self.incident_response_plan.to_dict(),
            "phishing_data": self.phishing_data.to_dict(),
            "category_scores": [s.to_dict() for s in self.category_scores],
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "recommendations": self.recommendations,
            "created_at": self.created_at,
            "version": self.version,
            "supersedes_audit_id": self.supersedes_audit_id,
            "root_audit_id": self.root_audit_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CustomerAuditResult:
        """Deserialisiert ein Dict."""
        try:
            mode = AuditMode(d.get("audit_mode", "customer"))
        except ValueError:
            mode = AuditMode.CUSTOMER
        return cls(
            audit_id=d.get("audit_id", ""),
            audit_mode=mode,
            customer_data=CustomerData.from_dict(d.get("customer_data", {})),
            infrastructure_data=InfrastructureData.from_dict(
                d.get("infrastructure_data", {})
            ),
            organizational_data=OrganizationalData.from_dict(
                d.get("organizational_data", {})
            ),
            network_data=NetworkData.from_dict(d.get("network_data", {})),
            backup_audit=BackupAuditResult.from_dict(d.get("backup_audit", {})),
            sovereignty_audit=SovereigntyAuditResult.from_dict(
                d.get("sovereignty_audit", {})
            ),
            incident_response_plan=IncidentResponsePlan.from_dict(
                d.get("incident_response_plan", {})
            ),
            phishing_data=PhishingData.from_dict(d.get("phishing_data", {})),
            category_scores=[
                CategoryScore.from_dict(s) for s in d.get("category_scores", [])
            ],
            overall_score=d.get("overall_score", 0.0),
            risk_level=d.get("risk_level", "Kritisch"),
            recommendations=d.get("recommendations", []),
            created_at=d.get("created_at", ""),
            subject_id=d.get("subject_id", ""),
            version=int(d.get("version", 1)),
            supersedes_audit_id=d.get("supersedes_audit_id", ""),
            root_audit_id=d.get("root_audit_id", ""),
        )


def unescape_strings(obj: Any) -> Any:
    """Wendet:func:`unescape_text` rekursiv auf alle Strings einer JSON-artigen
    Struktur (dict/list/str) an.

    NUR für die einmalige Daten-Migration ``t315_escape_at_render_v1`` — der frühere-Edit-Unescape (``unescaped_copy``) ist
    entfallen, weil die DB seit Klartext enthält.
    """
    if isinstance(obj, dict):
        return {k: unescape_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [unescape_strings(x) for x in obj]
    if isinstance(obj, str):
        return unescape_text(obj)
    return obj
