"""core.security_subject.models — Domain-Modelle der Subjekt-Identität.

Reine, unveränderliche Datenklassen ohne externe Abhängigkeiten.

Schichtzugehörigkeit: core/ — keine I/O, keine Imports aus tools/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SubjectKind(StrEnum):
    """Art des bewerteten Subjekts.

    Die String-Werte sind bewusst identisch zu
    ``security_scoring.domain.tech_stack.enums.SystemType`` — so bildet
    ``SubjectKind(system_type.value)`` verlustfrei ab, ohne dass core ein
    Tool importieren muss.

    EIGENES: Das eigene System (genau eines, nicht löschbar). Bekommt als
        einziges Subjekt technisches Scoring (Scans laufen nur lokal).
    KUNDE: Ein externer Kunde/Mandant (beliebig viele, löschbar).
        Fragebogen-Audit only — kein technisches Scoring.
    """

    EIGENES = "eigenes"
    KUNDE = "kunde"


@dataclass(frozen=True)
class Subject:
    """Kanonische, tool-übergreifende Identität des bewerteten Subjekts.

    Single Source of Truth, auf die ``customer_audit``, ``security_scoring``
    (Org-Assessment + technisches Scoring) und das Dashboard über
    ``subject_id`` referenzieren.

    Attributes:
        subject_id: UUID — stabil über Audits und Scorings hinweg.
        kind::class:`SubjectKind` (eigenes | kunde).
        name: Anzeigename bzw. Firmenname.
        branche: Branche (nur für Kunden-Stammdaten relevant).
        groesse: Unternehmensgröße (Freitext-/Bucket-String).
        contact: Ansprechpartner (nur für Kunden sinnvoll).
        created_at: ISO-8601-UTC-Timestamp der Erstellung.
        updated_at: ISO-8601-UTC-Timestamp der letzten Änderung.
        fte: Vollzeitäquivalente Einstiegs-Scoping, eigenes System);
            ``None`` = nicht erfasst.
        umsatz_eur: Jahresumsatz in ganzen EUR; ``None`` = nicht erfasst.
        bilanzsumme_eur: Bilanzsumme in ganzen EUR; ``None`` = nicht erfasst.
        sektor_key: NIS2-Sektor-Schlüssel; 
            ``core.security_subject.scoping_constants``).
        nis2_anhang: Aus ``sektor_key`` abgeleiteter NIS2-Anhang ('I'|'II'|'').
        rolle: Rolle der erfassenden Person Stammdaten).
        segment: Nutzungs-Segment des eigenen Systems (W1-Interview;
            ``core.security_subject.w1_profil.Segment``); ``""`` = nicht erfasst.
        hat_eigene_website: Tri-state (0/1/``None``) — eigene Website/Domain;
            gated den Zertifikats-Monitor.
        hat_eigene_api: Tri-state (0/1/``None``) — eigene öffentliche API; gated
            die API-Security.
        ist_entwickler: Tri-state (0/1/``None``) — eigene Software-Entwicklung;
            gated den Dependency-Auditor.
        hat_server_infrastruktur: Tri-state (0/1/``None``) — eigener Server/NAS
; Segment-/Zukunfts-Gating).
    """

    subject_id: str
    kind: SubjectKind
    name: str
    branche: str = ""
    groesse: str = ""
    contact: str = ""
    created_at: str = ""
    updated_at: str = ""
    # Einstiegs-Scoping (eigenes System). Geld/FTE nullable: None = unbekannt.
    fte: int | None = None
    umsatz_eur: int | None = None
    bilanzsumme_eur: int | None = None
    sektor_key: str = ""
    nis2_anhang: str = ""
    rolle: str = ""
    # W1-Interview (eigenes System). segment: Enum-String (s. w1_profil).
    # Booleans tri-state nullable: None = nicht erfasst, klar von 0/1 getrennt.
    segment: str = ""
    hat_eigene_website: int | None = None
    hat_eigene_api: int | None = None
    ist_entwickler: int | None = None
    hat_server_infrastruktur: int | None = None

    @property
    def is_own_system(self) -> bool:
        """True, wenn dies das eigene System ist."""
        return self.kind is SubjectKind.EIGENES

    @property
    def display_name(self) -> str:
        """Anzeigename mit Typ-Suffix für das eigene System."""
        if self.kind is SubjectKind.EIGENES:
            return f"{self.name} (Eigenes System)"
        return self.name


@dataclass(frozen=True)
class NutzungsSignale:
    """Tri-state Nutzungssignale eines Subjekts für die Org-Auto-Detection.

    Aus realen Cross-Tool-Daten (``customer_audit``-Sovereignty-Audit) abgeleitete,
    kategorisierte Nutzungs-Indikatoren. Bewusst **PII-frei**: nur Bool/None je
    Kategorie, KEINE Provider-Namen oder Firmennamen §Threat-Model).

    Tri-state je Feld (Konservativitäts-Kern /):
        ``True`` — Nutzung positiv festgestellt (erkannt oder deklariert) →
            Frage aktiv halten.
        ``False`` — Nicht-Nutzung positiv festgestellt (abgeschlossenes
            SELF-Audit, Kategorie nachweislich leer) → Frage als N/A vorbelegen.
        ``None`` — unbekannt (kein belastbares Audit) → No-op, kein Auto-N/A.

    Attributes:
        nutzt_m365: Microsoft 365 / Azure im Einsatz.
        nutzt_kanzlei_software: Steuerberater-/Kanzlei-Software (DATEV, BMD, …).
        nutzt_cloud_speicher: Cloud-Speicher (OneDrive, Dropbox, Google Drive, …).
        hat_auftragsverarbeiter: Externe Auftragsverarbeiter vorhanden.
        audit_datum: ISO-Datum des zugrunde liegenden SELF-Audits (``""`` wenn
            keins) — ausschließlich für den erklärenden Wizard-Tooltip
 Mechanismus 3), nicht score-relevant.
    """

    nutzt_m365: bool | None = None
    nutzt_kanzlei_software: bool | None = None
    nutzt_cloud_speicher: bool | None = None
    hat_auftragsverarbeiter: bool | None = None
    audit_datum: str = ""
