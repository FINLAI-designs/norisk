"""
tech_stack.entities — Domain-Entities für System-Profile und Tech-Stack.

Enthält reine Datenklassen ohne externe Abhängigkeiten.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tools.security_scoring.domain.tech_stack.enums import SystemType, ToolStatus


@dataclass(frozen=True)
class OSEntry:
    """Eintrag für ein Betriebssystem.

    Attributes:
        name: Name des Betriebssystems (z.B. "Windows 11").
        version: Version-String (z.B. "23H2").
    """

    name: str
    version: str = ""


@dataclass(frozen=True)
class BrowserEntry:
    """Eintrag für einen Browser.

    Attributes:
        name: Browser-Name (z.B. "Chrome").
        version: Version-String (z.B. "124.0").
    """

    name: str
    version: str = ""


@dataclass(frozen=True)
class SecurityTool:
    """Sicherheits-Tool mit Name und Status.

    Attributes:
        name: Tool-Name (z.B. "Windows Defender").
        status: Betriebsstatus (aktiv/inaktiv/fehlt/unbekannt).
    """

    name: str = ""
    status: ToolStatus = ToolStatus.UNBEKANNT


@dataclass(frozen=True)
class TechStack:
    """Vollständiger Tech-Stack eines Systems.

    Attributes:
        operating_systems: Liste installierter Betriebssysteme.
        antivirus: Antivirus/EDR-Lösung.
        firewall: Firewall-Lösung.
        browsers: Liste installierter Browser.
        encryption: Liste aktivierter Verschlüsselungsmethoden.
        vpn: VPN-Name oder None.
        remote_access: Liste genutzter Remote-Access-Tools.
        server_infra: Server-Infrastruktur (Freitext).
        custom_software: Sonstige Software (Freiliste).
    """

    operating_systems: list[OSEntry] = field(default_factory=list)
    antivirus: SecurityTool = field(default_factory=SecurityTool)
    firewall: SecurityTool = field(default_factory=SecurityTool)
    browsers: list[BrowserEntry] = field(default_factory=list)
    encryption: list[str] = field(default_factory=list)
    vpn: str | None = None
    remote_access: list[str] = field(default_factory=list)
    server_infra: str = ""
    custom_software: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SystemProfile:
    """Profil eines zu bewertenden Systems.

    Attributes:
        id: UUID (wird automatisch generiert).
        name: Anzeigename (editierbar).
        system_type: EIGENES oder KUNDE.
        description: Optionale Beschreibung.
        contact: Ansprechpartner (nur für KUNDE-Systeme sinnvoll).
        branche: Branche (Subjekt-Stammdaten; aus dem Audit übernommen).
        groesse: Unternehmensgröße (Subjekt-Stammdaten).
        tech_stack: Tech-Stack-Daten.
        created_at: ISO-Timestamp der Erstellung.
        updated_at: ISO-Timestamp der letzten Änderung.
        fte: Vollzeitäquivalente des eigenen Systems Einstiegs-
            Scoping); ``None`` bedeutet "nicht erfasst" (nicht 0).
        umsatz_eur: Jahresumsatz in ganzen EUR; ``None`` = nicht erfasst.
        bilanzsumme_eur: Bilanzsumme in ganzen EUR; ``None`` = nicht erfasst.
        sektor_key: Stabiler Sektor-Schlüssel nach NIS2-Anhang-Klassifikation
; siehe ``core.security_subject.scoping_constants``).
        nis2_anhang: Aus ``sektor_key`` abgeleiteter NIS2-Anhang ('I' | 'II' | '')
            — denormalisiert für die spätere W0-Betroffenheitsabfrage.
        rolle: Rolle/Funktion der erfassenden Person Stammdaten).
        segment: Nutzungs-Segment des eigenen Systems (W1-Interview;
            ``core.security_subject.w1_profil.Segment``); ``""`` = nicht erfasst.
        hat_eigene_website: Tri-state (0/1/``None``) — eigene Website/Domain
            vorhanden; gated den Zertifikats-Monitor.
        hat_eigene_api: Tri-state (0/1/``None``) — eigene öffentliche API
            vorhanden; gated die API-Security.
        ist_entwickler: Tri-state (0/1/``None``) — eigene Software-Entwicklung;
            gated den Dependency-Auditor.
        hat_server_infrastruktur: Tri-state (0/1/``None``) — eigener Server/NAS
; Segment-/Zukunfts-Gating). Bewusst NICHT ``server_infra``
            (das ist der TechStack-Freitext-Blob).
    """

    id: str
    name: str
    system_type: SystemType
    description: str = ""
    contact: str = ""
    branche: str = ""
    groesse: str = ""
    tech_stack: TechStack = field(default_factory=TechStack)
    created_at: str = ""
    updated_at: str = ""
    # Einstiegs-Scoping (NIS2-taugliche Stammdaten des eigenen Systems).
    # Geld/FTE bewusst nullable INTEGER: None = unbekannt, klar getrennt von 0.
    fte: int | None = None
    umsatz_eur: int | None = None
    bilanzsumme_eur: int | None = None
    sektor_key: str = ""
    nis2_anhang: str = ""
    rolle: str = ""
    # W1-Interview (eigenes System). segment: Enum-String (s. w1_profil).
    # Booleans tri-state nullable INTEGER: None = nicht erfasst, klar von 0/1 getrennt.
    segment: str = ""
    hat_eigene_website: int | None = None
    hat_eigene_api: int | None = None
    ist_entwickler: int | None = None
    hat_server_infrastruktur: int | None = None

    @property
    def is_own_system(self) -> bool:
        """True wenn dies das eigene System ist."""
        return self.system_type == SystemType.EIGENES

    @property
    def display_name(self) -> str:
        """Anzeigename mit Typ-Suffix für Kunden."""
        if self.system_type == SystemType.EIGENES:
            return f"{self.name} (Eigenes System)"
        return self.name
