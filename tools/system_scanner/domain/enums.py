"""
enums — Enumerationen für das System-Scanner-Modul.

Schichtzugehörigkeit: domain/ — keine externen Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from enum import StrEnum


class ComponentType(StrEnum):
    """Typ einer Sicherheitskomponente."""

    ANTIVIRUS = "antivirus"
    FIREWALL = "firewall"
    ENCRYPTION = "encryption"
    BROWSER = "browser"
    OS_UPDATE = "os_update"
    VPN = "vpn"
    PASSWORD_MANAGER = "password_manager"
    REMOTE_ACCESS = "remote_access"


class ComponentStatus(StrEnum):
    """Betriebsstatus einer Sicherheitskomponente."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    OUTDATED = "outdated"
    UNKNOWN = "unknown"
    RISK = "risk"  # Remote-Access-Tools o.Ä. — aktiv aber Risiko


class OSPlatform(StrEnum):
    """Erkanntes Betriebssystem."""

    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    UNKNOWN = "unknown"


class UnmeasuredReason(StrEnum):
    """Ursache, warum ein Hardening-Check NICHT gemessen wurde.

    Trennt die drei Nicht-gemessen-Zustände, die heute alle in
    ``measurable=False`` kollabieren. Bestimmt Kommunikation (Mess-zuerst-Flow),
    Score-Behandlung und Report-Sektion:

    * ``NEEDS_ADMIN`` — behebbar: mit Adminrechten messbar (Owner-Prinzip P1).
      Treiber des „Mit Admin erneut prüfen"-Pfads; KEIN Endzustand.
    * ``PARSE_FAILED`` — Befehl lief, Ausgabe nicht interpretierbar (z.B.
      nicht-DE/EN-Locale). Behebbar via locale-unabhängige API (Phase 2).
    * ``NOT_APPLICABLE`` — Feature strukturell nicht vorhanden (z.B. BitLocker
      auf Windows-Home) ODER durch eine Alternative abgedeckt. Echt-n/a,
      score-neutral (nicht im Nenner).
    * ``USER_DECLINED`` — der Nutzer hat die Messung bewusst übersprungen
      (Opt-out, P5). Zählt im Rating als Defizit (P6a), erscheint im Report
      als „nicht geprüft" mit Begründung (P6b).
    """

    NEEDS_ADMIN = "needs_admin"
    PARSE_FAILED = "parse_failed"
    NOT_APPLICABLE = "not_applicable"
    USER_DECLINED = "user_declined"


class RecheckReason(StrEnum):
    """Grund, warum der elevierte Hardening-Recheck KEIN Mess-Ergebnis lieferte.

    Wird vom elevierten Entry in den signierten Reject-Marker geschrieben
, D6), damit die GUI den Ausgang sichtbar machen kann statt still
    in den Timeout zu laufen. Geschlossene Liste — bewusst KEIN Freitext/
    Exception-Text (Info-Disclosure in den PDF-Export vermeiden).

    * ``PROBE_UNAVAILABLE`` — Probe nicht verfügbar (z.B. Nicht-Windows / Probe
      lieferte ``None``).
    * ``SCAN_FAILED`` — die Messung selbst schlug fehl (Probe-Exception).
    * ``NOT_ADMIN`` — der elevierte Relaunch lief wider Erwarten ohne Adminrechte.
    * ``PATH_UNTRUSTED`` — Laufzeit-Image nicht vertrauenswürdig (frozen Build).
    * ``INTERNAL`` — unerwarteter Fehler im Entry vor/nach der Messung.
    """

    PROBE_UNAVAILABLE = "probe_unavailable"
    SCAN_FAILED = "scan_failed"
    NOT_ADMIN = "not_admin"
    PATH_UNTRUSTED = "path_untrusted"
    INTERNAL = "internal"
