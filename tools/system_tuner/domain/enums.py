"""
enums — Aufzaehlungstypen fuer system_tuner.

Alle Werte sind ``StrEnum`` — die String-Repraesentation entspricht 1:1
den YAML-Katalog-Werten (z. B. ``risk_tier: "T1_safe"``) und ist direkt
JSON-/Audit-serialisierbar.

Schichtzugehoerigkeit: domain/ — keine Imports aus aeusseren Schichten.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from enum import StrEnum


class RiskTier(StrEnum):
    """Risiko-Stufe eines Tweaks (steuert Sichtbarkeit + Gating).

    * ``T0_BLOCKED`` — In NEVER_DISABLE. Kann NICHT als Katalog-Tweak
      existieren; der Loader wirft bei Kollision.
    * ``T1_SAFE`` — Voll reversibel, keine Breakage-Historie.
    * ``T2_CAUTION`` — Reversibler Dienst-Startmode, konservative Allow-Liste.
    * ``T3_ADVANCED`` — Nicht sauber reversibel oder drift-anfaellig (AppX).
    """

    T0_BLOCKED = "T0_blocked"
    T1_SAFE = "T1_safe"
    T2_CAUTION = "T2_caution"
    T3_ADVANCED = "T3_advanced"


class ChangeOp(StrEnum):
    """Art der System-Aenderung eines Tweaks."""

    REGISTRY_SET = "registry_set"
    SERVICE_STARTMODE = "service_startmode"
    APPX_REMOVE = "appx_remove"


class ServiceStartMode(StrEnum):
    """Windows-Dienst-Starttyp."""

    AUTOMATIC = "automatic"
    MANUAL = "manual"
    DISABLED = "disabled"


class RegistryValueType(StrEnum):
    """Unterstuetzte Registry-Werttypen."""

    REG_DWORD = "REG_DWORD"
    REG_SZ = "REG_SZ"
    REG_QWORD = "REG_QWORD"


class RevertKind(StrEnum):
    """Art der Rueckabwicklung eines Tweaks.

    * ``RESTORE_PRIOR`` — den vor dem Write gesicherten Wert zurueckschreiben.
    * ``SET_VALUE`` — ein deterministisches Inverses setzen.
    * ``IRREVERSIBLE`` — nicht sauber rueckabwickelbar (nur T3, z. B. AppX).
    """

    RESTORE_PRIOR = "restore_prior"
    SET_VALUE = "set_value"
    IRREVERSIBLE = "irreversible"


class TweakCategory(StrEnum):
    """Fachliche Kategorie eines Tweaks."""

    TELEMETRY = "telemetry"
    SERVICES = "services"
    APPX = "appx"
    PRIVACY = "privacy"


class Recommendation(StrEnum):
    """Voreinstellungs-Profil (Laien vs. Experte).

    * ``STANDARD`` — sichere Default-Empfehlung (Beginner).
    * ``STRICT`` — strengeres Profil (Experte).
    """

    STANDARD = "standard"
    STRICT = "strict"


class TweakStatus(StrEnum):
    """Zustand eines Tweaks bei Scan bzw. Apply/Revert.

    Scan (read-only):
        ``APPLIED`` (bereits im Soll), ``NOT_APPLIED`` (Default/offen),
        ``UNKNOWN`` (nicht lesbar).
    Apply/Revert (Phase 2):
        ``DRY_RUN``, ``SUCCESS``, ``FAILED``, ``FAILED_ROLLED_BACK``,
        ``BLOCKED`` (NEVER_DISABLE/Edition-Gate), ``IRREVERSIBLE``,
        ``SKIPPED``.
    """

    APPLIED = "applied"
    NOT_APPLIED = "not_applied"
    UNKNOWN = "unknown"
    DRY_RUN = "dry_run"
    SUCCESS = "success"
    FAILED = "failed"
    FAILED_ROLLED_BACK = "failed_rolled_back"
    BLOCKED = "blocked"
    IRREVERSIBLE = "irreversible"
    SKIPPED = "skipped"
