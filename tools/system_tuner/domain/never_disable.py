"""
never_disable — Harte Sperrliste (Ladezeit-Invariante).

Kanonische Menge kritischer Windows-Dienste, Telemetrie-Endpoints und
Registry-Ziele, die system_tuner NIEMALS anfassen darf — egal was im
Katalog steht. Der ``catalog_loader`` prueft jeden Tweak hiergegen und
wirft:class:`NeverDisableViolation` bei Kollision (fail-closed).

**Vertrag:** Diese Mengen sind die *kanonische Untergrenze*. Eine
mitgelieferte ``resources/system_tuner/NEVER_DISABLE.yaml`` (Phase 2:
signiert) darf die Liste nur ERWEITERN — ein Test stellt sicher, dass
die YAML diese Konstanten als Teilmenge enthaelt (kein Schrumpfen).

Quelle/Begruendung der Auswahl: Microsoft-Dienst-Dokumentation +
Debloat-Breakage-Recherche — Disabling dieser Dienste bricht Windows
Update, Defender, BitLocker/TLS-Zertpruefung, COM/Event, Servicing,
Gruppenrichtlinien, Firewall oder die Netzwerk-Basis.

Schichtzugehoerigkeit: domain/ — reine Konstanten + Prueffunktionen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

#: Kritische Dienste (Service-Kurznamen, lowercase). Liste darf nur wachsen.
NEVER_DISABLE_SERVICES: frozenset[str] = frozenset(
    {
        # Defender-Stack
        "windefend",
        "sense",
        "wdnissvc",
        # Windows Update + Servicing-Kette
        "wuauserv",
        "bits",
        "usosvc",
        "waasmedicsvc",
        "trustedinstaller",
        "msiserver",
        # AppX-/Lizenz-Laufzeit
        "appxsvc",
        "clipsvc",
        # Krypto / Zertifikate / BitLocker
        "cryptsvc",
        # COM / System-Event
        "rpcss",
        "dcomlaunch",
        "sens",
        # Gruppenrichtlinien
        "gpsvc",
        # Logging / Scheduler
        "eventlog",
        "schedule",
        # Firewall / Security Center
        "mpssvc",
        "wscsvc",
        # Netzwerk-Basis
        "dnscache",
        "nlasvc",
        "lanmanworkstation",
    }
)

#: Telemetrie-/Auth-Endpoints, die nie geblockt werden duerfen
#: (settings-win steuert/drosselt Events ohne selbst Telemetrie zu senden;
#: login.live.com = Geraete-Authentifizierung).
NEVER_BLOCK_ENDPOINTS: frozenset[str] = frozenset(
    {
        "settings-win.data.microsoft.com",
        "login.live.com",
    }
)

#: Gesperrte Registry-Ziele als ``(HIVE_UPPER, key_lower, value_lower)``.
#: Verhindert, dass ueber den Registry-Pfad doch Defender/Update lahmgelegt
#: wird ("disable Defender"/"disable Windows Update" leben NUR hier).
NEVER_TOUCH_REGISTRY: frozenset[tuple[str, str, str]] = frozenset(
    {
        (
            "HKLM",
            r"software\policies\microsoft\windows defender",
            "disableantispyware",
        ),
        (
            "HKLM",
            r"software\policies\microsoft\windows defender\real-time protection",
            "disablerealtimemonitoring",
        ),
        (
            "HKLM",
            r"software\policies\microsoft\windows\windowsupdate\au",
            "noautoupdate",
        ),
    }
)


def is_never_disable_service(name: str) -> bool:
    """``True`` wenn ``name`` ein kritischer, gesperrter Dienst ist.

    Case-insensitiv und whitespace-tolerant.
    """
    return name.strip().lower() in NEVER_DISABLE_SERVICES


def is_never_touch_registry(hive: str, key_path: str, value_name: str) -> bool:
    """``True`` wenn ``(hive, key_path, value_name)`` ein gesperrtes Ziel ist."""
    target = (hive.strip().upper(), key_path.strip().lower(), value_name.strip().lower())
    return target in NEVER_TOUCH_REGISTRY


def is_never_block_endpoint(host: str) -> bool:
    """``True`` wenn ``host`` ein nie-zu-blockender Endpoint ist."""
    return host.strip().lower() in NEVER_BLOCK_ENDPOINTS
