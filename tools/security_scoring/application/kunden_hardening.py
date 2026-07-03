"""kunden_hardening — Manuelle Hardening-Erfassung für Kunden E2/Phase B).

Eine Kundenmaschine ist nicht fern-messbar; der Berater trägt die Hardening-
Fakten manuell ein. Dieses Modul übersetzt die eingetragenen Fakten in
:class:`ScoreComponent`-Objekte für die bestehende Hardening-Pipeline. Reine
application-Logik (kein I/O, keine GUI).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.security_scoring.domain.models import ScoreComponent

#: Bekannte, manuell erfassbare Hardening-Fakten: ``key -> Anzeige-Label``.
#: Reihenfolge = Anzeige-Reihenfolge im Erfassungs-Dialog (Step 8).
KUNDEN_HARDENING_FACTS: tuple[tuple[str, str], ...] = (
    ("firewall", "Firewall aktiv"),
    ("disk_encryption", "Festplattenverschlüsselung aktiv"),
    ("rdp_closed", "Fernzugriff (RDP) geschlossen oder abgesichert"),
    ("patch_current", "Betriebssystem-Updates aktuell"),
    ("antivirus", "Aktueller Virenschutz vorhanden"),
    ("mfa", "Mehr-Faktor-Authentifizierung aktiv"),
    ("backup", "Regelmäßiges Backup vorhanden"),
)

_VALID_KEYS = frozenset(k for k, _ in KUNDEN_HARDENING_FACTS)


def facts_to_components(facts: dict[str, bool | None]) -> list[ScoreComponent]:
    """Übersetzt manuell erfasste Hardening-Fakten in eine ScoreComponent.

    Nur bekannte, mit ``True``/``False`` beantwortete Fakten zählen; ``None``
    (nicht beantwortet) und unbekannte Keys fallen aus dem Nenner (Microsoft-
    Secure-Score-Stil). Ergibt EINE ``SYSTEM_HARDENING``-Komponente
    (``source_tool="system_scanner"``), die die bestehende
:func:`tools.security_scoring.domain.hardening_score.compute_hardening_score`-
    Pipeline konsumiert.

    Args:
        facts: Mapping ``Fakt-Key -> True/False/None``.

    Returns:
        Liste mit genau einer:class:`ScoreComponent`. Ohne beantwortete Fakten
        ist sie ``data_available=False`` (grauer No-Data-Balken, kein 0-Score).
    """
    beantwortet = {
        k: v for k, v in facts.items() if k in _VALID_KEYS and v is not None
    }
    if not beantwortet:
        return [
            ScoreComponent(
                name="Härtung (erfasst)",
                score=0.0,
                weight=1.0,
                source_tool="system_scanner",
                data_available=False,
                details="Keine Angaben erfasst",
            )
        ]
    erfuellt = sum(1 for v in beantwortet.values() if v)
    gesamt = len(beantwortet)
    return [
        ScoreComponent(
            name="Härtung (erfasst)",
            score=round(erfuellt / gesamt * 100.0, 1),
            weight=1.0,
            source_tool="system_scanner",
            findings_high=gesamt - erfuellt,
            data_available=True,
            details=f"{erfuellt}/{gesamt} Härtungsmaßnahmen erfüllt",
        )
    ]
