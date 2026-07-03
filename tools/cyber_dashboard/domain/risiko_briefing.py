"""Domain-DTOs fuer das Tab-1-Risikobriefing.

Das Risikobriefing gibt — anhand der echten Systemdaten — die **wichtigen
Punkte** wieder und erklaert je Punkt **das Risiko bei Nichtbeachtung**
(Patrick-Leitsatz 2026-06-29). Diese Datei haelt nur die unveraenderlichen
Transport-Typen; die Ableitungs-Logik (RisikoPunkt-Engine) und die
Aggregation liegen in ``application/risiko_briefing_service.py``.

Schichtregel (domain): nur stdlib-Importe, keine I/O, keine Fremd-Tool-Typen.
Der ``RisikoBriefingService`` (application) uebersetzt Fremd-Typen
(HardeningScoreResult, CustomerAuditResult, AuditPrefill, AffectedCveRow) in
diese primitiven DTOs — so bleibt ``cyber_dashboard`` frei von statischen
Cross-Tool-Importen.

INVARIANTE::class:`RiskBriefingSnapshot` traegt **kein**
aggregiertes Gesamt-Score-Feld. Audit-Score und Hardening-Score sind zwei
getrennte Dimensionen und stehen immer beschriftet nebeneinander — nie
gemittelt (NIS2-Beweiswert).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Prioritaet(Enum):
    """Dringlichkeit eines:class:`RisikoPunkt` (steuert Sortierung + Farbe)."""

    KRITISCH = "kritisch"
    HOCH = "hoch"
    MITTEL = "mittel"
    NIEDRIG = "niedrig"

    @property
    def rang(self) -> int:
        """Sortier-Rang (0 = dringlichste zuerst)."""
        return {"kritisch": 0, "hoch": 1, "mittel": 2, "niedrig": 3}[self.value]


class Konfidenz(Enum):
    """Sicherheit, mit der ein CVE das System betrifft, 2 Stufen)."""

    BESTAETIGT = "bestaetigt"  # CPE-genau aus Patch-Monitor-Inventar
    MOEGLICH = "moeglich"  # Techstack-Keyword-Treffer (mit Unsicherheit)


@dataclass(frozen=True)
class AffectedCveItem:
    """Ein CVE, von dem das lokale System (wahrscheinlich) betroffen ist.

    ``konfidenz`` trennt die zwei lokalen Stufen aus:
    BESTAETIGT (Patch-Monitor, CPE-genau) und MOEGLICH (Techstack-Treffer).
    """

    cve_id: str
    cvss_score: float | None
    exploit_available: bool
    eol: bool
    konfidenz: Konfidenz
    affected_apps: tuple[str, ...] = ()
    update_available: bool = False


@dataclass(frozen=True)
class PatchBacklogInfo:
    """Patch-Rueckstand aus dem Patch-Monitor."""

    open_updates: int
    eol_without_patch: int
    last_scan_at: datetime | None


@dataclass(frozen=True)
class HardeningInfo:
    """Mess-Dimension (Hardening-Score) — getrennt von der Audit-Dimension."""

    score: float | None
    stage_label: str
    missing_categories: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditScoreInfo:
    """Selbsteinschaetzungs-Dimension (Security-Audit) + BSI-Top-Risiken.

    ``top_risks`` ist eine Liste von ``(titel, risiko_level_label)`` aus der
    BSI-200-3-Risiko-Matrix des SELF-Audits.
    """

    score: float | None
    top_risks: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class MeasuredFacts:
    """Gemessene/erfasste Sicherheits-Eckwerte. ``None`` = unbekannt/ungeprueft
    (wird neutral behandelt, nie als Verstoss — vgl. L: Mess-Fehlschlag neutral).
    """

    firewall_active: bool | None = None
    rdp_exposed: bool | None = None
    disk_encryption_active: bool | None = None
    mfa_active: bool | None = None
    backup_documented: bool | None = None


@dataclass(frozen=True)
class RisikoPunkt:
    """Ein wichtiger Punkt im Risikobriefing — Befund + erklaerte Folge.

    ``befund`` und die Auswahl sind deterministisch aus den Quelldaten;
    ``risiko_bei_nichtbeachtung`` ist die Klartext-Erklaerung der Folge
    (Template; optionale LLM-Veredelung erst spaeter, immer grounded).
    """

    titel: str
    kategorie: str  # "Patch" | "Haertung" | "CVE" | "Organisatorisch"
    prioritaet: Prioritaet
    befund: str
    risiko_bei_nichtbeachtung: str
    empfohlene_massnahme: str
    quelle: str
    evidenz: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskBriefingSnapshot:
    """Tab-1-Gesamtbild (transient, nicht persistiert).

/-INVARIANTE: kein aggregiertes Gesamt-Score-Feld.
    ``hardening`` (gemessen) und ``audit`` (selbst-deklariert) stehen
    getrennt — der Aufrufer rendert sie als zwei beschriftete Kacheln.
    """

    risiko_punkte: tuple[RisikoPunkt, ...]
    affected_cves: tuple[AffectedCveItem, ...]
    patch_backlog: PatchBacklogInfo | None = None
    hardening: HardeningInfo | None = None
    audit: AuditScoreInfo | None = None
    apps_without_cpe: int = 0

    @property
    def bestaetigte_cves(self) -> tuple[AffectedCveItem, ...]:
        """CVEs der Stufe BESTAETIGT (CPE-genau)."""
        return tuple(
            c for c in self.affected_cves if c.konfidenz is Konfidenz.BESTAETIGT
        )

    @property
    def moegliche_cves(self) -> tuple[AffectedCveItem, ...]:
        """CVEs der Stufe MOEGLICH (Techstack-Treffer, unsicher)."""
        return tuple(c for c in self.affected_cves if c.konfidenz is Konfidenz.MOEGLICH)
