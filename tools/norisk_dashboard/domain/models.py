"""
models — Domain-Datenmodelle für das NoRisk-Dashboard (Phase 1).

Reine Daten-Klassen ohne externe Abhängigkeiten.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 0.1 (Phase 1)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from tools.security_scoring.domain.hardening_score import HardeningScoreResult
from tools.security_scoring.domain.models import ScoreComponent


class TimeRange(Enum):
    """Zeit-Filter für 'Was hat sich geändert'."""

    WEEK = "week"
    MONTH = "month"
    QUARTER = "quarter"

    @property
    def days(self) -> int:
        """Dauer in Tagen."""
        return {
            TimeRange.WEEK: 7,
            TimeRange.MONTH: 30,
            TimeRange.QUARTER: 90,
        }[self]

    @property
    def label(self) -> str:
        """Deutsches Label."""
        return {
            TimeRange.WEEK: "Woche",
            TimeRange.MONTH: "Monat",
            TimeRange.QUARTER: "Quartal",
        }[self]


class ChangeType(Enum):
    """Art einer Änderung in Sektion 1."""

    NEW = "new"
    CHANGED = "changed"
    DELETED = "deleted"

    @property
    def badge(self) -> str:
        """Badge-Text in der GUI."""
        return {
            ChangeType.NEW: "NEU",
            ChangeType.CHANGED: "GEÄNDERT",
            ChangeType.DELETED: "GELÖSCHT",
        }[self]


class ScanStatus(Enum):
    """Status eines Scan-Ergebnisses für die Heatmap."""

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    MISSING = "missing"


@dataclass
class ChangeEntry:
    """Ein Eintrag in 'Was hat sich geändert'.

    Attributes:
        change_type: NEU / GEÄNDERT / GELÖSCHT.
        title: Kurz-Titel, z.B. "CVE-2026-1234".
        detail: Ein-Satz-Beschreibung.
        timestamp: Zeitpunkt der Änderung.
        source: Quelle, z.B. "cve", "score", "scan".
    """

    change_type: ChangeType
    title: str
    detail: str
    timestamp: datetime
    source: str = ""


@dataclass
class ScoreSnapshot:
    """Aktueller Score + Trend gegenüber Referenzpunkt.

    Attributes:
        current: Aktueller Score 0-100 oder None wenn kein Score existiert.
        previous: Referenzscore oder None.
        timestamp: Zeitpunkt des aktuellen Scores oder None.
        target: Ziel-Name (Kunde) oder "Allgemein".
    """

    current: float | None = None
    previous: float | None = None
    timestamp: datetime | None = None
    target: str = "Allgemein"

    @property
    def delta(self) -> float | None:
        """Differenz current − previous (positiv = besser)."""
        if self.current is None or self.previous is None:
            return None
        return round(self.current - self.previous, 1)


@dataclass
class ScanEntry:
    """Ein einzelner Scan-Lauf für die Heatmap.

    Attributes:
        tool_key: Technischer Scanner-Name, z.B. "system_scanner".
        tool_label: Anzeigename, z.B. "System-Scanner".
        day: Tag des Scans (ohne Uhrzeit).
        status: OK / WARN / FAIL / MISSING.
    """

    tool_key: str
    tool_label: str
    day: datetime
    status: ScanStatus


@dataclass
class CveListEntry:
    """CVE-Eintrag für die Liste in Sektion 3.

    Attributes:
        cve_id: CVE-ID, z.B. "CVE-2026-1234".
        product: Produktname.
        description: Ein-Satz-Beschreibung.
        published: Veröffentlichungsdatum.
    """

    cve_id: str
    product: str
    description: str
    published: datetime


@dataclass
class OrgTile:
    """Eine Kachel in Sektion 5 (Organisatorische Sicherheit).

    Attributes:
        key: Technischer Metrik-Key (dsgvo/phishing/mfa/passwort_manager).
        label: Anzeigename, z.B. "DSGVO-Compliance".
        score: Aktueller Score 0-100 oder None (keine Daten).
        findings_open: Anzahl offener Kriterien (nicht-erfüllte Fragen).
    """

    key: str
    label: str
    score: float | None
    findings_open: int = 0


@dataclass
class OrgSnapshot:
    """Datensatz für Sektion 5.

    Attributes:
        tiles: Immer vier Kacheln (DSGVO, Phishing, MFA, Passwort-Manager).
        has_assessment: False bedeutet: noch kein Assessment gespeichert → CTA anzeigen.
    """

    tiles: list[OrgTile]
    has_assessment: bool


class CompletenessStatus(Enum):
    """Status eines Scan-Tools fuer das Vollstaendigkeits-Banner (Sprint S3c)."""

    FRESH = "fresh"        # letzter Scan < 7 Tage alt
    OUTDATED = "outdated"  # 7..30 Tage alt
    MISSING = "missing"    # > 30 Tage alt oder kein Scan registriert


@dataclass
class CompletenessEntry:
    """Eine Zeile im Score-Vollstaendigkeits-Banner (Sprint S3c, W3).

    Attributes:
        tool_key: Technischer Tool-Name (passend zum LastScanRegistry).
        tool_label: Deutscher Anzeigename ("Cert-Monitor", "API-Security"...).
        last_scan: Zeitpunkt des letzten Scans oder ``None`` wenn nie.
        status: Frisch / veraltet / fehlend.
    """

    tool_key: str
    tool_label: str
    last_scan: datetime | None
    status: CompletenessStatus


@dataclass
class CertBurndown:
    """Cert-Burndown-Tile-Daten (Sprint S3c, W2).

    Attributes:
        min_days: Tage bis zum nächsten ablaufenden Zertifikat,
            oder ``None`` wenn keine Zertifikate ueberwacht werden /
            keine Daten vorliegen.
        domain: Subject-Domain des Zertifikats mit der niedrigsten
            Restlaufzeit (zur Anzeige im Tooltip / Subline).
        count_total: Anzahl ueberwachter Zertifikate.
        count_warning: Anzahl mit Restlaufzeit <= 30 Tage (gelb).
        count_critical: Anzahl mit Restlaufzeit <= 7 Tage (rot).
    """

    min_days: int | None = None
    domain: str = ""
    count_total: int = 0
    count_warning: int = 0
    count_critical: int = 0


@dataclass
class CvssPercentiles:
    """CVSS-Perzentile-Widget-Daten (Sprint S3c, W6).

    Attributes:
        sample_count: Anzahl ausgewerteter CVE-Scores.
        p10: 10. Perzentil — die untersten 10 % der CVEs liegen darunter.
        p50: Median.
        p90: 90. Perzentil — die obersten 10 % der CVEs liegen darueber.
        sparkline: Letzte N Werte fuer den Sparkline-Trend (chronologisch
            absteigend zuerst — Konsumenten kuerzen oder reversen wie noetig).
    """

    sample_count: int = 0
    p10: float = 0.0
    p50: float = 0.0
    p90: float = 0.0
    sparkline: list[float] = field(default_factory=list)


@dataclass
class CustomerAuditSummary:
    """Kompakter Kunden-Audit-Score für die Subjekt-Ansicht-Folge).

    Gefüllt vom ``customer_audit_loader`` in ``tool.py`` — der adaptiert den
    ``CustomerAuditRepository``-Summary-Dict in dieses dashboard-eigene DTO,
    damit Aggregator/Domain KEINEN ``customer_audit``-Domain-Typ importieren
    (cert_burndown-Muster, kein tool→tool-Leak). Gerendert von
    ``gui/customer_audit_card.py:CustomerAuditCard``: ist im Header ein
    Kunden-Subjekt gewählt, ist der technische Hardening-Score self-only und
    nicht aussagekräftig §4) → diese Karte ersetzt den Hero.

    Effekt: Feldnamen werden von ``CustomerAuditCard.set_data`` gelesen; eine
    Umbenennung dort nachziehen. ``overall_score`` ist die 0–100-Zahl des
    jüngsten Audits (nicht des technischen Scorings).

    Attributes:
        subject_id: UUID des kanonischen Subjekts.
        firmenname: Anzeigename des Kunden (aus dem jüngsten Audit).
        overall_score: Gewichteter Gesamtscore 0–100 des jüngsten Audits.
        risk_level: Risikostufe (Kritisch/Hoch/Mittel/Niedrig).
        created_at: Zeitpunkt des jüngsten Audits oder ``None``.
        audit_id: UUID des jüngsten Audits (für die „Audit öffnen"-CTA).
        audit_count: Anzahl aller Audits dieses Subjekts.
    """

    subject_id: str
    firmenname: str
    overall_score: float
    risk_level: str
    created_at: datetime | None = None
    audit_id: str = ""
    audit_count: int = 0


@dataclass
class DashboardData:
    """Aggregierter Datenstand für einen Dashboard-Refresh.

    Attributes:
        time_range: Ausgewählter Zeit-Filter.
        changes: Einträge für Sektion 1.
        score: Score-Snapshot für Sektion 2.
        cves: CVE-Liste für Sektion 3 (techstack-gefiltert).
        scans: Scan-Einträge für die Heatmap.
        breakdown: Score-Komponenten des neuesten Scores (Sektion 4a).
        trend: (timestamp, overall_score)-Paare, ältester zuerst (Sektion 4b).
        org: Organisatorischer Sicherheits-Snapshot (Sektion 5) oder None.
        generated: Zeitpunkt der Aggregation.

    Sprint S3c — Quick-Win-Felder (alle optional, ``None``/leer wenn keine
    Daten verfuegbar; das Dashboard rendert in dem Fall einen
    Empty-State):

    Attributes:
        cert_burndown: Cert-Burndown-Tile-Daten (W2).
        cvss_percentiles: CVSS-Perzentile + Sparkline (W6).
        completeness: Score-Vollstaendigkeit-Liste (W3).
    """

    time_range: TimeRange
    changes: list[ChangeEntry] = field(default_factory=list)
    score: ScoreSnapshot = field(default_factory=ScoreSnapshot)
    cves: list[CveListEntry] = field(default_factory=list)
    scans: list[ScanEntry] = field(default_factory=list)
    breakdown: list[ScoreComponent] = field(default_factory=list)
    trend: list[tuple[datetime, float]] = field(default_factory=list)
    org: OrgSnapshot | None = None
    generated: datetime = field(default_factory=datetime.now)
    # Sprint S3c — Quick-Win-Widgets (W2/W3/W6).
    cert_burndown: CertBurndown | None = None
    cvss_percentiles: CvssPercentiles | None = None
    completeness: list[CompletenessEntry] = field(default_factory=list)
    # Phase 4.5: Optionaler Hardening-Score-Snapshot. Wenn der
    # DashboardAggregator ohne ``hardening_score_provider`` konstruiert
    # wird (Tests, alte Call-Sites) bleibt der Wert ``None`` und die
    # „Messung (Hardening)"-Kachel des Einstiegs-Cockpits zeigt
    # ihren Empty-State. Live-Setup setzt den Provider auf
    # ``ScoringService.lade_letztes_hardening_result`` und liefert dann
    # ein vollstaendiges Ergebnis (Score + Stage + Breakdown).
    hardening_score: HardeningScoreResult | None = None
    # Folge: Kunden-Audit-Score. Nur gesetzt, wenn im Header ein
    # Kunden-Subjekt gewählt ist UND für dieses Subjekt ein Audit existiert.
    # ``None`` (Default/„Allgemein"/eigenes System) → keine Kunden-Karte;
    # gesetzt → ``CustomerAuditCard`` erscheint (dashboard_widget._apply).
    customer_audit: CustomerAuditSummary | None = None
    # Phase 4): jüngste SELF-Audit-Zusammenfassung des EIGENEN
    # Systems — unabhängig vom Header-Subjekt-Selektor (immer SELF). Speist die
    # „Selbsteinschätzung (Audit)"-Kachel des Einstiegs-Cockpits neben der
    # gemessenen „Messung (Hardening)"-Kachel (``hardening_score``). Bewusst
    # getrennt von ``customer_audit`` (das dem gewählten Kunden-Subjekt folgt):
    # das Einstiegs-Band zeigt die zwei Dimensionen der eigenen Sicherheitslage,
    # nie Kundendaten. ``None`` = noch kein SELF-Audit → Kachel-Empty-State.
    self_audit: CustomerAuditSummary | None = None
