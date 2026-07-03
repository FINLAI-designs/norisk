"""
dashboard_aggregator — Sammelt Daten für das NoRisk-Dashboard.

Liest aus drei Quellen:
- Briefing-Cache (``~/.finlai/cyber_briefing.json``) — CVEs + Meldungen
- Security-Scoring-Repository — aktueller Score + Verlauf
- Scanner-Repositories — letzter Scan-Zeitpunkt pro Tool

Alle Quellen sind optional; fehlt eine, liefert der Aggregator leere
Teilbereiche statt zu scheitern. Dadurch bleibt das Dashboard auch in
einer frisch installierten App anzeigbar.

Schichtzugehörigkeit: application/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 0.1 (Phase 1)
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from core.finlai_paths import finlai_dir
from core.logger import get_logger
from tools.norisk_dashboard.domain.models import (
    CertBurndown,
    ChangeEntry,
    ChangeType,
    CompletenessEntry,
    CustomerAuditSummary,
    CveListEntry,
    CvssPercentiles,
    DashboardData,
    OrgSnapshot,
    OrgTile,
    ScanEntry,
    ScanStatus,
    ScoreSnapshot,
    TimeRange,
)
from tools.security_scoring.domain.hardening_score import HardeningScoreResult
from tools.security_scoring.domain.models import ScoreComponent

log = get_logger(__name__)

_BRIEFING_PATH = finlai_dir() / "cyber_briefing.json"


class DashboardAggregator:
    """Bündelt die Datenbeschaffung für das Dashboard.

    Konstruktor-Parameter sind alle optional und erlauben das Ersetzen
    der Quellen in Tests.

    Attributes:
        _score_loader: Callable target -> list[SecurityScore] oder None.
        _scan_loaders: Liste (tool_key, tool_label, callable -> datetime|None, status_callable).
        _briefing_path: Pfad zum Briefing-Cache.
    """

    def __init__(
        self,
        score_loader: Callable[[str], list] | None = None,
        scan_loaders: list[tuple[str, str, Callable[[], datetime | None]]] | None = None,
        briefing_path: Path | None = None,
        org_loader: Callable[[], OrgSnapshot | None] | None = None,
        cert_burndown_loader: Callable[[], CertBurndown | None] | None = None,
        cvss_percentile_loader: Callable[[], CvssPercentiles | None] | None = None,
        completeness_loader: Callable[[], list[CompletenessEntry]] | None = None,
        hardening_score_provider: (
            Callable[[], HardeningScoreResult | None] | None
        ) = None,
        subjects_loader: Callable[[], list[tuple[str, str]]] | None = None,
        subject_score_loader: Callable[[str], list] | None = None,
        customer_audit_loader: (
            Callable[[str], CustomerAuditSummary | None] | None
        ) = None,
        self_audit_loader: (
            Callable[[], CustomerAuditSummary | None] | None
        ) = None,
    ) -> None:
        """Initialisiert den Aggregator.

        Args:
            score_loader: Callable (target_name) -> Liste SecurityScore,
                            neueste zuerst. Speist Snapshot + Breakdown + Trend.
                            Default: keine Score-Daten.
            scan_loaders: Liste von Tupeln (tool_key, tool_label,
                            callable -> datetime | None). Default: leere Liste.
            briefing_path: Pfad zum Briefing-Cache. Default:
                            ``~/.finlai/cyber_briefing.json``.
            org_loader: Callable -> OrgSnapshot | None. Liefert den
                            fertig gebauten Snapshot (inkl. Tiles). Default: None.
            cert_burndown_loader: Sprint S3c W2 — Callable -> CertBurndown | None.
            cvss_percentile_loader: Sprint S3c W6 — Callable -> CvssPercentiles | None.
            completeness_loader: Sprint S3c W3 — Callable -> list[CompletenessEntry].
                Standard fuer alle drei: ``None`` -> Widget rendert Empty-State.
            hardening_score_provider: Phase 4.5 — Callable ->
                ``HardeningScoreResult | None``. Wenn gesetzt, ruft
:meth:`aggregate` den Provider auf und fuellt
                ``DashboardData.hardening_score``. ``None`` (Default) =
                Feld bleibt ``None``, die Hardening-Kachel des
                Einstiegs-Cockpits zeigt ihren Empty-State.
                Production-Wiring uebergibt
                ``ScoringService.lade_letztes_hardening_result``.
        """
        self._score_loader = score_loader
        self._scan_loaders = scan_loaders or []
        self._briefing_path = briefing_path or _BRIEFING_PATH
        self._org_loader = org_loader
        self._cert_burndown_loader = cert_burndown_loader
        self._cvss_percentile_loader = cvss_percentile_loader
        self._completeness_loader = completeness_loader
        self._hardening_score_provider = hardening_score_provider
        # Subjekt-Selektor-Quellen. ``subjects_loader`` liefert die
        # (subject_id, Anzeigename)-Paare fuer das Dropdown; ``subject_score_loader``
        # laedt die Score-Historie eines Subjekts. Beide optional → ohne sie
        # bleibt das Dashboard exakt beim ``target_name``-Pfad (Default-inert).
        self._subjects_loader = subjects_loader
        self._subject_score_loader = subject_score_loader
        # Folge: lädt den Kunden-Audit-Score eines Subjekts (als bereits
        # adaptiertes ``CustomerAuditSummary``-DTO — die customer_audit→DTO-
        # Übersetzung passiert im Loader, nicht hier). Optional/fail-soft.
        self._customer_audit_loader = customer_audit_loader
        # Phase 4): lädt die jüngste SELF-Audit-Zusammenfassung
        # des eigenen Systems — argumentlos (der Loader löst das SELF-Subjekt
        # selbst über den core-Resolver auf, kein Subjekt-Selektor). Optional/
        # fail-soft; speist ``DashboardData.self_audit`` (Einstiegs-Cockpit).
        self._self_audit_loader = self_audit_loader

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def aggregate(
        self,
        time_range: TimeRange,
        target_name: str = "Allgemein",
        *,
        subject_id: str | None = None,
    ) -> DashboardData:
        """Sammelt alle Daten für einen Dashboard-Refresh.

        Args:
            time_range: Zeit-Filter (Woche/Monat/Quartal).
            target_name: Anzeige-Label des Score-Ziels (Subjekt-/Kundenname
                oder ``"Allgemein"``).
            subject_id: Optionale Subjekt-UUID. Gesetzt + verfügbarer
                ``subject_score_loader`` → Score-Historie wird subjekt-bewusst
                geladen; sonst (Default) der bisherige ``target_name``-Pfad.
                Unbekanntes/leeres Subjekt → leere Historie → Empty-State.

        Returns:
            Aggregierter Datenstand. Teilbereiche können leer sein.
        """
        if subject_id and self._subject_score_loader is not None:
            history = self._load_history_by_subject(subject_id)
        else:
            history = self._load_history(target_name)
        score = self._snapshot_from_history(history, target_name)
        breakdown = self._breakdown_from_history(history)
        trend = self._trend_from_history(history, time_range)
        cves = self._load_cves_from_briefing()
        scans = self._collect_scans()
        changes = self._compute_changes(time_range, score, cves, scans)
        org = self._load_org()
        # Sprint S3c — Quick-Win-Felder, jeder Loader optional + defensive.
        cert_burndown = self._load_cert_burndown()
        cvss_percentiles = self._load_cvss_percentiles()
        completeness = self._load_completeness()
        # Phase 4.5 — Hardening-Score-Snapshot fuer die neuen
        # 4-Stufen-Widgets. Provider darf werfen — wir tolerieren das
        # defensiv damit ein Service-Init-Fehler nicht das ganze
        # Dashboard kippt (Aggregator-Konvention "leere Felder statt
        # Crash").
        hardening_score = self._load_hardening_score()
        # Folge: Kunden-Audit-Score nur bei explizit gewähltem Subjekt.
        # Im Default-Pfad ("Allgemein", subject_id=None) bleibt das Feld None
        # und das Dashboard zeigt unverändert den eigenen Hardening-Score.
        customer_audit = (
            self._load_customer_audit(subject_id) if subject_id else None
        )
        # Phase 4): SELF-Audit IMMER laden — unabhängig vom
        # Subjekt-Selektor (das Einstiegs-Cockpit zeigt stets die eigene Lage).
        self_audit = self._load_self_audit()
        return DashboardData(
            time_range=time_range,
            changes=changes,
            score=score,
            cves=cves,
            scans=scans,
            breakdown=breakdown,
            trend=trend,
            org=org,
            generated=datetime.now(),
            cert_burndown=cert_burndown,
            cvss_percentiles=cvss_percentiles,
            completeness=completeness,
            hardening_score=hardening_score,
            customer_audit=customer_audit,
            self_audit=self_audit,
        )

    def _load_self_audit(self) -> CustomerAuditSummary | None:
        """Lädt die jüngste SELF-Audit-Zusammenfassung oder ``None``.

        Fail-soft nach Aggregator-Konvention: ein Loader-Fehler darf das
        Dashboard nie crashen (→ ``None`` = Audit-Kachel-Empty-State). Der
        Loader ist argumentlos und löst das SELF-Subjekt selbst auf (core-
        Resolver), unabhängig vom Header-Subjekt-Selektor.
        """
        if self._self_audit_loader is None:
            return None
        try:
            return self._self_audit_loader()
        except Exception as exc:  # noqa: BLE001 -- injizierter Loader, fail-soft
            log.warning(
                "SELF-Audit-Loader fehlgeschlagen: %s", type(exc).__name__
            )
            return None

    def _load_customer_audit(
        self, subject_id: str
    ) -> CustomerAuditSummary | None:
        """Lädt den Kunden-Audit-Score eines Subjekts-Folge) oder ``None``.

        Fail-soft nach Aggregator-Konvention: ein Loader-Fehler darf das
        Dashboard nie crashen (→ ``None`` = Hero-Hardening-Empty-State bleibt).
        """
        if self._customer_audit_loader is None:
            return None
        try:
            return self._customer_audit_loader(subject_id)
        except Exception as exc:  # noqa: BLE001 -- injizierter Loader, fail-soft
            log.warning(
                "Customer-Audit-Loader fehlgeschlagen: %s", type(exc).__name__
            )
            return None

    def _load_hardening_score(self) -> HardeningScoreResult | None:
        """Liefert den Hardening-Score via Provider oder ``None``."""
        if self._hardening_score_provider is None:
            return None
        try:
            return self._hardening_score_provider()
        except Exception as exc:  # noqa: BLE001 — Aggregator darf nie crashen
            log.warning(
                "hardening_score_provider raised %s — Feld bleibt None.",
                type(exc).__name__,
            )
            return None

    # ------------------------------------------------------------------
    # Score-Historie (Basis für Snapshot, Breakdown und Trend)
    # ------------------------------------------------------------------

    def _load_history(self, target_name: str) -> list:
        """Lädt die komplette Score-Historie (neueste zuerst) oder leer."""
        if self._score_loader is None:
            return []
        try:
            return list(self._score_loader(target_name) or [])
        except Exception as exc:  # noqa: BLE001 -- Loader-Callable vom Konstruktor injected, kann beliebige Errors werfen
            log.warning("Score-Loader fehlgeschlagen: %s", type(exc).__name__)
            return []

    def _load_history_by_subject(self, subject_id: str) -> list:
        """Lädt die Score-Historie eines Subjekts oder leer."""
        if self._subject_score_loader is None:
            return []
        try:
            return list(self._subject_score_loader(subject_id) or [])
        except Exception as exc:  # noqa: BLE001 -- injizierter Loader, fail-soft
            log.warning(
                "Subjekt-Score-Loader fehlgeschlagen: %s", type(exc).__name__
            )
            return []

    def subjects(self) -> list[tuple[str, str]]:
        """Liefert die wählbaren Subjekte als ``(subject_id, Anzeigename)``.

        Speist das Subjekt-Dropdown im Dashboard-Header. Ohne
        ``subjects_loader`` (Default) leere Liste → der Header zeigt nur den
        ``"Allgemein"``-Eintrag.

        Returns:
            Liste von ``(subject_id, Anzeigename)`` (eigenes Subjekt zuerst,
            dann Kunden) — leer wenn kein Loader/Store verfügbar.
        """
        if self._subjects_loader is None:
            return []
        try:
            return list(self._subjects_loader() or [])
        except Exception as exc:  # noqa: BLE001 -- injizierter Loader, fail-soft
            log.info("Subjekt-Liste nicht verfügbar: %s", type(exc).__name__)
            return []

    @staticmethod
    def _snapshot_from_history(history: list, target_name: str) -> ScoreSnapshot:
        """Leitet den Score-Snapshot (aktuell + Vorgänger) aus der Historie ab."""
        if not history:
            return ScoreSnapshot(target=target_name)
        current_score = history[0]
        previous = history[1] if len(history) > 1 else None
        ts = _parse_iso(getattr(current_score, "timestamp", ""))
        return ScoreSnapshot(
            current=float(getattr(current_score, "overall_score", 0.0)),
            previous=(
                float(getattr(previous, "overall_score", 0.0))
                if previous is not None
                else None
            ),
            timestamp=ts,
            target=target_name,
        )

    @staticmethod
    def _breakdown_from_history(history: list) -> list[ScoreComponent]:
        """Liefert die Komponenten des neuesten Scores (leer wenn keine)."""
        if not history:
            return []
        latest = history[0]
        return list(getattr(latest, "components", []) or [])

    @staticmethod
    def _trend_from_history(
        history: list, time_range: TimeRange
    ) -> list[tuple[datetime, float]]:
        """Liefert (timestamp, overall_score)-Paare innerhalb des Zeitraums, älteste zuerst."""
        if not history:
            return []
        cutoff = datetime.now() - timedelta(days=time_range.days)
        pairs: list[tuple[datetime, float]] = []
        for item in history:
            ts = _parse_iso(getattr(item, "timestamp", ""))
            if ts is None:
                continue
            if ts < cutoff:
                continue
            pairs.append((ts, float(getattr(item, "overall_score", 0.0))))
        pairs.sort(key=lambda p: p[0])
        return pairs

    # ------------------------------------------------------------------
    # Organisatorische Sicherheit (Sektion 5)
    # ------------------------------------------------------------------

    def _load_org(self) -> OrgSnapshot | None:
        """Lädt den fertig gebauten Org-Snapshot.

        Fällt auf einen Snapshot mit ``has_assessment=False`` und leeren
        Scores zurück, wenn der Loader eine Exception wirft — so kann die
        GUI den CTA-Button sauber anzeigen. Liefert None nur, wenn
        kein Loader verdrahtet ist (z.B. in Tests ohne Org-Daten).
        """
        if self._org_loader is None:
            return None
        try:
            snap = self._org_loader()
        except Exception as exc:  # noqa: BLE001 -- Loader-Callable vom Konstruktor injected, kann beliebige Errors werfen
            log.warning("Org-Loader fehlgeschlagen: %s", type(exc).__name__)
            return OrgSnapshot(tiles=_empty_org_tiles(), has_assessment=False)
        if snap is None:
            return OrgSnapshot(tiles=_empty_org_tiles(), has_assessment=False)
        return snap

    # ------------------------------------------------------------------
    # Sprint S3c — Quick-Win-Loader (W2/W3/W6)
    # ------------------------------------------------------------------

    def _load_cert_burndown(self) -> CertBurndown | None:
        """Sprint S3c W2 — laedt die Cert-Burndown-Daten defensive.

        Returns:
            ``CertBurndown`` oder ``None``. ``None`` -> Empty-State im
            Tile, ein gefuelltes ``CertBurndown(min_days=None,...)``
            -> "keine Zertifikate ueberwacht"-Hinweis.
        """
        if self._cert_burndown_loader is None:
            return None
        try:
            return self._cert_burndown_loader()
        except Exception as exc:  # noqa: BLE001 -- Loader-Callable defensive
            log.warning(
                "Cert-Burndown-Loader fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return None

    def _load_cvss_percentiles(self) -> CvssPercentiles | None:
        """Sprint S3c W6 — laedt die CVSS-Perzentile defensive."""
        if self._cvss_percentile_loader is None:
            return None
        try:
            return self._cvss_percentile_loader()
        except Exception as exc:  # noqa: BLE001 -- Loader-Callable defensive
            log.warning(
                "CVSS-Perzentile-Loader fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return None

    def _load_completeness(self) -> list[CompletenessEntry]:
        """Sprint S3c W3 — laedt die Score-Vollstaendigkeit defensive."""
        if self._completeness_loader is None:
            return []
        try:
            entries = self._completeness_loader() or []
        except Exception as exc:  # noqa: BLE001 -- Loader-Callable defensive
            log.warning(
                "Vollstaendigkeit-Loader fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return []
        return list(entries)

    # ------------------------------------------------------------------
    # CVEs aus Briefing-Cache
    # ------------------------------------------------------------------

    def _load_cves_from_briefing(self) -> list[CveListEntry]:
        """Liest CVE-Einträge aus dem Briefing-JSON-Cache.

        Returns:
            Techstack-gefilterte CVE-Liste (leer wenn Cache fehlt
            oder Struktur abweicht).
        """
        if not self._briefing_path.exists():
            return []
        try:
            raw = json.loads(self._briefing_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Briefing-Cache nicht lesbar: %s", type(exc).__name__)
            return []
        eintraege = raw.get("techstack_eintraege") or raw.get("techstack") or []
        out: list[CveListEntry] = []
        for e in eintraege:
            if not isinstance(e, dict):
                continue
            cve_id = str(e.get("cve_id") or "").strip()
            if not cve_id:
                continue
            ts = _parse_iso(e.get("veroeffentlicht") or e.get("published") or "")
            out.append(
                CveListEntry(
                    cve_id=cve_id,
                    product=str(e.get("produkt") or e.get("product") or "").strip(),
                    description=str(
                        e.get("beschreibung") or e.get("description") or ""
                    ).strip(),
                    published=ts or datetime.now(),
                )
            )
        return out

    # ------------------------------------------------------------------
    # Scan-Status
    # ------------------------------------------------------------------

    def _collect_scans(self) -> list[ScanEntry]:
        """Sammelt den letzten Scan-Zeitpunkt je registriertem Tool."""
        out: list[ScanEntry] = []
        for key, label, loader in self._scan_loaders:
            try:
                last = loader()
            except Exception as exc:  # noqa: BLE001 -- Loader-Callable vom Konstruktor injected, kann beliebige Errors werfen
                log.warning(
                    "Scan-Loader %s fehlgeschlagen: %s", key, type(exc).__name__
                )
                last = None
            if last is None:
                out.append(
                    ScanEntry(
                        tool_key=key,
                        tool_label=label,
                        day=datetime.now().replace(hour=0, minute=0, second=0, microsecond=0),
                        status=ScanStatus.MISSING,
                    )
                )
                continue
            day = last.replace(hour=0, minute=0, second=0, microsecond=0)
            out.append(
                ScanEntry(
                    tool_key=key,
                    tool_label=label,
                    day=day,
                    status=ScanStatus.OK,
                )
            )
        return out

    # ------------------------------------------------------------------
    # Änderungen berechnen
    # ------------------------------------------------------------------

    def _compute_changes(
        self,
        time_range: TimeRange,
        score: ScoreSnapshot,
        cves: list[CveListEntry],
        scans: list[ScanEntry],
    ) -> list[ChangeEntry]:
        """Erzeugt Einträge für 'Was hat sich geändert seit Zeitraum'."""
        cutoff = datetime.now() - timedelta(days=time_range.days)
        out: list[ChangeEntry] = []

        for cve in cves:
            if cve.published >= cutoff:
                out.append(
                    ChangeEntry(
                        change_type=ChangeType.NEW,
                        title=cve.cve_id,
                        detail=cve.description or cve.product,
                        timestamp=cve.published,
                        source="cve",
                    )
                )

        if score.delta is not None and abs(score.delta) >= 0.1:
            out.append(
                ChangeEntry(
                    change_type=ChangeType.CHANGED,
                    title=f"Score {score.current:.1f}",
                    detail=f"Δ {score.delta:+.1f} Punkte gegenüber Vorwoche",
                    timestamp=score.timestamp or datetime.now(),
                    source="score",
                )
            )

        for scan in scans:
            if scan.status == ScanStatus.MISSING:
                continue
            if scan.day >= cutoff:
                out.append(
                    ChangeEntry(
                        change_type=ChangeType.NEW,
                        title=scan.tool_label,
                        detail=f"Neuer Scan-Lauf am {scan.day:%d.%m.%Y}",
                        timestamp=scan.day,
                        source="scan",
                    )
                )

        out.sort(key=lambda e: e.timestamp, reverse=True)
        return out


# ----------------------------------------------------------------------
# Hilfsfunktionen
# ----------------------------------------------------------------------


# Tuple-Eintraege sind (tile_key, ui_label, match_name).
# UI-Label und Match-Name sind getrennt — UI darf kuerzer sein, Match-Name MUSS
# byte-identisch zu ``METRIK_ANZEIGENAME`` aus der Domain sein. Vorher hatte
# das MFA-Tile UI-Label "Multi-Factor Auth" und matchte gegen denselben Wert,
# der OrgSecurityService liefert aber "Multi-Factor Authentication" → Mismatch
# → score=None → Tile zeigt "-" obwohl der Fragebogen ausgefuellt war.
_ORG_TILE_REIHENFOLGE: tuple[tuple[str, str, str], ...] = (
    ("dsgvo", "DSGVO-Compliance", "DSGVO-Compliance"),
    ("phishing", "Phishing-Schutz", "Phishing-Schutz"),
    ("mfa", "Multi-Factor Auth", "Multi-Factor Authentication"),
    ("passwort_manager", "Passwort-Manager", "Passwort-Manager"),
)


def _empty_org_tiles() -> list[OrgTile]:
    """Vier Kacheln mit Score=None — Empty-State-Darstellung."""
    return [
        OrgTile(key=k, label=ui_label, score=None)
        for k, ui_label, _match_name in _ORG_TILE_REIHENFOLGE
    ]


def tiles_from_components(components: list[ScoreComponent]) -> list[OrgTile]:
    """Hilfsfunktion für ``tool.py``: baut vier OrgTiles aus ScoreComponents.

    Matching erfolgt über ``component.name`` (siehe ``METRIK_ANZEIGENAME``
    in ``tools/security_scoring/domain/org_security.py``). Nicht gefundene
    Metriken bekommen ``score=None``.

    Match-Name aus dem Tuple ist nun byte-identisch zum
    Domain-``METRIK_ANZEIGENAME``-Wert, das UI-Label darf kuerzer sein.
    """
    by_name = {c.name: c for c in components}
    tiles: list[OrgTile] = []
    for key, ui_label, match_name in _ORG_TILE_REIHENFOLGE:
        comp = by_name.get(match_name)
        if comp is None:
            tiles.append(OrgTile(key=key, label=ui_label, score=None))
        else:
            tiles.append(
                OrgTile(
                    key=key,
                    label=ui_label,
                    score=float(comp.score),
                    findings_open=int(comp.findings_high),
                )
            )
    return tiles


def _parse_iso(value: str | None) -> datetime | None:
    """Parst ISO-8601 Strings robust; liefert None bei Fehler.

    Bugfix 2026-04-30: Strippt tzinfo, damit Vergleiche mit
    ``datetime.now`` (tz-naive) im Aggregator nicht mit
    ``TypeError: can't compare offset-naive and offset-aware datetimes``
    crashen. Score-Timestamps werden via ``datetime.now(UTC).isoformat``
    UTC-aware persistiert; intern arbeitet der Aggregator aber mit
    Tag-Cutoffs (7/30/90 Tage), wo der Stunden-Offset durch das
    Timezone-Stripping irrelevant ist.
    """
    if not value:
        return None
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if result.tzinfo is not None:
        result = result.replace(tzinfo=None)
    return result
