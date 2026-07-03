"""
norisk_dashboard.tool — Plugin-Definition für das NoRisk-Gesamt-Dashboard.

Registriert das Dashboard in der FINLAI ToolRegistry und baut den
Aggregator mit minimaler Kopplung zu Scanner-Repositories auf.

Author: Patrick Riederich
Version: 0.1 (Phase 1)
"""

from __future__ import annotations

from datetime import datetime

from core.base_tool import BaseTool
from core.finlai_paths import finlai_dir
from core.logger import get_logger

log = get_logger(__name__)


class NoRiskDashboardTool(BaseTool):
    """Plugin-Definition für das NoRisk-Gesamt-Dashboard.

    Sidebar-Label "Übersicht" — geschärft per Sprint S0c (Tool-Merger M3),
    damit "Übersicht (eigene Org)" und "Lagebild (die Welt)" auf einen Blick
    unterscheidbar sind.

    Attributes:
        name: Sidebar-Anzeigename — ``"Übersicht"``.
        icon: Material-Icon-Schlüssel.
        feature_name: Lizenz-Feature-Key.
    """

    name = "Übersicht"
    icon = "dashboard"
    feature_name = "norisk_dashboard"

    def create_widget(self, parent=None):  # noqa: ANN001
        """Baut das Dashboard-Widget inkl. Aggregator-Verdrahtung."""
        from tools.norisk_dashboard.application.dashboard_aggregator import (
            DashboardAggregator,
        )
        from tools.norisk_dashboard.gui.dashboard_widget import (
            NoRiskDashboardWidget,
        )

        aggregator = DashboardAggregator(
            score_loader=_build_score_loader(),
            scan_loaders=_build_scan_loaders(),
            org_loader=_build_org_loader(),
            cert_burndown_loader=_build_cert_burndown_loader(),
            cvss_percentile_loader=_build_cvss_percentile_loader(),
            completeness_loader=_build_completeness_loader(),
            hardening_score_provider=_build_hardening_score_provider(),
            subjects_loader=_build_subjects_loader(),
            subject_score_loader=_build_subject_score_loader(),
            customer_audit_loader=_build_customer_audit_loader(),
            self_audit_loader=_build_self_audit_loader(),
        )
        # Sprint S4a — Mainpage-Services defensive bauen (TaskService +
        # JournalService + QuickstartService teilen sich das gleiche
        # MainpageRepository). Wenn der Bau scheitert (z. B. SQLCipher-Init
        # nicht verfuegbar), bleiben die abhaengigen Sektionen einfach weg,
        # das restliche Dashboard funktioniert weiter.
        task_service, journal_service, quickstart_service = (
            _build_mainpage_services()
        )
        # 3c (Cockpit) — Phishing-Radar-ViewModel defensiv bauen
        # (None bei Fehler → Banner zeigt Placeholder, kein Crash).
        phishing_view_model = _build_phishing_view_model()
        widget = NoRiskDashboardWidget(
            aggregator=aggregator,
            parent=parent,
            task_service=task_service,
            journal_service=journal_service,
            quickstart_service=quickstart_service,
            phishing_view_model=phishing_view_model,
            workflow_service=_build_workflow_service(),
            subject_store=_build_workflow_subject_store(),
        )
        widget.setMinimumSize(1000, 640)
        return widget


# ----------------------------------------------------------------------
# Verdrahtung der externen Quellen (best-effort — jede Quelle ist optional)
# ----------------------------------------------------------------------


def _build_workflow_service():  # noqa: ANN201 — WorkflowService | None
    """Baut den WorkflowService best-effort; ``None`` bei Fehler.

    Ohne Service faellt der 4. Cockpit-Reiter „Workflow" einfach weg — das
    restliche Cockpit bleibt unberuehrt.
    """
    try:
        from core.ui_settings import UISettings  # noqa: PLC0415
        from tools.norisk_dashboard.application.workflow_service import (  # noqa: PLC0415
            WorkflowService,
        )
        from tools.norisk_dashboard.data.workflow_progress_repository import (  # noqa: PLC0415
            WorkflowProgressRepository,
        )

        try:
            gating = bool(UISettings.load().profile_gating_enabled)
        except Exception:  # noqa: BLE001 — Default: Gating an
            gating = True
        return WorkflowService(
            WorkflowProgressRepository(), gating_enabled=gating
        )
    except Exception:  # noqa: BLE001 — ohne Service faellt der Workflow-Tab weg
        return None


def _build_workflow_subject_store():  # noqa: ANN201 — SubjectStore | None
    """SubjectStore fuer die Subjekt-Aufloesung im Workflow-Tab (best-effort)."""
    try:
        from core.security_subject.resolver import (  # noqa: PLC0415
            create_subject_store,
        )

        return create_subject_store()
    except Exception:  # noqa: BLE001
        return None


def _memoized(factory):
    """Cacht das erste NICHT-``None``-Ergebnis von ``factory`` (Perf).

    Die Dashboard-Loader werden bei JEDEM ``aggregate`` aufgerufen (Initial +
    manueller + 2h-Auto-Refresh). Bauten sie ihr Repository/Service je Aufruf
    neu, zahlte jeder Refresh erneut ``EncryptedDatabase``-Open + Schema-Init pro
    Repo. ``_memoized`` baut die Instanz einmal (closure-lokal -> pro Widget, kein
    Modul-Global-Leak in Tests) und teilt sie ueber Folge-Refreshes.

    ``None`` (fail-soft, z.B. Store nicht verfuegbar) wird NICHT gecacht -> der
    naechste Refresh baut erneut; wirft ``factory``, propagiert die Exception
    (der Loader-``try/except`` faengt sie) -> ebenfalls nicht gecacht. Thread-
    sicher: die Repos halten nur DB-Name/-Key/-Pfad (immutable) + oeffnen die
    Connection pro Operation -> kein geteilter Connection-State zwischen
    aggregate-Worker und UI-Thread.
    """
    box: dict = {}

    def _get():
        inst = box.get("v")
        if inst is None:
            inst = factory()
            if inst is not None:
                box["v"] = inst
        return inst

    return _get


def _build_score_loader():
    """Baut einen Score-Loader oder None wenn Repository nicht verfügbar.

    Gibt eine längere Historie zurück (90 Einträge), damit Sektion 4
    (Breakdown + Trend) über das gewählte Zeitfenster genug Datenpunkte
    hat.

    Bugfix 2026-04-30: Fällt auf das Target mit dem jüngsten Score
    zurück, wenn das angefragte ``target_name`` keine Daten hat.
    Hintergrund: Das Dashboard ruft mit dem Default ``"Allgemein"`` auf,
    aber das Security-Scoring persistiert standardmaessig unter
    ``"Mein System"`` (siehe ``manage_profiles_use_case.py``). Statt
    den Konstantenwert zwischen beiden Tools zu koppeln, schaut der
    Loader nach dem juengsten Score-Eintrag in der DB — robust auch
    gegen frei vergebene Kunden-Targets.
    """

    def _make_repo():
        from tools.security_scoring.data.score_repository import (  # noqa: PLC0415
            ScoreRepository,
        )

        return ScoreRepository()

    _repo = _memoized(_make_repo)

    def _load(target: str) -> list:
        try:
            repo = _repo()
            scores = repo.lade_letzte_scores(target, 90)
            if scores:
                return scores
            fallback_target = _pick_freshest_target(repo, exclude=target)
            if fallback_target is None:
                return []
            log.info(
                "Score-Loader: kein Eintrag fuer '%s' — Fallback auf '%s'.",
                target,
                fallback_target,
            )
            return repo.lade_letzte_scores(fallback_target, 90)
        except (ImportError, OSError, RuntimeError, AttributeError) as exc:
            log.info("Score-Verlauf nicht verfügbar: %s", type(exc).__name__)
            return []

    return _load


def _pick_freshest_target(repo, exclude: str) -> str | None:  # noqa: ANN001
    """Liefert den ``target_name`` mit dem juengsten Score-Eintrag.

    Iteriert ueber alle bekannten Targets (alphabetisch via
    ``lade_bekannte_targets``) und vergleicht den Top-Score-Timestamp
    pro Target. ``exclude`` (typisch das bereits erfolglos abgefragte
    Default-Target) wird ausgelassen, um eine zweite identische Query
    zu sparen.

    Returns:
        Name des Targets mit dem neuesten Score oder ``None`` wenn die
        DB komplett leer ist.
    """
    targets = repo.lade_bekannte_targets()
    best_name: str | None = None
    best_ts: str = ""
    for name in targets:
        if name == exclude:
            continue
        top = repo.lade_letzte_scores(name, 1)
        if not top:
            continue
        ts = getattr(top[0], "timestamp", "") or ""
        if ts > best_ts:
            best_ts = ts
            best_name = name
    return best_name


def _build_subjects_loader():
    """Baut einen Loader für die Subjekt-Auswahl des Dashboards.

    Liefert ``(subject_id, Anzeigename)``-Paare über den core-Resolver
    (kein tool→tool-Import). Fail-soft: ohne verfügbaren Store eine leere
    Liste → der Header zeigt nur ``"Allgemein"``.
    """

    def _make_store():
        from core.security_subject.resolver import (  # noqa: PLC0415
            create_subject_store,
        )

        return create_subject_store()

    _store = _memoized(_make_store)

    def _load() -> list[tuple[str, str]]:
        try:
            store = _store()
            if store is None:
                return []
            return [(s.subject_id, s.display_name) for s in store.list_all()]
        except (ImportError, OSError, RuntimeError, AttributeError) as exc:
            log.info("Subjekt-Liste nicht verfügbar: %s", type(exc).__name__)
            return []

    return _load


def _build_subject_score_loader():
    """Baut einen subjekt-bewussten Score-Loader.

    Lädt die Score-Historie eines Subjekts über ``subject_id`` (stabil über
    eine Umbenennung des ``target_name``). Fail-soft → leere Liste.
    """

    def _make_repo():
        from tools.security_scoring.data.score_repository import (  # noqa: PLC0415
            ScoreRepository,
        )

        return ScoreRepository()

    _repo = _memoized(_make_repo)

    def _load(subject_id: str) -> list:
        try:
            return _repo().lade_letzte_scores_by_subject(subject_id, 90)
        except (ImportError, OSError, RuntimeError, AttributeError) as exc:
            log.info(
                "Subjekt-Score-Verlauf nicht verfügbar: %s", type(exc).__name__
            )
            return []

    return _load


def _build_customer_audit_loader():
    """Baut einen Loader für den Kunden-Audit-Score eines Subjekts-Folge).

    Liest die jüngste Audit-Zusammenfassung des Subjekts aus dem
    ``CustomerAuditRepository`` (rein lesend, leichtgewichtige Score-Spalten)
    und adaptiert sie in das dashboard-eigene ``CustomerAuditSummary``-DTO —
    so importiert der Aggregator KEINEN ``customer_audit``-Domain-Typ
    (cert_burndown-/Resolver-Muster, kein tool→tool-Leak im Aggregator;
 §3.2). Der ``customer_audit``-Repository-Zugriff läuft bewusst
    lazy innerhalb des Loaders, damit keine statische tool→tool-Kante entsteht.

    Fail-soft: ohne Audit / bei Repo-Fehler → ``None`` (Hero-Hardening-
    Empty-State bleibt). Speist ``DashboardData.customer_audit``.
    """

    def _make_repo():
        from tools.customer_audit.data.customer_audit_repository import (  # noqa: PLC0415
            CustomerAuditRepository,
        )

        return CustomerAuditRepository()

    _repo = _memoized(_make_repo)

    def _load(subject_id: str):
        try:
            from tools.norisk_dashboard.domain.models import (  # noqa: PLC0415
                CustomerAuditSummary,
            )

            summary = _repo().latest_summary_by_subject(subject_id)
            if not summary:
                return None
            return CustomerAuditSummary(
                subject_id=subject_id,
                firmenname=str(summary.get("firmenname") or ""),
                overall_score=float(summary.get("overall_score") or 0.0),
                risk_level=str(summary.get("risk_level") or ""),
                created_at=_parse_ts(summary.get("created_at")),
                audit_id=str(summary.get("audit_id") or ""),
                audit_count=int(summary.get("audit_count") or 0),
            )
        except (
            ImportError,
            OSError,
            RuntimeError,
            AttributeError,
            ValueError,
            TypeError,
        ) as exc:
            log.info(
                "Kunden-Audit-Score nicht verfügbar: %s", type(exc).__name__
            )
            return None

    return _load


def _build_self_audit_loader():
    """Baut einen Loader für die jüngste SELF-Audit-Zusammenfassung.

    Anders als ``_build_customer_audit_loader`` (folgt dem Header-Selektor) ist
    dieser Loader argumentlos: er löst das EIGENE Subjekt selbst über den
    core-Resolver auf (``create_subject_store.get_self`` — rein lesend, kein
    Anlegen) und liest dessen jüngste Audit-Zusammenfassung aus dem
    ``CustomerAuditRepository``, adaptiert in das dashboard-eigene
    ``CustomerAuditSummary``-DTO. So importiert der Aggregator KEINEN
    ``customer_audit``-Domain-Typ; die tool→tool-Zugriffe (customer_audit-Repo +
    security_subject-Resolver) laufen bewusst lazy innerhalb des Loaders
    (etabliertes Muster §3.2 — beide Kanten sind import-linter-Baseline).

    Speist die „Selbsteinschätzung (Audit)"-Kachel des Einstiegs-Cockpits
 Phase 4) neben der gemessenen Hardening-Kachel.

    Fail-soft: kein SELF-Subjekt / kein Audit / Repo-Fehler → ``None``
    (Kachel-Empty-State „Noch kein Audit").
    """

    def _make_store():
        from core.security_subject.resolver import (  # noqa: PLC0415
            create_subject_store,
        )

        return create_subject_store()

    def _make_repo():
        from tools.customer_audit.data.customer_audit_repository import (  # noqa: PLC0415
            CustomerAuditRepository,
        )

        return CustomerAuditRepository()

    _store = _memoized(_make_store)
    _repo = _memoized(_make_repo)

    def _load():
        try:
            from tools.norisk_dashboard.domain.models import (  # noqa: PLC0415
                CustomerAuditSummary,
            )

            store = _store()
            if store is None:
                return None
            self_subject = store.get_self()
            if self_subject is None:
                return None
            summary = _repo().latest_summary_by_subject(
                self_subject.subject_id
            )
            if not summary:
                return None
            return CustomerAuditSummary(
                subject_id=self_subject.subject_id,
                firmenname=str(
                    summary.get("firmenname")
                    or getattr(self_subject, "display_name", "")
                    or ""
                ),
                overall_score=float(summary.get("overall_score") or 0.0),
                risk_level=str(summary.get("risk_level") or ""),
                created_at=_parse_ts(summary.get("created_at")),
                audit_id=str(summary.get("audit_id") or ""),
                audit_count=int(summary.get("audit_count") or 0),
            )
        except (
            ImportError,
            OSError,
            RuntimeError,
            AttributeError,
            ValueError,
            TypeError,
        ) as exc:
            log.info("SELF-Audit-Score nicht verfügbar: %s", type(exc).__name__)
            return None

    return _load


def _build_hardening_score_provider():
    """Baut einen Provider fuer den Hardening-Score des Dashboards.

    Liest den **zuletzt persistierten** Hardening-Score (geschrieben vom
    Security-Scoring-Tab via ``compute_hardening_score(target_name=…)``,
) ueber die application-API ``ScoringService.
    lade_letztes_hardening_result`` und rehydriert ihn zu einem vollen
    ``HardeningScoreResult``.

    Ersetzt den frueheren Live-Compute ueber
    ``ScoringService.create_for_audit_snapshot``, der bei JEDEM
    ``aggregate`` (Auto-Refresh + manuell) den kompletten Sub-Service-Stack
    (api/network/cve-Scanner + mehrere DB-Reads) SYNCHRON auf dem GUI-Thread
    aufbaute — Latenz-/Freeze-Risiko, P2 aus dem-Security-Review).
    Ein reiner Repository-Read ist O(1) und blockiert die UI nicht spuerbar.

    Damit zeigt das Dashboard dieselbe Zahl, die der Tab zuletzt berechnet
    hat. ``None`` (→ Hardening-Kachel-Empty-State statt irrefuehrendem
    0/Critical) wenn noch kein Score persistiert wurde, das Result keine
    aktiven Kategorien hat, oder der DB-Zugriff scheitert.
    """

    def _make_service():
        from tools.security_scoring.application.scoring_service import (  # noqa: PLC0415
            ScoringService,
        )

        return ScoringService()

    _service = _memoized(_make_service)

    def _load():
        try:
            # P0-A: nur den GEMESSENEN (SELF-)Score — manuell fuer Kunden
            # erfasste Eintraege (Herkunft 'erfasst') duerfen die Eigen-System-
            # Kachel nie stellen (sonst zeigt sie bei neuerem Timestamp Kundendaten).
            result = _service().lade_letztes_gemessenes_hardening_result()
            if result is None or not result.category_scores:
                # Kein persistierter Score / keine aktiven Kategorien →
                # kein aussagekraeftiger Wert.
                return None
            return result
        except (ImportError, OSError, RuntimeError, AttributeError) as exc:
            log.info(
                "Hardening-Score nicht verfuegbar: %s", type(exc).__name__
            )
            return None

    return _load


def _build_org_loader():
    """Baut einen Org-Snapshot-Loader oder None wenn Services fehlen.

    Ruft ``OrgSecurityService.lade_letztes`` + ``baue_komponenten``
    auf und formt das Ergebnis in einen ``OrgSnapshot`` um (Helper aus
    dem Aggregator-Modul).
    """

    def _make_svc():
        from tools.security_scoring.application.org_security_service import (  # noqa: PLC0415
            OrgSecurityService,
        )
        from tools.security_scoring.data.org_assessment_repository import (  # noqa: PLC0415
            OrgAssessmentRepository,
        )

        return OrgSecurityService(OrgAssessmentRepository())

    _svc = _memoized(_make_svc)

    def _load():
        try:
            from tools.norisk_dashboard.application.dashboard_aggregator import (  # noqa: PLC0415
                tiles_from_components,
            )
            from tools.norisk_dashboard.domain.models import (  # noqa: PLC0415
                OrgSnapshot,
            )

            svc = _svc()
            assessment = svc.lade_letztes()
            components = svc.baue_komponenten(assessment)
            tiles = tiles_from_components(components)
            return OrgSnapshot(tiles=tiles, has_assessment=assessment is not None)
        except (ImportError, OSError, RuntimeError, AttributeError) as exc:
            log.info("Org-Security nicht verfügbar: %s", type(exc).__name__)
            return None

    return _load


def _build_scan_loaders() -> list[tuple[str, str, object]]:
    """Baut eine Liste von (tool_key, tool_label, callable) für die Heatmap.

    Jeder Loader liefert entweder ``datetime`` (letzter Scan) oder None.
    Fehler in einem Loader führen nicht zu Fehlern im Dashboard — der
    Scanner erscheint dann als 'Kein Scan'.

    Vorher hatten die fünf Loader jeweils eigene SQL-/
    Repository-Zugriffe — und mindestens einer war falsch verdrahtet
    (``_api_security`` suchte ``h.timestamp``, das ``ScanLauf`` aber gar
    nicht hat — Feldname ist ``scan_start``). Folge: API-Security blieb in
    der Heatmap immer auf ``Kein Scan``, obwohl Scans existierten. Fix:
    alle Loader gehen jetzt durch:func:`core.registry.last_scan_registry.get_last_scan`,
    Single-Source-of-Truth gemeinsam mit dem Score-Vollstaendigkeits-Banner.
    """
    from core.registry.last_scan_registry import get_last_scan  # noqa: PLC0415

    def _make_loader(tool_key: str):
        def _load() -> datetime | None:
            ts = get_last_scan(tool_key)
            if ts is None:
                return None
            # Dashboard-Aggregator vergleicht ``scan.day`` tz-naiv —
            # tzinfo strippen analog zum bestehenden _parse_ts-Helper.
            return ts.replace(tzinfo=None) if ts.tzinfo is not None else ts
        return _load

    return [
        ("system_scanner", "System-Scanner", _make_loader("system_scanner")),
        ("network_scanner", "Netzwerk-Scanner", _make_loader("network_scanner")),
        ("api_security", "API-Security", _make_loader("api_security")),
        ("cert_monitor", "Zertifikats-Monitor", _make_loader("cert_monitor")),
        ("document_scanner", "Datei-Scanner", _make_loader("document_scanner")),
    ]


def _parse_ts(value) -> datetime | None:  # noqa: ANN001
    """Parst ISO-String oder datetime; None bei Fehler.

    Bugfix 2026-04-30: Wie ``_parse_iso`` im Aggregator strippt diese
    Funktion ebenfalls tzinfo, damit das Heatmap-Datum (``scan.day``)
    sauber mit dem tz-naiven ``cutoff`` in ``_compute_changes``
    vergleichbar ist.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        result = value
    else:
        try:
            result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    if result.tzinfo is not None:
        result = result.replace(tzinfo=None)
    return result


# ----------------------------------------------------------------------
# Sprint S3c — Quick-Win-Loader (W2/W3/W6)
# ----------------------------------------------------------------------


def _build_cert_burndown_loader():
    """Baut einen Loader fuer den Cert-Burndown-Tile.

    Liest aus ``CertRepository`` und sucht das Cert mit der niedrigsten
    Restlaufzeit. Liefert ``None`` bei Service-Fehler — der Tile zeigt
    dann den Empty-State.
    """

    def _load():
        try:
            from tools.cert_monitor.data.cert_repository import (  # noqa: PLC0415
                CertRepository,
            )
            from tools.norisk_dashboard.domain.models import (  # noqa: PLC0415
                CertBurndown,
            )

            entries = CertRepository().lade_ergebnisse()
            if not entries:
                return CertBurndown()
            valid = [e for e in entries if e.tage_verbleibend is not None]
            if not valid:
                return CertBurndown()
            min_entry = min(valid, key=lambda e: e.tage_verbleibend)
            return CertBurndown(
                min_days=int(min_entry.tage_verbleibend),
                domain=getattr(min_entry, "domain", "") or "",
                count_total=len(valid),
                count_warning=sum(
                    1 for e in valid if 0 <= e.tage_verbleibend <= 30
                ),
                count_critical=sum(
                    1 for e in valid if e.tage_verbleibend <= 7
                ),
            )
        except (ImportError, OSError, RuntimeError, AttributeError) as exc:
            log.info(
                "Cert-Burndown nicht verfuegbar: %s", type(exc).__name__
            )
            return None

    return _load


def _build_cvss_percentile_loader():
    """Baut einen Loader fuer das CVSS-Perzentil-Widget.

    Pulled die ``cvss_score``-Werte aus dem Briefing-CVE-Cache (selbe
    Quelle wie die Sektion-3-Liste) und rechnet daraus p10/p50/p90 +
    eine Sparkline ueber die letzten N Median-Werte. MVP: Sparkline
    bleibt leer, weil es keinen historischen Median-Speicher gibt —
    der wird in einer Folge-Iteration ergaenzt.
    """

    def _load():
        try:
            import json  # noqa: PLC0415

            from tools.norisk_dashboard.domain.models import (  # noqa: PLC0415
                CvssPercentiles,
            )

            briefing_path = finlai_dir() / "cyber_briefing.json"
            if not briefing_path.exists():
                return CvssPercentiles()
            raw = json.loads(briefing_path.read_text(encoding="utf-8"))
            cves = raw.get("cves", []) if isinstance(raw, dict) else []
            scores: list[float] = []
            for cve in cves:
                if not isinstance(cve, dict):
                    continue
                value = cve.get("cvss_score")
                if value is None:
                    continue
                try:
                    scores.append(float(value))
                except (TypeError, ValueError):
                    continue
            if not scores:
                return CvssPercentiles()
            sorted_scores = sorted(scores)
            return CvssPercentiles(
                sample_count=len(sorted_scores),
                p10=_percentile(sorted_scores, 10),
                p50=_percentile(sorted_scores, 50),
                p90=_percentile(sorted_scores, 90),
                # Sparkline: bis zu 12 Werte aus der sortierten Liste
                # in absteigender Reihenfolge — gibt einen Eindruck der
                # CVSS-Verteilung ohne historischen Speicher.
                sparkline=sorted_scores[-12:],
            )
        except (
            ImportError,
            OSError,
            RuntimeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            log.info(
                "CVSS-Perzentile nicht verfuegbar: %s", type(exc).__name__
            )
            return None

    return _load


def _build_completeness_loader():
    """Baut einen Loader fuer das Score-Vollstaendigkeits-Banner.

    Nutzt die:class:`LastScanRegistry` aus Sprint S0b — kennt 8 Tools
    und liefert pro Tool den Last-Scan-Zeitpunkt oder None.
    Status-Schwellen:
      * < 7 Tage -> FRESH
      * 7..30 Tage -> OUTDATED
      * > 30 Tage / None -> MISSING
    """

    _LABELS = {
        "api_security": "API-Security",
        "cert_monitor": "Cert-Monitor",
        "csaf_advisor": "CSAF-Advisor",
        "cyber_dashboard": "Cyber-Dashboard",
        "document_scanner": "Datei-Scanner",
        "network_monitor": "Netzwerk-Monitor",
        "network_scanner": "Netzwerk-Scanner",
        "system_scanner": "System-Scanner",
    }

    def _load():
        try:
            from datetime import UTC, datetime, timedelta  # noqa: PLC0415

            from core.registry.last_scan_registry import (  # noqa: PLC0415
                get_last_scan,
                list_known_tools,
            )
            from tools.norisk_dashboard.domain.models import (  # noqa: PLC0415
                CompletenessEntry,
                CompletenessStatus,
            )

            now = datetime.now(UTC)
            entries: list[CompletenessEntry] = []
            for tool in list_known_tools():
                last = get_last_scan(tool)
                if last is None:
                    status = CompletenessStatus.MISSING
                else:
                    age = now - last
                    if age <= timedelta(days=7):
                        status = CompletenessStatus.FRESH
                    elif age <= timedelta(days=30):
                        status = CompletenessStatus.OUTDATED
                    else:
                        status = CompletenessStatus.MISSING
                entries.append(
                    CompletenessEntry(
                        tool_key=tool,
                        tool_label=_LABELS.get(tool, tool),
                        last_scan=last,
                        status=status,
                    )
                )
            return entries
        except (ImportError, OSError, RuntimeError, AttributeError) as exc:
            log.info(
                "Vollstaendigkeit nicht verfuegbar: %s", type(exc).__name__
            )
            return []

    return _load


def _build_mainpage_services():
    """Sprint S4a / 3c — baut das Mainpage-Service-Buendel.

    Nutzt die zentrale Factory ``create_mainpage_services`` (EIN geteiltes
    ``MainpageRepository`` fuer Journal/Tasks/Quickstart), statt die
    Wire-Reihenfolge hier zu duplizieren.

    Returns:
        Tuple ``(TaskService, JournalService, QuickstartService)`` oder
        ``(None, None, None)`` wenn die Initialisierung scheitert (z. B.
        SQLCipher-Probleme). Ein ``None``-Tupel sorgt dafuer, dass die
        abhaengigen Sektionen (Kanban/Notizen/Schnellstart/Aufgaben-Snippet)
        gar nicht erst angelegt werden — der Rest des Dashboards bleibt
        funktional.
    """
    try:
        from tools.mainpage.application.services import (  # noqa: PLC0415
            create_mainpage_services,
        )

        services = create_mainpage_services()
        return services.tasks, services.journal, services.quickstart
    except (ImportError, OSError, RuntimeError, AttributeError) as exc:
        log.info(
            "Mainpage-Services nicht verfuegbar (%s) — "
            "Kanban/Notizen/Schnellstart-Sektionen werden ausgeblendet.",
            type(exc).__name__,
        )
        return None, None, None


def _build_phishing_view_model():
    """ 3c (Cockpit) — baut das Phishing-Radar-ViewModel defensiv.

    Nutzt das ``_safe_dashboard_service``-Muster der Mainpage (defensiver
    Cyber-Dashboard-Service, ``None`` bei Fehler) und reicht es als Datenquelle
    ins ``PhishingRadarViewModel`` (Modus ``"easy"``). Cross-Tool-Imports
    laufen bewusst lazy innerhalb dieser Funktion.

    Returns:
        Ein ``PhishingRadarViewModel`` oder ``None``, wenn schon der Bau
        scheitert — der Banner zeigt dann seinen Placeholder-Zustand.
    """
    try:
        from tools.mainpage.gui.phishing_radar_data import (  # noqa: PLC0415
            PhishingRadarViewModel,
        )

        return PhishingRadarViewModel(
            dashboard_service=_safe_dashboard_service(),
            modus="easy",
        )
    except Exception as exc:  # noqa: BLE001 -- Cockpit darf nie am Phishing-VM scheitern
        log.info(
            "Phishing-Radar-ViewModel nicht verfuegbar: %s", type(exc).__name__
        )
        return None


def _safe_dashboard_service():  # noqa: ANN202
    """Baut den ``DashboardService`` defensiv — ``None`` bei Fehler 3c).

    Spiegelt das gleichnamige Muster aus ``mainpage_widget.py``: liest aus dem
    RSS-Cache die aktuellen Phishing-Warnungen. Wenn das Cyber-Dashboard-Tool
    nicht initialisiert ist (Stripped-Tier o.ae.), bleibt der Banner mit
    Placeholder sichtbar. Cross-Tool-Import lazy.
    """
    try:
        from tools.cyber_dashboard.application.dashboard_service import (  # noqa: PLC0415
            create_default_dashboard_service,
        )

        return create_default_dashboard_service()
    except Exception as exc:  # noqa: BLE001 -- Cross-Tool defensiv
        log.debug(
            "DashboardService fuer Phishing-Radar nicht verfuegbar: %s",
            type(exc).__name__,
        )
        return None


def _percentile(sorted_values: list[float], p: int) -> float:
    """Liefert das p-te Perzentil (0..100) einer **sortierten** Liste.

    Linear-Interpolation zwischen Nachbarn — ausreichend fuer
    UI-Anzeige; wir vermeiden die numpy-Abhaengigkeit fuer einen
    kleinen Wert.
    """
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    k = (len(sorted_values) - 1) * p / 100.0
    lo_idx = int(k)
    hi_idx = min(lo_idx + 1, len(sorted_values) - 1)
    fraction = k - lo_idx
    return sorted_values[lo_idx] + (
        sorted_values[hi_idx] - sorted_values[lo_idx]
    ) * fraction
