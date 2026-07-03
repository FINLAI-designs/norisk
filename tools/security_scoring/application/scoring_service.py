"""
scoring_service — Aggregiert Ergebnisse aller Security-Tools zu einem Score.

Sammelt Daten aus API-Security-, Netzwerk-Scanner-, Dependency-Auditor-,
Zertifikats-Monitor- und Passwort-Checker-Services und berechnet den
gewichteten Gesamt-Security-Score.

Schichtzugehörigkeit: application/ — keine GUI-Imports, kein direktes DB.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from core.herkunft import Herkunft
from core.logger import get_logger
from tools.security_scoring.domain.interfaces import IScoreRepository
from tools.security_scoring.domain.models import ScoreComponent, SecurityScore
from tools.security_scoring.domain.scoring_engine import (
    DEFAULT_WEIGHTS,
    calculate_component_score,
    calculate_overall_score,
    score_to_grade,
)

if TYPE_CHECKING:
    from core.probes.hardening_probe import IHardeningProbe
    from core.security_subject.models import SubjectKind
    from core.security_subject.ports import SubjectStore
    from tools.cert_monitor.domain.models import CertInfo
    from tools.dependency_auditor.domain.models import DependencyAuditResult
    from tools.security_scoring.data.hardening_score_repository import (
        HardeningScoreRepository,
    )
    from tools.security_scoring.domain.hardening_score import HardeningScoreResult
    from tools.system_scanner.domain.entities import ScanResult

log = get_logger(__name__)


def generate_security_report_pdf(
    score: SecurityScore,
    output_path: str,
    verlauf: list[SecurityScore] | None = None,
    include_details: bool = True,
    hardening: HardeningScoreResult | None = None,
) -> None:
    """Standalone-Wrapper um:class:`SecurityReportGenerator`.

    Erlaubt GUIs ohne ScoringService-Instanz (z. B. AssessmentWizard)
    den PDF-Report ueber die application-Schicht zu erzeugen, statt
    direkt aus ``data/`` zu importieren.

    Args:
        score: Berechneter SecurityScore.
        output_path: Zieldateipfad (.pdf).
        verlauf: Optionale Score-Historie.
        include_details: Ob Detail-Seiten pro Komponente eingefuegt werden.
        hardening: Optionales HardeningScoreResult. Default ``None``
            = Legacy-Score (Backwards-Compat fuer AssessmentWizard u. a.).
    """
    from tools.security_scoring.data.report_generator import (  # noqa: PLC0415
        SecurityReportGenerator,
    )

    SecurityReportGenerator().generate(
        score,
        output_path,
        verlauf=verlauf,
        include_details=include_details,
        hardening=hardening,
    )


class ScoringService:
    """Berechnet Security-Scores durch Aggregation aller Tool-Ergebnisse.

    Attributes:
        _repo: Repository für Score-Persistenz.
        _api_sec: Optionaler ScannerService (API Security).
        _network: Optionaler NetworkService (Netzwerk-Scanner).
    """

    def __init__(
        self,
        score_repo: IScoreRepository | None = None,
        api_security_service=None,
        network_service=None,
        cert_monitor_service=None,
        password_checker_service=None,
        org_security_service=None,
        cve_exposure_service=None,
        ki_todo_emitter=None,
        subject_store: SubjectStore | None = None,
    ) -> None:
        """Initialisiert den ScoringService.

        Args:
            score_repo: Repository für Score-Verlauf.
            api_security_service: ScannerService-Instanz oder None.
            network_service: NetworkService-Instanz oder None.
            cert_monitor_service: CertMonitorService-Instanz oder None.
            password_checker_service: PasswordCheckerService-Instanz oder None.
            org_security_service: OrgSecurityService-Instanz oder None.
            cve_exposure_service: CveExposureService-Instanz oder None.
            ki_todo_emitter: Optional ein
:class:`core.storytelling.ki_todo_emitter.KiTodoEmitter`
                fuer die "Was tun?"-Section auf der Mainpage. Wird nach
                Hardening-Score-Compute aufgerufen, damit
                ``HardeningCheck(passed=False)`` als KI-Todo-Karten
                landen. ``None`` (Default) → lazy-instanziiert
                beim ersten Hook-Call. Tests injizieren einen Mock.
            subject_store: Optionaler:class:`SubjectStore` (core-Port)
                zum Aufloesen der ``subject_id`` des eigenen Subjekts.
                ``None`` (Default) → fail-soft, ``subject_id`` bleibt leer.
        """
        self._repo = score_repo
        self._api_sec = api_security_service
        self._network = network_service
        self._cert_monitor = cert_monitor_service
        self._password_checker = password_checker_service
        self._org_security = org_security_service
        self._cve_exposure = cve_exposure_service
        self._ki_todo_emitter = ki_todo_emitter
        # optionaler SubjectStore (core-Port) zum Aufloesen der
        # ``subject_id``. ``None`` (Default) → Scores behalten ``subject_id=''``
        # und der Retention-/Join-Schluessel faellt auf ``target_name`` zurueck.
        self._subject_store = subject_store
        # Perf Stage 1b: Lazy-Singleton statt 3–5 Ad-hoc-Instanziierungen pro
        # Aktion. Jede ``HardeningScoreRepository`` öffnet im ctor eine
        # SQLCipher-Connection und läuft ``executescript(_SCHEMA)`` +
        # ``ensure_column`` + ``CREATE INDEX``. Eine Instanz halten spart pro
        # Score-Render mehrere DB-Öffnungen + die wiederholte Schemaarbeit.
        self._hardening_repo: HardeningScoreRepository | None = None

    def _get_hardening_repo(self) -> HardeningScoreRepository:
        """Liefert die gehaltene ``HardeningScoreRepository`` (lazy, einmalig).

        Der Import bleibt lazy (kein Circular-Import application→data beim
        Modul-Load); nur die *Instanz* wird über Aufrufe hinweg wiederverwendet.
        """
        if self._hardening_repo is None:
            from tools.security_scoring.data.hardening_score_repository import (  # noqa: PLC0415
                HardeningScoreRepository,
            )

            self._hardening_repo = HardeningScoreRepository()
        return self._hardening_repo

    # ------------------------------------------------------------------
    # Score-Berechnung
    # ------------------------------------------------------------------

    def berechne_score(
        self,
        target_name: str,
        audit_result: DependencyAuditResult | None = None,
    ) -> SecurityScore:
        """Berechnet den aktuellen Security-Score.

        Zieht Daten aus den letzten Scans aller verfügbaren Tools.
        Dependency-Ergebnisse werden als optionaler Parameter übergeben.

        Args:
            target_name: Name des Ziels / Kunden.
            audit_result: Optionales letztes Dependency-Audit-Ergebnis.

        Returns:
            Berechneter SecurityScore.
        """
        components: list[ScoreComponent] = []

        components.extend(self._api_security_component())
        components.extend(self._network_component())
        components.extend(self._cert_monitor_component())
        if audit_result is not None:
            components.extend(self._dependency_component(audit_result))
        components.extend(self._password_policy_component())
        components.extend(self._org_security_components())
        components.extend(self._cve_exposure_component())

        overall = calculate_overall_score(components)
        score = SecurityScore(
            id=str(uuid.uuid4()),
            target_name=target_name,
            timestamp=datetime.now(UTC).isoformat(),
            overall_score=round(overall, 1),
            grade=score_to_grade(overall),
            components=components,
            summary=self._build_summary(components, overall),
            subject_id=self._resolve_self_subject_id(target_name),
        )

        if self._repo:
            try:
                self._repo.speichere_score(score)
            except (OSError, RuntimeError) as exc:
                log.warning("Score-Speicherung fehlgeschlagen: %s", type(exc).__name__)

        return score

    def _resolve_self_subject_id(self, target_name: str) -> str:
        """Resolved die ``subject_id`` des eigenen Subjekts (fail-soft).

        Technisches Scoring laeuft ausschliesslich auf dem eigenen System — daher das Singleton ``eigenes``-Subjekt. Ohne SubjectStore
        (Default) oder bei DB-Fehlern bleibt die ``subject_id`` leer; der
        Retention-/Join-Schluessel faellt dann auf ``target_name`` zurueck.

        Args:
            target_name: Anzeigename, falls das eigene Subjekt neu angelegt
                werden muss.

        Returns:
            UUID des eigenen Subjekts oder leerer String (fail-soft).
        """
        if self._subject_store is None:
            return ""
        try:
            return self._subject_store.ensure_self_subject(target_name).subject_id
        except Exception as exc:  # noqa: BLE001 — Subjekt-Aufloesung ist fail-soft
            log.warning("Subjekt-Aufloesung fehlgeschlagen: %s", type(exc).__name__)
            return ""

    @classmethod
    def create_for_audit_snapshot(cls) -> ScoringService:
        """Baut einen ScoringService mit minimalem Sub-Service-Stack ohne Persistenz.

 P2: Konsolidiert das Wiring, das vorher in
        ``briefing_factory.py:_try_build_scoring_service`` und
        ``security_scoring/tool.py`` doppelt vorhanden war. Aufrufer fuer
        ad-hoc Snapshots (z. B. Briefing-Audit-Trail) brauchen keine
        Score-Persistenz und keinen target_name — daher ``score_repo=None``.

        Wirft Exceptions weiter — der Aufrufer entscheidet, ob er sie
        schluckt (z. B. fail-safe Wiring) oder durchreicht. Cross-Tool-
        Imports laufen lazy: jede Komponente kann fehlen, ohne das gesamte
        Wiring zu brechen.

        Returns:
            Voll-konfigurierter:class:`ScoringService` ohne ``score_repo``.

        Raises:
            ImportError: Wenn Sub-Service-Module nicht importierbar sind.
            RuntimeError: Wenn ein Sub-Service-Init scheitert (z. B. DB).
        """
        from tools.api_security.application.scanner_service import (  # noqa: PLC0415
            ScannerService as ApiScannerService,
        )
        from tools.api_security.data.http_scanner import HttpScanner  # noqa: PLC0415
        from tools.api_security.data.report_adapter import (
            ReportAdapter,  # noqa: PLC0415
        )
        from tools.api_security.data.scan_repository import (  # noqa: PLC0415
            ScanRepository as ApiScanRepository,
        )
        from tools.network_scanner.application.network_service import (  # noqa: PLC0415
            NetworkService,
        )
        from tools.network_scanner.data.nmap_scanner import NmapScanner  # noqa: PLC0415
        from tools.network_scanner.data.scan_repository import (  # noqa: PLC0415
            ScanRepository as NetworkScanRepository,
        )
        from tools.network_scanner.data.socket_scanner import (
            SocketScanner,  # noqa: PLC0415
        )
        from tools.security_scoring.application.cve_exposure_service import (  # noqa: PLC0415
            CveExposureService,
        )
        from tools.security_scoring.application.org_security_service import (  # noqa: PLC0415
            OrgSecurityService,
        )
        from tools.security_scoring.data.org_assessment_repository import (  # noqa: PLC0415
            OrgAssessmentRepository,
        )

        return cls(
            score_repo=None,  # Snapshot pollutiert sonst Score-History
            api_security_service=ApiScannerService(
                scanner=HttpScanner(verify_ssl=True),
                reporter=ReportAdapter(),
                scan_repo=ApiScanRepository(),
            ),
            network_service=NetworkService(
                scanner=SocketScanner(),
                repo=NetworkScanRepository(),
                nmap_scanner=NmapScanner(),
            ),
            org_security_service=OrgSecurityService(
                repository=OrgAssessmentRepository()
            ),
            cve_exposure_service=CveExposureService(),
        )

    def aktueller_overall_score(self) -> int | None:
        """Berechnet den Overall-Score ohne Persistenz fuer Audit-Snapshots.

        Im Unterschied zu:meth:`berechne_score` wird hier weder ein
        target_name benoetigt noch der Score ins Repository persistiert.
        Gedacht fuer ad-hoc Snapshots (z. B. Briefing-Audit-Trail).
        Die Dependency-Komponente entfaellt mangels ``audit_result`` —
        Coverage-Cap behandelt das automatisch.

        Returns:
            Gerundeter Overall-Score (0..100) oder ``None`` wenn keine
            aktiven Komponenten verfuegbar.
        """
        components: list[ScoreComponent] = []
        components.extend(self._api_security_component())
        components.extend(self._network_component())
        components.extend(self._cert_monitor_component())
        components.extend(self._password_policy_component())
        components.extend(self._org_security_components())
        components.extend(self._cve_exposure_component())
        if not components:
            return None
        return int(round(calculate_overall_score(components)))

    def compute_hardening_score(
        self,
        scan_result: ScanResult | None = None,
        *,
        target_name: str | None = None,
    ) -> HardeningScoreResult:
        """Berechnet den Hardening-Score Phase 3.4).

        Verbindet die 7-Tool-ScoreComponents aus
:meth:`aktueller_overall_score` mit dem optionalen
:class:`ScanResult` aus dem:class:`WindowsHardeningScanner`
        (Phase 3.3) und ruft die domain-Pipeline
:func:`hardening_score.compute_hardening_score` auf.

        Pipeline:

        1. ScoreComponents der 7 Tools sammeln (api/network/cert/
           password/org/cve_exposure — wie ``aktueller_overall_score``).
        2. Falls ``scan_result`` vorhanden + ``hardening_checks`` nicht
           leer: ``build_system_scanner_component`` aggregiert die
           Checks zu einer ``ScoreComponent`` mit
           ``source_tool="system_scanner"`` (Kategorie E).
        3. Domain-Pipeline ``compute_hardening_score(components,
           scan_result=scan_result)`` berechnet Bundle / Redistribute /
           Hard-Caps / Stage.

        Args:
            scan_result: Optionales:class:`ScanResult` mit
                ``hardening_checks`` aus dem
:class:`WindowsHardeningScanner`. Aktiviert Kategorie E
                + Caps 3+4. ``None`` → Kategorie E ist ``missing``,
                Caps 3+4 inaktiv.
            target_name: Optionaler Ziel-Identifier. Ist er gesetzt, wird
                das Ergebnis fail-soft in der Hardening-History
                persistiert (Voraussetzung fuer Trend + Verlauf).
                ``None`` (Default) → keine Persistenz (z. B. Audit-
                Snapshot-Pfad, Dashboard-Live-Compute).

        Returns:
:class:`HardeningScoreResult` mit gecapptem Score, Stage,
            Per-Category-Breakdown und Hard-Cap-Events.
        """
        # Lazy-Imports — schliessen den circular-Import-Pfad
        # (scoring_service ↔ hardening_score) und vermeiden
        # unnoetige Module-Lade-Kosten in Tests, die nur
        # aktueller_overall_score brauchen.
        from tools.security_scoring.domain.hardening_aggregation import (  # noqa: PLC0415
            build_system_scanner_component,
        )
        from tools.security_scoring.domain.hardening_score import (  # noqa: PLC0415
            compute_hardening_score as _compute,
        )

        components: list[ScoreComponent] = []
        components.extend(self._api_security_component())
        components.extend(self._network_component())
        components.extend(self._cert_monitor_component())
        components.extend(self._password_policy_component())
        components.extend(self._org_security_components())
        components.extend(self._cve_exposure_component())

        # System-Scanner-Component aus Hardening-Checks
        if scan_result is not None and scan_result.hardening_checks:
            sys_comp = build_system_scanner_component(scan_result.hardening_checks)
            if sys_comp is not None:
                components.append(sys_comp)

        result = _compute(components, scan_result=scan_result)

        # Hardening-Checks an die KI-Todo-Engine reichen, damit
        # die "Was tun?"-Section auf der Mainpage echte Befunde (statt
        # Evergreens aus) anzeigt. Hook ist fail-soft — die Score-
        # Berechnung darf nie durch einen KI-Todo-Fehler crashen.
        if scan_result is not None and scan_result.hardening_checks:
            self._emit_hardening_findings(scan_result.hardening_checks)

        if target_name is not None:
            self._persistiere_hardening_score(
                target_name, result, self._resolve_self_subject_id(target_name)
            )

        return result

    def berechne_und_persistiere_baseline(
        self,
        target_name: str,
        *,
        probe: IHardeningProbe | None = None,
    ) -> HardeningScoreResult:
        """Erhebt einen frischen Hardening-Scan und persistiert den Score C0b).

        Headless + Qt-frei. Schliesst die Luecke, dass der frische
        Category-E-Hardening-Scan
        (:meth:`tools.system_scanner.application.windows_hardening_scanner.WindowsHardeningScanner.scan_all`)
        bisher nur ueber den GUI-Button lief — produktiv wurde
:meth:`compute_hardening_score` nur mit ``scan_result=None`` (ohne
        Kategorie E) aufgerufen. Verdrahtet die Pipeline::

            run_hardening_baseline_scan -> ScanResult(hardening_checks=…)
            -> compute_hardening_score(scan_result=…, target_name=…)

        Damit entsteht ein VOLLSTAENDIGER, persistierter Hardening-Score
        (Pflichtfeld des Fleet-Collectors), den
:meth:`lade_letztes_hardening_result` bzw. der
        ``SecurityScoringProvider`` headless lesen koennen.

        Non-Windows: liefert ``run_hardening_baseline_scan`` ``None`` (Probe
        nicht verfuegbar) → der Score wird wie bisher ohne Kategorie E
        berechnet (sicherheitsneutraler Default, keine fehlerhaften
        Probe-Fehler-Checks).

        Frische-Grenze C0b vs. C1): die uebrigen sechs
        Tool-Komponenten fliessen weiterhin nur mit ihrem zuletzt
        persistierten Stand ein — bzw. leer, wenn dieser ``ScoringService``
        ohne Sub-Services konstruiert wurde. Das Sequenzieren ALLER
        Tool-Scans VOR dem Compute ist Sache des Fleet-Scan-Runners (C1);
        hier wird ausschliesslich Kategorie E frisch erhoben.

        Args:
            target_name: Stabiler Ziel-Identifier des eigenen Systems
                (Retention-/Trend-Schluessel + Subjekt-Mapping). Konvention:
                der Name des eigenen ``SystemProfile`` (Default
                ``"Mein System"`` — METADATEN-ONLY, kein Hostname); dieselbe
                Konvention nutzt das Scoring-Dashboard.
            probe: Optionaler:class:`IHardeningProbe`. ``None`` (Default) →
                Production-:class:`WindowsHardeningProbe`. Tests injizieren
                einen:class:`MockHardeningProbe`.

        Returns:
            Das berechnete und (fail-soft) persistierte
:class:`HardeningScoreResult`.
        """
        from tools.system_scanner.application.windows_hardening_scanner import (  # noqa: PLC0415
            run_hardening_baseline_scan,
        )

        scan_result = run_hardening_baseline_scan(probe)
        return self.compute_hardening_score(
            scan_result=scan_result, target_name=target_name
        )

    def _emit_hardening_findings(self, checks) -> None:  # noqa: ANN001
        """Konvertiert fehlgeschlagene Hardening-Checks zu KI-Todo-
        Findings und emittiert sie ueber den ``KiTodoEmitter``.

        Lazy-Init des Emitters: wir bauen erst beim ersten Hook-Call,
        damit ScoringService-Tests die nicht brauchen ohne zusaetzliches
        Setup laufen.
        """
        try:
            from tools.system_scanner.application.storytelling_adapter import (  # noqa: PLC0415
                hardening_checks_to_findings,
            )

            findings = hardening_checks_to_findings(checks)
            if not findings:
                return
            emitter = self._ki_todo_emitter
            if emitter is None:
                from core.storytelling.ki_todo_emitter import (  # noqa: PLC0415
                    KiTodoEmitter,
                )

                emitter = KiTodoEmitter()
                self._ki_todo_emitter = emitter
            emitter.emit(findings)
        except Exception as exc:  # noqa: BLE001 — Hook darf den Score nicht brechen
            log.warning(
                "ScoringService.compute_hardening_score: KI-Todo-Hook "
                "fehlgeschlagen (%s) — %d checks verworfen.",
                type(exc).__name__,
                len(checks) if checks else 0,
            )

    def _persistiere_hardening_score(
        self, target_name: str, result: HardeningScoreResult, subject_id: str = ""
    ) -> None:
        """Speichert das Hardening-Ergebnis fail-soft in der History.

        Die Persistenz ist Voraussetzung fuer Trend-Pfeil und
        Verlauf — vor wurde nie ein Hardening-Score gespeichert
        (``save_score`` hatte keinen Produktiv-Aufrufer). Schlaegt das
        Speichern fehl, bleibt die Score-Berechnung gueltig (fail-soft,
        analog ``berechne_score``).

        Args:
            target_name: Identifier des gescannten Systems (Trend-Achse).
            result: Das zu persistierende Hardening-Ergebnis.
            subject_id: UUID des eigenen Subjekts — wird zum
                Retention-/Join-Schluessel. Leer = Fallback auf
                ``target_name``.
        """
        # Fail-closed Provenance-Gate P0-B): eine GEMESSENE Messung darf
        # keinem KUNDEN zugeordnet werden. Bewusst VOR dem fail-soft try
        # (ScoringModeViolationError ist ein RuntimeError und wuerde dort
        # geschluckt). Nur relevant, wenn ein konkretes Subjekt bekannt ist —
        # der SELF-Pfad ohne SubjectStore hat subject_id="".
        if result.herkunft is Herkunft.GEMESSEN and subject_id:
            from tools.security_scoring.domain.mode_gate import (  # noqa: PLC0415
                assert_messung_nur_self,
            )

            assert_messung_nur_self(result.herkunft, self._subject_kind(subject_id))
        try:
            self._get_hardening_repo().save_score(
                target_name, result, subject_id=subject_id
            )
        except (OSError, RuntimeError) as exc:
            log.warning(
                "Hardening-Score-Speicherung fehlgeschlagen: %s",
                type(exc).__name__,
            )

    def _subject_kind(self, subject_id: str) -> SubjectKind | None:
        """Ermittelt fail-soft den ``SubjectKind`` eines ``subject_id``.

        Returns:
            Den ``SubjectKind`` oder ``None`` (kein SubjectStore, leeres
            ``subject_id``, unbekannt oder Lookup-Fehler).
        """
        if not subject_id or self._subject_store is None:
            return None
        try:
            subj = self._subject_store.get(subject_id)
        except Exception:  # noqa: BLE001 — Lookup ist fail-soft (Gate-Backstop)
            return None
        return subj.kind if subj is not None else None

    def previous_hardening_score(self, target_name: str) -> float | None:
        """Liefert den ``overall_score`` des vorletzten Hardening-Snapshots.

 Phase 4.5: GUI-Trend-Indikator nutzt das fuer die Delta-
        Anzeige. Schicht-Vertrag: gui/ darf data/ nicht direkt
        importieren — diese Service-Methode kapselt den Repository-
        Zugriff.

        Args:
            target_name: Score-Ziel-Name (z. B. eigener System-Name).

        Returns:
            ``overall_score`` des vorletzten Snapshots oder ``None`` wenn
            keine zwei Snapshots fuer das Target vorhanden sind.
        """
        try:
            repo = self._get_hardening_repo()
            history = repo.load_history(target_name, limit=2)
            if len(history) < 2:
                return None
            # load_history liefert (timestamp, overall_score)-Tupel,
            # neueste zuerst: [0] = juengster, [1] = der davor.
            return float(history[1][1])
        except Exception:  # noqa: BLE001 — Trend-Lookup ist optional
            return None

    def lade_hardening_verlauf(
        self, target_name: str, limit: int = 10
    ) -> list[tuple[str, float]]:
        """Laedt den Hardening-Score-Verlauf (neueste zuerst).

        Kapselt den Repository-Zugriff fuer die GUI (Schicht-
        Vertrag: gui/ darf data/ nicht direkt importieren). Liefert
        ``(timestamp, overall_score)``-Tupel — vorwaerts-only ab
        Einfuehrung der Hardening-Persistenz, alte Legacy-Verlaufswerte
        fließen bewusst nicht ein.

        Args:
            target_name: Score-Ziel-Name.
            limit: Maximale Anzahl Eintraege.

        Returns:
            Liste ``(timestamp, overall_score)`` neueste zuerst; leer bei
            fehlender History oder Lade-Fehler (fail-soft).
        """
        try:
            return self._get_hardening_repo().load_history(target_name, limit=limit)
        except (OSError, RuntimeError) as exc:
            log.warning("Hardening-Verlauf nicht ladbar: %s", type(exc).__name__)
            return []

    def lade_letztes_hardening_result(
        self, target_name: str | None = None
    ) -> HardeningScoreResult | None:
        """Laedt den zuletzt persistierten Hardening-Score.

        Kapselt den Repository-Read fuer Konsumenten ausserhalb des
        Scoring-Tools (Schicht-Vertrag: andere Tools/GUI greifen ueber die
        application-Schicht zu, nicht direkt auf ``data/``). Das
        ``norisk_dashboard`` nutzt das, um den im Tab zuletzt berechneten
        Score anzuzeigen, ohne pro ``aggregate`` einen vollen Live-Compute
        (Sub-Service-Stack) auf dem GUI-Thread aufzubauen.

        Args:
            target_name: Optionaler Ziel-Filter. ``None`` (Default) liefert
                den global juengsten Eintrag (in der Praxis ein eigenes
                System, ein stabiler ``target_name``).

        Returns:
            Das rehydrierte:class:`HardeningScoreResult` oder ``None`` wenn
            kein Eintrag existiert oder der Read/das Rehydrate fehlschlaegt
            (fail-soft — ``ValueError``/``KeyError`` decken korruptes oder
            schema-driftendes ``data_json`` ab).
        """
        try:
            return self._get_hardening_repo().load_latest_result(target_name)
        except (OSError, RuntimeError, ValueError, KeyError) as exc:
            log.warning("Letzter Hardening-Score nicht ladbar: %s", type(exc).__name__)
            return None

    def lade_letztes_gemessenes_hardening_result(self) -> HardeningScoreResult | None:
        """Juengster GEMESSENER Hardening-Score P0-A).

        Kapselt ``HardeningScoreRepository.load_latest_measured_result`` fuer
        Konsumenten ausserhalb des Scoring-Tools (Schicht-Vertrag: andere Tools
        greifen ueber die application-Schicht zu). Das ``norisk_dashboard`` nutzt
        das fuer die SELF-Kachel „Messung (Hardening)", damit ein manuell fuer
        einen Kunden erfasster Eintrag (Herkunft ``erfasst``) die Eigen-System-
        Kachel nie verfaelscht: ohne Filter wuerde ein Kunden-Eintrag mit neuerem
        Timestamp den global juengsten Eintrag stellen.

        Returns:
            Das rehydrierte:class:`HardeningScoreResult` oder ``None`` (fail-soft).
        """
        try:
            return self._get_hardening_repo().load_latest_measured_result()
        except (OSError, RuntimeError, ValueError, KeyError) as exc:
            log.warning(
                "Letzter gemessener Hardening-Score nicht ladbar: %s",
                type(exc).__name__,
            )
            return None

    def lade_letztes_hardening_result_by_subject(
        self, subject_id: str
    ) -> HardeningScoreResult | None:
        """Juengster Hardening-Score eines Subjekts Phase A, fail-soft)."""
        try:
            return self._get_hardening_repo().load_latest_result_by_subject(
                subject_id
            )
        except (OSError, RuntimeError, ValueError, KeyError) as exc:
            log.warning(
                "Hardening-Score (Subjekt) nicht ladbar: %s", type(exc).__name__
            )
            return None

    def lade_hardening_verlauf_by_subject(
        self, subject_id: str, limit: int = 10
    ) -> list[tuple[str, float]]:
        """Hardening-Verlauf eines Subjekts (neueste zuerst, fail-soft)."""
        try:
            return self._get_hardening_repo().load_history_by_subject(
                subject_id, limit=limit
            )
        except (OSError, RuntimeError) as exc:
            log.warning(
                "Hardening-Verlauf (Subjekt) nicht ladbar: %s", type(exc).__name__
            )
            return []

    def previous_hardening_score_by_subject(self, subject_id: str) -> float | None:
        """``overall_score`` des vorletzten Snapshots eines Subjekts (Trend)."""
        try:
            zwei = self._get_hardening_repo().get_last_two_scores_by_subject(
                subject_id
            )
            return zwei[0] if zwei is not None else None
        except Exception:  # noqa: BLE001 — Trend-Lookup ist optional
            return None

    def lade_verlauf_by_subject(
        self, subject_id: str, limit: int = 10
    ) -> list[SecurityScore]:
        """Legacy-Score-Verlauf eines Subjekts (fail-soft, leer ohne Repo)."""
        if not self._repo:
            return []
        try:
            return self._repo.lade_letzte_scores_by_subject(subject_id, limit)
        except (OSError, RuntimeError, AttributeError) as exc:
            log.warning(
                "Score-Verlauf (Subjekt) nicht ladbar: %s", type(exc).__name__
            )
            return []

    def erfasse_kunden_hardening(
        self, subject_id: str, facts: dict[str, bool | None]
    ) -> HardeningScoreResult:
        """Erfasst manuell Hardening-Fakten für einen KUNDEN E2/Phase B).

        Eine Kundenmaschine ist nicht fern-messbar -> KEIN Live-Scan. Die
        eingetragenen Fakten ergeben einen Hardening-Score mit Provenance
        ``ERFASST`` (nie ``GEMESSEN``), subjekt-keyed persistiert. ``target_name``
        ist die ``subject_id`` (UUID) — nie der Firmenname (PII F-4).

        Fail-closed: das Ziel-Subjekt MUSS ein auflösbarer ``KUNDE`` sein (ohne
        SubjectStore / unbekanntes / eigenes Subjekt -> Abbruch). Das eigene
        System wird gemessen (``berechne_und_persistiere_baseline``), nicht erfasst.

        Args:
            subject_id: UUID des Kunden-Subjekts.
            facts: Mapping bekannter Hardening-Fakten -> ``True``/``False``/
                ``None`` (:data:`tools.security_scoring.application.kunden_hardening.KUNDEN_HARDENING_FACTS`).

        Returns:
            Das persistierte:class:`HardeningScoreResult` (Provenance ERFASST).

        Raises:
            ScoringModeViolationError: Wenn das Subjekt kein auflösbarer KUNDE ist.
        """
        from core.security_subject.models import SubjectKind  # noqa: PLC0415
        from tools.security_scoring.application.kunden_hardening import (  # noqa: PLC0415
            facts_to_components,
        )
        from tools.security_scoring.domain.hardening_score import (  # noqa: PLC0415
            compute_hardening_score as _compute,
        )
        from tools.security_scoring.domain.mode_gate import (  # noqa: PLC0415
            ScoringModeViolationError,
        )

        if self._subject_kind(subject_id) is not SubjectKind.KUNDE:
            raise ScoringModeViolationError(
                "Manuelle Hardening-Erfassung ist nur für Kunden-Subjekte "
                "vorgesehen (das eigene System wird gemessen, nicht erfasst)."
            )
        components = facts_to_components(facts)
        result = _compute(components, herkunft=Herkunft.ERFASST)
        self._persistiere_hardening_score(subject_id, result, subject_id=subject_id)
        return result

    def generate_pdf_report(
        self,
        score: SecurityScore,
        output_path: str,
        verlauf: list[SecurityScore] | None = None,
        include_details: bool = True,
        hardening: HardeningScoreResult | None = None,
        compliance_rows: list | None = None,
    ) -> None:
        """Schreibt einen PDF-Security-Report (Service-Wrapper).

        Kapselt:class:`SecurityReportGenerator`, damit die GUI den
        Generator nicht direkt aus ``data/`` importieren muss.

        Args:
            score: Berechneter SecurityScore.
            output_path: Zieldateipfad (.pdf).
            verlauf: Optionale Score-Historie.
            include_details: Ob Detail-Seiten pro Komponente eingefuegt werden.
            hardening: Optionales HardeningScoreResult — fuer die
                Executive-Summary durchgereicht. ``None`` → Legacy-Score.
            compliance_rows: Optionale ``ComplianceRow``-Liste W3). Ist
                sie gesetzt, haengt der Report eine indikative Regulatorik-Sektion
                an. Die Konvertierung in die primitive Tabelle passiert HIER
                (application), damit die data-Schicht keine application importiert.

        Raises:
            OSError: Wenn die Ausgabedatei nicht geschrieben werden kann.
        """
        from tools.security_scoring.data.report_generator import (  # noqa: PLC0415
            SecurityReportGenerator,
        )

        compliance_table = None
        compliance_disclaimer = ""
        if compliance_rows:
            from core.compliance.regulatory_mapping import (  # noqa: PLC0415
                REGULATORY_DISCLAIMER,
            )
            from tools.system_scanner.application.compliance_report_service import (  # noqa: PLC0415
                compliance_rows_to_table,
            )

            compliance_table = compliance_rows_to_table(compliance_rows)
            compliance_disclaimer = (
                f"Anwaltliche Pruefung ausstehend. {REGULATORY_DISCLAIMER}"
            )

        SecurityReportGenerator().generate(
            score,
            output_path,
            verlauf=verlauf,
            include_details=include_details,
            hardening=hardening,
            compliance_table=compliance_table,
            compliance_disclaimer=compliance_disclaimer,
        )

    def lade_verlauf(
        self,
        target_name: str,
        limit: int = 10,
    ) -> list[SecurityScore]:
        """Lädt den Score-Verlauf für ein Ziel.

        Args:
            target_name: Name des Ziels.
            limit: Maximale Anzahl.

        Returns:
            Scores, neueste zuerst. Leer wenn kein Repository.
        """
        if not self._repo:
            return []
        try:
            return self._repo.lade_letzte_scores(target_name, limit)
        except (OSError, RuntimeError) as exc:
            log.warning("Verlauf-Laden fehlgeschlagen: %s", type(exc).__name__)
            return []

    def lade_bekannte_targets(self) -> list[str]:
        """Gibt alle bekannten Target-Namen aus dem Repository zurück.

        Returns:
            Alphabetisch sortierte Liste. Leer wenn kein Repository.
        """
        if not self._repo:
            return []
        try:
            return self._repo.lade_bekannte_targets()
        except (OSError, RuntimeError) as exc:
            log.warning("Target-Liste fehlgeschlagen: %s", type(exc).__name__)
            return []

    def loesche_target(self, target_name: str) -> int:
        """Löscht alle Scores eines Targets aus dem Repository.

        Args:
            target_name: Name des zu löschenden Ziels.

        Returns:
            Anzahl gelöschter Score-Einträge. 0 wenn kein Repository.
        """
        if not self._repo:
            return 0
        try:
            return self._repo.loesche_target(target_name)  # type: ignore[attr-defined]
        except (OSError, RuntimeError) as exc:
            log.warning("Target-Löschung fehlgeschlagen: %s", type(exc).__name__)
            return 0

    # ------------------------------------------------------------------
    # Interne Komponenten-Extraktion
    # ------------------------------------------------------------------

    def _api_security_component(self) -> list[ScoreComponent]:
        """Extrahiert API-Security-Komponente aus dem letzten Scan-Lauf."""
        if not self._api_sec:
            return []
        try:
            verlauf = self._api_sec.lade_verlauf(limit=1)
            if not verlauf:
                return []
            lauf = verlauf[0]
            sev = lauf.severity_summary
            crit = sev.get("critical", 0)
            high = sev.get("high", 0)
            med = sev.get("medium", 0)
            low = sev.get("low", 0)
            return [
                ScoreComponent(
                    name="API Security",
                    score=calculate_component_score(crit, high, med, low),
                    weight=DEFAULT_WEIGHTS["api_security"],
                    findings_critical=crit,
                    findings_high=high,
                    findings_medium=med,
                    last_scan=lauf.scan_start,
                    source_tool="api_security",
                )
            ]
        except Exception as exc:  # noqa: BLE001 -- Aggregator: Sub-Service-Defekt darf Score nicht crashen
            log.warning("API-Security-Daten nicht verfügbar: %s", type(exc).__name__)
            return []

    def _network_component(self) -> list[ScoreComponent]:
        """Extrahiert Netzwerk-Komponente aus dem letzten Scan-Ergebnis."""
        if not self._network:
            return []
        try:
            scans = self._network.lade_letzte_scans(limit=1)
            if not scans:
                return []
            from tools.network_scanner.domain.models import PortRisk

            scan = scans[0]
            crit = sum(
                1
                for h in scan.hosts
                for p in h.offene_ports
                if p.risk == PortRisk.KRITISCH
            )
            high = sum(
                1 for h in scan.hosts for p in h.offene_ports if p.risk == PortRisk.HOCH
            )
            med = sum(
                1
                for h in scan.hosts
                for p in h.offene_ports
                if p.risk == PortRisk.MITTEL
            )
            return [
                ScoreComponent(
                    name="Netzwerk",
                    score=calculate_component_score(crit, high, med),
                    weight=DEFAULT_WEIGHTS["network_scanner"],
                    findings_critical=crit,
                    findings_high=high,
                    findings_medium=med,
                    last_scan=scan.gestartet_am.isoformat()
                    if hasattr(scan.gestartet_am, "isoformat")
                    else str(scan.gestartet_am),
                    source_tool="network_scanner",
                )
            ]
        except Exception as exc:  # noqa: BLE001 -- Aggregator: Sub-Service-Defekt darf Score nicht crashen
            log.warning("Netzwerk-Daten nicht verfügbar: %s", type(exc).__name__)
            return []

    def _dependency_component(
        self,
        result: DependencyAuditResult,
    ) -> list[ScoreComponent]:
        """Extrahiert Dependency-Komponente aus einem Audit-Ergebnis.

        Args:
            result: Abgeschlossenes DependencyAuditResult.

        Returns:
            Liste mit genau einer ScoreComponent.
        """
        crit = result.critical_count()
        high = result.high_count()
        med = result.medium_count()
        low = result.low_count()
        return [
            ScoreComponent(
                name="Dependencies",
                score=calculate_component_score(crit, high, med, low),
                weight=DEFAULT_WEIGHTS["dependency_auditor"],
                findings_critical=crit,
                findings_high=high,
                findings_medium=med,
                last_scan=result.scan_timestamp,
                source_tool="dependency_auditor",
            )
        ]

    def _cert_monitor_component(self) -> list[ScoreComponent]:
        """Extrahiert Zertifikats-Komponente aus den letzten Scan-Ergebnissen."""
        if not self._cert_monitor:
            return []
        try:
            from tools.cert_monitor.domain.models import CertStatus

            ergebnisse: list[CertInfo] = self._cert_monitor.lade_letzte_ergebnisse()
            if not ergebnisse:
                return []
            crit = sum(1 for c in ergebnisse if c.status == CertStatus.KRITISCH)
            high = sum(1 for c in ergebnisse if c.status == CertStatus.WARNUNG)
            letzte_pruefung = max(
                (c.letzte_pruefung for c in ergebnisse if c.letzte_pruefung),
                default="",
            )
            return [
                ScoreComponent(
                    name="Zertifikate (TLS)",
                    score=calculate_component_score(crit, high, 0),
                    weight=DEFAULT_WEIGHTS["cert_monitor"],
                    findings_critical=crit,
                    findings_high=high,
                    findings_medium=0,
                    last_scan=letzte_pruefung,
                    source_tool="cert_monitor",
                )
            ]
        except Exception as exc:  # noqa: BLE001 -- Aggregator: Sub-Service-Defekt darf Score nicht crashen
            log.warning("Cert-Monitor-Daten nicht verfügbar: %s", type(exc).__name__)
            return []

    def _password_policy_component(self) -> list[ScoreComponent]:
        """Liest den letzten Passwort-Policy-Check und wandelt ihn in eine ScoreComponent.

        Erfordert einen injizierten password_checker_service. Gibt leer zurück
        wenn kein Service konfiguriert ist.

        Returns:
            Liste mit genau einer ScoreComponent (oder leer wenn kein Service).
        """
        if not self._password_checker:
            return []
        try:
            result = self._password_checker.letztes_ergebnis()
            if result is None:
                return []
            score = result.get("score", 100.0)
            crit = result.get("findings_critical", 0)
            high = result.get("findings_high", 0)
            med = result.get("findings_medium", 0)
            return [
                ScoreComponent(
                    name="Passwort-Policy",
                    score=float(score),
                    weight=DEFAULT_WEIGHTS["password_policy"],
                    findings_critical=crit,
                    findings_high=high,
                    findings_medium=med,
                    source_tool="password_policy",
                )
            ]
        except Exception as exc:  # noqa: BLE001 -- Aggregator: Sub-Service-Defekt darf Score nicht crashen
            log.warning("Passwort-Policy-Daten nicht verfügbar: %s", type(exc).__name__)
            return []

    def _org_security_components(self) -> list[ScoreComponent]:
        """Lädt das letzte Org-Assessment und erzeugt daraus ScoreComponents."""
        if not self._org_security:
            return []
        try:
            assessment = self._org_security.lade_letztes()
            return self._org_security.baue_komponenten(assessment)
        except Exception as exc:  # noqa: BLE001 -- Aggregator: Sub-Service-Defekt darf Score nicht crashen
            log.warning("Org-Security-Daten nicht verfügbar: %s", type(exc).__name__)
            return []

    def _cve_exposure_component(self) -> list[ScoreComponent]:
        """Baut die CVE-Exposure-Komponente aus dem aggregierten Signal.

        Liefert eine ScoreComponent mit ``data_available=False`` wenn
        weder Techstack-CVEs noch Advisory-Matches gecached sind — das
        Widget rendert dann einen grauen No-Data-Balken und der Gesamtscore
        ignoriert die Komponente.

        Returns:
            Liste mit genau einer ScoreComponent oder leer wenn kein Service.
        """
        if not self._cve_exposure:
            return []
        try:
            data = self._cve_exposure.get_current_exposure()
        except Exception as exc:  # noqa: BLE001 -- Aggregator: Sub-Service-Defekt darf Score nicht crashen
            log.warning("CVE-Exposure-Daten nicht verfügbar: %s", type(exc).__name__)
            return []

        if data.score is None:
            return [
                ScoreComponent(
                    name="CVE-Exposition",
                    score=0.0,
                    weight=DEFAULT_WEIGHTS["cve_exposure"],
                    last_scan="",
                    source_tool="cve_exposure",
                    data_available=False,
                    details="Techstack-Scan erforderlich",
                )
            ]
        return [
            ScoreComponent(
                name="CVE-Exposition",
                score=float(data.score),
                weight=DEFAULT_WEIGHTS["cve_exposure"],
                findings_critical=data.critical_count,
                findings_high=data.high_count,
                findings_medium=data.medium_count,
                last_scan=data.last_updated,
                source_tool="cve_exposure",
                data_available=True,
                details=(
                    f"{data.total_cves} CVEs · {data.kev_count} KEV · "
                    f"{data.affected_advisories} Advisories"
                ),
            )
        ]

    @staticmethod
    def _build_summary(components: list[ScoreComponent], overall: float) -> str:
        """Erstellt eine Kurzbeschreibung des Scores.

        Args:
            components: Berechnete Komponenten.
            overall: Gesamtscore.

        Returns:
            Einzeiliger Beschreibungstext.
        """
        if not components:
            return "Kein Scan-Ergebnis verfügbar."
        total_crit = sum(c.findings_critical for c in components)
        total_high = sum(c.findings_high for c in components)
        basis = f"Dein System erfüllt {overall:.0f}% der geprüften Kriterien."
        finding_parts = []
        if total_crit:
            finding_parts.append(f"{total_crit} Finding(s) mit CVSS-Stufe Critical")
        if total_high:
            finding_parts.append(f"{total_high} mit Stufe High")
        if not finding_parts:
            return basis + " Keine Findings auf Stufe Critical oder High."
        return basis + " Dokumentiert: " + ", ".join(finding_parts) + "."
