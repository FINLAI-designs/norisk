"""
audit_service — Anwendungsservice fuer den Dependency-Auditor.

Orchestriert: Requirements parsen → Advisory-DB abfragen → Ergebnis.
Keine Netzwerk-Calls direkt, keine GUI-Abhaengigkeiten.

Sicherheitsdesign (STRIDE):
    Tampering: Dateipfad wird im Parser mit validate_file_path
                    geprueft (Path-Traversal-Schutz).
    Repudiation: Audit-Start und -Ende werden im AuditLog protokolliert.
    Info Discl.: Nur Package-Namen werden geloggt, keine Versions-Details
                    mit potenziellem CVE-Kontext (koennten Fingerprinting ermoeglichen).
    DoS: progress_callback erlaubt Abbruch aus der GUI;
                    OSV-Rate-Limiting via zentralem HTTP-Client.

Schichtzugehoerigkeit: application/ — kein GUI-Import, kein direktes HTTP.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from core.audit_log import AuditLogger
from core.logger import get_logger
from tools.dependency_auditor.data.installed_versions import resolve_installed_versions
from tools.dependency_auditor.data.requirements_parser import parse_requirements
from tools.dependency_auditor.domain.analyzer import analyze_dependencies
from tools.dependency_auditor.domain.interfaces import IAdvisorySource, IAuditRepository
from tools.dependency_auditor.domain.models import (
    DependencyAuditResult,
    DependencyInfo,
)

_log = get_logger(__name__)
_audit = AuditLogger()

ProgressCallback = Callable[[int, int, str], None]
"""Typ fuer Fortschritts-Callbacks: (aktuell, gesamt, package_name)."""


class AuditService:
    """Orchestriert vollstaendige Dependency-Audits.

    Attributes:
        _advisory: Implementierung von IAdvisorySource (OSV-Client).
        _repo: Optionales Audit-Repository fuer Verlauf-Persistenz.
    """

    def __init__(
        self,
        advisory_source: IAdvisorySource,
        audit_repo: IAuditRepository | None = None,
        ki_todo_emitter: object | None = None,
    ) -> None:
        """Initialisiert den Service.

        Args:
            advisory_source: Konkreter Advisory-Client (data-Schicht).
            audit_repo: Optionales Repository; wenn None werden
                             Ergebnisse nicht persistiert.
            ki_todo_emitter: Optionaler ``KiTodoEmitter``. Default
                wird lazy gebaut.
        """
        self._advisory = advisory_source
        self._repo = audit_repo
        if ki_todo_emitter is None:
            from core.storytelling.ki_todo_emitter import KiTodoEmitter  # noqa: PLC0415
            ki_todo_emitter = KiTodoEmitter()
        self._ki_todo_emitter = ki_todo_emitter

    def lade_letztes_ergebnis(self) -> DependencyAuditResult | None:
        """Laedt das zuletzt persistierte Audit-Ergebnis (kein Live-Scan).

        Returns:
            Das juengste gespeicherte Ergebnis, oder ``None`` wenn kein
            Repository konfiguriert ist bzw. noch kein Audit lief.
        """
        if self._repo is None:
            return None
        return self._repo.lade_letztes_ergebnis()

    # ------------------------------------------------------------------
    # Audit-Operationen
    # ------------------------------------------------------------------

    def audit_requirements(
        self,
        file_path: str,
        progress_callback: ProgressCallback | None = None,
        *,
        resolve_installed: bool = False,
    ) -> DependencyAuditResult:
        """Vollstaendiger Audit-Durchlauf fuer eine requirements.txt (.txt/.pip).

        Args:
            file_path: Pfad zur zu pruefenden requirements.txt.
            progress_callback: Optionaler Callback (aktuell, gesamt, pkg).
            resolve_installed: True NUR beim Selbst-Audit: fuer
                Dependencies ohne ``==``-Pin wird die installierte Version
                der laufenden Umgebung als Fallback aufgeloest. Beim Scan
                fremder requirements-Dateien waere die lokale Umgebung die
                falsche Quelle — Default False. Steuert zugleich den
                KiTodo-Reconcile (:meth:`_run_audit`).

        Returns:
            DependencyAuditResult mit allen Befunden.
        """
        _audit.log_action("DEPENDENCY_AUDIT_START", {"file": file_path})
        _log.info("Dependency-Audit gestartet: %s", file_path)

        try:
            dependencies = parse_requirements(file_path)
        except (ValueError, FileNotFoundError) as exc:
            _log.warning("Audit abgebrochen — Parser-Fehler: %s", exc)
            return DependencyAuditResult(
                source_file=file_path,
                scan_timestamp=datetime.now(UTC).isoformat(),
                total_dependencies=0,
                total_vulnerabilities=0,
                error=str(exc),
            )

        if resolve_installed:
            dependencies = resolve_installed_versions(dependencies)

        return self._run_audit(
            dependencies, file_path, progress_callback, self_audit=resolve_installed
        )

    def audit_file(
        self,
        file_path: str,
        progress_callback: ProgressCallback | None = None,
    ) -> DependencyAuditResult:
        """Vollstaendiger Audit-Durchlauf fuer beliebige Datei-Formate.

        Erkennt das Format anhand der Dateiendung (.txt,.pip,.json,
.xlsx,.pdf) und parst entsprechend.

        Args:
            file_path: Pfad zur Eingabe-Datei.
            progress_callback: Optionaler Callback (aktuell, gesamt, pkg).

        Returns:
            DependencyAuditResult mit allen Befunden.
        """
        from tools.dependency_auditor.data.file_parser import (  # noqa: PLC0415
            parse_dependency_file,
        )

        _audit.log_action("DEPENDENCY_AUDIT_START", {"file": file_path})
        _log.info("Dependency-Audit (Datei) gestartet: %s", file_path)

        try:
            dependencies = parse_dependency_file(file_path)
        except (ValueError, FileNotFoundError, RuntimeError) as exc:
            _log.warning("Audit abgebrochen — Parser-Fehler: %s", exc)
            return DependencyAuditResult(
                source_file=file_path,
                scan_timestamp=datetime.now(UTC).isoformat(),
                total_dependencies=0,
                total_vulnerabilities=0,
                error=str(exc),
            )

        return self._run_audit(dependencies, file_path, progress_callback)

    def _run_audit(
        self,
        dependencies: list[DependencyInfo],
        source_file: str,
        progress_callback: ProgressCallback | None = None,
        *,
        self_audit: bool = False,
    ) -> DependencyAuditResult:
        """Fuehrt OSV-Abfragen + Analyse fuer eine fertig geparste Dependency-Liste durch.

        Args:
            dependencies: Geparste DependencyInfo-Objekte.
            source_file: Pfad-String fuer Metadaten (Logging, Result).
            progress_callback: Optionaler Callback (aktuell, gesamt, pkg).
            self_audit: True beim Selbst-Audit: Der KiTodo-Hook
                emittiert dann mit ``reconcile_tool`` (Voll-Sync) —
                verschwundene Findings schliessen ihre Karten automatisch.
                Fremddatei-Audits emittieren ohne Reconcile.

        Returns:
            DependencyAuditResult mit allen Befunden.
        """
        total = len(dependencies)
        _log.info("Dependency-Audit: %d Dependencies geladen", total)

        # OSV-Abfragen — mit effektiver Version (Pin vor installierter
        # Version): OSV filtert dann serverseitig schon nach Version;
        # das lokale Matching im Analyzer bleibt als zweite Sicherung.
        vulnerabilities: dict[str, list] = {}
        for idx, dep in enumerate(dependencies, start=1):
            if progress_callback:
                progress_callback(idx, total, dep.name)

            vulns = self._advisory.query_vulnerabilities(
                dep.name, dep.effective_version()
            )
            if vulns:
                vulnerabilities[dep.name.lower()] = vulns

        # Analyse
        result = analyze_dependencies(dependencies, vulnerabilities)
        result.source_file = source_file
        result.scan_timestamp = datetime.now(UTC).isoformat()

        _log.info(
            "Dependency-Audit abgeschlossen: %d Dependencies, %d Vulnerabilities",
            result.total_dependencies,
            result.total_vulnerabilities,
        )
        _audit.log_action(
            "DEPENDENCY_AUDIT_COMPLETE",
            {
                "file": source_file,
                "total": result.total_dependencies,
                "vulns": result.total_vulnerabilities,
                "critical": result.critical_count(),
                "high": result.high_count(),
                "unverified": result.unverified_count(),
            },
        )

        # Optional persistieren
        if self._repo and not result.error:
            try:
                self._repo.speichere_audit(result)
                _log.info("Audit-Ergebnis gespeichert.")
            except Exception:  # noqa: BLE001
                _log.warning(
                    "Audit konnte nicht gespeichert werden (Repository-Fehler)"
                )

        # (a)+(b): KiTodo-Hook nach Audit-Complete. Beim Self-Audit
        # mit Reconcile: audit_to_ki_inputs ist dort die
        # vollstaendige Findings-Liste des Tools.
        if not result.error:
            from tools.dependency_auditor.application.storytelling_adapter import (  # noqa: PLC0415
                emit_to_ki_emitter,
            )
            emit_to_ki_emitter(self._ki_todo_emitter, result, self_audit=self_audit)

        return result

    def audit_self(
        self,
        progress_callback: ProgressCallback | None = None,
    ) -> DependencyAuditResult:
        """Prueft FINLAIs eigene requirements.txt.

        Ermittelt den Projektroot automatisch:
        - PyInstaller-Bundle: neben der.exe
        - Entwicklungsumgebung: relativ zu diesem Modul (4 Ebenen hoch)

        Beim Selbst-Audit wird fuer Dependencies ohne ``==``-Pin die
        installierte Version der laufenden Umgebung herangezogen
        (``resolve_installed=True``) — nur hier ist die lokale
        Umgebung die richtige Quelle.

        Args:
            progress_callback: Optionaler Fortschritts-Callback.

        Returns:
            DependencyAuditResult.
        """
        if getattr(sys, "frozen", False):
            base = Path(sys.executable).parent
        else:
            # tools/dependency_auditor/application/audit_service.py → root
            base = Path(__file__).resolve().parents[3]

        req_path = base / "requirements.txt"
        if not req_path.exists():
            _log.warning("audit_self: requirements.txt nicht gefunden: %s", req_path)
            return DependencyAuditResult(
                source_file=str(req_path),
                scan_timestamp=datetime.now(UTC).isoformat(),
                total_dependencies=0,
                total_vulnerabilities=0,
                error=f"requirements.txt nicht gefunden: {req_path}",
            )

        return self.audit_requirements(
            str(req_path), progress_callback, resolve_installed=True
        )


def create_default_audit_service() -> AuditService:
    """Baut einen voll verdrahteten AuditService inkl. Persistenz (headless).

    Wiring ueber funktionslokale data-Importe (Schicht-Vertrag): OSV/PyPI-Client
    + persistierendes:class:`DbAuditRepository`. Erlaubt Konsumenten ausserhalb
    des Tools (z.B. den Fleet-Agent) die Erzeugung ueber die application-Schicht,
    ohne ``data/`` direkt zu importieren.

    Returns:
        Einsatzbereiter:class:`AuditService` mit Repository.
    """
    from tools.dependency_auditor.data.audit_repository import (  # noqa: PLC0415
        DbAuditRepository,
    )
    from tools.dependency_auditor.data.pypi_advisory_client import (  # noqa: PLC0415
        PyPIAdvisoryClient,
    )

    return AuditService(advisory_source=PyPIAdvisoryClient(), audit_repo=DbAuditRepository())
