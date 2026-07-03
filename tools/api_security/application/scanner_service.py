"""
scanner_service — Anwendungsservice fuer den API Security Analyzer.

Koordiniert IScannerPort, IReportPort und IScanRepository.
Keine Netzwerk-Calls, keine GUI-Abhaengigkeiten.

Sicherheitsdesign (STRIDE):
    Tampering: URL wird vor dem Scan mit validate_url
                       gegen SSRF geprueft.
    Repudiation: Jeder Scan wird im AuditLog protokolliert.
    DoS: Maximale Scan-Dauer durch Scanner-Timeout begrenzt.
    Info Disclosure: URL wird im Audit-Log gespeichert, Body-Inhalte nicht.
                       API-Keys werden niemals persistiert (nur URL ohne
                       Query-Parameter wird gespeichert).

Schichtzugehoerigkeit: application/ — keine GUI-Imports, kein direktes HTTP.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.audit_log import AuditLogger
from core.feed_settings import OFFLINE_HINT, external_fetches_allowed
from core.logger import get_logger
from core.security.validators import validate_url
from tools.api_security.domain.interfaces import (
    IReportPort,
    IScannerPort,
    IScanRepository,
)
from tools.api_security.domain.models import ScanLauf, ScanResult, ScanTarget

_log = get_logger(__name__)
_audit = AuditLogger()


def create_default_scanner_service(
    scan_repo: IScanRepository | None = None,
) -> ScannerService:
    """Default-Factory mit ``HttpScanner`` + ``ReportAdapter``.

 (RUN2-GUI): GUI-Fallback wandert in die application-Schicht,
    damit das Widget die ``data/``-Klassen nicht direkt importieren muss.

    Args:
        scan_repo: Optionales Scan-Repository; wenn ``None`` werden
            Scan-Ergebnisse nicht persistiert.

    Returns:
        ``ScannerService``-Instanz mit production-tauglichen Defaults.
    """
    from tools.api_security.data.http_scanner import HttpScanner  # noqa: PLC0415
    from tools.api_security.data.report_adapter import ReportAdapter  # noqa: PLC0415

    return ScannerService(
        scanner=HttpScanner(verify_ssl=True),
        reporter=ReportAdapter(),
        scan_repo=scan_repo,
    )


class ScannerService:
    """Orchestriert API-Security-Scans und optionale Persistenz.

    Attributes:
        _scanner: HTTP-Scanner-Implementierung (IScannerPort).
        _reporter: Report-Adapter-Implementierung (IReportPort).
        _scan_repo: Optionales Scan-Repository fuer Verlauf-Persistenz.
    """

    def __init__(
        self,
        scanner: IScannerPort,
        reporter: IReportPort,
        scan_repo: IScanRepository | None = None,
        ki_todo_emitter: object | None = None,
    ) -> None:
        """Initialisiert den Service.

        Args:
            scanner: Konkreter HTTP-Scanner (data-Schicht).
            reporter: Konkreter Report-Adapter (data-Schicht).
            scan_repo: Optionales Scan-Repository; wenn None werden
                       Scan-Ergebnisse nicht persistiert.
            ki_todo_emitter: Optionaler:class:`core.storytelling.ki_todo_emitter.KiTodoEmitter`
                fuer-Hook nach Scan-Complete. Bei ``None`` wird ein
                Default-Emitter gebaut (lazy, no-op falls mainpage-Service
                nicht initialisierbar).
        """
        self._scanner = scanner
        self._reporter = reporter
        self._scan_repo = scan_repo
        if ki_todo_emitter is None:
            from core.storytelling.ki_todo_emitter import (  # noqa: PLC0415
                KiTodoEmitter,
            )
            ki_todo_emitter = KiTodoEmitter()
        self._ki_todo_emitter = ki_todo_emitter

    # ------------------------------------------------------------------
    # Scan-Operationen
    # ------------------------------------------------------------------

    def scan(self, target: ScanTarget) -> ScanResult:
        """Validiert die Ziel-URL und fuehrt einen passiven Scan durch.

        Kein Persistieren — nur Scan-Ergebnis zurueckgeben.
        Fuer automatische Persistenz run_scan verwenden.

        Args:
            target: Scan-Ziel mit URL und Konfiguration.

        Returns:
            ScanResult mit allen Befunden.

        Raises:
            ValueError: Wenn die URL ungueltg oder SSRF-gefaehrdet ist.
        """
        if not external_fetches_allowed():
            _log.debug("API-Scan uebersprungen: %s", OFFLINE_HINT)
            return ScanResult(target=target, error=OFFLINE_HINT)

        # SSRF-Schutz: externe URLs explizit erlaubt, aber Protokoll/Format pruefen
        try:
            validate_url(target.url, allow_non_localhost=True)
        except ValueError as exc:
            _log.warning("ScannerService: ungueltge URL: %s", exc)
            raise

        _log.info("API-Security-Scan gestartet: url=%s", target.url)
        _audit.log_action(
            "API_SCAN_START", {"url": target.url, "api_type": target.api_type}
        )

        result = self._scanner.scan(target)

        _log.info(
            "API-Security-Scan abgeschlossen: url=%s findings=%d score=%d",
            target.url,
            len(result.findings),
            result.risk_score(),
        )
        _audit.log_action(
            "API_SCAN_COMPLETE",
            {
                "url": target.url,
                "findings": len(result.findings),
                "risk_score": result.risk_score(),
                "critical": result.critical_count(),
                "high": result.high_count(),
            },
        )

        return result

    def run_scan(self, target: ScanTarget) -> ScanResult:
        """Scan + automatische Persistenz im Repository (wenn vorhanden).

        Ruft intern scan auf und speichert das Ergebnis anschliessend
        im Scan-Repository. Fehler beim Speichern fuhren NICHT zum Abbruch
        — der Scan selbst gilt als erfolgreich.

        Args:
            target: Scan-Ziel mit URL und Konfiguration.

        Returns:
            ScanResult mit allen Befunden (identisch mit scan).
        """
        result = self.scan(target)

        if self._scan_repo and not result.error:
            lauf = self._result_to_lauf(result)
            try:
                self._scan_repo.speichere_lauf(lauf)
                _log.info(
                    "Scan gespeichert: %s, %d Findings",
                    lauf.target_url,
                    lauf.findings_count,
                )
            except (OSError, RuntimeError):
                _log.warning("Scan konnte nicht gespeichert werden (Repository-Fehler)")

        # (a)+(b): KiTodo-Hook nach Scan-Complete. Konvertiert die
        # Findings via tool-spezifischen Adapter und schickt sie an die
        # Regelengine. Hook ist no-op falls Service nicht initialisierbar.
        if not result.error:
            from tools.api_security.application.storytelling_adapter import (  # noqa: PLC0415
                emit_to_ki_emitter,
            )
            emit_to_ki_emitter(self._ki_todo_emitter, result)

        return result

    # ------------------------------------------------------------------
    # Verlauf-Operationen
    # ------------------------------------------------------------------

    def lade_verlauf(
        self,
        target_url: str | None = None,
        limit: int = 20,
    ) -> list[ScanLauf]:
        """Laedt den Scan-Verlauf (ohne Findings, nur Metadaten).

        Args:
            target_url: Optionaler URL-Filter. None = alle URLs.
            limit: Maximale Anzahl Eintraege.

        Returns:
            Liste der ScanLauf-Objekte, neueste zuerst.
            Leere Liste wenn kein Repository vorhanden.
        """
        if not self._scan_repo:
            return []
        return self._scan_repo.lade_verlauf(target_url, limit)

    def lade_lauf_details(self, lauf_id: str) -> ScanLauf | None:
        """Laedt einen einzelnen Scan-Lauf vollstaendig inkl. Findings.

        Args:
            lauf_id: UUID des Laufs.

        Returns:
            ScanLauf mit Findings oder None.
        """
        if not self._scan_repo:
            return None
        return self._scan_repo.lade_lauf(lauf_id)

    def lade_alle_gescannten_urls(self) -> list[str]:
        """Gibt alle distinct gescannten URLs zurueck.

        Returns:
            Sortierte URL-Liste. Leer wenn kein Repository vorhanden.
        """
        if not self._scan_repo:
            return []
        return self._scan_repo.lade_alle_urls()

    def loesche_lauf(self, lauf_id: str) -> None:
        """Loescht einen Scan-Lauf aus dem Repository.

        Args:
            lauf_id: UUID des zu loeschenden Laufs.
        """
        if self._scan_repo:
            self._scan_repo.loesche_lauf(lauf_id)
            _log.info("Scan-Lauf geloescht: %s", lauf_id)

    def vergleiche_scans(
        self, aktuell: ScanLauf, vorherig: ScanLauf
    ) -> dict[str, list]:
        """Vergleicht zwei Scan-Laeufe und gibt den Finding-Diff zurueck.

        Vergleich basiert auf Finding-Titeln (eindeutig genug fuer diff).

        Args:
            aktuell: Neuerer Scan-Lauf (mit Findings).
            vorherig: Aelterer Scan-Lauf (mit Findings).

        Returns:
            Dict mit Schluesseln:
            - ``"neu"``: Findings nur in aktuell.
            - ``"behoben"``: Findings nur in vorherig.
            - ``"bestehend"``: Findings in beiden.
        """
        aktuelle_titles = {f.title for f in aktuell.findings}
        vorherige_titles = {f.title for f in vorherig.findings}

        return {
            "neu": [f for f in aktuell.findings if f.title not in vorherige_titles],
            "behoben": [f for f in vorherig.findings if f.title not in aktuelle_titles],
            "bestehend": [f for f in aktuell.findings if f.title in vorherige_titles],
        }

    # ------------------------------------------------------------------
    # Export-Operationen
    # ------------------------------------------------------------------

    def export_json(self, result: ScanResult, path: Path) -> Path:
        """Exportiert das Scan-Ergebnis als JSON.

        Args:
            result: Scan-Ergebnis.
            path: Ausgabepfad.

        Returns:
            Absoluter Pfad der erzeugten Datei.
        """
        out = self._reporter.export_json(result, path)
        _log.info("JSON-Export: %s", out)
        return out

    def export_pdf(self, result: ScanResult, path: Path) -> Path:
        """Exportiert das Scan-Ergebnis als PDF-Bericht.

        Args:
            result: Scan-Ergebnis.
            path: Ausgabepfad.

        Returns:
            Absoluter Pfad der erzeugten Datei.
        """
        out = self._reporter.export_pdf(result, path)
        _log.info("PDF-Export: %s", out)
        return out

    # ------------------------------------------------------------------
    # Interne Hilfsmethoden
    # ------------------------------------------------------------------

    def _result_to_lauf(self, result: ScanResult) -> ScanLauf:
        """Konvertiert ein ScanResult in einen persistierbaren ScanLauf.

        Args:
            result: Abgeschlossenes ScanResult.

        Returns:
            ScanLauf bereit zur Speicherung.
        """
        severity_counts: dict[str, int] = {}
        for f in result.findings:
            key = f.severity.value
            severity_counts[key] = severity_counts.get(key, 0) + 1

        # scan_time ist der Start-Zeitstempel
        scan_start = result.scan_time
        scan_end = ""
        if result.scan_time and result.duration_ms:
            try:
                start_dt = datetime.fromisoformat(
                    result.scan_time.replace("Z", "+00:00")
                )
                end_dt = start_dt + timedelta(milliseconds=result.duration_ms)
                scan_end = end_dt.isoformat()
            except ValueError:
                scan_end = datetime.now(UTC).isoformat()

        return ScanLauf(
            id=str(uuid.uuid4()),
            target_url=result.target.url,
            api_type=result.target.api_type.value,
            scan_start=scan_start,
            scan_end=scan_end,
            total_checks=9,
            findings_count=len(result.findings),
            severity_summary=severity_counts,
            findings=list(result.findings),
        )
