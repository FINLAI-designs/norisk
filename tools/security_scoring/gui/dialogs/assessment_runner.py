"""
assessment_runner — QThread-basierter Orchestrator für Security Assessments.

Führt die ausgewählten Testbereiche sequenziell durch und emittiert
Fortschritts-Signals an den AssessmentWizard.

Jeder Testbereich ruft den bestehenden Application-Service-Stack auf:
  - api_security: letzte gespeicherte Scan-Ergebnisse aus DB
  - network_scanner: letzte gespeicherte Scan-Ergebnisse aus DB
  - cert_monitor: frischer Scan aller konfigurierten Domains
  - dependency_auditor: audit_self auf FINLAIs requirements.txt
  - system_scanner: Systemsicherheit aus lokalem Software-Scan

Schichtzugehörigkeit: gui/ — darf application/ und domain/ importieren.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from PySide6.QtCore import QThread, Signal

from core.exceptions import ConfigurationError
from core.logger import get_logger
from tools.security_scoring.domain.models import ScoreComponent, SecurityScore
from tools.security_scoring.domain.scoring_engine import (
    calculate_component_score,
    calculate_overall_score,
    score_to_grade,
)

if TYPE_CHECKING:
    from tools.security_scoring.domain.interfaces import IScoreRepository

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Testbereiche-Konfiguration
# ---------------------------------------------------------------------------

TESTBEREICHE: list[dict] = [
    {
        "key": "api_security",
        "name": "API Security",
        "beschreibung": "Prüft REST-Endpoints auf Schwachstellen (letzte Scan-Ergebnisse)",
        "gewichtung": 0.25,
        "icon": "",
        "standard_aktiv": True,
    },
    {
        "key": "network_scanner",
        "name": "Netzwerk-Scan",
        "beschreibung": "Host-Discovery + Port-Scan (letzte Scan-Ergebnisse)",
        "gewichtung": 0.20,
        "icon": "",
        "standard_aktiv": True,
    },
    {
        "key": "cert_monitor",
        "name": "Zertifikats-Check",
        "beschreibung": "SSL/TLS-Zertifikate aller konfigurierten Domains prüfen",
        "gewichtung": 0.20,
        "icon": "",
        "standard_aktiv": True,
    },
    {
        "key": "dependency_auditor",
        "name": "Dependency Audit",
        "beschreibung": "Python-Pakete auf bekannte CVEs prüfen (requirements.txt)",
        "gewichtung": 0.20,
        "icon": "",
        "standard_aktiv": True,
    },
    {
        "key": "system_scanner",
        "name": "Systemsicherheit",
        "beschreibung": "OS-Status, Antivirus, Firewall, Verschlüsselung aus lokalem Scan",
        "gewichtung": 0.15,
        "icon": "",
        "standard_aktiv": True,
    },
]


def berechne_gewichtungen(aktive_bereiche: list[dict]) -> dict[str, float]:
    """Verteilt die Gewichtung proportional auf aktive Bereiche.

    Args:
        aktive_bereiche: Liste der aktiven Bereich-Dicts (mit 'gewichtung').

    Returns:
        Dict {key: normalisierte_gewichtung}.
    """
    gesamt = sum(b["gewichtung"] for b in aktive_bereiche)
    if gesamt == 0:
        return {b["key"]: 1.0 / len(aktive_bereiche) for b in aktive_bereiche}
    return {b["key"]: b["gewichtung"] / gesamt for b in aktive_bereiche}


# ---------------------------------------------------------------------------
# AssessmentRunner (QThread)
# ---------------------------------------------------------------------------


class AssessmentRunner(QThread):
    """Führt ausgewählte Security-Tests sequenziell im Hintergrund-Thread durch.

    Jeder Testbereich wird nacheinander abgearbeitet. Schlägt ein Test fehl,
    erhält dieser Bereich Score 0 und ein Fehler-Signal wird emittiert — die
    übrigen Tests laufen weiter.

    Signals:
        test_gestartet(str, int, int): bereich_name, index (0-based), gesamt.
        test_fortschritt(str, int): bereich_name, prozent (0–100).
        test_fertig(str, float, list): bereich_name, score, befunde (str-Liste).
        alle_fertig(SecurityScore): Gesamtscore nach Abschluss aller Tests.
        fehler(str, str): bereich_name, fehlermeldung.
    """

    test_gestartet: Signal = Signal(str, int, int)
    test_fortschritt: Signal = Signal(str, int)
    test_fertig: Signal = Signal(str, float, list)
    alle_fertig: Signal = Signal(object)
    fehler: Signal = Signal(str, str)

    def __init__(
        self,
        services: dict,
        aktive_bereiche: list[dict],
        klient_name: str,
        score_repo: IScoreRepository | None = None,
    ) -> None:
        """Initialisiert den AssessmentRunner.

        Args:
            services: Dict mit Service-Instanzen je Tool-Schlüssel.
            aktive_bereiche: Ausgewählte Bereich-Dicts (aus TESTBEREICHE).
            klient_name: Name des Klienten für den Score-Eintrag.
            score_repo: Optionales Repository zur Score-Persistenz.
        """
        super().__init__()
        self._services = services
        self._bereiche = aktive_bereiche
        self._klient = klient_name
        self._score_repo = score_repo
        self._abgebrochen = False

    def abbrechen(self) -> None:
        """Markiert den Lauf als abgebrochen (nach aktuellem Test)."""
        self._abgebrochen = True

    # ------------------------------------------------------------------
    # QThread.run
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Führt alle aktiven Testbereiche sequenziell durch."""
        gewichtungen = berechne_gewichtungen(self._bereiche)
        components: list[ScoreComponent] = []
        n = len(self._bereiche)

        for i, bereich in enumerate(self._bereiche):
            if self._abgebrochen:
                break

            name = bereich["name"]
            key = bereich["key"]
            self.test_gestartet.emit(name, i, n)

            try:
                self.test_fortschritt.emit(name, 10)
                score, befunde, crit, high, med = self._fuehre_test_durch(bereich)
                self.test_fortschritt.emit(name, 100)
                components.append(
                    ScoreComponent(
                        name=name,
                        score=score,
                        weight=gewichtungen[key],
                        findings_critical=crit,
                        findings_high=high,
                        findings_medium=med,
                        last_scan=datetime.now(UTC).isoformat(),
                        source_tool=key,
                    )
                )
                self.test_fertig.emit(name, score, befunde)
            except Exception as exc:  # noqa: BLE001 -- Test-Worker-Loop muss bei jedem Test-Fehler weiterlaufen
                log.warning("Assessment-Fehler [%s]: %s", key, exc)
                self.fehler.emit(name, str(exc))
                components.append(
                    ScoreComponent(
                        name=name,
                        score=0.0,
                        weight=gewichtungen[key],
                        source_tool=key,
                    )
                )

        if self._abgebrochen or not components:
            return

        overall = calculate_overall_score(components)
        grade = score_to_grade(overall)
        security_score = SecurityScore(
            id=str(uuid.uuid4()),
            target_name=self._klient,
            timestamp=datetime.now(UTC).isoformat(),
            overall_score=round(overall, 1),
            grade=grade,
            components=components,
            summary=self._build_summary(components, overall),
        )

        if self._score_repo:
            try:
                self._score_repo.speichere_score(security_score)
            except (OSError, RuntimeError) as exc:
                log.warning("Score-Speicherung fehlgeschlagen: %s", exc)

        self.alle_fertig.emit(security_score)

    # ------------------------------------------------------------------
    # Test-Implementierungen (eine pro Bereich)
    # ------------------------------------------------------------------

    def _fuehre_test_durch(
        self, bereich: dict
    ) -> tuple[float, list[str], int, int, int]:
        """Dispatcht auf die bereichsspezifische Test-Methode.

        Args:
            bereich: Bereich-Dict aus TESTBEREICHE.

        Returns:
            Tuple (score, befunde, findings_critical, findings_high, findings_medium).
        """
        key = bereich["key"]
        dispatch = {
            "api_security": self._test_api_security,
            "network_scanner": self._test_network_scanner,
            "cert_monitor": self._test_cert_monitor,
            "dependency_auditor": self._test_dependency_auditor,
            "system_scanner": self._test_system_scanner,
        }
        handler = dispatch.get(key)
        if handler is None:
            raise ConfigurationError(f"Unbekannter Testbereich: {key!r}")
        return handler()

    def _test_api_security(self) -> tuple[float, list[str], int, int, int]:
        """Liest den letzten API-Security-Scan aus der Datenbank."""
        service = self._services.get("api_security")
        if service is None:
            return 100.0, ["Service nicht konfiguriert — Score 100 angenommen"], 0, 0, 0

        verlauf = service.lade_verlauf(limit=1)
        if not verlauf:
            return (
                100.0,
                ["Kein Scan-Ergebnis vorhanden — bitte manuellen Scan starten"],
                0,
                0,
                0,
            )

        lauf = verlauf[0]
        sev = lauf.severity_summary
        crit = sev.get("critical", 0)
        high = sev.get("high", 0)
        med = sev.get("medium", 0)
        low = sev.get("low", 0)
        score = calculate_component_score(crit, high, med, low)
        befunde = _befunde_aus_zaehlen(crit, high, med, low)
        return score, befunde, crit, high, med

    def _test_network_scanner(self) -> tuple[float, list[str], int, int, int]:
        """Liest den letzten Netzwerk-Scan aus der Datenbank."""
        service = self._services.get("network_scanner")
        if service is None:
            return 100.0, ["Service nicht konfiguriert — Score 100 angenommen"], 0, 0, 0

        scans = service.lade_letzte_scans(limit=1)
        if not scans:
            return (
                100.0,
                ["Kein Scan-Ergebnis vorhanden — bitte manuellen Scan starten"],
                0,
                0,
                0,
            )

        from tools.network_scanner.domain.models import PortRisk  # noqa: PLC0415

        scan = scans[0]
        crit = sum(
            1 for h in scan.hosts for p in h.offene_ports if p.risk == PortRisk.KRITISCH
        )
        high = sum(
            1 for h in scan.hosts for p in h.offene_ports if p.risk == PortRisk.HOCH
        )
        med = sum(
            1 for h in scan.hosts for p in h.offene_ports if p.risk == PortRisk.MITTEL
        )
        low = sum(
            1 for h in scan.hosts for p in h.offene_ports if p.risk == PortRisk.NIEDRIG
        )
        score = calculate_component_score(crit, high, med, low)
        befunde = _befunde_aus_zaehlen(crit, high, med, low)
        return score, befunde, crit, high, med

    def _test_cert_monitor(self) -> tuple[float, list[str], int, int, int]:
        """Scannt alle konfigurierten Domains frisch."""
        service = self._services.get("cert_monitor")
        if service is None:
            return 100.0, ["Service nicht konfiguriert — Score 100 angenommen"], 0, 0, 0

        from tools.cert_monitor.domain.models import CertStatus  # noqa: PLC0415

        # Frischen Scan aller Domains anstoßen
        ergebnisse = service.scanne_alle(
            progress_callback=lambda *_: None,
        )

        if not ergebnisse:
            return (
                100.0,
                ["Keine Domains konfiguriert — Score 100 angenommen"],
                0,
                0,
                0,
            )

        crit = sum(1 for c in ergebnisse if c.status == CertStatus.KRITISCH)
        high = sum(1 for c in ergebnisse if c.status == CertStatus.WARNUNG)
        score = calculate_component_score(crit, high, 0)
        befunde = []
        if crit:
            befunde.append(f"KRIT: {crit} abgelaufene / kritische Zertifikate")
        if high:
            befunde.append(f"HOCH: {high} bald ablaufende Zertifikate")
        if not befunde:
            befunde.append(f"OK — Alle {len(ergebnisse)} Zertifikate gültig")
        return score, befunde, crit, high, 0

    def _test_dependency_auditor(self) -> tuple[float, list[str], int, int, int]:
        """Führt audit_self auf FINLAIs requirements.txt aus.

        In den Score fließen nur versions-verifizierte Findings ein
        (critical/high/medium/low zählen seit keine Advisories mit
        unbekannter Version mehr). „Version unbekannt"-Advisories werden
        als eigener Befund ausgewiesen, aber nicht wie echte Vulns gewichtet.
        """
        service = self._services.get("dependency_auditor")
        if service is None:
            return 100.0, ["Service nicht konfiguriert — Score 100 angenommen"], 0, 0, 0

        result = service.audit_self(
            progress_callback=lambda *_: None,
        )

        if result.error:
            raise ConfigurationError(result.error)

        crit = result.critical_count()
        high = result.high_count()
        med = result.medium_count()
        low = result.low_count()
        score = calculate_component_score(crit, high, med, low)
        befunde = _befunde_aus_zaehlen(crit, high, med, low)
        if result.unpinned_dependencies:
            befunde.append(
                f"[WARN] {len(result.unpinned_dependencies)} ungepinnte Abhängigkeiten"
            )
        unverified = result.unverified_count()
        if unverified:
            befunde.append(
                f"[?] {unverified} Advisories ohne Versionsabgleich "
                f"(Version unbekannt) — nicht in den Score eingerechnet"
            )
        return score, befunde, crit, high, med

    def _test_system_scanner(self) -> tuple[float, list[str], int, int, int]:
        """Bewertet Systemsicherheit anhand des letzten lokalen Software-Scans.

        Liest das aktuellste ScanResult aus der system_scanner-Datenbank und
        leitet daraus einen Score ab:
          - Inaktiver Antivirus/Firewall → hohe Findings
          - Inaktive Verschlüsselung → kritisches Finding
          - Remote-Access-Tools (RISK) → mittlere Findings
          - Fehlender/veralteter Scan → Score 50, Warnung

        Returns:
            Tuple (score, befunde, findings_critical, findings_high, findings_medium).
        """
        from datetime import UTC, datetime  # noqa: PLC0415

        from tools.system_scanner.application.scan_history_use_case import (  # noqa: PLC0415
            create_default_scan_history_use_case,
        )
        from tools.system_scanner.domain.enums import (  # noqa: PLC0415
            ComponentStatus,
            ComponentType,
        )

        # Scan-Alter-Limit
        _MAX_SCAN_ALTER_TAGE = 30

        try:
            result = create_default_scan_history_use_case().get_latest()
        except (OSError, RuntimeError, ImportError) as exc:
            log.warning("System-Scanner-Repository nicht erreichbar: %s", exc)
            return (
                50.0,
                ["System-Scanner-Datenbank nicht erreichbar — Score 50 angenommen"],
                0,
                0,
                0,
            )

        if result is None:
            return (
                50.0,
                [
                    "Kein System-Scan vorhanden — bitte 'Scan starten' ausführen.",
                    "Score 50 angenommen.",
                ],
                0,
                0,
                0,
            )

        # Scan-Alter prüfen
        alter_tage = (datetime.now(tz=UTC) - result.timestamp).days
        if alter_tage > _MAX_SCAN_ALTER_TAGE:
            return (
                50.0,
                [
                    f"Letzter Scan ist {alter_tage} Tage alt (Limit: {_MAX_SCAN_ALTER_TAGE} Tage).",
                    "Bitte einen neuen System-Scan durchführen.",
                    "Score 50 angenommen.",
                ],
                0,
                1,
                0,
            )

        # Scoring aus SecurityComponents
        score = 100.0
        befunde: list[str] = []
        crit = 0
        high = 0
        med = 0

        for comp in result.security_components:
            if comp.type == ComponentType.ANTIVIRUS:
                if comp.status == ComponentStatus.INACTIVE:
                    score -= 25
                    high += 1
                    befunde.append(f"[!] Antivirus inaktiv: {comp.name}")
                elif comp.status == ComponentStatus.OUTDATED:
                    score -= 15
                    med += 1
                    befunde.append(f"[!] Antivirus veraltet: {comp.name}")
                elif comp.status == ComponentStatus.UNKNOWN:
                    score -= 10
                    med += 1
                    befunde.append(f"[?] Antivirus-Status unbekannt: {comp.name}")

            elif comp.type == ComponentType.FIREWALL:
                if comp.status == ComponentStatus.INACTIVE:
                    score -= 20
                    high += 1
                    befunde.append(f"[!] Firewall inaktiv: {comp.name}")
                elif comp.status == ComponentStatus.UNKNOWN:
                    score -= 5
                    befunde.append(f"[?] Firewall-Status unbekannt: {comp.name}")

            elif comp.type == ComponentType.ENCRYPTION:
                if comp.status == ComponentStatus.INACTIVE:
                    score -= 30
                    crit += 1
                    befunde.append(f"[KRIT] Verschlüsselung inaktiv: {comp.name}")
                elif comp.status == ComponentStatus.UNKNOWN:
                    score -= 10
                    med += 1
                    befunde.append(
                        f"[?] Verschlüsselungs-Status unbekannt: {comp.name}"
                    )

            elif comp.type == ComponentType.REMOTE_ACCESS:
                if comp.status == ComponentStatus.RISK:
                    score -= 10
                    med += 1
                    befunde.append(f"[WARN] Remote-Access-Tool: {comp.name}")

        score = max(0.0, score)

        if not befunde:
            befunde.append(
                f"OK — Systemsicherheit geprüft ({len(result.security_components)}"
                " Komponenten, keine Probleme)"
            )
        else:
            befunde.insert(
                0,
                f"Scan vom {result.timestamp.strftime('%d.%m.%Y %H:%M')}"
                f" ({len(result.security_components)} Komponenten)",
            )

        return score, befunde, crit, high, med

    # ------------------------------------------------------------------
    # Hilfsmethoden
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(components: list[ScoreComponent], overall: float) -> str:
        """Erstellt eine einzeilige Kurzbeschreibung des Gesamt-Scores.

        Args:
            components: Berechnete Komponenten.
            overall: Gesamtscore.

        Returns:
            Beschreibungstext.
        """
        total_crit = sum(c.findings_critical for c in components)
        total_high = sum(c.findings_high for c in components)
        parts = []
        if total_crit:
            parts.append(f"{total_crit} kritische Findings")
        if total_high:
            parts.append(f"{total_high} hohe Findings")
        if not parts:
            return f"Score {overall:.0f}/100 — keine kritischen Findings."
        return f"Score {overall:.0f}/100 — {', '.join(parts)}."


# ---------------------------------------------------------------------------
# Hilfsfunktionen (modul-privat)
# ---------------------------------------------------------------------------


def _befunde_aus_zaehlen(crit: int, high: int, med: int, low: int = 0) -> list[str]:
    """Erzeugt eine lesbare Befund-Liste aus Finding-Zählern.

    Args:
        crit: Kritische Findings.
        high: Hohe Findings.
        med: Mittlere Findings.
        low: Niedrige Findings.

    Returns:
        Liste von lesbaren Befund-Strings.
    """
    befunde = []
    if crit:
        befunde.append(f"KRIT: {crit} kritische Befunde")
    if high:
        befunde.append(f"HOCH: {high} hohe Befunde")
    if med:
        befunde.append(f"MITTEL: {med} mittlere Befunde")
    if low:
        befunde.append(f"NIEDRIG: {low} niedrige Befunde")
    if not befunde:
        befunde.append("Keine Befunde")
    return befunde
