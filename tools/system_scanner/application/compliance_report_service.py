"""compliance_report_service — pro-Check Regulatorik-/KMU-Sicht aus Hardening-Checks W1).

Bruecke zwischen den Windows-Hardening-Checks (SH-001..SH-010) und der
deterministischen Regulatorik-/KMU-Engine (:mod:`core.compliance`). Pro
FEHLGESCHLAGENEM Check entsteht eine:class:`ComplianceRow` mit indikativen
Norm-Bezuegen, KMU-Prioritaet und Aufwands-Schaetzung — rein berechnend, keine
Persistenz, keine KI.

Datenpfad (alle Bausteine existieren bereits):
``HardeningCheck`` (severity, check_id) ->:func:`hardening_checks_to_findings`
(nur ``passed=False``) ->:meth:`RuleEngine.evaluate` (urgency aus dem
Effort-Klassifikator) ->:func:`core.compliance.build_compliance_view`.

Schicht: ``tools/system_scanner/application`` — importiert nur ``core`` (rules,
compliance) und das eigene ``system_scanner`` (Adapter/Scanner). Konsumenten
(security_scoring-Dashboard/-Report, norisk_dashboard-PDF) lesen die Rows.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from core.compliance.kmu_priority import ComplianceView, build_compliance_view
from core.probes.hardening_probe import IHardeningProbe
from core.rules.rule_engine import RuleEngine
from core.security.severity import Severity
from tools.system_scanner.application.storytelling_adapter import (
    hardening_checks_to_findings,
)
from tools.system_scanner.application.windows_hardening_scanner import (
    WindowsHardeningScanner,
)
from tools.system_scanner.domain.entities import HardeningCheck

#: Alle SH-Checks gehoeren zur Hardening-Kategorie E (``system_scanner``).
_HARDENING_CATEGORY_VALUE = "system_hardening"

#: Konservativer Effort-Default, falls keine Regel matcht (sollte nicht
#: vorkommen — hardening.yaml deckt ``hardening_check_failed`` ab).
_FALLBACK_URGENCY = "mittel"


@dataclass(frozen=True, slots=True)
class ComplianceRow:
    """Eine pro-Check-Zeile der Regulatorik-/KMU-Sicht (Render-DTO).

    Attributes:
        check_id: Stabiler Check-Identifier (``"SH-001"``...).
        label: Menschenlesbarer Check-Name (deutsch).
        severity: Schweregrad des Checks (kanonisch).
        urgency: Effort-Klasse (``quick``/``mittel``/``langfrist``).
        view: Deterministische:class:`ComplianceView` (Norm-Bezuege,
            KMU-Prioritaet, Aufwand, Pflicht-Disclaimer).
    """

    check_id: str
    label: str
    severity: Severity
    urgency: str
    view: ComplianceView


def build_hardening_compliance_rows(
    checks: Iterable[HardeningCheck], rule_engine: RuleEngine
) -> list[ComplianceRow]:
    """Baut pro fehlgeschlagenem Hardening-Check eine:class:`ComplianceRow`.

    Nur ``passed=False``-Checks (via:func:`hardening_checks_to_findings`). Die
    Effort-Klasse kommt aus der ``rule_engine`` (Fallback ``mittel``). Sortiert
    nach KMU-Prioritaet absteigend (wichtigstes zuerst), Tiebreaker ``check_id``.

    Args:
        checks: Ergebnis von:meth:`WindowsHardeningScanner.scan_all`.
        rule_engine: Geladene:class:`RuleEngine` (typisch ``configs/rules``).

    Returns:
        Deterministisch sortierte Liste der Rows (leer, wenn alle Checks passen).
    """
    rows: list[ComplianceRow] = []
    for finding in hardening_checks_to_findings(checks):
        actions = rule_engine.evaluate(finding)
        urgency = actions[0].urgency if actions else _FALLBACK_URGENCY
        view = build_compliance_view(
            _HARDENING_CATEGORY_VALUE,
            finding.severity,
            urgency,
            check_id=finding.evidence_id,
        )
        rows.append(
            ComplianceRow(
                check_id=finding.evidence_id,
                label=finding.subject,
                severity=finding.severity,
                urgency=urgency,
                view=view,
            )
        )
    rows.sort(key=lambda row: (-row.view.kmu_priority, row.check_id))
    return rows


def collect_hardening_compliance(
    probe: IHardeningProbe, rule_engine: RuleEngine
) -> list[ComplianceRow]:
    """Fuehrt den Windows-Hardening-Scan aus und baut die ComplianceRows.

    I/O-Variante fuer Aufrufer (GUI-Thread/PDF), die einen frischen Scan wollen.
    Der Scan selbst ist plattformabhaengig ueber den injizierten ``probe``
    gekapselt (Prod: ``WindowsHardeningProbe``; Tests: ``MockHardeningProbe``).

    Args:
        probe: Hardening-Probe (System-Zugriff).
        rule_engine: Geladene:class:`RuleEngine`.

    Returns:
        Sortierte:class:`ComplianceRow`-Liste (nur fehlgeschlagene Checks).
    """
    checks = WindowsHardeningScanner(probe).scan_all()
    return build_hardening_compliance_rows(checks, rule_engine)


def default_rule_engine() -> RuleEngine:
    """Laedt die Default-:class:`RuleEngine` aus ``configs/rules`` (Repo-Root-relativ).

    Spiegelt:meth:`KiTodoService.for_default_rules` — ``parents[3]`` des
    application-Moduls ist der Repo-Root. Fehlt das Verzeichnis (z.B. gepackt
    ohne configs), liefert:meth:`RuleEngine.from_directory` eine leere Engine
    (dann greift der ``_FALLBACK_URGENCY`` in:func:`build_hardening_compliance_rows`).

    Returns:
        Die geladene RuleEngine (ggf. leer, nie ``None``).
    """
    rules_dir = Path(__file__).resolve().parents[3] / "configs" / "rules"
    return RuleEngine.from_directory(rules_dir)


def collect_default_hardening_compliance() -> list[ComplianceRow]:
    """Frischer Haertungs-Scan mit Prod-Probe + Default-Regeln -> ComplianceRows.

    Bequemer Ein-Aufruf-Einstieg fuer GUI/PDF. Kapselt bewusst die data-Schicht
    (``WindowsHardeningProbe``), damit der GUI-Aufrufer KEINEN data-Adapter
    importieren muss (Hexagonal-Contract „gui darf data nicht importieren"). Der
    Probe-Import ist lazy (Windows-spezifisch) — auf Nicht-Windows wirft der
    Scan, was der GUI-Thread fail-soft als Fehler-Signal behandelt.

    Returns:
        Sortierte:class:`ComplianceRow`-Liste (nur fehlgeschlagene Checks).
    """
    from core.probes.windows_hardening_probe import (  # noqa: PLC0415
        WindowsHardeningProbe,
    )

    return collect_hardening_compliance(WindowsHardeningProbe(), default_rule_engine())


_SEVERITY_LABELS_DE: dict[Severity, str] = {
    Severity.CRITICAL: "Kritisch",
    Severity.HIGH: "Hoch",
    Severity.MEDIUM: "Mittel",
    Severity.LOW: "Niedrig",
    Severity.INFO: "Info",
}

#: Spaltenueberschriften der Regulatorik-Tabelle (GUI + beide PDF-Reports).
COMPLIANCE_TABLE_HEADER: tuple[str, ...] = (
    "Pruefung",
    "Schweregrad",
    "Norm-Bezug (indikativ)",
    "Prioritaet",
    "Aufwand",
)


def severity_label(severity: Severity) -> str:
    """Deutsches Anzeige-Label fuer einen Schweregrad (geteilt GUI + PDF)."""
    return _SEVERITY_LABELS_DE.get(severity, severity.value)


def compliance_rows_to_table(rows: list[ComplianceRow]) -> list[list[str]]:
    """Wandelt ComplianceRows in eine Tabelle (Kopfzeile + Datenzeilen) — pure.

    Geteilte Render-Quelle fuer GUI und beide PDF-Reports (DRY): jede Zelle ist
    ein reiner String. ``norm`` ist die Joined-Liste der indikativen Labels oder
    ein Platzhalter (Lueckentoleranz). Eine KI beruehrt diese Werte nie.

    Returns:
        ``[[header...], [row...],...]`` (erste Zeile =:data:`COMPLIANCE_TABLE_HEADER`).
    """
    table: list[list[str]] = [list(COMPLIANCE_TABLE_HEADER)]
    for row in rows:
        norm = (
            " · ".join(row.view.reg_labels)
            if row.view.reg_labels
            else "(kein indikativer Norm-Bezug)"
        )
        table.append(
            [
                f"{row.label} ({row.check_id})",
                severity_label(row.severity),
                norm,
                f"{row.view.kmu_priority}/100",
                row.view.capacity_hint,
            ]
        )
    return table


__all__ = [
    "COMPLIANCE_TABLE_HEADER",
    "ComplianceRow",
    "build_hardening_compliance_rows",
    "collect_default_hardening_compliance",
    "collect_hardening_compliance",
    "compliance_rows_to_table",
    "default_rule_engine",
    "severity_label",
]
