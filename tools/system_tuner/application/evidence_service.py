"""
evidence_service — NIS2/DSGVO-Nachweis + Empfehlungspaket (Pro, Phase 2b).

Read-only: erzeugt aus einem:class:`ScanReport` (a) einen Compliance-NACHWEIS
(Markdown + PDF) und (b) ein reviewbares GPO/Registry-Empfehlungspaket, das die
IT/der MSP anwenden kann. Keine Systemmutation — daher unabhaengig vom
gesperrten Apply-Pfad (allow_apply).

Wording (R1/R2): Auf FEATURE-Ebene sind Art. 30 (Dokumentationspflicht) + NIS2
Art. 21 (Risikomanagement-Nachweis) korrekt — nicht auf Einzeltweaks. Keine
"konform"-Claims; Formulierung als "Nachweis/Dokumentation/unterstuetzt".

Schichtzugehoerigkeit: application/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.logger import get_logger
from tools.system_tuner.domain.entities import Tweak
from tools.system_tuner.domain.enums import ChangeOp, ServiceStartMode, TweakStatus
from tools.system_tuner.domain.scan_entities import ScanReport

log = get_logger(__name__)

_STATUS_LABEL: dict[TweakStatus, str] = {
    TweakStatus.APPLIED: "Angewandt",
    TweakStatus.NOT_APPLIED: "Offen",
    TweakStatus.UNKNOWN: "Unbekannt",
}

_MODE_TO_SC: dict[ServiceStartMode, str] = {
    ServiceStartMode.AUTOMATIC: "auto",
    ServiceStartMode.MANUAL: "demand",
    ServiceStartMode.DISABLED: "disabled",
}

#: Feature-Ebene Compliance-Einordnung (R1-korrekt; KEINE Konformitaets-Claims).
_COMPLIANCE_FRAMING: tuple[str, ...] = (
    "Dokumentiert die getroffenen technischen Massnahmen (DSGVO Art. 32) und "
    "unterstuetzt die Datenminimierung (DSGVO Art. 5 Abs. 1 lit. c).",
    "Dient als Dokumentation i.S.d. DSGVO Art. 30 und der Nachweispflicht zum "
    "Risikomanagement nach NIS2 Art. 21 — mit Wert, Zeitpunkt und Geraet im Audit-Log.",
    "Ersetzt NICHT die Verantwortlichkeit des Betreibers und ist keine Rechtsberatung.",
)


@dataclass(frozen=True, slots=True)
class EvidenceLine:
    """Eine Befund-/Empfehlungszeile im Nachweis."""

    tweak_id: str
    title: str
    status_label: str
    transition: str
    instruction: str
    compliance: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EvidenceReport:
    """Strukturierter Compliance-Nachweis (Quelle fuer Markdown + PDF)."""

    generated_at: str
    edition_banner: str
    managed_detail: str
    score_value: int
    score_label: str
    score_disclaimer: str
    lines: tuple[EvidenceLine, ...]
    framing: tuple[str, ...] = _COMPLIANCE_FRAMING


def _instruction(tweak: Tweak) -> str:
    """Leitet die manuelle/GPO-Anweisung aus der ChangeSpec ab."""
    change = tweak.change
    if change.op is ChangeOp.REGISTRY_SET:
        return (
            f"Registry: {change.hive}\\{change.key} -> {change.value_name} = "
            f"{change.desired} ({change.value_type.value if change.value_type else '?'})"
        )
    if change.op is ChangeOp.SERVICE_STARTMODE:
        mode = change.desired_start_mode
        sc = _MODE_TO_SC.get(mode) if mode else "?"
        return (
            f"Dienst {change.service_name}: Starttyp = "
            f"{mode.value if mode else '?'} (sc config {change.service_name} start= {sc})"
        )
    return f"AppX entfernen: {change.package_family}"


def build_evidence_report(scan: ScanReport, *, generated_at: str) -> EvidenceReport:
    """Baut den strukturierten Nachweis aus einem Scan-Report (pure)."""
    by_id = {tweak.id: tweak for tweak in scan.tweaks}
    lines: list[EvidenceLine] = []
    for state in scan.states:
        tweak = by_id.get(state.tweak_id)
        if tweak is None:
            continue
        lines.append(
            EvidenceLine(
                tweak_id=tweak.id,
                title=tweak.title_de,
                status_label=_STATUS_LABEL.get(state.status, state.status.value),
                transition=f"{state.current_value or '?'} -> {state.desired_value or '?'}",
                instruction=_instruction(tweak),
                compliance=tweak.compliance_relevance,
            )
        )
    return EvidenceReport(
        generated_at=generated_at,
        edition_banner=scan.edition.banner_de,
        managed_detail=scan.managed.detail_de,
        score_value=scan.score.value,
        score_label=scan.score.label_de,
        score_disclaimer=scan.score.disclaimer_de,
        lines=tuple(lines),
    )


def render_markdown(report: EvidenceReport) -> str:
    """Rendert den Nachweis + das Empfehlungspaket als Markdown (pure)."""
    out: list[str] = [
        "# NoRisk — Datenschutz-/Telemetrie-Nachweis",
        "",
        f"Erstellt: {report.generated_at}",
        "",
        "## Zusammenfassung",
        f"- Edition-Hinweis: {report.edition_banner}",
        f"- Verwaltungsstatus: {report.managed_detail}",
        f"- Privacy-Score: {report.score_value}/100 ({report.score_label})",
        f"- Hinweis: {report.score_disclaimer}",
        "",
        "## Compliance-Einordnung",
    ]
    out += [f"- {line}" for line in report.framing]
    out += ["", "## Befunde", "", "| Empfehlung | Status | Ist -> Soll |", "|---|---|---|"]
    out += [
        f"| {ln.title} | {ln.status_label} | {ln.transition} |" for ln in report.lines
    ]
    out += ["", "## Empfehlungspaket (durch IT/MSP anwendbar)", ""]
    for line in report.lines:
        out.append(f"### {line.title} ({line.tweak_id})")
        out.append(f"- {line.instruction}")
        if line.compliance:
            out.append(f"- Bezug: {'; '.join(line.compliance)}")
        out.append("")
    return "\n".join(out).strip() + "\n"


class EvidenceExporter:
    """Schreibt den Nachweis als Markdown oder PDF (FINLAI Dark Theme)."""

    def export_markdown(self, report: EvidenceReport, path: str | Path) -> bool:
        Path(path).write_text(render_markdown(report), encoding="utf-8")
        log.info("Evidence-Markdown geschrieben: %s", path)
        return True

    def export_pdf(self, report: EvidenceReport, path: str | Path) -> bool:
        """Erzeugt den Nachweis als Dark-Theme-PDF (Muster system_exporter)."""
        from reportlab.lib.units import cm  # noqa: PLC0415
        from reportlab.platypus import Paragraph, Spacer  # noqa: PLC0415

        from core.pdf.pdf_report_builder import DarkReportBuilder  # noqa: PLC0415

        builder = DarkReportBuilder(
            output_path=str(path),
            title="Datenschutz-/Telemetrie-Nachweis",
            subtitle=f"NoRisk by FINLAI  ·  {report.generated_at}",
        )
        builder.add_cover(date_str=report.generated_at)
        styles = builder._styles  # noqa: SLF001
        story = builder._story  # noqa: SLF001

        story.append(Paragraph("Zusammenfassung", styles["h2"]))
        story.append(Paragraph(report.edition_banner, styles["body"]))
        story.append(
            Paragraph(
                f"Privacy-Score: {report.score_value}/100 ({report.score_label}) — "
                f"{report.score_disclaimer}",
                styles["body"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("Compliance-Einordnung", styles["h2"]))
        for line in report.framing:
            story.append(Paragraph(line, styles["body"]))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("Befunde &amp; Empfehlungen", styles["h2"]))
        for ln in report.lines:
            story.append(
                Paragraph(
                    f"<b>{ln.title}</b> — {ln.status_label} ({ln.transition})",
                    styles["body"],
                )
            )
            story.append(Paragraph(ln.instruction, styles["body"]))
        builder.add_footer_page()
        builder.build()
        log.info("Evidence-PDF geschrieben: %s", path)
        return True
