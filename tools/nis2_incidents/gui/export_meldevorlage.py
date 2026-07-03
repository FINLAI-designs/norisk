"""export_meldevorlage — Klartext-/Markdown-Meldevorlagen fuer NIS2-Fristen.

Baut je NIS2-Frist (24h-Fruehwarnung / 72h-Meldung / 30d-Abschluss) eine
lesbare Markdown-Vorlage aus den Incident-Header-Daten und den persistierten
Phasen-Payloads. Die Vorlage ist zum **Copy-paste ins CSIRT-Portal** gedacht
(AT: nis.govcert.gv.at) und traegt einen **Disclaimer** oben:

    Dies ist KEINE Meldung. Sie uebermitteln dieses Dokument eigenstaendig …

Die Build-Funktionen sind bewusst **module-level und GUI-frei** (kein
PySide6-Import), damit sie ohne Qt-Fixture getestet werden koennen. Der
GUI-Einstieg (Button im Timeline-/Detail-Widget) ruft:func:`build_meldevorlage`
und legt das Ergebnis per QFileDialog ab oder in die Zwischenablage.

Schichtzugehoerigkeit: gui/ — liest Domain-Modelle + Schema (domain/),
keine data/-Direktzugriffe.

ADR-Bezug: docs/adr/-nis2-tracker-revisionssicher.md §7.

Author: Patrick Riederich
Version: 0.1 (NIS2-revisionssicher, Schicht 2 GUI)
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from tools.customer_audit.domain import nis2_phase_schema
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    Nis2Incident,
)

#: Disclaimer als Klartext (ohne Markdown-Markup) fuer den PDF-Export.
DISCLAIMER_PLAIN: Final[str] = (
    "Dies ist KEINE Meldung. Sie uebermitteln dieses Dokument eigenstaendig "
    "an Ihr CSIRT (AT: nis.govcert.gv.at) bzw. bei Personenbezug an die "
    "Datenschutzbehoerde. NoRisk erzeugt nur die Vorlage — der Versand und die "
    "Verantwortung liegen bei Ihnen."
)

#: Disclaimer-Block §7) — steht IMMER ganz oben in der Vorlage.
DISCLAIMER: Final[str] = (
    "> **Dies ist KEINE Meldung.** Sie uebermitteln dieses Dokument "
    "eigenstaendig an Ihr CSIRT (AT: nis.govcert.gv.at) bzw. bei "
    "Personenbezug an die Datenschutzbehoerde. NoRisk erzeugt nur die "
    "Vorlage — der Versand und die Verantwortung liegen bei Ihnen."
)


class MeldeFrist(StrEnum):
    """Die drei NIS2-Meldefristen, fuer die eine Vorlage existiert."""

    FRUEHWARNUNG_24H = "fruehwarnung_24h"
    MELDUNG_72H = "meldung_72h"
    ABSCHLUSS_30D = "abschluss_30d"


#: Anzeige-Titel je Frist.
_FRIST_TITEL: Final[dict[MeldeFrist, str]] = {
    MeldeFrist.FRUEHWARNUNG_24H: "NIS2 Art. 23 — 24h-Fruehwarnung",
    MeldeFrist.MELDUNG_72H: "NIS2 Art. 23 — 72h-Meldung",
    MeldeFrist.ABSCHLUSS_30D: "NIS2 Art. 23 — 30d-Abschlussbericht",
}

#: Welche Phasen-Payloads je Frist in die Vorlage einfliessen (kumulativ:
#: spaetere Fristen tragen den Kontext der frueheren mit).
_FRIST_PHASEN: Final[dict[MeldeFrist, tuple[IncidentPhase, ...]]] = {
    MeldeFrist.FRUEHWARNUNG_24H: (
        IncidentPhase.DETECT,
        IncidentPhase.TRIAGE,
        IncidentPhase.EARLY_WARNING,
    ),
    MeldeFrist.MELDUNG_72H: (
        IncidentPhase.DETECT,
        IncidentPhase.TRIAGE,
        IncidentPhase.EARLY_WARNING,
        IncidentPhase.NOTIFICATION,
    ),
    MeldeFrist.ABSCHLUSS_30D: (
        IncidentPhase.DETECT,
        IncidentPhase.TRIAGE,
        IncidentPhase.EARLY_WARNING,
        IncidentPhase.NOTIFICATION,
        IncidentPhase.FINAL_REPORT,
    ),
}

_PHASE_TITEL: Final[dict[IncidentPhase, str]] = {
    IncidentPhase.DETECT: "Detect — Kenntnisnahme",
    IncidentPhase.TRIAGE: "Triage — Erst-Einschaetzung",
    IncidentPhase.EARLY_WARNING: "24h Fruehwarnung",
    IncidentPhase.NOTIFICATION: "72h Meldung",
    IncidentPhase.FINAL_REPORT: "30d Abschlussbericht",
    IncidentPhase.POST_INCIDENT: "Post-Incident",
}

#: Label je Payload-Schluessel, gesammelt aus dem Schema (key → label).
_KEY_LABELS: Final[dict[str, str]] = {
    f.key: f.label
    for phase in IncidentPhase
    for f in nis2_phase_schema.fields_for(phase)
}


def build_meldevorlage(
    incident: Nis2Incident,
    frist: MeldeFrist,
    phase_payloads: dict[IncidentPhase, dict],
) -> str:
    """Baut die Markdown/Klartext-Meldevorlage fuer eine Frist.

    Args:
        incident: Der Vorfall (Header: Titel, Severity, Personenbezug …).
        frist: Die Ziel-Frist (steuert Titel + welche Phasen einfliessen).
        phase_payloads: Map ``IncidentPhase`` → Payload-Dict (aus den
            eingereichten Events). Phasen ohne Payload werden uebersprungen.

    Returns:
        Die fertige Vorlage als String — Disclaimer oben, dann Vorfall-Kopf,
        dann je relevanter Phase die lesbar gelabelten Felder.
    """
    lines: list[str] = []
    lines.append(DISCLAIMER)
    lines.append("")
    lines.append(f"# {_FRIST_TITEL[frist]}")
    lines.append("")
    lines.extend(_header_block(incident))
    lines.append("")

    for phase in _FRIST_PHASEN[frist]:
        payload = phase_payloads.get(phase)
        if not payload:
            continue
        block = _phase_block(phase, payload)
        if block:
            lines.extend(block)
            lines.append("")

    if incident.personenbezug:
        lines.append("## DSGVO-Hinweis")
        lines.append(
            "Personenbezug ist markiert: Pruefen Sie die parallele "
            "Meldepflicht nach DSGVO Art. 33 (Datenschutzbehoerde, binnen "
            "72h ab Kenntnisnahme)."
        )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def meldung_pflicht_luecken(
    frist: MeldeFrist,
    phase_payloads: dict[IncidentPhase, dict],
) -> dict[IncidentPhase, list[str]]:
    """Pure: fehlende NIS2-Pflichtangaben (als Labels) je Phase fuer eine Frist.

 (richtlinienkonform): prueft fuer alle Phasen, die in diese Frist
    einfliessen (:data:`_FRIST_PHASEN`), welche als ``required`` markierten
    Schema-Felder noch nicht ausgefuellt sind. So kann der Export anzeigen, ob
    die Meldung die Art.-23-Pflichtangaben der jeweiligen Stufe vollstaendig
    enthaelt, BEVOR der User sie ans CSIRT uebermittelt.

    Args:
        frist: Ziel-Frist (24h/72h/30d).
        phase_payloads: Map ``IncidentPhase`` -> Payload-Dict.

    Returns:
        Map ``IncidentPhase`` -> Liste fehlender Pflichtfeld-Labels. Phasen ohne
        Luecken (oder ohne Pflichtformular) fehlen im Dict. Leeres Dict =
        alle Pflichtangaben der Frist vorhanden.
    """
    luecken: dict[IncidentPhase, list[str]] = {}
    for phase in _FRIST_PHASEN[frist]:
        fields = nis2_phase_schema.fields_for(phase)
        if not fields:
            continue
        payload = phase_payloads.get(phase) or {}
        missing_keys = nis2_phase_schema.validate(phase, payload)
        if missing_keys:
            label_by_key = {f.key: f.label for f in fields}
            luecken[phase] = [label_by_key.get(k, k) for k in missing_keys]
    return luecken


def build_meldevorlage_pdf(
    incident: Nis2Incident,
    frist: MeldeFrist,
    phase_payloads: dict[IncidentPhase, dict],
    output_path,  # noqa: ANN001 — pathlib.Path; lazy-typed um reportlab-Import-Kopplung zu vermeiden
):  # noqa: ANN201
    """Rendert die NIS2-Meldevorlage als FINLAI-PDF, richtlinienkonform).

    Gleiche Inhalte wie:func:`build_meldevorlage` (Disclaimer, Vorfall-Kopf,
    Phasen-Pflichtfelder, DSGVO-Hinweis), zusaetzlich eine
    **Pflichtangaben-Status**-Sektion, die anhand des NIS2-Schemas zeigt, ob die
    Art.-23-Pflichtangaben der gewaehlten Frist vollstaendig sind. reportlab +
    ``core.pdf`` werden LAZY importiert, damit der Markdown-Pfad ohne reportlab
    funktioniert.

    Args:
        incident: Der Vorfall (Header-Daten).
        frist: Ziel-Frist (steuert Titel + einfliessende Phasen).
        phase_payloads: Map ``IncidentPhase`` -> Payload-Dict.
        output_path: Ziel-PDF-Pfad (wird ueberschrieben).

    Returns:
        Der Output-Pfad (``pathlib.Path``).
    """
    from pathlib import Path  # noqa: PLC0415

    from reportlab.lib import colors  # noqa: PLC0415
    from reportlab.lib.pagesizes import A4  # noqa: PLC0415
    from reportlab.lib.styles import ParagraphStyle  # noqa: PLC0415
    from reportlab.lib.units import cm  # noqa: PLC0415
    from reportlab.platypus import (  # noqa: PLC0415
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
    )

    from core.pdf.pdf_colors import PDF_ACCENT, PDF_TEXT_SECONDARY  # noqa: PLC0415
    from core.pdf.pdf_fonts import (  # noqa: PLC0415
        FONT_RALEWAY,
        FONT_RALEWAY_BOLD,
        register_fonts,
    )

    register_fonts()
    body_font = _safe_font(FONT_RALEWAY)
    bold_font = _safe_font(FONT_RALEWAY_BOLD)
    text_primary = colors.HexColor("#1f2933")
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    h1 = ParagraphStyle(
        "h1", fontName=bold_font, fontSize=16, textColor=PDF_ACCENT,
        spaceAfter=4,
    )
    h2 = ParagraphStyle(
        "h2", fontName=bold_font, fontSize=12, textColor=text_primary,
        spaceBefore=10, spaceAfter=3,
    )
    body = ParagraphStyle(
        "body", fontName=body_font, fontSize=10, textColor=text_primary,
        leading=14,
    )
    meta = ParagraphStyle(
        "meta", fontName=body_font, fontSize=8.5, textColor=PDF_TEXT_SECONDARY,
    )
    disclaimer = ParagraphStyle(
        "disc", fontName=bold_font, fontSize=9.5,
        textColor=colors.HexColor("#b71c1c"), leading=13, spaceAfter=6,
        borderColor=colors.HexColor("#b71c1c"), borderWidth=1,
        borderPadding=6, backColor=colors.HexColor("#fdecea"),
    )

    story: list = []
    story.append(Paragraph(_FRIST_TITEL[frist], h1))
    story.append(HRFlowable(width="100%", thickness=1.5, color=PDF_ACCENT,
                            spaceBefore=2, spaceAfter=6))
    story.append(Paragraph(DISCLAIMER_PLAIN, disclaimer))

    # Pflichtangaben-Status — direkt nach dem Disclaimer, weil es die
    # Richtlinienkonformitaet der Meldung auf einen Blick zeigt.
    luecken = meldung_pflicht_luecken(frist, phase_payloads)
    if luecken:
        offen = "; ".join(
            f"{_PHASE_TITEL.get(p, p.value)}: {', '.join(labels)}"
            for p, labels in luecken.items()
        )
        story.append(Paragraph(
            f"<b>Pflichtangaben unvollstaendig.</b> Fuer diese Frist fehlen noch: "
            f"{offen}.",
            ParagraphStyle("warn", parent=body,
                           textColor=colors.HexColor("#b71c1c")),
        ))
    else:
        story.append(Paragraph(
            "<b>Pflichtangaben vollstaendig</b> — alle NIS2-Art.-23-"
            "Pflichtfelder dieser Frist sind ausgefuellt.",
            ParagraphStyle("ok", parent=body,
                           textColor=colors.HexColor("#2e7d32")),
        ))
    story.append(Spacer(1, 0.3 * cm))

    # Vorfall-Kopf.
    story.append(Paragraph("Vorfall", h2))
    for line in _header_block(incident):
        story.append(Paragraph(_md_to_pdf(line), body))

    # Phasen.
    for phase in _FRIST_PHASEN[frist]:
        payload = phase_payloads.get(phase)
        if not payload:
            continue
        rows = _phase_block(phase, payload)
        if not rows:
            continue
        story.append(Paragraph(_PHASE_TITEL.get(phase, phase.value), h2))
        for row in rows[1:]:  # rows[0] ist die Markdown-Ueberschrift "##..."
            story.append(Paragraph(_md_to_pdf(row), body))

    if incident.personenbezug:
        story.append(Paragraph("DSGVO-Hinweis", h2))
        story.append(Paragraph(
            "Personenbezug ist markiert: Pruefen Sie die parallele Meldepflicht "
            "nach DSGVO Art. 33 (Datenschutzbehoerde, binnen 72h ab "
            "Kenntnisnahme).",
            body,
        ))

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        "NoRisk by FINLAI — financial-analytics.eu · Vorlage, keine Meldung.",
        meta,
    ))

    SimpleDocTemplate(
        str(out), pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title=_FRIST_TITEL[frist], author="NoRisk by FINLAI",
    ).build(story)
    return out


def _safe_font(name: str) -> str:
    """Gibt ``name`` zurueck, wenn der Font registriert ist, sonst Helvetica.

    Schuetzt den PDF-Build, falls die Schrift-Assets fehlen (CI/Stripped-Build):
    ein nicht registrierter Font-Name liesse reportlab beim Build crashen.
    """
    from reportlab.pdfbase import pdfmetrics  # noqa: PLC0415

    bold = name.endswith("-Bold")
    return name if name in pdfmetrics.getRegisteredFontNames() else (
        "Helvetica-Bold" if bold else "Helvetica"
    )


def _md_to_pdf(line: str) -> str:
    """Pure: wandelt eine Markdown-Bullet-Zeile in reportlab-Mini-HTML.

    ``- **Label:** Wert`` -> ``<b>Label:</b> Wert``. Reduziert ``**`` zu
    ``<b>``/``</b>`` und entfernt das fuehrende ``- ``. Robust gegen Zeilen ohne
    Markup.
    """
    text = line.lstrip()
    if text.startswith("- "):
        text = text[2:]
    # Escape die wenigen reportlab-relevanten Zeichen, dann ** -> <b>.
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    parts = text.split("**")
    # Ungerade Indizes sind die gefetteten Segmente.
    out = []
    for i, part in enumerate(parts):
        out.append(f"<b>{part}</b>" if i % 2 == 1 else part)
    return "".join(out)


def _header_block(incident: Nis2Incident) -> list[str]:
    """Pure: Vorfall-Kopfdaten als Markdown-Zeilen."""
    detected = incident.detected_at.strftime("%Y-%m-%d %H:%M UTC")
    pb = "Ja" if incident.personenbezug else "Nein"
    return [
        f"- **Vorfall:** {incident.title}",
        f"- **Schweregrad:** {incident.severity.value.upper()}",
        f"- **Kenntnisnahme (UTC):** {detected}",
        f"- **Personenbezug:** {pb}",
        f"- **Aktuelle Phase:** {_PHASE_TITEL.get(incident.current_phase, incident.current_phase.value)}",
    ]


def _phase_block(phase: IncidentPhase, payload: dict) -> list[str]:
    """Pure: eine Phasen-Sektion mit lesbar gelabelten Feldern.

    Args:
        phase: Die Phase (liefert die Sektion-Ueberschrift).
        payload: Die Phasen-Formulardaten.

    Returns:
        Markdown-Zeilen (Ueberschrift + ``- Label: Wert``), leer wenn der
        Payload keine darstellbaren Werte hat.
    """
    rows: list[str] = []
    for key, value in payload.items():
        text = _format_value(value)
        if not text:
            continue
        label = _KEY_LABELS.get(key, key)
        rows.append(f"- **{label}:** {text}")
    if not rows:
        return []
    return [f"## {_PHASE_TITEL.get(phase, phase.value)}", *rows]


def _format_value(value: object) -> str:
    """Pure: rendert einen Payload-Wert lesbar (bool/list/leer beruecksichtigt)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Ja" if value else "Nein"
    if isinstance(value, (list, tuple)):
        items = [str(v).strip() for v in value if str(v).strip()]
        return ", ".join(items)
    text = str(value).strip()
    return text
