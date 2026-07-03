"""
ir_plan_generator — Erstellt das Notfallhandbuch aus dem IR-Plan-Eintrag.

Zwei Ausgabe-Formate:
- **Markdown** (Default) — leichtgewichtig, direkt im Brain / Kanzlei-Wiki
  ablegbar.
- **PDF** (optional, wenn ``reportlab`` verfuegbar ist) — fuer formale
  Ablage / Audit-Nachweis.

Inhalt:
1. Stammdaten + Audit-Zeitstempel
2. Koordinator + Eskalationskette
3. Kritische Systeme
4. Backup-Verweis (Iter 1a)
5. Externer Forensik-Vendor
6. Cyber-Versicherung
7. Letzte Notfall-Uebung + Erkenntnisse
8. 6-Phasen-Checkliste (BSI DER.2.1 + NIST RS/RC)
9. Meldepflicht-Vorlagen: DSGVO Art. 33 (72h), Art. 34 (Mandanten),
   NIS2 Art. 23 (24h), §43e BRAO

Schichtzugehoerigkeit: application/ — darf domain importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from core.logger import get_logger
from tools.customer_audit.domain.entities import (
    IR_PHASEN,
    CustomerAuditResult,
    IncidentResponsePlan,
)

_log = get_logger(__name__)


_DSGVO_MELDUNG_TEMPLATE = """\
## Meldung-Template: DSGVO Art. 33 — Verletzung des Schutzes personenbezogener Daten

Frist: **innerhalb von 72 Stunden** nach Bekanntwerden des Vorfalls.

Empfaenger:
- **Deutschland:** zustaendige Landesdatenschutzbehoerde
  (https://www.bfdi.bund.de → "Aufsichtsbehoerden in den Laendern")
- **Oesterreich:** Datenschutzbehoerde, dsb@dsb.gv.at,
  https://www.dsb.gv.at

Pflichtangaben:
1. Art der Verletzung (Beschreibung, Zeitpunkt der Entdeckung)
2. Kategorien + Anzahl der betroffenen Personen + Datensaetze
3. Wahrscheinliche Folgen
4. Getroffene/geplante Massnahmen
5. Name + Kontakt des Datenschutzbeauftragten

**HINWEIS:** Bei vorsaetzlich verletzten Mandantengeheimnissen
(§ 203 StGB) ggf. auch Strafanzeige.
"""

_MANDANTEN_TEMPLATE = """\
## Mandanten-Benachrichtigung: DSGVO Art. 34

Pflicht **wenn voraussichtlich hohes Risiko** fuer die Rechte und
Freiheiten der Betroffenen.

Inhalt (in klarer + einfacher Sprache):
- Was ist passiert?
- Welche Daten waren betroffen?
- Welche Folgen koennen das fuer mich haben?
- Was hat die Kanzlei dagegen unternommen?
- Was sollte ich selbst tun?
- Kontaktstelle in der Kanzlei + DSB

Versand: einzeln per Brief / sicher gehostete Mail.
"""

_NIS2_TEMPLATE = """\
## NIS2-Fruehwarn-Meldung (Art. 23, falls Kanzlei NIS2-pflichtig)

Frist:
- **24 Stunden** Fruehwarnung
- **72 Stunden** detaillierte Meldung
- **1 Monat** Abschlussbericht

Pflichtig: Kanzleien typischerweise NICHT direkt (zu klein), aber als
Lieferant fuer NIS2-pflichtige Mandanten ggf. ueber Lieferketten-
Klauseln getroffen.

Empfaenger:
- **Deutschland:** BSI ueber das Meldeportal
  https://meldeportal.bsi.bund.de
- **Oesterreich:** GovCERT (govcert@govcert.gv.at) oder CERT.at
"""

_RAK_TEMPLATE = """\
## Rechtsanwaltskammer-Meldung (Berufsrechtspflicht)

Bei Verletzung der Verschwiegenheitspflicht (§ 43e BRAO / § 9 RAO) ist
eine Meldung an die zustaendige Rechtsanwaltskammer in Erwaegung zu
ziehen — sowohl zur Schadensbegrenzung als auch zur Dokumentation der
Sorgfaltspflicht.

Empfaenger:
- **Deutschland:** zustaendige regionale Rechtsanwaltskammer
- **Oesterreich:** zustaendige Rechtsanwaltskammer
  (https://www.rechtsanwaelte.at)
"""


def render_plan_markdown(
    plan: IncidentResponsePlan,
    *,
    firmenname: str = "",
    audit_id: str = "",
) -> str:
    """Erzeugt das Notfallhandbuch als Markdown.

    Args:
        plan: Fragebogen-Eingaben.
        firmenname: Optional, fuer Kopfzeile.
        audit_id: Optional, fuer Querverweis.

    Returns:
        Markdown-String. Direkt in eine Datei schreibbar.
    """
    today = datetime.now(UTC).date().isoformat()
    title = f"# Incident-Response-Plan{' — ' + firmenname if firmenname else ''}"
    audit_ref = f"_Audit-ID: {audit_id}_  \n" if audit_id else ""

    lines = [
        title,
        "",
        f"{audit_ref}_Stand: {today}_",
        "",
        "## 1. Koordinator",
        "",
        f"- Name: **{plan.coordinator_name or '—'}**",
        f"- Kontakt: {plan.coordinator_contact or '—'}",
        "",
        "## 2. Eskalationskette",
        "",
    ]
    if plan.escalation_chain:
        lines.extend(f"- {ch}" for ch in plan.escalation_chain)
    else:
        lines.append("_(keine Empfaenger ausgewaehlt)_")

    lines += [
        "",
        "## 3. Kritische Systeme",
        "",
        plan.critical_systems or "_(nicht ausgefuellt)_",
        "",
        "## 4. Backup-Verweis",
        "",
        plan.backup_location_ref or "_(nicht ausgefuellt — siehe Backup-Audit)_",
        "",
        "## 5. Externer Forensik-Dienstleister",
        "",
        f"- Vendor: {plan.forensic_vendor or '_nicht kontraktiert_'}",
        f"- Kontakt: {plan.forensic_vendor_contact or '—'}",
        "",
        "## 6. Cyber-Versicherung",
        "",
        f"- Vorhanden: {'Ja' if plan.cyber_insurance else 'Nein'}",
        f"- Police: {plan.cyber_insurance_policy or '—'}",
        "",
        "## 7. Letzte Notfall-Uebung",
        "",
        f"- Datum: {plan.last_drill_date or '_noch nie geuebt_'}",
        f"- Erkenntnisse: {plan.drill_findings or '—'}",
        "",
        "## 8. 6-Phasen-Checkliste (BSI DER.2.1 + NIST RS/RC)",
        "",
    ]
    for i, phase in enumerate(IR_PHASEN, start=1):
        lines.append(f"{i}. **{phase}**")
        lines.append("   - Owner: ____________________")
        lines.append("   - Time-Box: ____________________")

    lines += [
        "",
        "## 9. Meldepflicht-Vorlagen",
        "",
        _DSGVO_MELDUNG_TEMPLATE,
        "",
        _MANDANTEN_TEMPLATE,
        "",
        _NIS2_TEMPLATE,
        "",
        _RAK_TEMPLATE,
    ]
    return "\n".join(lines)


def render_plan_from_result(result: CustomerAuditResult) -> str:
    """Convenience-Wrapper: rendert direkt aus einem ``CustomerAuditResult``."""
    return render_plan_markdown(
        result.incident_response_plan,
        firmenname=result.customer_data.firmenname,
        audit_id=result.audit_id,
    )


def export_plan(
    plan: IncidentResponsePlan,
    output_path: Path,
    *,
    fmt: Literal["markdown", "pdf"] = "markdown",
    firmenname: str = "",
    audit_id: str = "",
) -> bool:
    """Schreibt den Plan in eine Datei.

    Args:
        plan: Fragebogen-Eingaben.
        output_path: Zielpfad. ``.md`` oder ``.pdf`` je nach ``fmt``.
        fmt: ``"markdown"`` (Default) oder ``"pdf"`` (braucht
            ``reportlab``).
        firmenname: Optional, fuer Kopfzeile.
        audit_id: Optional, fuer Querverweis.

    Returns:
        ``True`` bei Erfolg, ``False`` bei Fehlern (geloggt).
    """
    md = render_plan_markdown(plan, firmenname=firmenname, audit_id=audit_id)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if fmt == "markdown":
            output_path.write_text(md, encoding="utf-8")
            return True
        if fmt == "pdf":
            return _export_pdf(md, output_path, firmenname=firmenname)
        raise ValueError(f"Unbekanntes Format: {fmt}")
    except Exception as exc:  # noqa: BLE001 -- Plan-Export darf nie crashen
        _log.warning("IR-Plan-Export fehlgeschlagen (fmt=%s): %s", fmt, exc)
        return False


def _export_pdf(markdown_text: str, output_path: Path, *, firmenname: str) -> bool:
    """Schreibt ein einfaches PDF aus Markdown-Text.

    Nicht-Markdown-Renderer (kein Zeilen-Wrap-Highlight) — bewusst
    minimalistisch. Fuer ein hochwertiges PDF kann der Anwender den
    Markdown-Output durch Pandoc o. ae. schicken.
    """
    try:
        from reportlab.lib.pagesizes import A4  # noqa: PLC0415
        from reportlab.lib.styles import getSampleStyleSheet  # noqa: PLC0415
        from reportlab.lib.units import cm  # noqa: PLC0415
        from reportlab.platypus import (  # noqa: PLC0415
            Paragraph,
            SimpleDocTemplate,
            Spacer,
        )
    except ImportError:
        _log.warning(
            "PDF-Export uebersprungen — ``reportlab`` nicht verfuegbar."
        )
        return False

    # reportlab Paragraph parst ``<...>`` als XML — User-Input mit ``<``
    # bricht den Export, "<script>" wuerde gerendert. Escapen.
    #/: zentrale Hilfe statt saxutils (identische Zeichen-
    # menge plus Quotes — Superset, fuer Paragraph-Inhalte unschaedlich).
    from core.escape import escape_html as xml_escape  # noqa: PLC0415

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        # PDF-DocInfo-Titel ist Plaintext-METADATUM (kein XML-Kontext) —
        # Entities würden dort literal erscheinen-Review).
        title=f"IR-Plan {firmenname}",
    )
    styles = getSampleStyleSheet()
    story = []
    for line in markdown_text.splitlines():
        if line.startswith("# "):
            story.append(Paragraph(xml_escape(line[2:]), styles["Title"]))
        elif line.startswith("## "):
            story.append(Paragraph(xml_escape(line[3:]), styles["Heading2"]))
        elif line.strip():
            story.append(
                Paragraph(
                    xml_escape(line.replace("**", "")),
                    styles["BodyText"],
                )
            )
        else:
            story.append(Spacer(1, 0.3 * cm))
    doc.build(story)
    return True
