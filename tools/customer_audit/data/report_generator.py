"""
report_generator — PDF-Report-Generator für das Kunden-Assessment.

Erstellt Dark-Theme-Reports aus CustomerAuditResult-Objekten.
Verwendet core/pdf/pdf_report_builder.py (DarkReportBuilder).

Schichtzugehörigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from core.escape import escape_html
from core.logger import get_logger
from core.pdf.pdf_report_builder import DarkReportBuilder
from tools.customer_audit.domain.entities import CustomerAuditResult
from tools.customer_audit.domain.risk_entities import (
    DEFAULT_RISK_CATALOG_BY_KEY,
    RiskAssessment,
    RiskLevel,
)

log = get_logger(__name__)


def _escape_rows(rows: list[dict]) -> list[dict]:
    """Escaped ``label``/``value`` aller Detail-Zeilen für ReportLab.

/: Die DB liefert Klartext; der DarkReportBuilder rendert
    ``label``/``value`` als ``Paragraph`` (XML-Kontext — ein rohes ``<``
    crasht den Export oder injiziert Markup). ``status`` ist ein interner
    Enum-Wert und bleibt unangetastet. Der Builder selbst escaped bewusst
    NICHT (andere Tools übergeben absichtlich Markup, z.B. ``<b>``).

    Args:
        rows: Zeilen im ``add_category_details``-Format.

    Returns:
        Neue Liste mit escapten ``label``/``value``-Werten.
    """
    return [
        {**row, "label": escape_html(row["label"]), "value": escape_html(row["value"])}
        for row in rows
    ]


def _format_date(iso_ts: str) -> str:
    """Formatiert einen ISO-Timestamp als deutsches Datum.

    Args:
        iso_ts: ISO-Timestamp-String.

    Returns:
        Deutsches Datum (TT.MM.JJJJ) oder originaler String bei Fehler.
    """
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return dt.strftime("%d.%m.%Y")
    except (ValueError, AttributeError):
        return iso_ts[:10] if len(iso_ts) >= 10 else iso_ts


def _build_infra_rows(result: CustomerAuditResult) -> list[dict]:
    """Erstellt Detail-Tabellenzeilen für IT-Infrastruktur.

    Args:
        result: CustomerAuditResult.

    Returns:
        Zeilen-Liste für add_category_details.
    """
    infra = result.infrastructure_data
    rows = []

    if infra.betriebssysteme:
        rows.append(
            {
                "label": "Betriebssysteme",
                "value": ", ".join(infra.betriebssysteme),
                "status": "ok",
            }
        )
    rows.append(
        {
            "label": "Antivirus",
            "value": infra.antivirus_name or "—",
            "status": infra.antivirus_status,
        }
    )
    rows.append(
        {
            "label": "AV-Status",
            "value": infra.antivirus_status,
            "status": infra.antivirus_status,
        }
    )
    rows.append(
        {
            "label": "Firewall",
            "value": infra.firewall_name or "—",
            "status": infra.firewall_status,
        }
    )
    rows.append(
        {
            "label": "FW-Status",
            "value": infra.firewall_status,
            "status": infra.firewall_status,
        }
    )
    if infra.verschluesselung:
        rows.append(
            {
                "label": "Verschlüsselung",
                "value": ", ".join(infra.verschluesselung),
                "status": "aktiv"
                if "Keine" not in infra.verschluesselung
                else "inaktiv",
            }
        )
    if infra.vpn_loesung:
        rows.append({"label": "VPN", "value": infra.vpn_loesung, "status": "ok"})
    if infra.remote_access_tools:
        risky = [
            t
            for t in infra.remote_access_tools
            if t in {"TeamViewer", "AnyDesk", "VNC"}
        ]
        status = "Hoch" if risky else "ok"
        rows.append(
            {
                "label": "Remote-Access",
                "value": ", ".join(infra.remote_access_tools),
                "status": status,
            }
        )
    return rows


def _build_org_rows(result: CustomerAuditResult) -> list[dict]:
    """Erstellt Detail-Tabellenzeilen für organisatorische Sicherheit.

    Args:
        result: CustomerAuditResult.

    Returns:
        Zeilen-Liste für add_category_details.
    """
    org = result.organizational_data
    fields = [
        ("Zugangskontrollen", org.zugangskontrollen),
        ("Backup-Strategie", org.backup_strategie),
        ("Update-Management", org.update_management),
        ("Mitarbeitersensibilisierung", org.mitarbeitersensibilisierung),
        ("Incident-Response-Plan", org.incident_response_plan),
        ("DSGVO-Konformität", org.dsgvo_konformitaet),
    ]
    return [{"label": lbl, "value": val, "status": val} for lbl, val in fields]


def _build_network_rows(result: CustomerAuditResult) -> list[dict]:
    """Erstellt Detail-Tabellenzeilen für Netzwerksicherheit.

    Args:
        result: CustomerAuditResult.

    Returns:
        Zeilen-Liste für add_category_details.
    """
    net = result.network_data
    wlan_status = (
        "aktiv"
        if net.wlan_sicherheit in ("WPA3", "WPA2")
        else "Kritisch"
        if net.wlan_sicherheit in ("WEP", "Offen")
        else "unbekannt"
    )
    return [
        {
            "label": "Netzwerksegmentierung",
            "value": net.netzwerksegmentierung,
            "status": net.netzwerksegmentierung,
        },
        {
            "label": "WLAN-Sicherheit",
            "value": net.wlan_sicherheit,
            "status": wlan_status,
        },
        {
            "label": "Offene Ports bekannt",
            "value": net.offene_ports_bekannt,
            "status": net.offene_ports_bekannt,
        },
        {
            "label": "IDS/IPS vorhanden",
            "value": net.ids_ips_vorhanden,
            "status": net.ids_ips_vorhanden,
        },
        {
            "label": "Letzter Pentest",
            "value": net.letzter_pentest,
            "status": "ok"
            if net.letzter_pentest not in ("Nie", "Unbekannt")
            else "unbekannt",
        },
    ]


def _build_backup_rows(result: CustomerAuditResult) -> list[dict]:
    """Detail-Tabellenzeilen fuer Backup-Audit."""
    b = result.backup_audit
    rule = b.rule_3_2_1_1_0
    rule_summary = ", ".join(
        f"{k}={'Ja' if v else 'Nein'}" for k, v in rule.items()
    ) if rule else "—"
    return [
        {
            "label": "Detection aktiv",
            "value": "Ja" if b.detection_enabled else "Nein",
            "status": "ok" if b.detection_enabled else "unbekannt",
        },
        {
            "label": "Erkannte Tools",
            "value": ", ".join(b.detected_tools) if b.detected_tools else "—",
            "status": "ok" if b.detected_tools else "Nein",
        },
        {
            "label": "3-2-1-1-0",
            "value": rule_summary,
            "status": "ok" if rule and all(rule.values()) else "Teilweise",
        },
        {
            "label": "RPO / RTO",
            "value": (
                f"{b.rpo_hours or '—'} h / {b.rto_hours or '—'} h"
            ),
            "status": "ok" if b.rpo_hours and b.rto_hours else "Teilweise",
        },
        {
            "label": "Verschluesselung",
            "value": "Ja" if b.encryption_enabled else "Nein",
            "status": "ok" if b.encryption_enabled else "Nein",
        },
        {
            "label": "Letzter Restore-Test",
            "value": b.last_restore_test or "Nie",
            "status": "ok" if b.last_restore_test else "Kritisch",
        },
    ]


def _build_sovereignty_rows(result: CustomerAuditResult) -> list[dict]:
    """Detail-Tabellenzeilen fuer Datensouveraenitaet."""
    s = result.sovereignty_audit
    rows: list[dict] = [
        {
            "label": "Detection aktiv",
            "value": "Ja" if s.detection_enabled else "Nein",
            "status": "ok" if s.detection_enabled else "unbekannt",
        },
        {
            "label": "Domain",
            "value": s.domain or "—",
            "status": "ok" if s.domain else "unbekannt",
        },
    ]
    # Erkannte Provider mit Status-Hinweis
    all_providers = list(s.detected) + list(s.declared)
    for prov in all_providers[:10]:  # max 10 Eintraege im Report
        rows.append(
            {
                "label": f"{prov.name} ({prov.category})",
                "value": prov.via,
                "status": (
                    "Kritisch" if prov.status == "cloud_act"
                    else "Teilweise" if prov.status == "eu_boundary"
                    else "ok"
                ),
            }
        )
    # Erste 2 Rechtshinweise als eigene Zeilen
    for hint in s.rechtshinweise[:2]:
        rows.append(
            {
                "label": "Berufsrechts-Hinweis",
                "value": hint[:80] + ("…" if len(hint) > 80 else ""),
                "status": "Kritisch",
            }
        )
    return rows


def _build_incident_rows(result: CustomerAuditResult) -> list[dict]:
    """Detail-Tabellenzeilen fuer IR-Plan."""
    p = result.incident_response_plan
    return [
        {
            "label": "Koordinator",
            "value": (
                f"{p.coordinator_name} · {p.coordinator_contact}"
                if p.coordinator_name else "—"
            ),
            "status": "ok" if p.coordinator_name else "Kritisch",
        },
        {
            "label": "Eskalationskette",
            "value": (
                f"{len(p.escalation_chain)} Stellen"
                if p.escalation_chain else "Keine"
            ),
            "status": (
                "ok" if len(p.escalation_chain) >= 3
                else "Teilweise" if p.escalation_chain
                else "Kritisch"
            ),
        },
        {
            "label": "Kritische Systeme",
            "value": (p.critical_systems[:60] + "…") if len(p.critical_systems) > 60 else (p.critical_systems or "—"),
            "status": "ok" if p.critical_systems else "Kritisch",
        },
        {
            "label": "Forensik-Vendor",
            "value": p.forensic_vendor or "—",
            "status": "ok" if p.forensic_vendor else "unbekannt",
        },
        {
            "label": "Cyber-Versicherung",
            "value": (
                "Ja: " + p.cyber_insurance_policy
                if p.cyber_insurance and p.cyber_insurance_policy
                else "Ja" if p.cyber_insurance
                else "Nein"
            ),
            "status": "ok" if p.cyber_insurance else "Teilweise",
        },
        {
            "label": "Letzte Uebung",
            "value": p.last_drill_date or "Nie",
            "status": "ok" if p.last_drill_date else "Kritisch",
        },
    ]


def _build_summary_text(result: CustomerAuditResult) -> str:
    """Generiert einen kurzen Zusammenfassungstext.

    Args:
        result: CustomerAuditResult.

    Returns:
        Zusammenfassungstext (2–3 Sätze).
    """
    rec_count = len(result.recommendations)
    critical_recs = sum(1 for r in result.recommendations if r.startswith("[Kritisch]"))
    from tools.customer_audit.domain.entities import AuditMode  # noqa: PLC0415

    mode_text = (
        "Selbst-Audit der eigenen Kanzlei"
        if result.audit_mode == AuditMode.SELF
        # Firmenname ist Freitext — Summary landet in ReportLab-Paragraph
        # (XML-Kontext): escapen.
        else f"Kunden-Audit fuer {escape_html(result.customer_data.firmenname)}"
    )
    text = (
        f"{mode_text}. Der Gesamtscore betraegt "
        f"{result.overall_score:.1f}/100 — Risikostufe: {result.risk_level}."
    )
    if critical_recs > 0:
        text += (
            f" Es wurden {critical_recs} kritische Handlungsempfehlung(en) identifiziert,"
            " die umgehend umgesetzt werden sollten."
        )
    elif rec_count > 0:
        text += (
            f" Es wurden {rec_count} Handlungsempfehlung(en) generiert."
            " Bitte prüfen Sie die Empfehlungen im Detailbereich."
        )
    else:
        text += " Alle bewerteten Bereiche erfüllen die Mindestanforderungen."
    return text


_RISK_LEVEL_PDF_LABELS: dict[RiskLevel, str] = {
    RiskLevel.GERING: "gering",
    RiskLevel.MITTEL: "mittel",
    RiskLevel.HOCH: "hoch",
    RiskLevel.SEHR_HOCH: "sehr hoch",
}


def _build_risk_rows(risk_assessments: list[RiskAssessment]) -> list[dict]:
    """Baut die Detail-Zeilen fuer die Risiko-Bewertungs-Sektion.

    Format folgt dem ``add_category_details``-Pattern: ``label`` / ``value`` /
    ``status``. ``status`` wird vom DarkReportBuilder farblich behandelt
    (z. B. rot bei "Hoch", gruen bei "ok").
    """
    rows: list[dict] = []
    # Sortierung: hoechste Scores zuerst, dann nach Titel
    sorted_risks = sorted(
        risk_assessments,
        key=lambda a: (
            -(a.probability.value * a.impact.value),
            a.display_title(DEFAULT_RISK_CATALOG_BY_KEY),
        ),
    )
    for assessment in sorted_risks:
        title = assessment.display_title(DEFAULT_RISK_CATALOG_BY_KEY)
        level_label = _RISK_LEVEL_PDF_LABELS[assessment.level]
        value_parts = [
            f"Eintritt: {assessment.probability.label}",
            f"Schaden: {assessment.impact.label}",
        ]
        if assessment.is_accepted:
            value_parts.append("akzeptiert")
        if assessment.notes:
            note_excerpt = assessment.notes.splitlines()[0]
            if len(note_excerpt) > 80:
                note_excerpt = note_excerpt[:77] + "..."
            value_parts.append(f"Notiz: {note_excerpt}")
        # Status-Spalte: vom DarkReportBuilder farblich behandelt.
        # Akzeptierte Risiken bekommen "ok" — der User hat die Entscheidung
        # bewusst getroffen, der PDF-Report soll sie nicht rot markieren.
        if assessment.is_accepted:
            status = "ok"
        else:
            status = {
                RiskLevel.GERING: "ok",
                RiskLevel.MITTEL: "mittel",
                RiskLevel.HOCH: "Hoch",
                RiskLevel.SEHR_HOCH: "Kritisch",
            }[assessment.level]
        rows.append(
            {
                "label": f"{title} ({level_label})",
                "value": " | ".join(value_parts),
                "status": status,
            }
        )
    return rows


def _calculate_risk_section_score(
    risk_assessments: list[RiskAssessment],
) -> tuple[float, str]:
    """Synthetischer Score fuer die Risiko-Sektion (0..100) + Risiko-Label.

    Logik: Anteil der "handled" Risiken — d. h. GERING ODER explizit
    akzeptiert (User hat bewusst entschieden, das Risiko zu tragen).

    Returns:
        ``(score, risk_label)``. Bei leerer Liste: ``(0.0, "Info")``.
    """
    if not risk_assessments:
        return (0.0, "Info")
    handled = sum(
        1
        for a in risk_assessments
        if a.level is RiskLevel.GERING or a.is_accepted
    )
    score = (handled / len(risk_assessments)) * 100.0
    # Label nach Customer-Audit-Konvention.
    if score >= 80:
        label = "Niedrig"
    elif score >= 60:
        label = "Mittel"
    elif score >= 40:
        label = "Hoch"
    else:
        label = "Kritisch"
    return (score, label)


class CustomerReportGenerator:
    """Erstellt PDF-Reports für Kunden-Assessments im FINLAI Dark Theme.

    Verwendet DarkReportBuilder aus core/pdf/pdf_report_builder.py.
    """

    def generate(
        self,
        result: CustomerAuditResult,
        output_path: str | Path,
        *,
        risk_assessments: list[RiskAssessment] | None = None,
        risk_matrix_png: bytes | None = None,
        hardening_score: float | None = None,
        hardening_herkunft: str = "",
    ) -> Path:
        """Generiert den PDF-Report für ein Kunden-Assessment.

        Args:
            result: Vollständiges CustomerAuditResult.
            output_path: Zieldateipfad (.pdf).

        Returns:
            Pfad zur erzeugten PDF-Datei.

        Raises:
            OSError: Wenn die Ausgabedatei nicht geschrieben werden kann.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        date_str = _format_date(result.created_at)
        report_id = result.audit_id[:8].upper() if result.audit_id else ""

        builder = DarkReportBuilder(
            output_path=output_path,
            title="Security Assessment Report",
            subtitle="NoRisk by FINLAI",
            # Freitext → Cover-Paragraph (XML-Kontext): escapen
            company=escape_html(result.customer_data.firmenname),
        )

        # Deckblatt
        builder.add_cover(date_str=date_str, report_id=report_id)

        # Risikomatrix an Position 1 — direkt nach dem Deckblatt als erster
        # visueller Risiko-Ueberblick (Patrick 2026-06-30). Das Bild wird in der
        # application-Schicht gerendert + als Bytes uebergeben Phase D);
        # die data-Schicht bettet nur ein.
        if risk_matrix_png:
            builder.add_image(
                risk_matrix_png,
                caption=(
                    "BSI-200-3-Risikomatrix — "
                    "Eintrittswahrscheinlichkeit x Schadenshöhe"
                ),
            )

        # Executive Summary
        category_scores = [s.to_dict() for s in result.category_scores]
        builder.add_executive_summary(
            overall_score=result.overall_score,
            risk_level=result.risk_level,
            category_scores=category_scores,
            summary_text=_build_summary_text(result),
        )

        # Kategorie-Details
        for cat in result.category_scores:
            if cat.name == "IT-Infrastruktur":
                rows = _build_infra_rows(result)
            elif cat.name == "Organisatorische Sicherheit":
                rows = _build_org_rows(result)
            elif cat.name == "Netzwerksicherheit":
                rows = _build_network_rows(result)
            elif cat.name == "Backup-Audit":
                rows = _build_backup_rows(result)
            elif cat.name == "Datensouveraenitaet":
                rows = _build_sovereignty_rows(result)
            elif cat.name == "Incident-Response-Plan":
                rows = _build_incident_rows(result)
            else:
                rows = []
            builder.add_category_details(
                category_name=cat.name,
                category_score=cat.score,
                category_risk=cat.label,
                rows=_escape_rows(rows),
            )

        # Iter 2e-ii: Risiko-Bewertung (BSI 200-3) als eigene Sektion.
        # Score ist synthetisch (Anteil "handled" Risiken).
        if risk_assessments:
            risk_score, risk_label = _calculate_risk_section_score(risk_assessments)
            builder.add_category_details(
                category_name="Risiko-Bewertung (BSI 200-3)",
                category_score=risk_score,
                category_risk=risk_label,
                rows=_escape_rows(_build_risk_rows(risk_assessments)),
            )

        # Phase D: Sicherheits-Scoring (Messung/Erfassung) als Sektion —
        # ergibt den kombinierten Kunden-Report (Audit + Scoring in EINEM Dokument).
        if hardening_score is not None:
            builder.add_category_details(
                category_name="Sicherheits-Scoring (Messung)",
                category_score=hardening_score,
                category_risk=(hardening_herkunft or "erfasst"),
                rows=_escape_rows(
                    [
                        {
                            "label": "Hardening-Score",
                            "value": f"{hardening_score:.0f}/100",
                            "status": "ok",
                        },
                        {
                            "label": "Herkunft",
                            "value": hardening_herkunft or "erfasst",
                            "status": "ok",
                        },
                    ]
                ),
            )

        # Handlungsempfehlungen (koennen Freitext-Fragmente tragen) — Builder
        # rendert sie als Paragraph: escapen
        builder.add_recommendations(
            [escape_html(r) for r in result.recommendations]
        )

        # Abschlussseite
        builder.add_footer_page()
        saved_path = builder.build()

        # DSGVO: Firmennamen NICHT loggen (Anwaltsgeheimnis).
        log.info(
            "Kunden-Audit PDF generiert: %s",
            result.audit_id[:8] if result.audit_id else "(no-id)",
        )
        return saved_path
