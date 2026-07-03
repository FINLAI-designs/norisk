"""
report_generator — Generiert PDF-Security-Reports im FINLAI Dark Theme.

Verwendet core/pdf/pdf_report_builder.py (DarkReportBuilder).
Behält die bestehende SecurityReportGenerator.generate-Schnittstelle.

Sicherheitsdesign (DSGVO):
  - Nur Firmenname, kein personenbezogenes Datum im Report-Inhalt
  - Kein Logging von Report-Inhalt
  - Ausgabepfad wird nicht geloggt

Schichtzugehörigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 2.0 (Dark Theme Redesign)
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from core.logger import get_logger
from core.pdf.pdf_report_builder import DarkReportBuilder
from tools.security_scoring.domain.hardening_score import (
    HardeningScoreResult,
    build_hardening_summary,
)
from tools.security_scoring.domain.models import ScoreComponent, SecurityScore

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Risikostufen-Mapping (Score → Stufe)
# ---------------------------------------------------------------------------
_RISK_THRESHOLDS = [(75.0, "Niedrig"), (55.0, "Mittel"), (35.0, "Hoch")]
_RISK_KRITISCH = "Kritisch"


def _score_to_risk(score: float) -> str:
    """Wandelt Score in Risikostufe um.

    Args:
        score: Numerischer Score 0–100.

    Returns:
        Risikostufe als String.
    """
    for threshold, label in _RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return _RISK_KRITISCH


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


def _build_summary_text(score: SecurityScore) -> str:
    """Generiert einen kurzen Zusammenfassungstext aus dem SecurityScore.

    Args:
        score: SecurityScore-Objekt.

    Returns:
        Zusammenfassungstext (2–3 Sätze).
    """
    risk = _score_to_risk(score.overall_score)
    crit_total = sum(c.findings_critical for c in score.components)
    high_total = sum(c.findings_high for c in score.components)

    text = (
        f"Der Gesamtscore beträgt {score.overall_score:.1f}/100 — Risikostufe: {risk}."
    )
    if crit_total > 0 or high_total > 0:
        text += (
            f" Es wurden {crit_total} kritische und {high_total} hohe Findings gefunden,"
            " die umgehend behoben werden sollten."
        )
    else:
        text += " Es wurden keine kritischen oder hohen Findings gefunden."
    return text


def _component_to_category_score(comp: ScoreComponent) -> dict:
    """Konvertiert eine ScoreComponent in das Category-Score-Dict.

    Args:
        comp: ScoreComponent-Objekt.

    Returns:
        Dict mit "name", "score", "label".
    """
    return {
        "name": comp.name,
        "score": comp.score,
        "label": _score_to_risk(comp.score),
    }


def _component_to_detail_rows(comp: ScoreComponent) -> list[dict]:
    """Konvertiert eine ScoreComponent in Detail-Tabellenzeilen.

    Args:
        comp: ScoreComponent-Objekt.

    Returns:
        Liste von Dicts mit "label", "value", "status".
    """
    risk = _score_to_risk(comp.score)
    rows = [
        {
            "label": "Teilscore",
            "value": f"{comp.score:.1f} / 100",
            "status": risk,
        },
    ]
    if comp.findings_critical > 0:
        rows.append(
            {
                "label": "Kritische Findings",
                "value": str(comp.findings_critical),
                "status": "Kritisch",
            }
        )
    if comp.findings_high > 0:
        rows.append(
            {
                "label": "Hohe Findings",
                "value": str(comp.findings_high),
                "status": "Hoch",
            }
        )
    if comp.findings_medium > 0:
        rows.append(
            {
                "label": "Mittlere Findings",
                "value": str(comp.findings_medium),
                "status": "Mittel",
            }
        )
    if comp.last_scan:
        rows.append(
            {
                "label": "Letzter Scan",
                "value": _format_date(comp.last_scan),
                "status": "ok",
            }
        )
    if comp.weight:
        rows.append(
            {
                "label": "Gewichtung",
                "value": f"{comp.weight * 100:.0f} %",
                "status": "ok",
            }
        )
    return rows


def _build_recommendations(score: SecurityScore) -> list[str]:
    """Generiert Empfehlungs-Strings aus dem SecurityScore.

    Args:
        score: SecurityScore-Objekt.

    Returns:
        Liste von Empfehlungs-Strings.
    """
    recs: list[str] = []
    for comp in score.components:
        if comp.findings_critical > 0:
            recs.append(
                f"[Kritisch] {comp.name}: Kritische Findings beheben — "
                f"{comp.findings_critical} kritische(s) Finding(s) gefunden. "
                "Sofortige Maßnahmen erforderlich."
            )
        if comp.findings_high > 0:
            recs.append(
                f"[Hoch] {comp.name}: Hohe Findings beheben — "
                f"{comp.findings_high} hohe(s) Finding(s). "
                "Zeitnahes Handeln empfohlen."
            )
        if comp.score < 55.0:
            recs.append(
                f"[Mittel] {comp.name}: Score verbessern — "
                f"Aktueller Teilscore: {comp.score:.0f}/100. "
                "Sicherheitsmaßnahmen überprüfen und verstärken."
            )
    if not recs:
        recs.append(
            "[Niedrig] Allgemein: Regelmäßige Überprüfung — "
            "Alle Bereiche sind gut konfiguriert. "
            "Regelmäßige Überprüfung und Aktualisierung der Sicherheitsmaßnahmen empfohlen."
        )
    return recs


# Prioritäts-Reihenfolge für die Sortierung
_SEVERITY_ORDER = {"KRITISCH": 0, "HOCH": 1, "MITTEL": 2}


def _build_priorities(score: SecurityScore) -> list[tuple[str, str]]:
    """Erstellt priorisierte Liste von Findings aus allen Komponenten.

    Args:
        score: SecurityScore-Objekt.

    Returns:
        Liste von (Komponenten-Name, Schweregrad)-Tupeln, sortiert nach Schweregrad
        (KRITISCH zuerst, dann HOCH, dann MITTEL).
    """
    entries: list[tuple[str, str]] = []
    for comp in score.components:
        if comp.findings_critical > 0:
            entries.append((comp.name, "KRITISCH"))
        if comp.findings_high > 0:
            entries.append((comp.name, "HOCH"))
        if comp.findings_medium > 0:
            entries.append((comp.name, "MITTEL"))
    entries.sort(key=lambda e: _SEVERITY_ORDER.get(e[1], 99))
    return entries


# Beschreibungs-Templates pro Tool + Schweregrad
_FINDING_DESCRIPTIONS: dict[tuple[str, str], str] = {
    ("network_scanner", "KRITISCH"): (
        "Kritisch: Gefährliche Ports offen (z.B. RDP Port 3389, Telnet). "
        "Netzwerk-Exposition sofort reduzieren."
    ),
    ("network_scanner", "HOCH"): (
        "Hoch: Mehrere risikoreiche Ports offen. Netzwerk-Firewall überprüfen."
    ),
    ("api_security", "KRITISCH"): (
        "Kritisch: Schwerwiegende API-Sicherheitslücken gefunden (OWASP API Top 10)."
    ),
    ("api_security", "HOCH"): (
        "Hoch: Sicherheitsrelevante API-Konfigurationsprobleme gefunden."
    ),
    ("cert_monitor", "KRITISCH"): (
        "Kritisch: Zertifikate abgelaufen oder TLS 1.0/1.1 aktiv."
    ),
    ("password_checker", "KRITISCH"): (
        "Kritisch: Passwort-Policy nicht erfüllt (BSI/NIST-Mindestanforderungen)."
    ),
}


def _finding_description(tool_name: str, severity: str, count: int) -> str:
    """Erstellt eine lesbare Beschreibung für ein Finding.

    Args:
        tool_name: Interner Tool-Name (z.B. ``"network_scanner"``).
        severity: Schweregrad-String (z.B. ``"KRITISCH"``).
        count: Anzahl der Findings.

    Returns:
        Beschreibungstext für das Finding.
    """
    key = (tool_name, severity)
    if key in _FINDING_DESCRIPTIONS:
        return _FINDING_DESCRIPTIONS[key]
    return f"{count} {severity}-Finding(s) in {tool_name} gefunden."


# ---------------------------------------------------------------------------
# Haupt-Generator-Klasse
# ---------------------------------------------------------------------------


class SecurityReportGenerator:
    """Erstellt PDF-Security-Reports im FINLAI Dark Theme aus SecurityScore-Daten.

    Behält die bestehende Schnittstelle bei:
        generator = SecurityReportGenerator
        generator.generate(score, output_path, verlauf=verlauf)
    """

    def generate(
        self,
        score: SecurityScore,
        output_path: str,
        verlauf: list[SecurityScore] | None = None,
        include_details: bool = True,
        hardening: HardeningScoreResult | None = None,
        compliance_table: list[list[str]] | None = None,
        compliance_disclaimer: str = "",
    ) -> None:
        """Generiert den PDF-Report im FINLAI Dark Theme.

        Args:
            score: Berechneter SecurityScore.
            output_path: Zieldateipfad (.pdf).
            verlauf: Optionale Score-Historie (aktuell nicht in PDF verwendet).
            include_details: Ob Detail-Seiten pro Komponente eingefügt werden.
            hardening: Optionales HardeningScoreResult. Ist es
                gesetzt, zeigt die Executive-Summary den kanonischen
                Hardening-Score (Zahl + Stufe) statt des Legacy-Scores;
                die Schulnote A–F bleibt als Sekundaer-Angabe erhalten
 §8). ``None`` → reiner Legacy-Pfad (Backwards-
                Compat fuer Aufrufer ohne Hardening, z. B. AssessmentWizard).

        Raises:
            OSError: Wenn die Ausgabedatei nicht geschrieben werden kann.
        """
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        date_str = _format_date(score.timestamp)

        # Executive-Summary zeigt den kanonischen Hardening-Score,
        # falls vorhanden — sonst den Legacy-Score (Backwards-Compat).
        if hardening is not None:
            summary_score = hardening.overall_score
            # Risiko-Label + Gauge-Farbe aus dem numerischen Score ableiten
            # (deutsche Stufen) — ``risk_color`` im PDF-Builder mappt nur
            # deutsche Begriffe; der englische Hardening-Stage ("Secure"
            # etc.) erscheint stattdessen im Summary-Text.
            risk_level = _score_to_risk(hardening.overall_score)
            summary_text = (
                f"{build_hardening_summary(hardening)}. "
                f"Schulnote (Detailbewertung): {score.grade}."
            )
        else:
            summary_score = score.overall_score
            risk_level = _score_to_risk(score.overall_score)
            summary_text = _build_summary_text(score)

        builder = DarkReportBuilder(
            output_path=output_path,
            title="Security Assessment Report",
            subtitle="NoRisk by FINLAI",
            company=score.target_name,
        )

        # Deckblatt
        builder.add_cover(
            date_str=date_str,
            report_id=score.id[:8].upper() if score.id else "",
        )

        # Executive Summary — nur bewertete Komponenten. Eine Komponente ohne
        # Daten (data_available=False, z.B. CVE-Exposition ohne Techstack-Scan)
        # wuerde sonst als "0/100 kritisch" rendern und den Kunden glauben
        # lassen, es gaebe ein kritisches Risiko — tatsaechlich fehlt nur der
        # Scan. Der Gesamtscore ignoriert diese Komponenten bereits.
        category_scores = [
            _component_to_category_score(c)
            for c in score.components
            if c.data_available
        ]
        builder.add_executive_summary(
            overall_score=summary_score,
            risk_level=risk_level,
            category_scores=category_scores,
            summary_text=summary_text,
        )

        # Detail-Seiten — ebenfalls nur bewertete Komponenten (s.o.).
        if include_details:
            for comp in score.components:
                if not comp.data_available:
                    continue
                comp_risk = _score_to_risk(comp.score)
                rows = _component_to_detail_rows(comp)
                builder.add_category_details(
                    category_name=comp.name,
                    category_score=comp.score,
                    category_risk=comp_risk,
                    rows=rows,
                )

        # Handlungsempfehlungen
        builder.add_recommendations(_build_recommendations(score))

        # W3: indikative Regulatorik-Sektion (primitive Tabelle aus der
        # application-Schicht durchgereicht — data importiert KEINE application).
        if compliance_table:
            builder.add_compliance_section(
                "Regulatorik-Bezug (indikativ) — ENTWURF",
                compliance_disclaimer,
                compliance_table,
            )

        # Abschlussseite
        builder.add_footer_page()
        builder.build()

        log.debug(
            "PDF-Report generiert: %s, %d Komponenten",
            score.target_name,
            len(score.components),
        )
