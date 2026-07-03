"""
security_findings — App-Ergebnis-Kontext für den vereinten FINLAI-Assistenten.

Der Chatbot ist bewusst NON-AGENTIC (kein Tool-/Function-Calling — technisch
nicht vorgesehen). Damit er den Nutzer bei der Beurteilung seiner eigenen
Sicherheitswerte unterstützen kann („Ist ein Score von 83 schlecht?"), werden
die aktuellen Ergebnisse als GEPRÜFTER DATENBLOCK (RAG-artiges Spotlighting) vor
dem EINEN Ollama-Aufruf eingebettet — genau wie die Handbuch-/Korpus-Quellen.
Diese Datei definiert die tool-freien, unveränderlichen DTOs, das
Provider-Protocol und den kompakten Formatter.

Bewusste Leitplanken:

* **Zwei GETRENNTE Dimensionen** (Audit = Selbsteinschätzung, Hardening =
  Messung) — NIEMALS zu einem Mischwert verrechnet. Der Bundle trägt kein
  ``combined_score``, der Formatter mittelt nicht.
* **SELF-only** — die Werte beschreiben ausschließlich das eigene System des
  Nutzers. Der Adapter am Composition-Root (apps/) löst SELF intern auf und
  speist NIE Kunden-Daten (``AuditMode.CUSTOMER``) ein.
* **PII-frei** — kein Firmenname/Kontakt, nur technische Kennzahlen/Labels.
* **Kompakt** — ein knapper, vorformatierter Block, damit das lokale
  gemma3:4b-Modell fokussiert bleibt (kein Roh-Dump).

Schichtzugehörigkeit: core/ — reine, unveränderliche Datenklassen + reine
Formatierung, keine I/O, KEIN Import aus ``tools/`` (R5). Die Tool-Reads und das
Bundle-Bauen (inkl. SELF-Auflösung) liegen am Composition-Root (apps/), der die
Tool-Ergebnisse auf diese core-DTOs abbildet.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from core.logger import get_logger

_log = get_logger(__name__)

#: Anzeige-Label des injizierten App-State als geprüfte Quelle (Quellen-Panel +
#: Spotlighting-Kontext). Bewusst „aus NoRisk" statt „berechnet": die Scores sind
#: berechnet, einzelne Risiko-Titel stammen aber aus der Selbsteinschätzung
#: (Freitext) — das Label soll das nicht als vollständig maschinell überklaimen.
APP_STATE_SOURCE_LABEL: str = "Aktuelle Sicherheitswerte dieses Systems (aus NoRisk)"

#: Deutungsrahmen vor dem Datenblock. Verhindert, dass das Modell die zwei
#: bewusst getrennten Dimensionen zu einem Mittelwert verrechnet.
_BLOCK_HEADER: str = (
    "Dies sind die aktuellen, von NoRisk berechneten Sicherheitswerte des "
    "eigenen Systems des Nutzers. Höher ist besser (Skala 0–100). Die beiden "
    "Punktzahlen sind BEWUSST getrennt (Selbsteinschätzung vs. Messung) und "
    "dürfen nicht zu einem Mittelwert verrechnet werden."
)


def _fmt_score(value: float) -> str:
    """Formatiert eine 0–100-Punktzahl als ganze Zahl (wie in der App angezeigt)."""
    return f"{value:.0f}"


@dataclass(frozen=True, slots=True)
class HardeningSummary:
    """Gemessener Härtungs-Score des eigenen Systems (Dimension „Messung").

    Attributes:
        overall_score: Punktzahl 0–100 (gemessen, Herkunft „gemessen").
        stage_label: Ampel-Stufe als Klartext (z. B. ``"Moderate"``).
        scale_hint: Kurzbeschreibung der Stufen-Schwellen (aus der Domäne
            übernommen, kein hartkodierter Wert im Formatter), z. B.
            ``"Secure ab 85, Moderate 65–84, At Risk 40–64, Critical unter 40"``.
        coverage_ratio: Anteil abgedeckter Kategorien (0.0–1.0) oder ``None``.
        stage_capped_by_coverage: True, wenn die Stufe wegen geringer Abdeckung
            gedeckelt wurde (der Score ist dann konservativ).
        weakest_categories: Klartext-Labels der schwächsten Kategorien.
        missing_categories: Klartext-Labels noch nicht gemessener Kategorien.
    """

    overall_score: float
    stage_label: str
    scale_hint: str = ""
    coverage_ratio: float | None = None
    stage_capped_by_coverage: bool = False
    weakest_categories: tuple[str, ...] = ()
    missing_categories: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AuditSummary:
    """Selbst deklarierter Audit-Score (Dimension „Selbsteinschätzung").

    Attributes:
        overall_score: Punktzahl 0–100 (selbst deklariert, schwächerer Beweiswert).
        risk_level: Risikostufe als Klartext (z. B. ``"Niedrig"``).
        scale_hint: Kurzbeschreibung der Risikostufen-Schwellen (aus der Domäne).
        audit_count: Anzahl erfasster Audits für das eigene System.
        top_risks: Kurztitel der wichtigsten Risiken (je „Titel (Stufe)").
    """

    overall_score: float
    risk_level: str
    scale_hint: str = ""
    audit_count: int = 0
    top_risks: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CveExposureSummary:
    """Offene Schwachstellen-Exposition des eigenen Systems.

    Attributes:
        critical_count: Anzahl kritischer offener CVEs.
        high_count: Anzahl hoher offener CVEs.
        kev_count: Davon aktiv ausgenutzt (Known-Exploited-Vulnerabilities).
    """

    critical_count: int = 0
    high_count: int = 0
    kev_count: int = 0


@dataclass(frozen=True, slots=True)
class SecurityFindingsBundle:
    """Gebündelte, PII-freie Ergebnis-Sicht — zwei getrennte Dimensionen, nie gemischt.

    Jedes Feld ist ``None``, wenn die Dimension (noch) nicht vorliegt (fail-soft).

    Attributes:
        hardening: Mess-Score oder ``None`` (noch keine Messung).
        audit: Selbsteinschätzungs-Score oder ``None`` (noch kein Audit).
        cve: Schwachstellen-Exposition oder ``None``.
        abweichung_hinweis: Vorformulierter Hinweis zur Abweichung zwischen den
            beiden Punktzahlen (aus ``bewerte_score_abweichung`` abgeleitet) oder
            ``None``. Der Formatter mittelt NICHT — dies ist nur ein Deutungs-Hinweis.
    """

    hardening: HardeningSummary | None = None
    audit: AuditSummary | None = None
    cve: CveExposureSummary | None = None
    abweichung_hinweis: str | None = None

    @property
    def is_empty(self) -> bool:
        """``True``, wenn keine einzige Ergebnis-Dimension vorliegt."""
        return self.hardening is None and self.audit is None and self.cve is None


class FindingsProvider(Protocol):
    """Port: liefert den kompakten App-State-Datenblock (oder ``None``).

    Der Assistent kennt nur diesen schmalen Vertrag — die konkrete Impl
    (Composition-Root, apps/) liest SELF-only die Tool-Ergebnisse.
    """

    def self_findings_block(self) -> str | None:
        """Kompakter, geerdeter Datenblock des eigenen Systems oder ``None``."""
        ...


def format_findings_block(bundle: SecurityFindingsBundle) -> str:
    """Formatiert das Bündel als kompakten, geerdeten Datenblock (Deutsch).

    Reine Funktion (keine I/O, voll testbar). Enthält bewusst KEINEN Mischwert —
    die zwei Dimensionen bleiben getrennt beschriftet. Nur gesetzte
    Felder werden aufgenommen (fail-soft).

    Args:
        bundle: Das (nicht-leere) Ergebnis-Bündel.

    Returns:
        Mehrzeiliger Datenblock mit Deutungsrahmen; leerer String, wenn das
        Bündel keine Dimension trägt.
    """
    if bundle.is_empty:
        return ""

    lines: list[str] = []
    hardening = bundle.hardening
    if hardening is not None:
        lines.append(_format_hardening(hardening))
    audit = bundle.audit
    if audit is not None:
        lines.append(_format_audit(audit))
    cve = bundle.cve
    if cve is not None:
        lines.append(
            f"- Offene Schwachstellen (CVE): {cve.critical_count} kritisch, "
            f"{cve.high_count} hoch, davon {cve.kev_count} aktiv ausgenutzt (KEV)."
        )
    if bundle.abweichung_hinweis:
        lines.append(f"- Hinweis: {bundle.abweichung_hinweis}")

    return f"{_BLOCK_HEADER}\n" + "\n".join(lines)


def _format_hardening(hardening: HardeningSummary) -> str:
    """Baut die Mess-Zeile (Dimension „Messung/Hardening")."""
    parts = [
        f"- Messung (Hardening): {_fmt_score(hardening.overall_score)}/100, "
        f"Stufe „{hardening.stage_label}“"
    ]
    if hardening.scale_hint:
        parts.append(f" (Skala: {hardening.scale_hint})")
    if hardening.coverage_ratio is not None:
        parts.append(f"; Datenabdeckung {round(hardening.coverage_ratio * 100)}%")
        if hardening.stage_capped_by_coverage:
            parts.append(" (Stufe wegen geringer Abdeckung gedeckelt)")
    if hardening.weakest_categories:
        parts.append(f"; schwächste Bereiche: {', '.join(hardening.weakest_categories)}")
    if hardening.missing_categories:
        parts.append(f"; noch nicht gemessen: {', '.join(hardening.missing_categories)}")
    return "".join(parts) + "."


def _format_audit(audit: AuditSummary) -> str:
    """Baut die Selbsteinschätzungs-Zeile (Dimension „Audit")."""
    parts = [
        f"- Selbsteinschätzung (Audit): {_fmt_score(audit.overall_score)}/100, "
        f"Risikostufe „{audit.risk_level}“"
    ]
    if audit.scale_hint:
        parts.append(f" (Skala: {audit.scale_hint})")
    if audit.audit_count:
        parts.append(f"; {audit.audit_count} Audit(s) erfasst")
    if audit.top_risks:
        parts.append(f"; wichtigste Risiken: {', '.join(audit.top_risks)}")
    return "".join(parts) + "."


class CallableFindingsProvider:
    """FindingsProvider aus einem injizierten Bundle-Builder (Composition-Root).

    Der Builder (apps/) liest SELF-only die Tool-Ergebnisse und bildet sie auf
    das core-DTO ab. Diese Klasse ist fail-soft: jeder Fehler beim Bauen → ``None``
    (der Assistent läuft ohne App-State weiter, statt zu crashen).

    Args:
        build_bundle: Callable, das ein ``SecurityFindingsBundle`` (oder ``None``)
            liefert. Wird pro Anfrage EINMAL aufgerufen (im Worker-Thread).
    """

    def __init__(
        self, build_bundle: Callable[[], SecurityFindingsBundle | None]
    ) -> None:
        self._build_bundle = build_bundle

    def self_findings_block(self) -> str | None:
        """Liefert den formatierten Datenblock oder ``None`` (fail-soft)."""
        try:
            bundle = self._build_bundle()
        except Exception as exc:  # noqa: BLE001 — App-State fail-soft (Cross-Tool-Grenze)
            _log.warning("App-State-Aufbau fehlgeschlagen: %s", type(exc).__name__)
            return None
        if bundle is None or bundle.is_empty:
            return None
        return format_findings_block(bundle)
