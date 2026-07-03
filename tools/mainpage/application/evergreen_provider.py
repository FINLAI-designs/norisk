"""
evergreen_provider — Always-on Housekeeping-Vorschlaege fuer die "Was tun?"-
Section.

Hintergrund: die regel-basierte KI-Todo-Engine (``KiTodoService``) erzeugt
Tasks nur wenn ein Scanner-Tool ein Finding emittiert das eine Regel matcht.
Frisch installierte App / Scanner noch nicht gelaufen / nur unverdaechtige
Scans → keine Tasks → "Was tun?"-Section zeigt dauerhaft den Empty-State.

Fix (Patrick-Vorschlag (d)): kuratierte Liste von Routine-
Empfehlungen ("Hardening pruefen", "Vollscan starten", "Patch-Inventar
aktualisieren") als Fallback wenn weniger als 3 akute Tasks vorliegen.

**: Dynamic Gating.** Vorher hat ``get_evergreens(3)``
immer 3 Top-Items aus der statischen Liste zurueckgegeben — auch wenn der
User gerade den Vollscan abgeschlossen hat ("Vollscan starten" haengt
trotzdem in der UI). Mit dem Context kann der Provider Predicates
auswerten: ein Template wird nur gezeigt wenn sein ``should_show(ctx)``
``True`` liefert. Ohne Context (Backwards-Compat) bleibt das Verhalten
unveraendert (alle Templates ungefiltert).

Architektur-Entscheidung: Evergreens leben **nicht** in der Tasks-DB —
sie sind statische Vorschlaege, kein User-State. Das KiTodoSection-
Widget mischt sie zur Render-Zeit unter die echten Tasks. Der Gating-
Context wird vom Widget zusammengebaut (LastScanRegistry + Scoring-
Service); die Predicates leben hier in der application/-Schicht.

Schichtzugehoerigkeit: ``application/`` — keine GUI-Imports.

Author: Patrick Riederich
Version: 2.0 Dynamic Gating, 2026-05-13)
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final

from tools.mainpage.domain.models import Task

#: Source-Marker fuer Evergreen-Tasks. Differenziert sie im Code von
#: ``"auto"`` (Regel-Engine) und ``"manual"`` (User).
EVERGREEN_SOURCE: Final[str] = "evergreen"

#: Synthetisches Task-ID-Praefix damit Evergreens kollisionsfrei mit
#: echten UUIDs sind und in Logs sofort als solche erkennbar.
_ID_PREFIX: Final[str] = "evergreen:"

#: Konstantes ``created_at`` damit der Sort-Order vorhersagbar ist.
_EVERGREEN_CREATED_AT: Final[str] = "2000-01-01T00:00:00+00:00"


# ---------------------------------------------------------------------------
# Dynamic Gating — Context + Predicates
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvergreenGatingContext:
    """State-Snapshot fuer Evergreen-Predicates.

    Wird vom:class:`KiTodoSection`-Widget gebaut aus
:func:`core.registry.last_scan_registry.get_last_scan` +
    Patch-Monitor-Service + Scoring-Service. Frozen damit der Provider
    den Context nicht mutieren kann.

    Alle Felder sind ``Optional`` — wenn ein Service nicht verfuegbar
    ist (z. B. Frische Installation, Service-Init-Fehler), bleibt das
    Feld ``None``. Die Predicates muessen damit umgehen — Konvention:
    ``None`` → Template wird gezeigt (defensive: lieber redundanten
    Hinweis anbieten als keinen).

    Attributes:
        last_system_scan: Letzter Scan via ``system_scanner``-Tool
            (steht stellvertretend fuer "ein Vollscan ist gelaufen").
        last_patch_scan: Letzter ``full_scan`` des Patch-Monitors.
        last_csaf_check: Letzter CSAF-Provider-Fetch.
        last_techstack_change: Letzte Aenderung am Tech-Stack
            (ungesetzt = leer / nie editiert).
        hardening_score: Aktueller Overall-Hardening-Score (0..100).
        now: Reference-Zeit fuer "vor X Tagen"-Vergleiche. Tests
            koennen das einfrieren; Production setzt ``datetime.now(UTC)``.
    """

    last_system_scan: datetime | None = None
    last_patch_scan: datetime | None = None
    last_csaf_check: datetime | None = None
    last_techstack_change: datetime | None = None
    hardening_score: float | None = None
    now: datetime = field(
        default_factory=lambda: datetime.now(tz=UTC)
    )

    def days_since(self, when: datetime | None) -> float | None:
        """Tage seit ``when`` (oder ``None`` wenn unbekannt)."""
        if when is None:
            return None
        delta: timedelta = self.now - when
        return delta.total_seconds() / 86400.0


#: Predicate-Signatur: prueft anhand des Contexts, ob das Template
#: angezeigt werden soll.
_Predicate = Callable[[EvergreenGatingContext], bool]


def _always(_: EvergreenGatingContext) -> bool:
    """Default-Predicate — Template immer zeigen."""
    return True


def _should_show_full_scan(ctx: EvergreenGatingContext) -> bool:
    """Vollscan-Erinnerung: zeigen wenn nie oder > 30 Tage her."""
    days = ctx.days_since(ctx.last_system_scan)
    if days is None:  # nie gelaufen
        return True
    return days > 30.0


def _should_show_patch_refresh(ctx: EvergreenGatingContext) -> bool:
    """Patch-Inventar-Refresh: zeigen wenn nie oder > 7 Tage her."""
    days = ctx.days_since(ctx.last_patch_scan)
    if days is None:
        return True
    return days > 7.0


def _should_show_hardening_check(ctx: EvergreenGatingContext) -> bool:
    """Hardening-Check: zeigen wenn Score < 80 ODER nie gelaufen."""
    if ctx.hardening_score is None:
        return True
    return ctx.hardening_score < 80.0


def _should_show_csaf_review(ctx: EvergreenGatingContext) -> bool:
    """CSAF-Review: zeigen wenn nie oder > 7 Tage seit letztem Fetch."""
    days = ctx.days_since(ctx.last_csaf_check)
    if days is None:
        return True
    return days > 7.0


def _should_show_techstack_review(ctx: EvergreenGatingContext) -> bool:
    """Tech-Stack-Review: zeigen wenn leer ODER > 90 Tage seit letzter
    Aenderung."""
    days = ctx.days_since(ctx.last_techstack_change)
    if days is None:
        return True
    return days > 90.0


# ---------------------------------------------------------------------------
# Template-Bundles — pairs Task + Predicate)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _EvergreenTemplate:
    """Ein Template: das fertige:class:`Task`-Objekt + Predicate."""

    task: Task
    should_show: _Predicate = _always


def _make_template(
    slug: str,
    title: str,
    explanation: str,
    action: str,
    *,
    urgency: str = "langfrist",
    source_tool: str = "Routine",
    should_show: _Predicate = _always,
) -> _EvergreenTemplate:
    """Helper: baut ein ``_EvergreenTemplate`` aus den Inhalts-Strings.

    ``description`` folgt der Storytelling-Konvention
    ``explanation + "\\n\\n" + action`` — das ``_HeroCard``-Widget liest
    die Action aus dem zweiten Absatz und zeigt sie als Sub-Text.
    """
    description = f"{explanation}\n\n{action}"
    task = Task(
        id=f"{_ID_PREFIX}{slug}",
        title=title,
        description=description,
        status="open",
        category="allgemein",
        source=EVERGREEN_SOURCE,
        source_tool=source_tool,
        priority="normal",
        urgency=urgency,
        created_at=_EVERGREEN_CREATED_AT,
        updated_at=_EVERGREEN_CREATED_AT,
    )
    return _EvergreenTemplate(task=task, should_show=should_show)


#: Kuratierte Liste der Evergreen-Templates inkl. Predicates.
#: Reihenfolge = Anzeige-Reihenfolge wenn alle Predicates ``True`` liefern.
_EVERGREEN_TEMPLATES: Final[tuple[_EvergreenTemplate, ...]] = (
    _make_template(
        slug="hardening_score_check",
        title="Hardening-Score pruefen",
        explanation=(
            "Der Hardening-Score zeigt wie gut dein System gegen typische "
            "Angriffe abgesichert ist. Werte unter 65 bedeuten dass "
            "Basis-Schutzmechanismen (Firewall, Defender, UAC, BitLocker) "
            "fehlen oder falsch konfiguriert sind."
        ),
        action=(
            "Lagebild oeffnen → Hardening-Score-Sektion. Falls < 65: "
            "die rot markierten Kategorien zuerst beheben."
        ),
        source_tool="Lagebild",
        should_show=_should_show_hardening_check,
    ),
    _make_template(
        slug="patch_inventory_refresh",
        title="Patch-Inventar aktualisieren",
        explanation=(
            "Das Patch-Inventar listet installierte Software inkl. Versionen "
            "und CVE-Status. Ohne regelmaessige Aktualisierung verpasst der "
            "Monitor neue Schwachstellen — typisch nach Software-Updates "
            "ausserhalb von winget."
        ),
        action=(
            "Patch-Monitor oeffnen → 'Scan starten'. Empfohlen: einmal "
            "pro Woche."
        ),
        source_tool="Patch-Monitor",
        should_show=_should_show_patch_refresh,
    ),
    _make_template(
        slug="full_scan",
        title="Regelmaessigen Vollscan starten",
        explanation=(
            "Ein Vollscan deckt alle Tools ab (Netzwerk, Zertifikate, API-"
            "Endpoints, Passworte). Empfohlen mindestens monatlich — zwischen "
            "den Scans laufen Daily/Weekly-Refreshs im Hintergrund."
        ),
        action=(
            "Lagebild → 'Scan starten' (oder einzelne Tools manuell). "
            "Ergebnisse landen direkt im Risikobriefing."
        ),
        source_tool="System-Scanner",
        should_show=_should_show_full_scan,
    ),
    _make_template(
        slug="csaf_advisories_review",
        title="CSAF-Advisories pruefen",
        explanation=(
            "Der CSAF-Advisor zieht Hersteller-Sicherheitsmeldungen (z. B. "
            "Microsoft, Mozilla, Cisco) und matcht sie gegen deinen "
            "TechStack. Neue High/Critical-Advisories sollten zeitnah "
            "begutachtet werden."
        ),
        action=(
            "Advisory-Monitor oeffnen → Filter 'Neu seit letztem Check'. "
            "Match-Treffer mit High/Critical-Severity priorisieren."
        ),
        source_tool="Advisory-Monitor",
        should_show=_should_show_csaf_review,
    ),
    _make_template(
        slug="techstack_review",
        title="Tech-Stack aktualisieren",
        explanation=(
            "Der Tech-Stack ist die Inventar-Liste deiner produktiven "
            "Systeme — er steuert welche CSAF-Advisories matchen. Bei "
            "neuen Servern / Anwendungen ohne Eintrag fehlen Warnungen."
        ),
        action=(
            "Techstack-Tool oeffnen → Komponenten ergaenzen / entfernen. "
            "Pflegezyklus: bei jeder groesseren System-Aenderung."
        ),
        source_tool="Techstack",
        should_show=_should_show_techstack_review,
    ),
)


def get_evergreens(
    limit: int,
    ctx: EvergreenGatingContext | None = None,
) -> list[Task]:
    """Liefert bis zu ``limit`` Evergreen-Tasks, optional gegated.

    Args:
        limit: Anzahl. ``0`` oder negativ → leere Liste (No-op).
        ctx: Optional ein:class:`EvergreenGatingContext`. Wenn
            angegeben, werden alle Templates gefiltert deren
            ``should_show(ctx)`` ``False`` liefert. ``None`` (Default)
            → Backwards-Compat: alle Templates werden geliefert
            (kein Filtering).

    Returns:
        Frische Task-Objekte (jeder Aufruf liefert dieselben Instanzen,
        weil das Modul-Tuple immutable ist — Konsumenten sollen die
        Tasks read-only behandeln).
    """
    if limit <= 0:
        return []
    if ctx is None:
        candidates = list(_EVERGREEN_TEMPLATES)
    else:
        candidates = [tpl for tpl in _EVERGREEN_TEMPLATES if tpl.should_show(ctx)]
    return [tpl.task for tpl in candidates[:limit]]


def is_evergreen(task: Task) -> bool:
    """``True`` wenn das Task aus diesem Provider stammt."""
    return task.source == EVERGREEN_SOURCE or task.id.startswith(_ID_PREFIX)


__all__ = [
    "EVERGREEN_SOURCE",
    "EvergreenGatingContext",
    "get_evergreens",
    "is_evergreen",
]
