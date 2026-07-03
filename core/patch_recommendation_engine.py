"""
patch_recommendation_engine — Enrichment-Pass fuer PatchScanResult Stop-Step B).

Nimmt eine vom Basis-Resolver erzeugte:class:`core.patch_result.PatchScanResult`
und reichert sie an mit:

* CSAF-Advisory-Kontext (via:class:`tools.csaf_advisor.domain.advisory_match.AdvisoryMatch`)
* End-of-Life-Status (via:class:`core.patch_eol_resolver.EolStatus`)

Das Ergebnis ist eine neue:class:`PatchScanResult` mit ggf. einer
**erweiterten** ``recommendation`` aus dem-Set:

* ``"workaround_available"`` — Software hat ein offenes CSAF-Advisory mit
  ``action_required="workaround"`` und kein verfuegbares Update — User soll
  die im Advisory dokumentierte Mitigation anwenden.
* ``"eol_no_patch"`` — Software ist End-of-Life. Vendor liefert keine
  Sicherheits-Patches mehr; Action: Migration / Isolierung.
* ``"patch_available_with_csaf_context"`` — Patch existiert UND mindestens
  ein passendes CSAF-Advisory mit Action-Required ``"update"``. Action-
  Text zeigt den Advisory-Titel / die Severity als Begruendung.

Plus ``action_text`` (User-lesbar) und ``recommendation_source`` (Audit-
Provenance, z. B. ``"csaf:CVE-2026-...."`` oder ``"eol:curated:office_2010"``).

Priorisierung (most-specific first):

    1. ``eol_no_patch`` — EOL beendet jede Patch-Diskussion.
    2. ``update_urgent`` (Basis bleibt) — CVSS≥9 / Exploit aktiv. Action-
       Text wird ggf. aus CSAF angereichert.
    3. ``workaround_available`` — wenn CSAF Workaround empfiehlt + kein
       Patch verfuegbar.
    4. ``patch_available_with_csaf_context`` — Patch + CSAF mit Action
       "update".
    5. existierende Basis-Recommendation bleibt unveraendert.

Architektur: Reine Funktion ohne State, keine I/O, keine DB. Inputs sind
immutable Domain-Objekte, Output ist ein neuer (frozen) PatchScanResult.

Schichtzugehoerigkeit: ``core/`` — Domain-Service.

Author: Patrick Riederich
Version: 1.0 Stop-Step B, 2026-05-12)
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from core.patch_eol_resolver import EolStatus
from core.patch_result import PatchScanResult

if TYPE_CHECKING:
    from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch


@runtime_checkable
class AdvisoryTitleResolver(Protocol):
    """: Optional injizierbarer Title-Resolver fuer den Action-Text.

    Ohne Resolver zeigt der Action-Text nur die ``advisory_id``
    (``"CSAF-Advisory BSI-2026-..."``). Mit Resolver wird stattdessen
    der ``CsafAdvisory.title`` angezeigt (``"CSAF-Advisory 'pfSense
    kritische SQL-Injection'..."``). Lookup-Failure (None) faellt auf
    den ID-Default zurueck.
    """

    def get_title(self, advisory_id: str) -> str | None:
        """Returns: Title oder ``None`` wenn Advisory unbekannt."""
        ...


def apply_recommendation_engine(
    result: PatchScanResult,
    *,
    advisories: list[AdvisoryMatch] | None = None,
    eol_status: EolStatus | None = None,
    title_resolver: AdvisoryTitleResolver | None = None,
) -> PatchScanResult:
    """Enrichment-Pass — gibt einen neuen ``PatchScanResult`` zurueck.

    Wenn keine Anreicherungs-Daten vorliegen (Default: ``advisories=None``
    und ``eol_status=None``), wird ``result`` unveraendert zurueckgegeben.
    Damit ist die Engine optional — bestehende Code-Pfade brauchen keine
    Anpassung.

    Priorisierung siehe Modul-Doc.

    Args:
        result: Basis-Resultat aus
:meth:`PatchScanResult.from_decision_and_cves`. Wird nicht
            mutiert (frozen).
        advisories: Optional eine Liste passender CSAF-Treffer. Default
            ``None`` (entspricht leerer Liste).
        eol_status: Optional ein End-of-Life-Befund aus dem
:class:`core.patch_eol_resolver.IEolResolver`. Default
            ``None`` (entspricht ``EolStatus.not_eol``).

    Returns:
        Neuer ``PatchScanResult`` mit ggf. ueberschriebener
        ``recommendation`` + ``action_text`` + ``recommendation_source``.
    """
    advisories = advisories or []
    eol_status = eol_status or EolStatus.not_eol()

    # 0.: User-Opt-out (PatchStrategy.NONE → "skipped_by_user") ist
    # terminal. Die Engine reichert eine bewusst vom Patchen ausgenommene
    # App NICHT mit Patch-/EOL-/CSAF-Empfehlungen an. Die Risikodaten
    # (``result.eol`` / ``cvss_max`` / ``cve_ids``) bleiben am Result und
    # damit in der UI sichtbar — nur das Handlungs-Label entfaellt.
    if result.recommendation == "skipped_by_user":
        return result

    # 1. EOL ueberschreibt alles
    if eol_status.is_eol:
        action_text = _eol_action_text(eol_status)
        return replace(
            result,
            recommendation="eol_no_patch",
            action_text=action_text,
            recommendation_source=eol_status.source,
        )

    # CSAF-Treffer nach Action-Required gruppieren (Workaround/Update)
    update_advisories = [a for a in advisories if a.action_required == "update"]
    workaround_advisories = [
        a for a in advisories if a.action_required == "workaround"
    ]

    # 2. update_urgent — Basis bleibt, Action-Text ggf. aus CSAF anreichern
    if result.recommendation == "update_urgent":
        if update_advisories:
            primary = update_advisories[0]
            return replace(
                result,
                action_text=_csaf_update_text(
                    primary, urgent=True, title_resolver=title_resolver
                ),
                recommendation_source=f"csaf:{primary.advisory_id}",
            )
        # Keine CSAF-Anreicherung — Basis bleibt
        return result

    # 3. workaround_available — CSAF Workaround + kein Update verfuegbar
    if workaround_advisories and not _has_update_available(result):
        primary = workaround_advisories[0]
        return replace(
            result,
            recommendation="workaround_available",
            action_text=_csaf_workaround_text(
                primary, title_resolver=title_resolver
            ),
            recommendation_source=f"csaf:{primary.advisory_id}",
        )

    # 4. patch_available_with_csaf_context — Patch + CSAF
    if update_advisories and _has_update_available(result):
        primary = update_advisories[0]
        return replace(
            result,
            recommendation="patch_available_with_csaf_context",
            action_text=_csaf_update_text(
                primary, urgent=False, title_resolver=title_resolver
            ),
            recommendation_source=f"csaf:{primary.advisory_id}",
        )

    # 5. Basis bleibt unveraendert
    return result


# ---------------------------------------------------------------------------
# Action-Text-Helper
# ---------------------------------------------------------------------------


def _eol_action_text(eol: EolStatus) -> str:
    """Baut den User-lesbaren Action-Text fuer ``eol_no_patch``."""
    parts: list[str] = []
    if eol.cycle:
        parts.append(f"{eol.cycle} ist End-of-Life")
    else:
        parts.append("Software ist End-of-Life")
    if eol.eol_date:
        parts.append(f"(seit {eol.eol_date})")
    if eol.replacement:
        parts.append(f"— Empfehlung: {eol.replacement}")
    else:
        parts.append("— Migration empfohlen")
    return " ".join(parts)


def _csaf_workaround_text(
    match: AdvisoryMatch,
    *,
    title_resolver: AdvisoryTitleResolver | None = None,
) -> str:
    """Action-Text fuer ``workaround_available``.

    Falls ein ``title_resolver`` injiziert ist, wird der Titel
    des Advisorys mit-angezeigt — ergibt eine deutlich lesbarere
    Empfehlung (``"CSAF-Advisory 'pfSense kritische SQL-Injection'
    empfiehlt..."`` statt ``"CSAF-Advisory BSI-2026-...
    empfiehlt..."``).
    """
    label = _advisory_label(match, title_resolver)
    return (
        f"CSAF-Advisory {label} empfiehlt einen Workaround. "
        "Patch ist derzeit nicht verfuegbar — siehe Advisory-Details."
    )


def _csaf_update_text(
    match: AdvisoryMatch,
    *,
    urgent: bool,
    title_resolver: AdvisoryTitleResolver | None = None,
) -> str:
    """Action-Text fuer ``patch_available_with_csaf_context`` oder
    angereicherten ``update_urgent``-Fall."""
    prefix = "Sofort updaten" if urgent else "Update empfohlen"
    label = _advisory_label(match, title_resolver)
    return (
        f"{prefix}: CSAF-Advisory {label} verlangt "
        f"Aktion ``update`` (Confidence {match.confidence:.0%})."
    )


def _advisory_label(
    match: AdvisoryMatch,
    title_resolver: AdvisoryTitleResolver | None,
) -> str:
    """Gibt entweder ``"'<title>'"`` oder die ``advisory_id`` zurueck.

    Defensive: Resolver-Failure faellt stille auf die ID zurueck.
    """
    if title_resolver is None:
        return match.advisory_id
    try:
        title = title_resolver.get_title(match.advisory_id)
    except Exception:  # noqa: BLE001 — Resolver darf nie crashen
        return match.advisory_id
    if title:
        return f"'{title}' ({match.advisory_id})"
    return match.advisory_id


def _has_update_available(result: PatchScanResult) -> bool:
    """``True`` wenn die existing Recommendation auf 'Update verfuegbar' steht."""
    return result.recommendation in {
        "update_available",
        "update",
    }


__all__ = ["apply_recommendation_engine"]
