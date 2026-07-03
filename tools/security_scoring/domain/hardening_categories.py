"""
hardening_categories — 5-Kategorien-Modell fuer den NoRisk Hardening Score.

Phase 1 des Hardening-Score-Sprints (siehe [[NoRisk_HARDENING_SCORE]]).
Bildet die Per-Tool-ScoreComponents auf die 5 fixen Hardening-Score-
Kategorien (A-E) ab, ohne den bestehenden Per-Tool-Score-Pfad
(DEFAULT_WEIGHTS in scoring_engine.py) zu brechen.

Architektur-Prinzip:

* Dieses Modul ist **additiv** — die bestehende `scoring_engine`-API
  bleibt unveraendert. Der Hardening-Score wird ueber dieses Modul
  zusaetzlich angeboten (Phase 4 UI), die alten Per-Tool-Aggregate
  laufen weiter.
* **Pure Logik, keine Side-Effects.** Inputs werden vom Caller geliefert
  (Source-Tool-Strings + bestehende ScoreComponents).
* **Frozen Enums + frozen Dicts** — kein State, leicht testbar.

Kategorien-Reihenfolge (Brain-Variante, siehe v2):

    A — CVE / Patch-Status 30 % → dependency_auditor + cve_exposure + tech_stack
    B — Netzwerk-Exposition 20 % → network_scanner + cert_monitor + org_security(phishing)
    C — Passwort-Sicherheit 15 % → password_policy + org_security(mfa, pw_mgr)
    D — API-Sicherheit 15 % → api_security
    E — System-Hardening 20 % → system_scanner (Phase 3, aktuell Geruest)

DSGVO-Metrik aus org_security gehoert **nicht** in den technischen
Hardening-Score — sie ist Compliance-Notiz und wird in Phase 4 als
separater Report-Layer angezeigt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Final


class HardeningCategory(StrEnum):
    """Die 5 fixen Hardening-Score-Kategorien.

    Reihenfolge orientiert sich an der Brain-Konvention
    (siehe §1). Werte sind stabile Identifier — Aenderung
    bricht die Score-History-DB.
    """

    CVE_PATCH = "cve_patch"
    NETWORK = "network"
    PASSWORD = "password"
    API_SECURITY = "api_security"
    SYSTEM_HARDENING = "system_hardening"


#: Default-Gewichte der 5 Kategorien im Hardening-Score (Σ = 1.00).
#:
#: Konfigurierbar in Phase 1.1 ueber Policy-DB-Stil).
#: Aenderungen erfordern ``schema_version``-Bump in `score_repository`
#: (EN-05-09-C).
CATEGORY_WEIGHTS: Final[MappingProxyType[HardeningCategory, float]] = MappingProxyType(
    {
        HardeningCategory.CVE_PATCH:        0.30,
        HardeningCategory.NETWORK:          0.20,
        HardeningCategory.PASSWORD:         0.15,
        HardeningCategory.API_SECURITY:     0.15,
        HardeningCategory.SYSTEM_HARDENING: 0.20,
    }
)

#: Per-Tool-Quellen, deren `ScoreComponent.source_tool`-String
#: eindeutig auf eine Kategorie abbildet. Mehrdeutige Quellen
#: (`org_security` mit Sub-Metriken DSGVO/Phishing/MFA/PW-Mgr) werden
#: ueber separate Logik in:func:`map_org_security_metric` aufgeloest.
#:
#: Mapping-Tabelle synchron mit [[NoRisk_LICENSE_PHASE2_SPRINT]] §4
#: und [[NoRisk_HARDENING_SCORE]] §4.
SOURCE_TOOL_TO_CATEGORY: Final[MappingProxyType[str, HardeningCategory]] = MappingProxyType(
    {
        # A — CVE / Patch-Status
        "cve_exposure":       HardeningCategory.CVE_PATCH,
        "dependency_auditor": HardeningCategory.CVE_PATCH,
        "tech_stack":         HardeningCategory.CVE_PATCH,
        # B — Netzwerk-Exposition
        "network_scanner":    HardeningCategory.NETWORK,
        "cert_monitor":       HardeningCategory.NETWORK,
        # C — Passwort-Sicherheit
        "password_policy":    HardeningCategory.PASSWORD,
        # D — API-Sicherheit
        "api_security":       HardeningCategory.API_SECURITY,
        # E — System-Hardening (Phase 3 — system_scanner-Geruest)
        "system_scanner":     HardeningCategory.SYSTEM_HARDENING,
        # (org_security wird via map_org_security_metric aufgeloest)
    }
)


#: Org-Security-Sub-Metriken-Mapping (
#: tools/security_scoring/domain/org_security.py — METRIK_*-Konstanten).
#:
#: DSGVO-Metrik wird **nicht** auf eine Hardening-Score-Kategorie
#: gemappt — sie ist Compliance-Notiz fuer den Report-Layer und liefert
#: ``None`` zurueck.
_ORG_METRIC_TO_CATEGORY: Final[dict[str, HardeningCategory | None]] = {
    "mfa":              HardeningCategory.PASSWORD,
    "passwort_manager": HardeningCategory.PASSWORD,
    "phishing":         HardeningCategory.NETWORK,
    "dsgvo":            None,   # Report-Layer, kein Score-Einfluss
}


def map_source_tool_to_category(
    source_tool: str,
    *,
    org_metric: str | None = None,
) -> HardeningCategory | None:
    """Bildet einen ScoreComponent-Quell-Identifier auf eine Kategorie ab.

    Rueckgabe ``None`` bedeutet: gehoert nicht in den technischen
    Hardening-Score (z.B. DSGVO-Metrik aus org_security) — der Caller
    soll diese Komponenten weglassen oder in den Report-Layer routen.

    Args:
        source_tool: ``ScoreComponent.source_tool``-String, z.B.
            ``"network_scanner"``, ``"org_security"``.
        org_metric: Pflicht bei ``source_tool="org_security"`` — eine
            der `METRIK_*`-Konstanten aus
            ``tools/security_scoring/domain/org_security.py``.

    Returns:
        Zugeordnete:class:`HardeningCategory` oder ``None`` wenn die
        Komponente nicht in den technischen Hardening-Score gehoert.

    Raises:
        KeyError: Wenn ``source_tool`` unbekannt ist (kein Eintrag in
:data:`SOURCE_TOOL_TO_CATEGORY` und nicht ``"org_security"``).
            Soll vom Caller bewusst gefangen werden — neue Tools muessen
            hier explizit nachgepflegt werden, kein silent Fallback.
        ValueError: Wenn ``source_tool="org_security"`` aber ``org_metric``
            fehlt oder unbekannt ist.
    """
    if source_tool == "org_security":
        if org_metric is None:
            msg = (
                "source_tool='org_security' erfordert org_metric-Parameter "
                "(eine der METRIK_*-Konstanten aus core org_security)."
            )
            raise ValueError(msg)
        if org_metric not in _ORG_METRIC_TO_CATEGORY:
            msg = (
                f"Unbekannte org_security-Metrik: {org_metric!r}. "
                f"Erlaubt: {sorted(_ORG_METRIC_TO_CATEGORY.keys())}"
            )
            raise ValueError(msg)
        return _ORG_METRIC_TO_CATEGORY[org_metric]

    if source_tool not in SOURCE_TOOL_TO_CATEGORY:
        msg = (
            f"Unbekanntes source_tool fuer Hardening-Score-Kategorie: "
            f"{source_tool!r}. Erlaubt: "
            f"{sorted(SOURCE_TOOL_TO_CATEGORY.keys())} (plus 'org_security' "
            "mit org_metric)."
        )
        raise KeyError(msg)
    return SOURCE_TOOL_TO_CATEGORY[source_tool]


def validate_weights_sum_to_one(tolerance: float = 1e-9) -> None:
    """Verifiziert, dass:data:`CATEGORY_WEIGHTS` auf 1.0 summiert.

    Diese Funktion ist die Pflicht-Invariante fuer den Hardening-Score-
    Gesamt: ein User-Score von 100 % muss exakt der Summe der
    Maximal-Kategorie-Beitraege entsprechen.

    Args:
        tolerance: Maximal erlaubte Abweichung von 1.0 (Default Float-
            Rundungstoleranz).

    Raises:
        AssertionError: Wenn die Summe nicht in ``[1.0 - tolerance,
            1.0 + tolerance]`` liegt.
    """
    total = sum(CATEGORY_WEIGHTS.values())
    if abs(total - 1.0) > tolerance:
        msg = (
            f"CATEGORY_WEIGHTS summieren nicht auf 1.0: total={total!r}. "
            f"Differenz {total - 1.0:+.6f} ueberschreitet Toleranz {tolerance}."
        )
        raise AssertionError(msg)


# Modul-Lade-Pruefung — bricht den Modul-Import, wenn jemand die
# Gewichte falsch editiert.
validate_weights_sum_to_one()
