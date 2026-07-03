"""Factory: verdrahtet den RisikoBriefingService mit echten Quellen Phase 3b).

Composition-Root-Muster (analog ``norisk_dashboard/tool.py``): die Cross-Tool-
Zugriffe (patch_monitor, security_scoring, customer_audit, core.security_subject)
laufen **lazy** in den Loader-Closures, jede Quelle **fail-soft** (Fehler/keine
Daten -> der zugehoerige Teil entfaellt still, kein Crash). Die reinen
Uebersetzungs-Helfer (``_hardening_info_from_result`` etc.) sind ohne DB/Scan
testbar.

SELF-Gate: der Audit-Loader liest ausschliesslich das EIGENE Subjekt
(``create_subject_store.get_self``) — Tab 1 zeigt immer die eigene Lage, nie
die eines Kunden.

Eckwerte (Firewall/RDP/Disk/MFA/Backup): aus dem letzten SELF-Audit abgeleitet
(Patrick-Entscheid 2026-06-29) — guenstiger DB-Read statt Live-Hardening-Scan im
Tab-Open-Pfad (Perf). Konservatives Mapping: nur klare Negativ-Signale (z. B.
``firewall_status == "inaktiv"``, ``mfa_aktiv == "Nein"``) loesen einen Punkt
aus; mehrdeutige/leere Werte bleiben ``None`` (neutral, kein False-Positive).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from core.logger import get_logger
from tools.cyber_dashboard.application.risiko_briefing_service import (
    RisikoBriefingService,
)
from tools.cyber_dashboard.domain.risiko_briefing import (
    AuditScoreInfo,
    HardeningInfo,
    MeasuredFacts,
    PatchBacklogInfo,
)

log = get_logger(__name__)

#: Anzeige-Labels fuer Hardening-Kategorien (StrEnum-Wert -> Klartext).
_KATEGORIE_LABELS: dict[str, str] = {
    "cve_patch": "Schwachstellen/Patches",
    "network": "Netzwerk",
    "password": "Identitaet/Passwoerter",
    "api_security": "API-Sicherheit",
    "system_hardening": "Systemhaertung",
}

_LOADER_ERRORS = (
    ImportError,
    OSError,
    RuntimeError,
    AttributeError,
    ValueError,
    TypeError,
)


# ---------------------------------------------------------------------------
# Reine Uebersetzungs-Helfer (ohne I/O — direkt testbar)
# ---------------------------------------------------------------------------


def _kategorie_label(cat: Any) -> str:
    """Hardening-Kategorie (StrEnum/str) -> Klartext-Label."""
    key = getattr(cat, "value", None) or str(cat)
    return _KATEGORIE_LABELS.get(key, key)


def _hardening_info_from_result(result: Any) -> HardeningInfo | None:
    """``HardeningScoreResult`` -> ``HardeningInfo`` (None wenn unbrauchbar)."""
    if result is None or not getattr(result, "category_scores", None):
        return None
    missing = tuple(
        _kategorie_label(c) for c in getattr(result, "missing_categories", ())
    )
    return HardeningInfo(
        score=float(result.overall_score),
        stage_label=str(getattr(result.stage, "label", "")),
        missing_categories=missing,
    )


def _audit_info_from_result(
    result: Any, top_risks: tuple[tuple[str, str], ...] = ()
) -> AuditScoreInfo | None:
    """SELF-``CustomerAuditResult`` (+ BSI-Top-Risiken) -> ``AuditScoreInfo``."""
    if result is None:
        return None
    return AuditScoreInfo(
        score=float(getattr(result, "overall_score", 0.0) or 0.0),
        top_risks=tuple(top_risks),
    )


#: Klartext-Marker fuer einen RDP-Eintrag in ``remote_access_tools``.
_RDP_MARKER = ("rdp", "remote desktop", "remotedesktop", "remote-desktop")


def _ja(value: str | None) -> bool | None:
    """Ja/Nein/Status-Audit-Feld -> bool, oder ``None`` bei unklarem Wert.

    Konservativ: nur eindeutige Werte werden zu True/False; "teilweise",
    "unbekannt" oder Freitext bleiben ``None`` (neutral, kein False-Positive).
    """
    v = (value or "").strip().lower()
    if v in ("ja", "yes", "vorhanden", "aktiv"):
        return True
    if v in ("nein", "no", "keine", "kein", "inaktiv", "deaktiviert"):
        return False
    # Leer/"unbekannt"/"teilweise"/Freitext -> neutral (kein False-Positive).
    return None


def _measured_facts_from_audit(result: Any) -> MeasuredFacts | None:
    """Leitet die Eckwerte aus einem SELF-``CustomerAuditResult`` ab.

    Fail-closed: nur ``AuditMode.SELF`` speist das eigene Risikobild.
    Liefert ``None``, wenn nichts Verwertbares vorliegt (alle Felder neutral).
    """
    if result is None:
        return None
    try:
        from tools.customer_audit.domain.entities import AuditMode  # noqa: PLC0415

        if getattr(result, "audit_mode", None) is not AuditMode.SELF:
            return None
    except ImportError:
        return None

    infra = getattr(result, "infrastructure_data", None)
    org = getattr(result, "organizational_data", None)
    phish = getattr(result, "phishing_data", None)

    firewall = _ja(getattr(infra, "firewall_status", None)) if infra else None
    # Verschluesselung ist eine Liste der eingesetzten Verfahren. In einem
    # ausgefuellten SELF-Audit bedeutet eine LEERE Liste "keine Verschluesselung
    # deklariert" -> Befund (analog mfa/backup="Nein"). ``None`` nur, wenn das
    # Infrastruktur-Objekt selbst fehlt (kein Audit-Datensatz).
    disk = bool(getattr(infra, "verschluesselung", None)) if infra else None
    tools = [str(t).lower() for t in (getattr(infra, "remote_access_tools", []) or [])]
    rdp = True if any(m in t for t in tools for m in _RDP_MARKER) else None
    mfa = _ja(getattr(phish, "mfa_aktiv", None)) if phish else None
    backup = _ja(getattr(org, "backup_strategie", None)) if org else None

    if all(v is None for v in (firewall, disk, rdp, mfa, backup)):
        return None
    return MeasuredFacts(
        firewall_active=firewall,
        rdp_exposed=rdp,
        disk_encryption_active=disk,
        mfa_active=mfa,
        backup_documented=backup,
    )


# ---------------------------------------------------------------------------
# Loader-Builder (lazy, fail-soft)
# ---------------------------------------------------------------------------


def _build_patch_backlog_loader(
    patch_service: Any,
) -> Callable[[], PatchBacklogInfo | None]:
    def _load() -> PatchBacklogInfo | None:
        try:
            offen, eol = patch_service.offene_und_eol_counts()
            last = patch_service.letzter_vollscan()
            if offen <= 0 and eol <= 0 and last is None:
                return None
            return PatchBacklogInfo(
                open_updates=int(offen),
                eol_without_patch=int(eol),
                last_scan_at=last,
            )
        except _LOADER_ERRORS as exc:
            log.info("Patch-Backlog nicht verfuegbar: %s", type(exc).__name__)
            return None

    return _load


def _build_hardening_loader() -> Callable[[], HardeningInfo | None]:
    def _load() -> HardeningInfo | None:
        try:
            from tools.security_scoring.application.scoring_service import (  # noqa: PLC0415
                ScoringService,
            )

            return _hardening_info_from_result(
                ScoringService().lade_letztes_hardening_result()
            )
        except _LOADER_ERRORS as exc:
            log.info("Hardening-Score nicht verfuegbar: %s", type(exc).__name__)
            return None

    return _load


def _lade_self_audit() -> Any | None:
    """Juengstes SELF-``CustomerAuditResult`` ueber die customer_audit-Application-
    Fassade (KEIN data-Layer-Direktimport) — SELF-gegated + fail-soft.

    Audit-Score UND gemessene Eckwerte leiten beide aus DIESEM Ergebnis ab; der
    SELF-Gate gilt damit symmetrisch fuer beide Dimensionen.
    """
    try:
        from core.security_subject.resolver import (  # noqa: PLC0415
            create_subject_store,
        )
        from tools.customer_audit.application.self_audit_query import (  # noqa: PLC0415
            lade_self_audit_result,
        )

        store = create_subject_store()
        if store is None:
            return None
        self_subject = store.get_self()
        if self_subject is None:
            return None
        return lade_self_audit_result(self_subject.subject_id)
    except _LOADER_ERRORS as exc:
        log.info("SELF-Audit nicht verfuegbar: %s", type(exc).__name__)
        return None


def _lade_top_risiken(audit_id: str) -> tuple[tuple[str, str], ...]:
    """BSI-Top-Risiken eines Audits ueber die customer_audit-Fassade (fail-soft)."""
    if not audit_id:
        return ()
    try:
        from tools.customer_audit.application.self_audit_query import (  # noqa: PLC0415
            lade_top_risiken,
        )

        return lade_top_risiken(audit_id)
    except _LOADER_ERRORS as exc:
        log.info("Audit-Top-Risiken nicht verfuegbar: %s", type(exc).__name__)
        return ()


def _memoize_kurz(fn: Callable[[], Any], ttl_s: float = 2.0) -> Callable[[], Any]:
    """Kurz-Cache (Perf): teilt EINEN ``fn``-Aufruf zwischen Konsumenten, die
    innerhalb von ``ttl_s`` feuern. Score- und Measured-Loader laufen pro
    build_snapshot im ms-Abstand -> gemeinsamer Audit-Load statt zwei; ein
    spaeterer Refresh (> ttl_s) laedt frisch.
    """
    cache: dict[str, Any] = {}

    def _get() -> Any:
        now = time.monotonic()
        if "ts" not in cache or (now - cache["ts"]) > ttl_s:
            cache["val"] = fn()
            cache["ts"] = now
        return cache["val"]

    return _get


def _build_self_audit_loader(
    audit_provider: Callable[[], Any],
) -> Callable[[], AuditScoreInfo | None]:
    def _load() -> AuditScoreInfo | None:
        result = audit_provider()
        if result is None:
            return None
        top_risks = _lade_top_risiken(str(getattr(result, "audit_id", "")))
        return _audit_info_from_result(result, top_risks)

    return _load


def _build_measured_loader(
    audit_provider: Callable[[], Any],
) -> Callable[[], MeasuredFacts | None]:
    return lambda: _measured_facts_from_audit(audit_provider())


def create_risiko_briefing_service() -> RisikoBriefingService:
    """Baut den voll verdrahteten ``RisikoBriefingService`` fuer Tab 1.

    Off-thread aufzurufen (build_snapshot liest DB) — kein UI-Thread.
    """
    from tools.cyber_dashboard.application.risiko_briefing_patch_adapter import (  # noqa: PLC0415
        PatchAffectedCveQuelle,
    )
    from tools.patch_monitor.application.patch_inventory_service import (  # noqa: PLC0415
        PatchInventoryService,
    )

    patch_service = PatchInventoryService()
    # EIN geteilter, kurz-memoizter SELF-Audit-Load — Score- und Measured-Loader
    # teilen ihn pro Refresh statt das Audit zweimal zu lesen (Perf, Phase 5).
    audit_provider = _memoize_kurz(_lade_self_audit)
    return RisikoBriefingService(
        PatchAffectedCveQuelle(patch_service),
        patch_backlog_loader=_build_patch_backlog_loader(patch_service),
        hardening_loader=_build_hardening_loader(),
        audit_loader=_build_self_audit_loader(audit_provider),
        measured_loader=_build_measured_loader(audit_provider),
    )
