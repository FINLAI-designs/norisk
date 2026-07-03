"""core.security_subject.resolver — Lazy-Resolver auf die SubjectStore-Impl.

Der **einzige** Punkt im Codebestand, der die konkrete (security_scoring-)
SubjectStore-Implementierung referenziert. Konsumenten (``customer_audit``,
``norisk_dashboard``) importieren ausschließlich diesen core-Resolver
(tools→core, import-linter-konform) und bekommen die Implementierung als
:class:`SubjectStore`-Port geliefert — kein tool→tool-Import §3.2).

Fail-soft nach dem Hausmuster ``patch_monitor_linker`` /
``techstack_sync_service``: Ist die Implementierung nicht ladbar oder das
Repository nicht initialisierbar (z. B. fehlender SQLCipher-Schlüssel), liefert
der Resolver ``None`` statt zu werfen.

Schichtzugehörigkeit: core/ — der ``tools``-Import läuft bewusst **lazy**
innerhalb der Funktion, damit keine statische ``core → tools``-Kante entsteht.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from core.security_subject.ports import (
    AvvReferenceCheck,
    SubjectCleanupHook,
    SubjectStore,
    UsageSignalProvider,
)

log = get_logger(__name__)


def create_subject_store() -> SubjectStore | None:
    """Liefert die konkrete:class:`SubjectStore`-Implementierung (fail-soft).

    Returns:
        Einsatzbereiter Store oder ``None``, wenn die Implementierung nicht
        ladbar bzw. das zugrunde liegende Repository nicht initialisierbar ist.
        Die Fehlerbehandlung bleibt fail-soft beim Aufrufer (z. B. „Subjekt-
        Features deaktiviert").
    """
    try:
        # Lazy import: hält core frei von einer statischen tools-Abhängigkeit.
        from tools.security_scoring.application.subject_store import (  # noqa: PLC0415
            create_default_subject_store,
        )

        return create_default_subject_store()
    except Exception as exc:  # noqa: BLE001 — fail-soft Cross-Tool-Resolver-Grenze
        # warning statt info: ein degradiertes Subjekt-Feature soll sichtbar
        # sein. Broad except bleibt bewusst (Cross-Tool-Grenze, Hausmuster
        # patch_monitor_linker) — es darf den Konsumenten nie crashen.
        log.warning(
            "SubjectStore nicht verfuegbar (%s) — Subjekt-Features fail-soft "
            "deaktiviert.",
            type(exc).__name__,
        )
        return None


def create_usage_signal_provider() -> UsageSignalProvider | None:
    """Liefert den:class:`UsageSignalProvider` (customer_audit) — fail-soft.

    Cross-Tool-Lese-Resolver für die Org-Auto-Detection: liefert die
    ``customer_audit``-Implementierung, die das jüngste SELF-Sovereignty-Audit in
    tri-state-Nutzungssignale übersetzt. Wie:func:`create_subject_store` läuft der
    ``tools``-Import bewusst **lazy** innerhalb der Funktion — keine statische
    ``core → tools``-Kante (der eine bewusste Lazy-Eintrag ist in der
    import-linter-Baseline hinterlegt).

    Returns:
        Einsatzbereiter Provider oder ``None``, wenn die Implementierung nicht
        ladbar bzw. das zugrunde liegende Repository nicht initialisierbar ist
        (z. B. fehlender SQLCipher-Schlüssel) — fail-soft beim Aufrufer.
    """
    try:
        # Lazy import: hält core frei von einer statischen tools-Abhängigkeit.
        from tools.customer_audit.application.usage_signals import (  # noqa: PLC0415
            create_default_usage_signal_provider,
        )

        return create_default_usage_signal_provider()
    except Exception as exc:  # noqa: BLE001 — fail-soft Cross-Tool-Resolver-Grenze
        log.warning(
            "UsageSignalProvider nicht verfuegbar (%s) — Org-Auto-Detection "
            "fail-soft deaktiviert.",
            type(exc).__name__,
        )
        return None


class _SupplyChainReferenceCheck:
    """Composite-Referenz-Check ueber ALLE supply_chain-Bezuege eines Kunden.

    Der DSGVO-Art.-17-Loeschpfad blockiert die Kunden-Loeschung, solange
    supply_chain das Subjekt noch referenziert: aufbewahrungspflichtige
    Kunden-AVVs E4) ODER Subunternehmer-Verknuepfungen (H, Live-Test
    2026-07-01 — sonst verwaisen ``customer_subprocessors``-Links mit toter
    ``subject_id``). Duck-typed ueber:class:`AvvReferenceCheck` (nur
    ``has_references``); die konkreten Repos werden injiziert (kein statischer
    core→tools-Import in dieser Klasse).
    """

    def __init__(self, avv_repo: object, sub_repo: object) -> None:
        self._avv_repo = avv_repo
        self._sub_repo = sub_repo

    def has_references(self, subject_id: str) -> bool:
        return bool(
            self._avv_repo.has_references(subject_id)
            or self._sub_repo.has_customer_references(subject_id)
        )


def create_avv_reference_check() -> AvvReferenceCheck | None:
    """Liefert den supply_chain-Referenz-Checker fuer den Loeschschutz — fail-soft.

    Cross-Tool-Lese-Resolver für den DSGVO-Art.-17-Löschpfad (E4): bevor ein
    Kunden-Subjekt verworfen wird, prüft der Aufrufer über diesen Checker, ob noch
    aufbewahrungspflichtige Kunden-AVVs ODER Subunternehmer-Verknuepfungen (H)
    existieren — dann wird die Löschung blockiert. Wie:func:`create_subject_store`
    läuft der ``tools``-Import bewusst **lazy** innerhalb der Funktion — keine
    statische ``core → tools``-Kante (der bewusste Lazy-Eintrag ist in der
    import-linter-Baseline hinterlegt).

    Returns:
        Einsatzbereiter Checker oder ``None``, wenn die Implementierung nicht
        ladbar bzw. das Repository nicht initialisierbar ist (z. B. fehlender
        SQLCipher-Schlüssel) — fail-soft beim Aufrufer (kein Block bei Ausfall).
    """
    try:
        # Lazy import: hält core frei von einer statischen tools-Abhängigkeit.
        from tools.supply_chain_monitor.data.customer_avv_repository import (  # noqa: PLC0415
            CustomerAvvRepository,
        )
        from tools.supply_chain_monitor.data.subprocessor_repository import (  # noqa: PLC0415
            SubprocessorRepository,
        )

        return _SupplyChainReferenceCheck(
            CustomerAvvRepository(), SubprocessorRepository()
        )
    except Exception as exc:  # noqa: BLE001 — fail-soft Cross-Tool-Resolver-Grenze
        log.warning(
            "supply_chain-Referenz-Check nicht verfuegbar (%s) — Kunden-"
            "Loeschschutz fail-soft deaktiviert.",
            type(exc).__name__,
        )
        return None


class _WorkflowProgressCleanupHook:
    """Cleanup-Hook: loescht den Workflow-Fortschritt eines geloeschten Subjekts.

    Duck-typed ueber:class:`SubjectCleanupHook`; das Repository wird injiziert
    (kein statischer core→tools-Import in dieser Klasse).
    """

    def __init__(self, repo: object) -> None:
        self._repo = repo

    def cleanup(self, subject_id: str) -> None:
        self._repo.delete_for_subject(subject_id)


def create_subject_cleanup_hooks() -> list[SubjectCleanupHook]:
    """Liefert die nicht-blockierenden Cleanup-Hooks fuer den Loeschpfad.

    Cross-Tool-Resolver fuer den DSGVO-Art.-17-Loeschpfad: NACH der erfolgreichen
    Kunden-Loeschung raeumen diese Hooks Betriebs-/UX-Daten ohne
    Aufbewahrungspflicht ab (aktuell: Workflow-Fortschritt aus ``norisk_dashboard``).
    Wie:func:`create_subject_store` laufen die ``tools``-Importe bewusst **lazy**
    innerhalb der Funktion — keine statische ``core → tools``-Kante (die bewussten
    Lazy-Eintraege sind in der import-linter-Baseline hinterlegt).

    Returns:
        Liste einsatzbereiter Hooks (leer, wenn keiner ladbar ist — der
        Loeschpfad laeuft dann ohne Cascade-Cleanup weiter, fail-soft).
    """
    hooks: list[SubjectCleanupHook] = []
    try:
        # Lazy import: haelt core frei von einer statischen tools-Abhaengigkeit.
        from tools.norisk_dashboard.data.workflow_progress_repository import (  # noqa: PLC0415
            WorkflowProgressRepository,
        )

        hooks.append(_WorkflowProgressCleanupHook(WorkflowProgressRepository()))
    except Exception as exc:  # noqa: BLE001 — fail-soft Cross-Tool-Resolver-Grenze
        log.warning(
            "Workflow-Cleanup-Hook nicht verfuegbar (%s) — Loeschpfad ohne "
            "Workflow-Cleanup (fail-soft).",
            type(exc).__name__,
        )
    return hooks
