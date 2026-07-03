"""usage_signals — Cross-Tool-Nutzungssignale aus dem SELF-Sovereignty-Audit.

Read-Adapter, der den core-Port
:class:`core.security_subject.ports.UsageSignalProvider` implementiert: er liest
das **jüngste** SELF-Audit eines Subjekts und übersetzt die erkannten/deklarierten
Provider in kategorisierte tri-state:class:`NutzungsSignale`, Ebene 3).

Konservativitäts-Kern/018):
  * Ein Signal ist ``True``, sobald ein passender Provider (erkannt **oder**
    deklariert) vorliegt → Frage aktiv halten.
  * Ein Signal ist ``False`` nur bei einem **abgeschlossenen** Audit, in dem die
    Kategorie nachweislich leer ist → Frage als N/A vorbelegbar. „Abgeschlossen"
    = Detection lief **oder** mindestens ein Provider wurde deklariert.
  * Sonst ``None`` (kein belastbares Audit) → No-op, kein Auto-N/A.

PII: Es werden ausschließlich Kategorie-Bools zurückgegeben — keine
Provider-Namen, kein Firmenname (DSGVO Art. 5 §Threat-Model). Logging
bleibt frei von Audit-Inhalten.

Schichtzugehörigkeit: application/ — orchestriert data (Repository) + domain
(Entities); kein GUI-Import. Bezug (Cross-Tool über core-Resolver).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable

from core.logger import get_logger
from core.security_subject.models import NutzungsSignale
from core.security_subject.ports import UsageSignalProvider
from tools.customer_audit.data.customer_audit_repository import CustomerAuditRepository
from tools.customer_audit.domain.entities import AuditMode, DetectedProvider

log = get_logger(__name__)

# Provider-Name-Marker für Microsoft 365 / Azure (Katalog-Namen + gängige
# Schreibweisen, lowercase-Match). Bewusst name-basiert (präziser als die
# Kategorie ``office_suite``, die auch Google Workspace umfasst).
_M365_NAME_MARKERS: tuple[str, ...] = ("microsoft 365", "office 365", "azure")

# Cloud-Speicher umfasst File-Sync-Dienste (Dropbox, Google Drive) UND die
# Office-Suites (M365/Workspace bündeln OneDrive/SharePoint bzw. Drive).
_CLOUD_SPEICHER_KATEGORIEN: frozenset[str] = frozenset({"file_sync", "office_suite"})

# „Self-hosted" ist kein Auftragsverarbeiter; jeder andere Status ist ein
# externer Dienstleister (eu_sovereign/eu_boundary/cloud_act), für den ein AVV
# erforderlich ist.
_SELF_HOSTED_STATUS = "self_hosted"


def create_default_usage_signal_provider() -> UsageSignalProvider | None:
    """Default-Factory mit production-tauglichem Repository.

    Wird ausschließlich über den core-Resolver
:func:`core.security_subject.resolver.create_usage_signal_provider` (lazy)
    bezogen — kein tool→tool-Import bei den Konsumenten.

    Returns:
        Einsatzbereiter Provider oder ``None``, wenn das Repository nicht
        initialisierbar ist (z. B. fehlender SQLCipher-Schlüssel). Die
        Fehlerbehandlung bleibt fail-soft beim Resolver/Aufrufer.
    """
    return CustomerAuditUsageSignals(CustomerAuditRepository())


class CustomerAuditUsageSignals:
    """UsageSignalProvider über das jüngste SELF-Audit eines Subjekts."""

    def __init__(self, repository: CustomerAuditRepository) -> None:
        """Initialisiert den Adapter.

        Args:
            repository: Repository der Kunden-/Self-Audits.
        """
        self._repo = repository

    def signale_fuer(self, subject_id: str) -> NutzungsSignale:
        """Leitet Nutzungssignale aus dem jüngsten SELF-Audit ab (fail-soft).

        Args:
            subject_id: UUID des Subjekts (i. d. R. das eigene System).

        Returns:
:class:`NutzungsSignale`; alle Felder ``None``, wenn kein
            belastbares SELF-Audit vorliegt oder ein Lesefehler auftritt.
        """
        if not subject_id:
            return NutzungsSignale()
        try:
            return self._signale_aus_audit(subject_id)
        except Exception as exc:  # noqa: BLE001 — fail-soft: ohne Signal kein Auto-N/A
            log.warning(
                "Nutzungssignale nicht ableitbar (%s) — Org-Auto-Detection "
                "fail-soft.",
                type(exc).__name__,
            )
            return NutzungsSignale()

    def _signale_aus_audit(self, subject_id: str) -> NutzungsSignale:
        """Lädt das jüngste SELF-Audit und mappt es auf tri-state-Signale."""
        summary = self._repo.latest_summary_by_subject(subject_id)
        if summary is None:
            return NutzungsSignale()
        audit = self._repo.load_by_id(summary["audit_id"])
        # Defensiv: das eigene Subjekt verknüpft nur SELF-Audits — aber nie
        # aus einem Kunden-Audit auf die eigene Nutzung schließen.
        if audit is None or audit.audit_mode is not AuditMode.SELF:
            return NutzungsSignale()

        sov = audit.sovereignty_audit
        provider: list[DetectedProvider] = [*sov.detected, *sov.declared]
        # „Abgeschlossen": ein FEHLERFREI gelaufener Detection-Scan ODER eine aktive
        # Deklaration. Ein GESCHEITERTER Scan (scan_errors gesetzt, z. B. DNS nicht
        # auflösbar) ist Unwissen, kein Nicht-Nutzungs-Befund — er darf keine leere
        # Kategorie zu ``False`` machen: „Abwesenheit eines Signals ≠
        # Nicht-Nutzung"; 3-Sub-Agent-Review P2). Eine Deklaration bleibt unabhängig
        # vom Scan belastbar. Sonst → ``None`` (No-op, kein Auto-N/A).
        abgeschlossen = (sov.detection_enabled and not sov.scan_errors) or bool(
            sov.declared
        )

        return NutzungsSignale(
            nutzt_m365=_tri(provider, abgeschlossen, _ist_m365),
            nutzt_kanzlei_software=_tri(provider, abgeschlossen, _ist_kanzlei),
            nutzt_cloud_speicher=_tri(provider, abgeschlossen, _ist_cloud_speicher),
            hat_auftragsverarbeiter=_tri(provider, abgeschlossen, _ist_auftragsverarbeiter),
            audit_datum=audit.created_at,
        )


# ---------------------------------------------------------------------------
# Reine Matcher + tri-state-Auswertung
# ---------------------------------------------------------------------------


def _tri(
    provider: list[DetectedProvider],
    abgeschlossen: bool,
    passt: Callable[[DetectedProvider], bool],
) -> bool | None:
    """Tri-state-Auswertung einer Kategorie.

    Args:
        provider: Erkannte + deklarierte Provider.
        abgeschlossen: Ob das Audit belastbar abgeschlossen ist (Detection lief
            oder es wurde deklariert).
        passt: Prädikat, das einen Provider der Kategorie zuordnet.

    Returns:
        ``True`` bei Treffer, ``False`` bei abgeschlossenem Audit ohne Treffer,
        sonst ``None`` (kein belastbares Signal).
    """
    if any(passt(p) for p in provider):
        return True
    if abgeschlossen:
        return False
    return None


def _ist_m365(p: DetectedProvider) -> bool:
    """True, wenn der Provider Microsoft 365 / Azure ist (name-basiert)."""
    name = p.name.lower()
    return any(marker in name for marker in _M365_NAME_MARKERS)


def _ist_kanzlei(p: DetectedProvider) -> bool:
    """True, wenn der Provider Steuerberater-/Kanzlei-Software ist."""
    return p.category == "kanzlei_software"


def _ist_cloud_speicher(p: DetectedProvider) -> bool:
    """True, wenn der Provider Cloud-Speicher bereitstellt (File-Sync/Office-Suite)."""
    return p.category in _CLOUD_SPEICHER_KATEGORIEN


def _ist_auftragsverarbeiter(p: DetectedProvider) -> bool:
    """True, wenn der Provider ein externer Auftragsverarbeiter ist (nicht self-hosted)."""
    return p.status != _SELF_HOSTED_STATUS
