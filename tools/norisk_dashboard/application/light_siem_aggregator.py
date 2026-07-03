"""
light_siem_aggregator — Aggregator + Source-Adapter fuer den Light-SIEM.

Iter 3d:

Der Aggregator zieht periodisch (oder On-Demand bei Dashboard-Refresh)
neue Sicherheits-Events aus den anderen NoRisk-Tools, normalisiert sie
auf das:class:`LightSiemEvent`-Format und persistiert sie via
:class:`LightSiemRepository` (mit automatischem Dedup ueber
``dedup_hash``).

Adapter-Pattern: Pro Source-Tool eine Adapter-Funktion mit Signatur
`` -> list[LightSiemEvent]``. Die Funktion darf alles importieren
(Patch-Monitor-Service, EOL-Resolver, etc.) — bei Fehlern wird das
betreffende Source-Set leer geliefert (fail-silently), damit ein
defektes Source-Tool nicht das ganze SIEM blockiert.

Aktive Adapter: Supply-Chain-Renewals, Awareness-
Schulungs-Renewals, Patch-Monitor (EOL/Update), System-Scanner (Hardening-
Checks) und Cert-Monitor (Ablauf). Alle lesen PERSISTIERTE Daten — kein
Live-Scan/Netz im Ingest.

Schichtzugehoerigkeit: application/ — darf domain + data + andere
application-Module + core importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from core.logger import get_logger
from tools.norisk_dashboard.data.light_siem_repository import (
    LightSiemRepository,
)
from tools.norisk_dashboard.domain.light_siem_models import (
    DEFAULT_LOOKBACK_DAYS,
    EventSeverity,
    EventSource,
    LightSiemEvent,
    LightSiemSummary,
)

_log = get_logger(__name__)

SourceAdapter = Callable[[], list[LightSiemEvent]]


class LightSiemAggregator:
    """Orchestriert den Event-Ingest aus mehreren Source-Tools.

    Default-Adapter sind die Tools, die in 3a-3c angebunden wurden
    (Supply-Chain + Awareness). Tests koennen ueber den Konstruktor
    eigene Adapter injizieren.
    """

    def __init__(
        self,
        repository: LightSiemRepository | None = None,
        adapters: list[SourceAdapter] | None = None,
    ) -> None:
        """Initialisiert den Aggregator.

        Args:
            repository: Optional vorgefertigtes Repository (z. B. Test-DB).
            adapters: Liste von Source-Adapter-Callables. Default:
                        die im Modul registrierten Default-Adapter.
        """
        self._repo = repository or LightSiemRepository()
        self._adapters: list[SourceAdapter] = (
            adapters if adapters is not None else _default_adapters()
        )

    def run_ingest(self) -> tuple[int, int]:
        """Ruft alle Adapter auf und persistiert die gelieferten Events.

        Returns:
            ``(added, skipped_dedup)`` ueber alle Adapter aggregiert.
        """
        all_events: list[LightSiemEvent] = []
        for adapter in self._adapters:
            try:
                events = adapter()
            except Exception:  # noqa: BLE001 — fail-silently pro Adapter
                _log.exception(
                    "light_siem_adapter_failed adapter=%s",
                    getattr(adapter, "__name__", "?"),
                )
                continue
            all_events.extend(events)
        added, skipped = self._repo.bulk_add(all_events)
        _log.info(
            "light_siem_ingest_done added=%s skipped_dedup=%s adapters=%s",
            added,
            skipped,
            len(self._adapters),
        )
        return (added, skipped)

    def list_recent(
        self,
        lookback_days: int = DEFAULT_LOOKBACK_DAYS,
        limit: int = 200,
    ) -> list[LightSiemEvent]:
        """Pass-through zum Repository: die neuesten Events."""
        return self._repo.list_recent(lookback_days=lookback_days, limit=limit)

    def summary(
        self, lookback_days: int = DEFAULT_LOOKBACK_DAYS
    ) -> LightSiemSummary:
        """Pass-through zum Repository: aggregierte Kennzahlen."""
        return self._repo.summary(lookback_days=lookback_days)

    def load_dashboard_bundle(
        self,
        *,
        table_limit: int,
        chart_lookback_days: int,
        chart_limit: int,
    ) -> tuple[LightSiemSummary, list[LightSiemEvent], list[LightSiemEvent]]:
        """Pass-through: Summary + Tabellen- + Chart-Events in EINER Connection.

        Buendelt die drei Dashboard-Reads (Perf) —:meth:`LightSiemRepository.load_dashboard_bundle`.
        """
        return self._repo.load_dashboard_bundle(
            table_limit=table_limit,
            chart_lookback_days=chart_lookback_days,
            chart_limit=chart_limit,
        )

    def purge_older_than(self, retention_days: int = 180) -> int:
        """Loescht Events aelter als ``retention_days``."""
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        return self._repo.delete_older_than(cutoff)


# ---------------------------------------------------------------------------
# Default-Adapter Initial-Set)
# ---------------------------------------------------------------------------


def _default_adapters() -> list[SourceAdapter]:
    """Liefert die aktiven Source-Adapter.

    Patch-Monitor / System-Scanner / Cert-Monitor ergaenzt
    (3e/3f) — alle lesen PERSISTIERTE Daten (kein Live-Scan/Netz im Ingest),
    fail-soft pro Adapter.
    """
    return [
        supply_chain_avv_adapter,
        awareness_training_adapter,
        patch_monitor_adapter,
        system_scanner_adapter,
        cert_monitor_adapter,
    ]


def _map_core_severity(severity: object) -> EventSeverity:
    """Mappt ``core.security.severity.Severity`` auf:class:`EventSeverity`."""
    from core.security.severity import Severity  # noqa: PLC0415

    return {
        Severity.CRITICAL: EventSeverity.CRITICAL,
        Severity.HIGH: EventSeverity.ERROR,
        Severity.MEDIUM: EventSeverity.WARN,
        Severity.LOW: EventSeverity.INFO,
        Severity.INFO: EventSeverity.INFO,
    }.get(severity, EventSeverity.INFO)  # type: ignore[arg-type]


def patch_monitor_adapter() -> list[LightSiemEvent]:
    """Adapter fuer Update-Rueckstand + EOL aus dem Patch-Monitor/3e).

    Liest den PERSISTIERTEN Inventar-Stand (``load_from_db`` — kein Scan, kein
    Netz) und liefert je ein Event fuer End-of-Life-Software (CRITICAL) bzw.
    verfuegbare Updates (WARN; CRITICAL bei bekanntem Exploit). Fail-silently.
    """
    try:
        from tools.patch_monitor.application.patch_inventory_service import (  # noqa: PLC0415
            PatchInventoryService,
        )
    except ImportError:
        return []
    try:
        results = PatchInventoryService().load_from_db()
    except Exception:  # noqa: BLE001
        _log.exception("light_siem_patch_adapter_query_failed")
        return []

    events: list[LightSiemEvent] = []
    now = datetime.now(UTC)
    for r in results:
        update_available = bool(
            r.available_version
            and r.available_version not in ("", r.installed_version)
        )
        if r.eol:
            severity = EventSeverity.CRITICAL
            event_type = "software_eol"
            summary = (
                f"Software am End-of-Life: {r.name} ({r.installed_version}) — "
                "erhaelt keine Sicherheitsupdates mehr."
            )
        elif update_available:
            severity = (
                EventSeverity.CRITICAL if r.exploit_available else EventSeverity.WARN
            )
            exploit = " — Exploit oeffentlich bekannt" if r.exploit_available else ""
            summary = (
                f"Update verfuegbar: {r.name} {r.installed_version} -> "
                f"{r.available_version}{exploit}"
            )
            event_type = "update_available"
        else:
            continue
        events.append(
            LightSiemEvent(
                id=None,
                timestamp=now,
                source=EventSource.PATCH_MONITOR,
                event_type=event_type,
                severity=severity,
                summary=summary,
                payload_json=json.dumps(
                    {
                        "name": r.name,
                        "installed_version": r.installed_version,
                        "available_version": r.available_version,
                        "eol": r.eol,
                        "exploit_available": r.exploit_available,
                        "cvss_max": r.cvss_max,
                    }
                ),
            )
        )
    return events


def system_scanner_adapter() -> list[LightSiemEvent]:
    """Adapter fuer fehlgeschlagene Hardening-Checks aus dem System-Scanner/3e).

    Liest den letzten PERSISTIERTEN Scan (``ScanRepository.load_latest`` — kein
    Live-Scan) und liefert je ein Event pro Check, der MESSBAR und NICHT bestanden
    ist. Nicht-messbare Checks (``measurable=False``) bleiben aussen vor (Mess-
    Fehlschlag nie als roter Befund, vgl./). Fail-silently.
    """
    try:
        from tools.system_scanner.data.scanner_repository import (  # noqa: PLC0415
            ScanRepository,
        )
    except ImportError:
        return []
    try:
        scan = ScanRepository().load_latest()
    except Exception:  # noqa: BLE001
        _log.exception("light_siem_system_adapter_query_failed")
        return []
    if scan is None:
        return []

    events: list[LightSiemEvent] = []
    now = datetime.now(UTC)
    for check in scan.hardening_checks:
        if not check.measurable or check.passed:
            continue
        detail = f": {check.detail}" if check.detail else ""
        events.append(
            LightSiemEvent(
                id=None,
                timestamp=now,
                source=EventSource.SYSTEM_SCANNER,
                event_type=f"hardening_{check.check_id.lower()}",
                severity=_map_core_severity(check.severity),
                summary=f"Hardening nicht erfuellt: {check.label} ({check.check_id}){detail}",
                payload_json=json.dumps(
                    {
                        "check_id": check.check_id,
                        "label": check.label,
                        "detail": getattr(check, "detail", ""),
                    }
                ),
            )
        )
    return events


def cert_monitor_adapter() -> list[LightSiemEvent]:
    """Adapter fuer kritische/auslaufende Zertifikate aus dem Cert-Monitor/3f).

    Liest die letzten PERSISTIERTEN Ergebnisse (``lade_letzte_ergebnisse`` — kein
    Live-TLS-Handshake) und liefert je ein Event fuer Status KRITISCH (CRITICAL)
    bzw. WARNUNG (WARN). OK/UNBEKANNT/FEHLER (Mess-Fehlschlag) werden uebersprungen.
    Fail-silently.
    """
    try:
        from tools.cert_monitor.application.cert_monitor_service import (  # noqa: PLC0415
            CertMonitorService,
        )
        from tools.cert_monitor.domain.models import CertStatus  # noqa: PLC0415
    except ImportError:
        return []
    try:
        certs = CertMonitorService.create_default().lade_letzte_ergebnisse()
    except Exception:  # noqa: BLE001
        _log.exception("light_siem_cert_adapter_query_failed")
        return []

    events: list[LightSiemEvent] = []
    now = datetime.now(UTC)
    for cert in certs:
        if cert.status is CertStatus.KRITISCH:
            severity = EventSeverity.CRITICAL
            event_type = "cert_critical"
        elif cert.status is CertStatus.WARNUNG:
            severity = EventSeverity.WARN
            event_type = "cert_expiring"
        else:
            continue
        grund = cert.findings[0] if cert.findings else cert.status.value
        events.append(
            LightSiemEvent(
                id=None,
                timestamp=now,
                source=EventSource.CERT_MONITOR,
                event_type=event_type,
                severity=severity,
                summary=(
                    f"Zertifikat {cert.domain}: {grund} "
                    f"(noch {cert.tage_verbleibend} Tage gueltig)."
                ),
                payload_json=json.dumps(
                    {
                        "domain": cert.domain,
                        "status": cert.status.value,
                        "tage_verbleibend": cert.tage_verbleibend,
                        "gueltig_bis": cert.gueltig_bis,
                    }
                ),
            )
        )
    return events


def supply_chain_avv_adapter() -> list[LightSiemEvent]:
    """Adapter fuer AVV-Renewals aus dem Supply-Chain-Monitor.

    Liest ueberfaellige + bald auslaufende AVVs und liefert je ein
    LightSiem-Event mit passender Severity (CRITICAL fuer OVERDUE,
    WARN fuer EXPIRING_SOON).

    Fail-silently: Wenn das Supply-Chain-Tool nicht importierbar ist
    (z. B. White-Label-Build ohne das Tool), wird eine leere Liste
    zurueckgegeben.
    """
    try:
        from tools.supply_chain_monitor.application.avv_service import (  # noqa: PLC0415
            AvvService,
        )
        from tools.supply_chain_monitor.application.vendor_service import (  # noqa: PLC0415
            VendorService,
        )
        from tools.supply_chain_monitor.domain.models import (  # noqa: PLC0415
            RenewalStatus,
        )
    except ImportError:
        return []

    try:
        avvs = AvvService().list_all()
        vendor_map = {v.id: v.name for v in VendorService().list_vendors() if v.id is not None}
    except Exception:  # noqa: BLE001
        _log.exception("light_siem_supply_chain_adapter_query_failed")
        return []

    events: list[LightSiemEvent] = []
    now = datetime.now(UTC)
    for avv in avvs:
        status = avv.renewal_status(now=now)
        if status is RenewalStatus.OK:
            continue
        vendor_name = vendor_map.get(avv.vendor_id, f"Vendor #{avv.vendor_id}")
        if status is RenewalStatus.OVERDUE:
            severity = EventSeverity.CRITICAL
            verb = "abgelaufen"
            event_type = "avv_overdue"
        else:
            severity = EventSeverity.WARN
            verb = "laeuft demnaechst ab"
            event_type = "avv_expiring"
        summary = (
            f"AVV {vendor_name} {verb} (gueltig bis "
            f"{avv.valid_until.strftime('%Y-%m-%d')})."
        )
        events.append(
            LightSiemEvent(
                id=None,
                timestamp=now,
                source=EventSource.SUPPLY_CHAIN_MONITOR,
                event_type=event_type,
                severity=severity,
                summary=summary,
                payload_json=json.dumps(
                    {
                        "vendor_id": avv.vendor_id,
                        "vendor_name": vendor_name,
                        "valid_until": avv.valid_until.isoformat(),
                    }
                ),
            )
        )
    return events


def awareness_training_adapter() -> list[LightSiemEvent]:
    """Adapter fuer Schulungs-Renewals aus dem Awareness-Tracker.

    Liefert je ein Event pro Schulung mit Status EXPIRED (CRITICAL) oder
    EXPIRING_SOON (WARN).
    """
    try:
        from tools.awareness_tracker.application.awareness_service import (  # noqa: PLC0415
            AwarenessService,
        )
        from tools.awareness_tracker.domain.models import (  # noqa: PLC0415
            ValidityStatus,
        )
    except ImportError:
        return []

    try:
        service = AwarenessService()
        due = service.list_trainings_due_soon()
        employee_names = service.employee_lookup()
    except Exception:  # noqa: BLE001
        _log.exception("light_siem_awareness_adapter_query_failed")
        return []

    events: list[LightSiemEvent] = []
    now = datetime.now(UTC)
    for training in due:
        status = training.validity_status(now=now)
        if status is ValidityStatus.EXPIRED:
            severity = EventSeverity.CRITICAL
            verb = "abgelaufen"
            event_type = "training_expired"
        elif status is ValidityStatus.EXPIRING_SOON:
            severity = EventSeverity.WARN
            verb = "laeuft demnaechst ab"
            event_type = "training_expiring"
        else:
            continue
        emp_label = employee_names.get(
            training.employee_id, f"Mitarbeiter #{training.employee_id}"
        )
        if training.valid_until is None:
            # Eigentlich von list_trainings_due_soon ausgefiltert, aber
            # defensiv — Status EXPIRED ohne valid_until ist inkonsistent.
            continue
        summary = (
            f"Schulung '{training.title}' fuer {emp_label} {verb} "
            f"(gueltig bis {training.valid_until.strftime('%Y-%m-%d')})."
        )
        events.append(
            LightSiemEvent(
                id=None,
                timestamp=now,
                source=EventSource.AWARENESS_TRACKER,
                event_type=event_type,
                severity=severity,
                summary=summary,
                payload_json=json.dumps(
                    {
                        "employee_id": training.employee_id,
                        "employee_name": emp_label,
                        "training_id": training.id,
                        "training_title": training.title,
                        "valid_until": training.valid_until.isoformat(),
                    }
                ),
            )
        )
    return events
