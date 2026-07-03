"""scan_prefill_provider — ScanDataPort-Adapter für die Audit-Vorbefüllung.

Implementiert den core-Port:class:`core.scan_prefill.ports.ScanDataPort`, indem
er die bereits vorhandenen **headless** Mess-Pfade aggregiert und als
:class:`core.scan_prefill.models.AuditPrefill` (gemessene Werte mit Herkunft)
liefert — **ohne Persistenz, ohne Score-History-Pollution** Phase 2):

* Hardening-Baseline (frisch, Qt-frei):
:func:`tools.system_scanner.application.windows_hardening_scanner.run_hardening_baseline_scan`
  → SH-001 (Firewall), SH-003 (RDP), SH-004 (Windows-Update), SH-010 (BitLocker).
* OS-Eckdaten::func:`tools.system_scanner.application.os_info_use_case.detect_os_info`.
* Netzwerk-Scan-Präsenz: ``NetworkService.lade_letzte_scans`` (read-only) über eine
  eigene, persistenzfreie NetworkService-Wiring (gleiche Komponenten wie
:meth:`ScoringService.create_for_audit_snapshot`, aber ohne dessen Kollateral-
  Sub-Services).

Leitplanken, fail-closed/-soft):

* **Keine PII** — der Adapter kennt keinen Firmennamen/Kontakt; das DTO trägt nur
  technische Mess-Fakten über das *eigene* System.
* **Nur messbare Werte** — ein Hardening-Check mit ``measurable=False`` (kein
  Admin / nicht anwendbar / Parse-Fehler) liefert KEIN Prefill-Feld (das Wizard-
  Feld bleibt auf seinem Default; kein „unbekannt"-Vorbefüllen).
* **Fail-soft** — jede Quelle ist gekapselt; fällt eine aus, fehlt nur ihr Feld.

Schichtzugehörigkeit: application/ — orchestriert headless Mess-Pfade, kein GUI,
keine direkte DB, keine Persistenz.

Author: Patrick Riederich
Version: 1.0 Phase 2, 2026-06-27)
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from core.logger import get_logger
from core.scan_prefill.models import AuditPrefill, MeasuredField

if TYPE_CHECKING:
    from tools.system_scanner.domain.entities import HardeningCheck, OSInfo, ScanResult

log = get_logger(__name__)

#: Tool-Herkunft der Hardening-/OS-Messungen (für den Badge im Wizard).
_SOURCE_SYSTEM = "system_scanner"
#: Tool-Herkunft der Netzwerk-Messung.
_SOURCE_NETWORK = "network_scanner"


def _hardening_field(
    check: HardeningCheck | None,
    measured_at: str,
    *,
    exposed: bool = False,
) -> MeasuredField | None:
    """Baut ein:class:`MeasuredField` aus einem Hardening-Check (oder ``None``).

    Ein nicht vorhandener ODER nicht messbarer Check (``measurable=False`` —
    fehlende Adminrechte, nicht anwendbar, Parse-Fehler) liefert ``None``: das
    Wizard-Feld bleibt dann auf seinem Default: kein „unbekannt"-Prefill;
    ein nicht messbarer Check ist KEIN Verstoß).

    Args:
        check: Der Hardening-Check oder ``None`` (nicht im Scan enthalten).
        measured_at: ISO-8601-Zeitstempel (UTC) der Messung.
        exposed: ``False`` (Default) → ``value = check.passed`` (Schutz aktiv).
            ``True`` → ``value = not check.passed`` (Exposition/Risiko erkannt,
            z. B. SH-003: RDP erreichbar = Check NICHT bestanden).

    Returns:
        Ein:class:`MeasuredField` mit Herkunft oder ``None``.
    """
    if check is None or not check.measurable:
        return None
    value = (not check.passed) if exposed else check.passed
    return MeasuredField(
        value=value,
        check_id=check.check_id,
        source_tool=_SOURCE_SYSTEM,
        measured_at=measured_at,
        detail=check.detail,
    )


class ScanPrefillProvider:
    """Erhebt gemessene Audit-Vorbefüll-Werte (Implementierung des ScanDataPort).

    Alle Mess-Quellen sind injizierbar (Tests/Non-Windows); ``None`` (Default)
    bindet die Production-Pfade lazy. Konsumenten beziehen die Instanz über
:func:`core.scan_prefill.resolver.create_scan_data_provider`.
    """

    def __init__(
        self,
        *,
        scan_runner: Callable[[], ScanResult | None] | None = None,
        network_service: object | None = None,
        os_info_fn: Callable[[], OSInfo] | None = None,
    ) -> None:
        """Initialisiert den Adapter.

        Args:
            scan_runner: Liefert einen frischen Hardening-:class:`ScanResult`
                (oder ``None`` auf Non-Windows). ``None`` (Default) → lazy
                ``run_hardening_baseline_scan`` (Production-Probe).
            network_service: Objekt mit ``lade_letzte_scans(limit)`` (NetworkService).
                ``None`` (Default) → lazy eigene persistenzfreie NetworkService-Wiring
                (read-only ``lade_letzte_scans``).
            os_info_fn: Liefert die:class:`OSInfo` der Plattform. ``None``
                (Default) → lazy ``detect_os_info``.
        """
        self._scan_runner = scan_runner
        self._network_service = network_service
        self._os_info_fn = os_info_fn

    def build_audit_prefill(self) -> AuditPrefill:
        """Erhebt einen frischen Mess-Snapshot als:class:`AuditPrefill`.

        Headless + transient: persistiert NICHTS und trägt keine PII. Jede Quelle
        ist fail-soft gekapselt — fällt eine aus, fehlt nur ihr Feld.

        Returns:
            Ein:class:`AuditPrefill` mit den messbaren Feldern; nicht messbare
            Felder bleiben ``None``.
        """
        now = datetime.now(UTC).isoformat()
        firewall = remote_access_rdp = encryption = patch_ok = None

        scan = self._run_hardening_scan()
        if scan is not None:
            from tools.system_scanner.application.windows_hardening_scanner import (  # noqa: PLC0415
                SH_001_FIREWALL,
                SH_003_RDP,
                SH_004_AUTO_UPDATE,
                SH_010_BITLOCKER,
            )

            ts = scan.timestamp
            measured_at = ts.isoformat() if hasattr(ts, "isoformat") else now
            checks = {c.check_id: c for c in scan.hardening_checks}
            firewall = _hardening_field(checks.get(SH_001_FIREWALL), measured_at)
            remote_access_rdp = _hardening_field(
                checks.get(SH_003_RDP), measured_at, exposed=True
            )
            encryption = _hardening_field(checks.get(SH_010_BITLOCKER), measured_at)
            patch_ok = _hardening_field(checks.get(SH_004_AUTO_UPDATE), measured_at)

        return AuditPrefill(
            firewall_active=firewall,
            remote_access_rdp=remote_access_rdp,
            disk_encryption_active=encryption,
            patch_ok=patch_ok,
            os_name=self._os_field(now),
            open_ports_scanned=self._network_field(now),
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Mess-Quellen (lazy Production-Defaults, injizierbar für Tests)
    # ------------------------------------------------------------------

    def _run_hardening_scan(self) -> ScanResult | None:
        """Führt die frische Hardening-Baseline aus (fail-soft)."""
        runner = self._scan_runner
        if runner is None:
            from tools.system_scanner.application.windows_hardening_scanner import (  # noqa: PLC0415
                run_hardening_baseline_scan,
            )

            runner = run_hardening_baseline_scan
        try:
            return runner()
        except Exception as exc:  # noqa: BLE001 — Mess-Quelle darf den Prefill nicht crashen
            log.warning(
                "Hardening-Baseline fuer Audit-Prefill fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return None

    def _os_field(self, now: str) -> MeasuredField | None:
        """Baut das OS-Feld aus den OS-Eckdaten (fail-soft)."""
        fn = self._os_info_fn
        if fn is None:
            from tools.system_scanner.application.os_info_use_case import (  # noqa: PLC0415
                detect_os_info,
            )

            fn = detect_os_info
        try:
            os_info = fn()
        except Exception as exc:  # noqa: BLE001 — OS-Info ist optional
            log.warning("OS-Info fuer Audit-Prefill fehlgeschlagen: %s", type(exc).__name__)
            return None
        # detect_os_info/os_info_fn liefern vertraglich immer ein OSInfo
        # (Fallback OSPlatform.UNKNOWN mit name=""); leerer Name = nicht messbar.
        if not os_info.name:
            return None
        detail = (
            f"{os_info.name} {os_info.version}".strip()
            if os_info.version
            else os_info.name
        )
        return MeasuredField(
            value=os_info.name,
            check_id="os_info",
            source_tool=_SOURCE_SYSTEM,
            measured_at=now,
            detail=detail,
        )

    def _network_field(self, now: str) -> MeasuredField | None:
        """Baut das Netzwerk-Feld aus der Scan-Präsenz (read-only, fail-soft).

        ``value=True`` bedeutet „mindestens ein Netzwerk-Scan liegt vor" → der
        Wizard kann ``offene_ports_bekannt`` auf „Ja" vorbelegen. Kein Scan →
        ``None`` (kein Prefill).
        """
        svc = self._resolve_network_service()
        if svc is None:
            return None
        try:
            scans = svc.lade_letzte_scans(limit=1)
        except Exception as exc:  # noqa: BLE001 — Netzwerk-Read darf den Prefill nicht crashen
            log.warning(
                "Netzwerk-Scan-Read fuer Audit-Prefill fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return None
        if not scans:
            return None
        scan = scans[0]
        ts = getattr(scan, "gestartet_am", None)
        measured_at = ts.isoformat() if hasattr(ts, "isoformat") else now
        count = 0
        try:
            count = int(scan.anzahl_offene_ports)
        except (TypeError, ValueError, AttributeError):
            count = 0
        return MeasuredField(
            value=True,
            check_id=_SOURCE_NETWORK,
            source_tool=_SOURCE_NETWORK,
            measured_at=measured_at,
            detail=f"Netzwerk-Scan vorhanden ({count} offene Ports erfasst)",
        )

    def _resolve_network_service(self) -> object | None:
        """Liefert den NetworkService (injiziert oder über die application-Factory).

        Default-Pfad bezieht den NetworkService über
:func:`tools.network_scanner.application.network_service.create_default_network_service`
        (application-Schicht des Netzwerk-Scanners, kein Cross-Tool-Zugriff auf
        dessen ``data/``-Klassen, A-1). Genutzt wird ausschliesslich der read-only
        Pfad ``lade_letzte_scans`` — keine Persistenz.
        """
        if self._network_service is not None:
            return self._network_service
        try:
            # Cross-Tool-Wiring über die application-Schicht des Netzwerk-Scanners
            # (Factory), nicht direkt dessen data/-Klassen — Schichtgrenze (A-1).
            from tools.network_scanner.application.network_service import (  # noqa: PLC0415
                create_default_network_service,
            )

            return create_default_network_service()
        except Exception as exc:  # noqa: BLE001 — fail-soft Wiring-Grenze
            log.warning(
                "Netzwerk-Service fuer Audit-Prefill nicht verfuegbar: %s",
                type(exc).__name__,
            )
            return None


def create_default_scan_prefill_provider() -> ScanPrefillProvider:
    """Default-Factory: Production-Wiring über die headless Mess-Pfade.

    Alle Quellen werden lazy beim ersten ``build_audit_prefill`` gebunden
    (Production-Probe, ``detect_os_info``, Snapshot-Netzwerk-Service) — daher kann
    die Factory selbst nicht scheitern. Cross-Tool-Konsumenten beziehen den
    Provider über den core-Resolver
:func:`core.scan_prefill.resolver.create_scan_data_provider`, ohne
    ``security_scoring``-Interna zu importieren.

    Returns:
        Einsatzbereiter:class:`ScanPrefillProvider`.
    """
    return ScanPrefillProvider()
