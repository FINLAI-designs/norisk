"""prefill_worker — Hintergrund-Worker fuer die SELF-Audit-Vorbefuellung Phase 3).

Erhebt den:class:`core.scan_prefill.models.AuditPrefill` ueber den
:class:`core.scan_prefill.ports.ScanDataPort` in einem **Worker-Thread**
(``QThreadPool``), damit der frische Hardening-Scan (netsh/PowerShell/manage-bde,
sekundenlang) die Wizard-GUI nicht einfriert. Das Ergebnis wird per Signal
zurueck auf den GUI-Thread geliefert (cross-thread → Qt queued automatisch).

Teardown-Sicherheit::class:`PrefillSignals` hat KEIN Parent und wird vom
:class:`PrefillTask` (den der ``QThreadPool`` bis Laufende hält) am Leben gehalten
— der Signal-Traeger kann also nie vor dem ``emit`` zerstoert werden. Der Wizard
ueberlebt einen Close mitten im Scan durch seinen Parent-Hold (parent=self +
exec), sodass der gequeuede Callback auf dem (versteckten, aber lebenden) Wizard
laeuft; und falls der Empfaenger doch einmal zerstoert wuerde, trennt Qt die
Verbindung automatisch (Slot-Auto-Disconnect). Beides verhindert ein use-after-free.

Schichtzugehoerigkeit: gui/ — Qt-Worker, ruft nur den core-Port (kein tool→tool).

Author: Patrick Riederich
Version: 1.0 Phase 3, 2026-06-27)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, QRunnable, Signal

from core.logger import get_logger

if TYPE_CHECKING:
    from core.scan_prefill.ports import ScanDataPort

log = get_logger(__name__)


class PrefillSignals(QObject):
    """Signal-Traeger fuer das Worker-Ergebnis (eigener QObject, kein Parent).

    Signals:
        done: Emittiert mit dem ``AuditPrefill`` (als ``object``) bei Erfolg.
        failed: Emittiert mit dem Exception-Klassennamen (str) bei Fehler.
    """

    done = Signal(object)  # AuditPrefill
    failed = Signal(str)


class PrefillTask(QRunnable):
    """QRunnable, das ``ScanDataPort.build_audit_prefill`` off-thread ausfuehrt."""

    def __init__(self, provider: ScanDataPort, signals: PrefillSignals) -> None:
        """Initialisiert den Task.

        Args:
            provider: Der:class:`ScanDataPort` (security_scoring-Adapter).
            signals: Der:class:`PrefillSignals`-Traeger; muss vom Aufrufer am
                Leben gehalten werden, bis der Task fertig ist.
        """
        super().__init__()
        self._provider = provider
        self._signals = signals

    def run(self) -> None:
        """Fuehrt die (potenziell langsame) Messung aus und meldet das Ergebnis."""
        try:
            prefill = self._provider.build_audit_prefill()
        except Exception as exc:  # noqa: BLE001 — Worker darf NIE crashen (Qt-Thread)
            log.warning(
                "Audit-Prefill-Worker fehlgeschlagen: %s", type(exc).__name__
            )
            self._signals.failed.emit(type(exc).__name__)
            return
        self._signals.done.emit(prefill)
