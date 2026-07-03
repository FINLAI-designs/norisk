"""network_monitor.data.etw_network_subscriber — pywintrace-ETW-Wiring B2/Regel 5).

Generischer Multi-Provider-Subscriber: abonniert eine oder mehrere ETW-Provider
(per GUID) und reicht jedes **rohe** Event ``(event_id, raw)`` an einen
injizierten Callback. Der Subscriber kennt weder Normalizer noch Aggregator noch
DB (Layer-Trennung: ``data/`` greift nicht in ``application/``); die
Normalisierung + das Routing zu den Aggregatoren macht der Collector
(``apps/collector_main.py``). So koennen mehrere Provider — Kernel-Network
(Bytes) UND DNS-Client (Queries) — eine einzige ETW-Session teilen.

Laufzeit-Voraussetzungen (NUR beim ``start``, nicht beim Import):
- **Administrator** — ``StartTrace`` ist elevation-pflichtig.
- **pywintrace** (``import etw``) — nur Windows; Lazy-Import in:meth:`start`.

Der pywintrace-Callback laeuft in einem **eigenen Consumer-Thread** — er bleibt
minimal (Roh-Event weiterreichen). Die Thread-Entkopplung (Queue) macht der
Collector. Kein provider-seitiger ``event_id_filters`` — der wuergt die
Kernel-Network-Capture ab (Smoke 2026-05-25); gefiltert wird in den Aggregatoren.

Stolperfalle: ETW-Sessions sind kernel-persistent → bei festem ``session_name``
vor ``start`` ein Best-Effort ``logman stop`` (:meth:`_cleanup_stale_session`).
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable, Iterable
from typing import Any, Final

from core.logger import get_logger

#: Kernel-Network-Provider (Per-Prozess-Bytes). PoC 2026-05-25 verifiziert.
KERNEL_NETWORK_PROVIDER_NAME: Final[str] = "Microsoft-Windows-Kernel-Network"
KERNEL_NETWORK_GUID: Final[str] = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
#: DNS-Client-Provider (Query-Namen, Event 3006) — Regel 5 DNS-Tunneling.
DNS_CLIENT_PROVIDER_NAME: Final[str] = "Microsoft-Windows-DNS-Client"
DNS_CLIENT_GUID: Final[str] = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
#: Kernel-Process-Provider (ProcessStart → Image-Pfad) — Regel 4 Unknown-Path.
KERNEL_PROCESS_PROVIDER_NAME: Final[str] = "Microsoft-Windows-Kernel-Process"
KERNEL_PROCESS_GUID: Final[str] = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
#: WINEVENT_KEYWORD_PROCESS — ohne dieses Keyword liefert der Kernel-Process-
#: Provider KEINE ProcessStart/Stop-Events.
KERNEL_PROCESS_KEYWORD: Final[int] = 0x10

#: Fester Session-Name — eindeutiges Cleanup verwaister Sessions moeglich.
DEFAULT_SESSION_NAME: Final[str] = "NoRiskNetCollector"
#: Default-Provider als ``(name, guid, any_keywords)`` — keyword 0 = alle Events.
DEFAULT_PROVIDERS: Final[tuple[tuple[str, str, int], ...]] = (
    (KERNEL_NETWORK_PROVIDER_NAME, KERNEL_NETWORK_GUID, 0),
    (DNS_CLIENT_PROVIDER_NAME, DNS_CLIENT_GUID, 0),
    (KERNEL_PROCESS_PROVIDER_NAME, KERNEL_PROCESS_GUID, KERNEL_PROCESS_KEYWORD),
)

_LOGMAN_TIMEOUT_S: Final[int] = 10
#: Anzahl Start-Events, deren SCHEMA (nicht Inhalt) zur Diagnose (DEBUG) geloggt wird.
_DUMP_LIMIT: Final[int] = 8


def _describe_field(value: object) -> str:
    """Beschreibt ein ETW-Roh-Feld INHALTSFREI: Typ (+ Länge bei Sequenzen).

    Liefert z. B. ``"<str:11>"`` / ``"<bytes:4>"`` / ``"<int>"`` — den Wert selbst
    (DNS-Name, Image-Pfad …) NIE. So bleibt der DEBUG-Diagnose-Dump/F-F)
    ohne Inhalt: man sieht, WELCHE Felder mit welchem Typ/welcher Länge ankamen,
    aber keinen einzigen echten Wert.
    """
    if isinstance(value, str):
        return f"<str:{len(value)}>"
    if isinstance(value, (bytes, bytearray)):
        return f"<bytes:{len(value)}>"
    return f"<{type(value).__name__}>"

# Callback-Signatur: (event_id, rohes_event_dict) -> None.
OnEvent = Callable[[int, dict[str, Any]], None]


def is_admin() -> bool:
    """True wenn der aktuelle Prozess Administrator-Rechte hat (Windows).

    Auf Nicht-Windows immer ``False`` (ETW gibt es dort nicht).
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — defensiv: API-Fehler == kein Admin
        return False


class EtwNetworkSubscriber:
    """Generischer Multi-Provider-pywintrace-Wrapper (forwardet Roh-Events)."""

    def __init__(
        self,
        on_event: OnEvent,
        *,
        providers: Iterable[tuple[str, str, int]] | None = None,
        session_name: str = DEFAULT_SESSION_NAME,
    ) -> None:
        """Initialisiert den Subscriber (startet noch nichts).

        Args:
            on_event: Callback ``(event_id, raw)`` — wird pro Event aus dem
                ETW-Consumer-Thread gerufen. Muss thread-safe sein (der
                Collector injiziert i.d.R. ein ``queue.put_nowait``).
            providers: Iterable von ``(name, guid, any_keywords)`` (keyword 0
                = alle Events). Default::data:`DEFAULT_PROVIDERS`
                (Kernel-Network + DNS-Client + Kernel-Process).
            session_name: Fester ETW-Session-Name (fuer Cleanup).
        """
        self._on_event = on_event
        self._providers = (
            list(providers) if providers is not None else list(DEFAULT_PROVIDERS)
        )
        self._session_name = session_name
        self._etw: Any = None
        self._dumped = 0
        self._log = get_logger(__name__)

    def start(self) -> None:
        """Startet die ETW-Capture. Erfordert Admin + pywintrace.

        Raises:
            PermissionError: Wenn der Prozess keine Admin-Rechte hat.
            RuntimeError: Wenn pywintrace nicht importierbar ist.
        """
        if not is_admin():
            raise PermissionError("ETW erfordert Administrator-Rechte.")
        try:
            import etw
        except ImportError as exc:  # pragma: no cover - nur ohne pywintrace
            raise RuntimeError(
                "pywintrace (import etw) nicht verfuegbar — "
                "pip install pywintrace (nur Windows)."
            ) from exc

        self._cleanup_stale_session()
        providers = [
            etw.ProviderInfo(name, etw.GUID(guid), any_keywords=(keyword or None))
            for name, guid, keyword in self._providers
        ]
        self._etw = etw.ETW(
            session_name=self._session_name,
            providers=providers,
            event_callback=self._dispatch,
        )
        self._etw.start()
        self._log.info(
            "ETW-Session '%s' gestartet (%d Provider).",
            self._session_name,
            len(providers),
        )

    def stop(self) -> None:
        """Stoppt die ETW-Capture (idempotent)."""
        if self._etw is not None:
            try:
                self._etw.stop()
            finally:
                self._etw = None
                self._log.info("ETW-Session '%s' gestoppt.", self._session_name)

    def _dispatch(self, event: tuple[int, dict[str, Any]]) -> None:
        """pywintrace-Callback: reicht das rohe ``(event_id, raw)`` weiter.

        Laeuft im Consumer-Thread; minimal + fehlertolerant (ein kaputtes
        Event darf die Capture nicht stoppen).
        """
        try:
            event_id, raw = event
            if self._dumped < _DUMP_LIMIT:
                self._dumped += 1
                # DEBUG-Diagnose-Dump des Event-SCHEMAS — bewusst INHALTSFREI
                #/F-F-Entscheid): Roh-Felder (QueryName/ImageName u.a.)
                # enthalten lokal beeinflussbare DNS-Namen/Pfade. Geloggt werden
                # nur Feldname + Typ + Laenge, NIE der Wert -> die "keine Inhalte
                # im Log"-Garantie gilt jetzt auch auf DEBUG (kein Carve-out mehr).
                if isinstance(raw, dict):
                    schema = {
                        k: _describe_field(v)
                        for k, v in raw.items()
                        if k != "EventHeader"
                    }
                    self._log.debug(
                        "ETW-Roh #%d id=%s schema=%r", self._dumped, event_id, schema
                    )
            self._on_event(event_id, raw)
        except Exception as exc:  # noqa: BLE001 — Callback darf nie hochblubbern
            self._log.debug("ETW-Event verworfen: %s", type(exc).__name__)

    def _cleanup_stale_session(self) -> None:
        """Stoppt eine evtl. verwaiste Session gleichen Namens (Best-Effort)."""
        if sys.platform != "win32":
            return
        try:
            subprocess.run(  # noqa: S603,S607 - fester Befehl, kein Shell
                ["logman", "stop", self._session_name, "-ets"],
                capture_output=True,
                timeout=_LOGMAN_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._log.debug("logman-Cleanup uebersprungen: %s", type(exc).__name__)

    def __enter__(self) -> EtwNetworkSubscriber:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
