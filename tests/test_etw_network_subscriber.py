"""Tests fuer den ETW-Subscriber-Dispatch B2/Regel 5).

Reiner Roh-Event-Forwarding (kein pywintrace, kein Admin). ``start`` ist nur
elevated real testbar (Smoke) und hier ausgeklammert.
"""

from __future__ import annotations

from tools.network_monitor.data.etw_network_subscriber import (
    EtwNetworkSubscriber,
    is_admin,
)


def _make_subscriber() -> tuple[EtwNetworkSubscriber, list[tuple[int, dict]]]:
    received: list[tuple[int, dict]] = []
    sub = EtwNetworkSubscriber(lambda eid, raw: received.append((eid, raw)))
    return sub, received


class TestDispatch:
    def test_event_wird_roh_weitergereicht(self) -> None:
        sub, received = _make_subscriber()
        raw = {"PID": 1234, "size": 500, "daddr": 67_305_985}
        sub._dispatch((10, raw))
        # Subscriber normalisiert NICHT mehr — das Roh-Event geht 1:1 durch.
        assert received == [(10, raw)]

    def test_callback_fehler_wird_geschluckt(self) -> None:
        def boom(_eid: int, _raw: dict) -> None:
            raise ValueError("kaputt")

        sub = EtwNetworkSubscriber(boom)
        sub._dispatch((10, {"PID": 1, "size": 2}))  # darf nicht hochblubbern

    def test_kaputtes_event_tupel_wird_geschluckt(self) -> None:
        sub, received = _make_subscriber()
        sub._dispatch(None)  # type: ignore[arg-type]
        assert received == []


class TestIsAdmin:
    def test_gibt_bool_zurueck(self) -> None:
        assert isinstance(is_admin(), bool)
