"""test_briefing_service_error_reason — GUI-Fehlerkanal ``_letzter_fehler``.

Nach dem Entfernen des write-only ``briefing_history``-Subsystems (2026-07-03,) bleibt der ``generiere_briefing``-Fehlergrund erhalten: er speist
``BriefingService._letzter_fehler``, das die GUI (``briefing_tab.py:299``) in
eine spezifische Meldung uebersetzt (statt eines generischen „Ollama nicht
erreichbar"). Diese Tests sichern zwei Fehler-Zweige des echten Pfads.

(Frueher ``test_briefing_service_history_hook`` — die drei reinen Hook-Tests
``_snapshot_score_before``/``_record_history_safe``/End-to-End-Repo entfielen mit
dem Subsystem; die zwei Verhaltens-Tests pruefen jetzt ``_letzter_fehler`` statt
den entfernten ``_FakeRepo``-Spy.)
"""

from __future__ import annotations

import sys

from tools.cyber_dashboard.application.briefing_service import (
    FEHLER_MODELL_FEHLT,
    BriefingService,
    _Kandidat,
)


class _FakeReqExceptions:
    class HTTPError(Exception):
        pass

    class Timeout(Exception):
        pass

    class ConnectionError(Exception):
        pass


class TestCancelBranchErrorReason:
    """Cancel waehrend Streaming -> Ergebnis None, ``_letzter_fehler == 'cancelled'``."""

    def test_cancel_waehrend_streaming_setzt_fehlergrund(self, monkeypatch) -> None:
        from tools.cyber_dashboard.application import briefing_service as bs_mod

        monkeypatch.setattr(bs_mod, "ensure_ollama_running", lambda: True)

        svc = BriefingService()
        monkeypatch.setattr(svc, "_modell_verfuegbar", lambda m: True)
        monkeypatch.setattr(svc, "_lade_consumer_meldungen", lambda: [])

        dummy = _Kandidat(produkt="x", cve_id="CVE-X", rohtext="...")
        monkeypatch.setattr(svc, "_waehle_kandidaten", lambda *_: ([dummy], []))
        monkeypatch.setattr(svc, "_waehle_consumer_kandidaten", lambda _: [])

        class _FakeResponse:
            status_code = 200

            def raise_for_status(self):
                return None

            def iter_lines(self):
                yield b'{"response": "...", "done": false}'

            def close(self):
                return None

        class _FakeRequests:
            exceptions = _FakeReqExceptions

            @staticmethod
            def post(*_, **__):
                return _FakeResponse()

        monkeypatch.setitem(sys.modules, "requests", _FakeRequests)

        result = svc.generiere_briefing(
            meldungen=[], cves=[], modell="llama3:8b",
            cancel_flag=lambda: True,  # sofort canceln nach dem ersten Yield
        )
        assert result is None
        assert svc._letzter_fehler == "cancelled"


class TestModelNotAvailableErrorReason:
    """Modell nicht verfuegbar -> Ergebnis None, ``_letzter_fehler == FEHLER_MODELL_FEHLT``."""

    def test_modell_nicht_verfuegbar_setzt_fehlergrund(self, monkeypatch) -> None:
        from tools.cyber_dashboard.application import briefing_service as bs_mod

        monkeypatch.setattr(bs_mod, "ensure_ollama_running", lambda: True)

        svc = BriefingService()
        monkeypatch.setattr(svc, "_modell_verfuegbar", lambda m: False)
        monkeypatch.setattr(svc, "_lade_consumer_meldungen", lambda: [])

        dummy = _Kandidat(produkt="x", cve_id="CVE-X", rohtext="...")
        monkeypatch.setattr(svc, "_waehle_kandidaten", lambda *_: ([dummy], []))
        monkeypatch.setattr(svc, "_waehle_consumer_kandidaten", lambda _: [])

        result = svc.generiere_briefing(
            meldungen=[], cves=[], modell="llama3:8b",
        )
        assert result is None
        assert svc._letzter_fehler == FEHLER_MODELL_FEHLT
