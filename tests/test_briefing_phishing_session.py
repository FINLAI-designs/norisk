"""Tests fuer BriefingService.generiere_phishing_briefing (c1 — 2. Session)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from tools.cyber_dashboard.application import briefing_service as bs_module
from tools.cyber_dashboard.application.briefing_service import BriefingService
from tools.cyber_dashboard.domain.models import (
    CyberMeldung,
    QuelleTyp,
    Schweregrad,
)


class _FakeResp:
    status_code = 200

    def __init__(self, frames: list[bytes]) -> None:
        self._frames = frames

    def raise_for_status(self) -> None:
        pass

    def iter_lines(self):  # noqa: ANN202 — Test-Double
        yield from self._frames

    def close(self) -> None:
        pass


def _frame(response: str, *, done: bool) -> bytes:
    return json.dumps({"response": response, "done": done}).encode("utf-8")


def _meldung(titel: str, *, quelle: QuelleTyp = QuelleTyp.WATCHLIST_AT) -> CyberMeldung:
    return CyberMeldung(
        titel=titel,
        beschreibung=f"Roh: {titel}",
        url=f"https://example.test/{abs(hash(titel))}",
        quelle=quelle,
        schweregrad=Schweregrad.HOCH,
        veroeffentlicht=datetime(2026, 6, 26, tzinfo=UTC),
    )


def _mock_ollama(monkeypatch, antwort_json: str) -> dict:
    """Mockt Ollama so, dass ``antwort_json`` als ein Frame zurueckkommt."""
    import requests

    captured: dict = {}

    def _fake_post(url, json=None, timeout=None, stream=None, **kw):  # noqa: A002
        captured["json"] = json
        return _FakeResp([_frame(antwort_json, done=True)])

    monkeypatch.setattr(requests, "post", _fake_post)
    monkeypatch.setattr(bs_module, "ensure_ollama_running", lambda: True)
    return captured


def test_leere_eingabe_gibt_leere_listen():
    svc = BriefingService()
    result = svc.generiere_phishing_briefing([], [])
    assert result == {"phishing_kmu": [], "phishing_consumer": []}


def test_llm_erfolg_formuliert_um_und_behaelt_quelle(monkeypatch):
    captured = _mock_ollama(
        monkeypatch,
        json.dumps(
            {
                "phishing_kmu": [
                    {"titel": "Fake-Rechnung", "beschreibung": "Umformuliert."}
                ],
                "phishing_consumer": [],
            }
        ),
    )
    svc = BriefingService()
    monkeypatch.setattr(svc, "_modell_verfuegbar", lambda _m: True)

    kmu = [_meldung("Gefälschte Rechnung", quelle=QuelleTyp.WATCHLIST_AT)]
    result = svc.generiere_phishing_briefing(kmu, [], modell="gemma3:4b")

    assert result["phishing_kmu"] == [
        {
            "titel": "Fake-Rechnung",
            "beschreibung": "Umformuliert.",
            "quelle": "Watchlist Internet",
        }
    ]
    assert result["phishing_consumer"] == []
    # think:false-Contract gilt auch fuer die Phishing-Session.
    assert captured["json"]["think"] is False


def test_ollama_nicht_erreichbar_faellt_auf_rohtext(monkeypatch):
    monkeypatch.setattr(bs_module, "ensure_ollama_running", lambda: False)
    svc = BriefingService()
    kmu = [_meldung("Gefälschte Rechnung")]
    result = svc.generiere_phishing_briefing(kmu, [], modell="gemma3:4b")
    # Fallback: Roh-Meldungstext statt nichts.
    assert result["phishing_kmu"][0]["beschreibung"] == "Roh: Gefälschte Rechnung"
    assert result["phishing_kmu"][0]["quelle"] == "Watchlist Internet"


def test_leerer_stream_faellt_auf_rohtext(monkeypatch):
    _mock_ollama(monkeypatch, "")  # done-Frame mit leerer response
    svc = BriefingService()
    monkeypatch.setattr(svc, "_modell_verfuegbar", lambda _m: True)
    consumer = [_meldung("Sparkassen-Phishing", quelle=QuelleTyp.MIMIKAMA)]
    result = svc.generiere_phishing_briefing([], consumer, modell="gemma3:4b")
    assert result["phishing_consumer"][0]["beschreibung"] == "Roh: Sparkassen-Phishing"


def test_kaputtes_json_faellt_auf_rohtext(monkeypatch):
    _mock_ollama(monkeypatch, "das ist kein json {")
    svc = BriefingService()
    monkeypatch.setattr(svc, "_modell_verfuegbar", lambda _m: True)
    kmu = [_meldung("Lieferantenbetrug")]
    result = svc.generiere_phishing_briefing(kmu, [], modell="gemma3:4b")
    assert result["phishing_kmu"][0]["beschreibung"] == "Roh: Lieferantenbetrug"


def test_leere_gruppe_bekommt_keine_halluzinierten_eintraege(monkeypatch):
    """Review P2: hat eine Gruppe keine Kandidaten, darf das LLM dort NICHTS
    erfinden (Grenze = Anzahl Eingabe-Kandidaten)."""
    _mock_ollama(
        monkeypatch,
        json.dumps(
            {
                # LLM halluziniert 2 KMU-Eintraege, obwohl kmu-Eingabe leer ist.
                "phishing_kmu": [
                    {"titel": "Erfunden 1", "beschreibung": "X."},
                    {"titel": "Erfunden 2", "beschreibung": "Y."},
                ],
                "phishing_consumer": [{"titel": "Paket", "beschreibung": "Echt."}],
            }
        ),
    )
    svc = BriefingService()
    monkeypatch.setattr(svc, "_modell_verfuegbar", lambda _m: True)
    result = svc.generiere_phishing_briefing(
        [],  # keine KMU-Kandidaten
        [_meldung("Paket-SMS", quelle=QuelleTyp.MIMIKAMA)],
        modell="gemma3:4b",
    )
    assert result["phishing_kmu"] == []  # nichts erfunden
    assert len(result["phishing_consumer"]) == 1


def test_beide_gruppen_bleiben_getrennt(monkeypatch):
    _mock_ollama(
        monkeypatch,
        json.dumps(
            {
                "phishing_kmu": [{"titel": "K", "beschreibung": "KMU-Satz."}],
                "phishing_consumer": [{"titel": "C", "beschreibung": "Consumer-Satz."}],
            }
        ),
    )
    svc = BriefingService()
    monkeypatch.setattr(svc, "_modell_verfuegbar", lambda _m: True)
    result = svc.generiere_phishing_briefing(
        [_meldung("Rechnung", quelle=QuelleTyp.WATCHLIST_AT)],
        [_meldung("Paket", quelle=QuelleTyp.MIMIKAMA)],
        modell="gemma3:4b",
    )
    assert result["phishing_kmu"][0]["beschreibung"] == "KMU-Satz."
    assert result["phishing_consumer"][0]["beschreibung"] == "Consumer-Satz."
    assert result["phishing_kmu"][0]["quelle"] == "Watchlist Internet"
    assert result["phishing_consumer"][0]["quelle"] == "Mimikama"
