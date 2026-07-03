""" — Briefing-Matcher-Präzision + Thinking-Modell-Hebel + Fail-Loud-UI.

Deckt die drei freigegebenen Fixes ab:
  - Symptom 1: Hybrid-Matcher (CPE-Vendor/Produkt-Token + Wortgrenzen, kurze Token
    nur gegen die strukturierte CVE-Produktliste) — ``act`` matcht NICHT mehr in
    ``Content``; echte Kurz-Produkte (``Git``) matchen über die Produktliste.
  - Symptom 2: ``"think": false`` im /api/generate-Payload; leerer Stream setzt
    ``_letzter_fehler="empty_stream"``.
  - Extra: ``_briefing_fehler_texte`` macht aus dem Grund eine spezifische
    GUI-Meldung statt eines generischen "Ollama nicht erreichbar".

Author: Patrick Riederich
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import tools.cyber_dashboard.application.briefing_service as bs_module
from tools.cyber_dashboard.application.briefing_service import (
    FEHLER_LEERER_STREAM,
    BriefingService,
    _cpe_produkt_tokens,
    _match_tokens,
    _token_im_text,
)
from tools.cyber_dashboard.domain.models import CveEintrag, TechStackEintrag


def _cve(beschreibung: str, produkte: list[str] | None = None) -> CveEintrag:
    now = datetime(2026, 6, 20, tzinfo=UTC)
    return CveEintrag(
        cve_id="CVE-2026-0001",
        beschreibung=beschreibung,
        schweregrad="HIGH",
        cvss_score=7.5,
        veroeffentlicht=now,
        geaendert=now,
        url="https://nvd.example/CVE-2026-0001",
        betroffene_produkte=produkte or [],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helper-Units
# ─────────────────────────────────────────────────────────────────────────────
class TestCpeTokens:
    def test_valider_cpe_liefert_vendor_und_produkt(self) -> None:
        toks = _cpe_produkt_tokens("cpe:2.3:a:apache:http_server:2.4")
        assert toks == ["apache", "http server"]  # _ -> Leerzeichen

    def test_kein_cpe_liefert_leer(self) -> None:
        assert _cpe_produkt_tokens("") == []
        assert _cpe_produkt_tokens("irgendwas") == []
        assert _cpe_produkt_tokens("cpe:2.3:a") == []

    def test_wildcards_werden_uebersprungen(self) -> None:
        assert _cpe_produkt_tokens("cpe:2.3:a:*:-:1.0") == []


class TestTokenImText:
    def test_wortgrenze_kein_substring_treffer(self) -> None:
        # Der eigentliche Bug: 'act' steckt in 'Content', darf NICHT matchen.
        assert _token_im_text("act", "joomla content editor") is False

    def test_ganzes_wort_matcht(self) -> None:
        assert _token_im_text("act", "the act runner is affected") is True

    def test_act_nicht_in_transaction(self) -> None:
        # Echter Substring-Fall: 'transaction' enthaelt 'act'.
        assert _token_im_text("act", "a transaction-handling flaw") is False

    def test_punktuierter_token_matcht(self) -> None:
        # C1: '.net' matcht trotz fuehrendem Nicht-Wort-Zeichen (\\b versagte hier).
        assert _token_im_text(".net", "uses .net here") is True
        assert _token_im_text(".net", "asp.net core") is False  # anderes Produkt

    def test_leer_ist_false(self) -> None:
        assert _token_im_text("", "x") is False
        assert _token_im_text("x", "") is False


class TestMatchTokens:
    def test_name_plus_cpe_dedupe(self) -> None:
        toks = _match_tokens("Apache", "cpe:2.3:a:apache:http_server:2.4")
        assert toks[0] == "apache"
        assert "http server" in toks
        # 'apache' nur einmal (Name == CPE-Vendor)
        assert toks.count("apache") == 1


# ─────────────────────────────────────────────────────────────────────────────
# Matcher im echten _waehle_kandidaten-Pfad
# ─────────────────────────────────────────────────────────────────────────────
class TestWaehleKandidatenMatcher:
    def test_act_matcht_nicht_als_substring(self) -> None:
        """Der Kern-Bug: 'act' (3 Zeichen) darf nicht in 'transaction' treffen."""
        svc = BriefingService()
        stack = [TechStackEintrag(name="act")]
        # 'transaction' enthaelt 'act' als Substring -> alter Code matchte hier.
        cves = [_cve("A transaction-handling flaw was found", [])]
        techstack_kand, allgemein_kand = svc._waehle_kandidaten(cves, [], stack)
        assert techstack_kand == []  # kein Fehl-Treffer mehr
        assert len(allgemein_kand) == 1  # landet in der allgemeinen Spalte

    def test_punktuierter_name_matcht_in_prosa(self) -> None:
        """C1: '.NET' (mit Punkt, >=4 Zeichen) matcht trotz Nicht-Wort-Zeichen."""
        svc = BriefingService()
        stack = [TechStackEintrag(name=".NET")]
        cves = [_cve("A .NET runtime vulnerability was disclosed", [])]
        techstack_kand, _ = svc._waehle_kandidaten(cves, [], stack)
        assert len(techstack_kand) == 1

    def test_kurzes_produkt_matcht_ueber_strukturierte_liste(self) -> None:
        """'Git' (3 Zeichen) matcht über betroffene_produkte, nicht über Prosa."""
        svc = BriefingService()
        stack = [TechStackEintrag(name="Git")]
        cves = [_cve("A vulnerability was found", ["Git"])]
        techstack_kand, _ = svc._waehle_kandidaten(cves, [], stack)
        assert len(techstack_kand) == 1
        assert techstack_kand[0].produkt.lower() == "git"

    def test_langes_produkt_matcht_in_prosa(self) -> None:
        svc = BriefingService()
        stack = [TechStackEintrag(name="Apache")]
        cves = [_cve("Apache HTTP server has a flaw", [])]
        techstack_kand, _ = svc._waehle_kandidaten(cves, [], stack)
        assert len(techstack_kand) == 1

    def test_cpe_token_matcht_strukturierte_produkte(self) -> None:
        svc = BriefingService()
        stack = [
            TechStackEintrag(name="WebServer", cpe="cpe:2.3:a:apache:http_server:2.4")
        ]
        cves = [_cve("Generic vuln text", ["Apache HTTP Server"])]
        techstack_kand, _ = svc._waehle_kandidaten(cves, [], stack)
        assert len(techstack_kand) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Symptom 2: think:false + empty_stream
# ─────────────────────────────────────────────────────────────────────────────
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


class TestThinkFalseUndEmptyStream:
    def test_payload_traegt_think_false_und_setzt_empty_stream(
        self, monkeypatch
    ) -> None:
        import requests

        captured: dict = {}

        def _fake_post(url, json=None, timeout=None, stream=None, **kw):  # noqa: A002
            captured["json"] = json
            # done-Frame mit leerer response -> empty_stream
            return _FakeResp([json_dumps_frame("", done=True)])

        monkeypatch.setattr(requests, "post", _fake_post)
        monkeypatch.setattr(bs_module, "ensure_ollama_running", lambda: True)

        svc = BriefingService()
        monkeypatch.setattr(svc, "_modell_verfuegbar", lambda _m: True)

        # Ein CVE als allgemeiner Kandidat -> Pfad erreicht den LLM-Call.
        result = svc.generiere_briefing(
            meldungen=[],
            cves=[_cve("some advisory", [])],
            techstack=[],
            modell="qwen3:8b",
            consumer_meldungen=[],
        )

        assert result is None
        assert svc._letzter_fehler == FEHLER_LEERER_STREAM
        assert captured["json"]["think"] is False


def json_dumps_frame(response: str, *, done: bool) -> bytes:
    return json.dumps({"response": response, "done": done}).encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Extra: Fail-Loud-UI-Mapping
# ─────────────────────────────────────────────────────────────────────────────
class TestBriefingFehlerTexte:
    def test_empty_stream_meldet_modell(self) -> None:
        from tools.cyber_dashboard.gui.briefing_tab import _briefing_fehler_texte

        titel, hinweis = _briefing_fehler_texte("empty_stream")
        assert "Modell" in titel
        assert "Ollama nicht erreichbar" not in titel

    def test_timeout_meldet_timeout(self) -> None:
        from tools.cyber_dashboard.gui.briefing_tab import _briefing_fehler_texte

        titel, _ = _briefing_fehler_texte("Timeout")
        assert "Timeout" in titel

    def test_none_faellt_auf_ollama_nicht_erreichbar(self) -> None:
        from tools.cyber_dashboard.gui.briefing_tab import _briefing_fehler_texte

        titel, _ = _briefing_fehler_texte(None)
        assert "Ollama nicht erreichbar" in titel

    def test_unbekannter_grund_maskiert_nicht_als_ollama_aus(self) -> None:
        # ARCH-3: ein unerwarteter Fehler darf nicht wie "Ollama aus" aussehen.
        from tools.cyber_dashboard.gui.briefing_tab import _briefing_fehler_texte

        titel, _ = _briefing_fehler_texte("ValueError: boom")
        assert "Ollama nicht erreichbar" not in titel
        assert "fehlgeschlagen" in titel.lower()
