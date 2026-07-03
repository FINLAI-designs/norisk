"""tests/test_password_checker.py — Unit-Tests für den Passwort-Policy-Checker.

Prüft:
  - Domain-Modelle (PasswordCheckResult, PasswordPolicy, PolicyCheck)
  - Entropie-Berechnung
  - Muster-Erkennung (Keyboard, Wiederholung, Nur-Ziffern)
  - Score-Berechnung und Stärke-Bewertung
  - Policy-Compliance-Checks (BSI, NIST, ISO27001)
  - PasswordService (mit gemocktem HIBP)
  - HIBP-Client (gemockte HTTP-Antwort)

Kein echtes Netzwerk-I/O — HIBP wird vollständig gemockt.

Author: Patrick Riederich
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from tools.password_checker.domain.models import (
    PasswordCheckResult,
    PasswordStaerke,
    PolicyCheck,
    PolicyVorlage,
)
from tools.password_checker.domain.password_analyzer import (
    analysiere_passwort,
    berechne_entropie,
    berechne_score,
    erkenne_muster,
    pruefe_policy,
    score_zu_staerke,
    staerke_bei_breach,
)
from tools.password_checker.domain.policy_templates import (
    ALLE_VORLAGEN,
    POLICY_BSI,
    POLICY_ISO27001,
    POLICY_NIST,
)

# ---------------------------------------------------------------------------
# Entropie-Tests
# ---------------------------------------------------------------------------


class TestEntropie:
    def test_leeres_passwort_null(self):
        assert berechne_entropie("") == 0.0

    def test_nur_kleinbuchstaben(self):
        e = berechne_entropie("abcde")
        # 5 × log2(26) ≈ 23.5
        assert 20.0 < e < 30.0

    def test_gross_und_klein(self):
        e = berechne_entropie("AbCdE")
        # 5 × log2(52) ≈ 28.5
        assert 25.0 < e < 35.0

    def test_alle_zeichenklassen(self):
        e = berechne_entropie("Abc1!")
        # 5 × log2(95) ≈ 32.9
        assert 30.0 < e < 40.0

    def test_langes_passwort_hohe_entropie(self):
        e = berechne_entropie("CorrectHorse4BatteryStaple!")
        assert e > 80.0

    def test_nur_ziffern_kleiner_zeichenraum(self):
        e = berechne_entropie("123456")
        e_alles = berechne_entropie("Ab1!ef")
        assert e < e_alles


# ---------------------------------------------------------------------------
# Muster-Erkennung
# ---------------------------------------------------------------------------


class TestMusterErkennung:
    def test_keyboard_muster_qwertz(self):
        muster = erkenne_muster("qwertzpass")
        assert any("qwertz" in m.lower() for m in muster)

    def test_keyboard_muster_1234(self):
        muster = erkenne_muster("1234abcd")
        assert any("sequenz" in m.lower() or "1234" in m for m in muster)

    def test_zeichenwiederholung(self):
        muster = erkenne_muster("aaabbb")
        assert any("wiederholung" in m.lower() for m in muster)

    def test_nur_ziffern(self):
        muster = erkenne_muster("12345678")
        assert any("ziffern" in m.lower() for m in muster)

    def test_bekanntes_schwaches_passwort(self):
        muster = erkenne_muster("password")
        assert any("schwach" in m.lower() or "liste" in m.lower() for m in muster)

    def test_starkes_passwort_keine_muster(self):
        muster = erkenne_muster("XkP9#mZ2!qLw")
        assert len(muster) == 0

    def test_nur_buchstaben(self):
        muster = erkenne_muster("abcdefgh")
        assert any("buchstaben" in m.lower() for m in muster)


# ---------------------------------------------------------------------------
# Score und Stärke
# ---------------------------------------------------------------------------


class TestScoreUndStaerke:
    def test_leeres_passwort_score_null(self):
        assert berechne_score("") == 0

    def test_schwaches_passwort_niedrig(self):
        assert berechne_score("123") < 30

    def test_starkes_passwort_hoch(self):
        score = berechne_score("Xk9#mZ2!qLwP3r")
        assert score >= 70

    def test_score_in_range(self):
        for pw in ["", "a", "abc123", "Abc1!", "CorrectHorseBatteryStaple42!"]:
            s = berechne_score(pw)
            assert 0 <= s <= 100

    def test_sehr_schwach(self):
        assert score_zu_staerke(10) == PasswordStaerke.SEHR_SCHWACH

    def test_schwach(self):
        assert score_zu_staerke(30) == PasswordStaerke.SCHWACH

    def test_mittel(self):
        assert score_zu_staerke(50) == PasswordStaerke.MITTEL

    def test_stark(self):
        assert score_zu_staerke(70) == PasswordStaerke.STARK

    def test_sehr_stark(self):
        assert score_zu_staerke(90) == PasswordStaerke.SEHR_STARK

    def test_muster_zieht_score_ab(self):
        score_ohne = berechne_score("Xk9#mZ2!qLwP")
        score_mit = berechne_score("qwerty123!!Ab")
        assert score_ohne > score_mit


# ---------------------------------------------------------------------------
# Policy-Compliance
# ---------------------------------------------------------------------------


class TestStaerkeBeiBreach:
    """-F2: HIBP-Treffer kappt das Stärke-Verdikt hart."""

    def test_breach_treffer_kappt_auf_sehr_schwach(self):
        staerke, score = staerke_bei_breach(PasswordStaerke.SEHR_STARK, 95, 12345)
        assert staerke is PasswordStaerke.SEHR_SCHWACH
        assert score == 0

    def test_kein_treffer_unveraendert(self):
        staerke, score = staerke_bei_breach(PasswordStaerke.SEHR_STARK, 95, 0)
        assert staerke is PasswordStaerke.SEHR_STARK
        assert score == 95

    def test_nicht_geprueft_unveraendert(self):
        staerke, score = staerke_bei_breach(PasswordStaerke.STARK, 70, -1)
        assert staerke is PasswordStaerke.STARK
        assert score == 70


class TestPolicyCompliance:
    def test_bsi_alle_checks(self):
        checks = pruefe_policy("GutesPasswort1!", POLICY_BSI)
        assert len(checks) == 5  # Länge + Groß + Klein + Ziffern + Sonderzeichen

    def test_bsi_laenge_nicht_erfuellt(self):
        checks = pruefe_policy("Kurz1!", POLICY_BSI)
        laenge_check = next(c for c in checks if "Mindestlänge" in c.bezeichnung)
        assert not laenge_check.erfuellt

    def test_bsi_laenge_erfuellt(self):
        checks = pruefe_policy("LangesPasswort12!", POLICY_BSI)
        laenge_check = next(c for c in checks if "Mindestlänge" in c.bezeichnung)
        assert laenge_check.erfuellt

    def test_nist_keine_komplexitaet(self):
        checks = pruefe_policy("nur_kleinbuchstaben_aber_lang", POLICY_NIST)
        # NIST fordert keine Zeichenklassen — nur Länge
        bezeichnungen = [c.bezeichnung for c in checks]
        assert all("Mindestlänge" in b or len(b) == 0 for b in bezeichnungen)
        assert len(checks) == 1  # Nur Länge

    def test_policy_erfuellt_property(self):
        checks = [PolicyCheck("Test", True), PolicyCheck("Test2", True)]
        result = PasswordCheckResult(
            staerke=PasswordStaerke.STARK,
            score=75,
            entropie_bits=60.0,
            laenge=14,
            policy_checks=checks,
        )
        assert result.policy_erfuellt

    def test_policy_nicht_erfuellt(self):
        checks = [PolicyCheck("Test", True), PolicyCheck("Test2", False)]
        result = PasswordCheckResult(
            staerke=PasswordStaerke.MITTEL,
            score=50,
            entropie_bits=40.0,
            laenge=10,
            policy_checks=checks,
        )
        assert not result.policy_erfuellt


# ---------------------------------------------------------------------------
# Policy-Vorlagen
# ---------------------------------------------------------------------------


class TestPolicyVorlagen:
    def test_alle_vorlagen_vorhanden(self):
        assert PolicyVorlage.BSI in ALLE_VORLAGEN
        assert PolicyVorlage.NIST in ALLE_VORLAGEN
        assert PolicyVorlage.ISO27001 in ALLE_VORLAGEN

    def test_bsi_laenge(self):
        assert POLICY_BSI.min_laenge == 12

    def test_nist_laenge(self):
        assert POLICY_NIST.min_laenge == 15

    def test_nist_kein_ablauf(self):
        assert POLICY_NIST.max_alter_tage == 0

    def test_nist_breach_check(self):
        assert POLICY_NIST.breach_check is True

    def test_iso_laenge(self):
        assert POLICY_ISO27001.min_laenge == 10


# ---------------------------------------------------------------------------
# Analyse-Funktion
# ---------------------------------------------------------------------------


class TestAnalysePasswort:
    def test_result_kein_passwort_im_objekt(self):
        """Sicherheitstest: PasswordCheckResult darf keine Passwort-Felder haben."""
        result = analysiere_passwort("geheimesPasswort1!", POLICY_BSI)
        result_dict = vars(result)
        for value in result_dict.values():
            if isinstance(value, str):
                assert "geheimesPasswort1!" not in value

    def test_result_hat_score(self):
        result = analysiere_passwort("Test123!", POLICY_BSI)
        assert 0 <= result.score <= 100

    def test_result_hat_entropie(self):
        result = analysiere_passwort("Test123!", POLICY_BSI)
        assert result.entropie_bits > 0

    def test_result_breach_nicht_geprueft(self):
        """HIBP-Check ist -1 (nicht geprüft) ohne Service."""
        result = analysiere_passwort("Test123!", POLICY_BSI)
        assert result.breach_vorkommnisse == -1
        assert not result.breach_geprueft


# ---------------------------------------------------------------------------
# PasswordService mit gemocktem HIBP
# ---------------------------------------------------------------------------


class TestPasswordService:
    def _make_service(self, hibp_mock=None):
        from tools.password_checker.application.password_service import PasswordService

        return PasswordService(hibp_client=hibp_mock)

    def test_ohne_hibp_kein_breach(self):
        service = self._make_service(None)
        result = service.pruefen("Test123!", mit_breach_check=True)
        assert result.breach_vorkommnisse == -1

    def test_mit_hibp_kompromittiert(self):
        hibp = MagicMock()
        hibp.ist_kompromittiert.return_value = (True, 12345)
        service = self._make_service(hibp)
        result = service.pruefen("password", mit_breach_check=True)
        assert result.ist_kompromittiert
        assert result.breach_vorkommnisse == 12345

    def test_mit_hibp_sicher(self):
        hibp = MagicMock()
        hibp.ist_kompromittiert.return_value = (False, 0)
        service = self._make_service(hibp)
        result = service.pruefen("Sicheres$Passwort99", mit_breach_check=True)
        assert not result.ist_kompromittiert
        assert result.breach_vorkommnisse == 0

    def test_breach_kappt_starkes_passwort_auf_sehr_schwach(self):
        """-F2: Ein entropie-„starkes", aber geleaktes Passwort wird hart
        auf SEHR_SCHWACH/0 gekappt (Score und Breach waren entkoppelt)."""
        starkes_pw = "K7$mZ9!qWp2&xL4@"  # hoher Score
        roh = analysiere_passwort(starkes_pw, POLICY_BSI)
        assert roh.staerke in (PasswordStaerke.STARK, PasswordStaerke.SEHR_STARK)

        hibp = MagicMock()
        hibp.ist_kompromittiert.return_value = (True, 999)
        service = self._make_service(hibp)
        result = service.pruefen(starkes_pw, mit_breach_check=True)

        assert result.ist_kompromittiert
        assert result.staerke is PasswordStaerke.SEHR_SCHWACH
        assert result.score == 0

    def test_sicheres_passwort_behaelt_staerke(self):
        """Ohne Breach-Treffer bleibt die score-basierte Stärke erhalten."""
        starkes_pw = "K7$mZ9!qWp2&xL4@"
        hibp = MagicMock()
        hibp.ist_kompromittiert.return_value = (False, 0)
        service = self._make_service(hibp)
        result = service.pruefen(starkes_pw, mit_breach_check=True)
        assert result.staerke in (PasswordStaerke.STARK, PasswordStaerke.SEHR_STARK)
        assert result.score > 0

    def test_breach_check_deaktiviert(self):
        hibp = MagicMock()
        service = self._make_service(hibp)
        service.pruefen("Test", mit_breach_check=False)
        hibp.ist_kompromittiert.assert_not_called()

    def test_lade_policy_bsi(self):
        service = self._make_service()
        policy = service.lade_policy("BSI Grundschutz")
        assert policy.vorlage == PolicyVorlage.BSI

    def test_lade_policy_nist(self):
        service = self._make_service()
        policy = service.lade_policy("NIST 800-63B (2024)")
        assert policy.vorlage == PolicyVorlage.NIST

    def test_lade_policy_unbekannt_fallback_bsi(self):
        service = self._make_service()
        policy = service.lade_policy("Unbekannte Policy")
        assert policy.vorlage == PolicyVorlage.BSI


# ---------------------------------------------------------------------------
# HIBP-Client (gemockt)
# ---------------------------------------------------------------------------


class TestHIBPClient:
    def _make_client(self):
        from tools.password_checker.data.hibp_client import HIBPClient

        return HIBPClient()

    def test_kompromittiertes_passwort(self):
        """Simuliert eine HIBP-Antwort die den Hash-Suffix enthält."""
        import hashlib

        passwort = "password"
        sha1 = (
            hashlib.sha1(passwort.encode(), usedforsecurity=False).hexdigest().upper()
        )
        suffix = sha1[5:]
        mock_response = MagicMock()
        mock_response.text = f"{suffix}:12345\nABCDE12345:100"
        mock_response.raise_for_status = MagicMock()

        with patch(
            "tools.password_checker.data.hibp_client.get_http_client"
        ) as mock_http:
            mock_http.return_value.get.return_value = mock_response
            client = self._make_client()
            kompromittiert, anzahl = client.ist_kompromittiert(passwort)

        assert kompromittiert is True
        assert anzahl == 12345

    def test_sicheres_passwort(self):
        """Simuliert eine HIBP-Antwort ohne den gesuchten Hash-Suffix."""
        mock_response = MagicMock()
        mock_response.text = "AAAAA11111:100\nBBBBB22222:200"
        mock_response.raise_for_status = MagicMock()

        with patch(
            "tools.password_checker.data.hibp_client.get_http_client"
        ) as mock_http:
            mock_http.return_value.get.return_value = mock_response
            client = self._make_client()
            kompromittiert, anzahl = client.ist_kompromittiert("XkP9#mZ2!qLw")

        assert kompromittiert is False
        assert anzahl == 0

    def test_netzwerkfehler_kein_alarm(self):
        """Netzwerkfehler darf keinen Alarm auslösen."""
        with patch(
            "tools.password_checker.data.hibp_client.get_http_client"
        ) as mock_http:
            mock_http.return_value.get.side_effect = Exception("Netzwerkfehler")
            client = self._make_client()
            kompromittiert, anzahl = client.ist_kompromittiert("beliebig")

        assert kompromittiert is False
        assert anzahl == 0
