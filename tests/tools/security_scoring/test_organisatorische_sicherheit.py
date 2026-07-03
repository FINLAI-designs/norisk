"""Tests für den Organisatorische-Sicherheit-Block.

Deckt ab:
    * ``calculate_self_assessment_score`` — Rand- und Normalfälle.
    * ``OrgSecurityService.baue_komponenten`` für alle / keine / gemischt
      beantwortete Fragen und für fehlendes Assessment.
    * Gewichtungssumme entspricht ``DEFAULT_ORG_WEIGHTS``.
    * Auto-Detection wirkt als zusätzliche Frage im Score-Nenner.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.security_subject.models import NutzungsSignale
from tools.security_scoring.application.org_security_service import OrgSecurityService
from tools.security_scoring.domain.org_security import (
    DEFAULT_ORG_WEIGHTS,
    FRAGEN_DSGVO,
    FRAGEN_MFA,
    FRAGEN_PASSWORT_MANAGER,
    FRAGEN_PHISHING,
    METRIK_DSGVO,
    METRIK_MFA,
    METRIK_PASSWORT_MANAGER,
    METRIK_PHISHING,
    NaVorbelegung,
    OrgAntwort,
    OrgAssessment,
    OrgMetrikErgebnis,
    konkret_beantwortete_keys,
    nutzungs_na_keys,
    profil_na_keys,
)
from tools.security_scoring.domain.scoring_engine import calculate_self_assessment_score


def _assessment_mit(mfa_antworten: dict[str, OrgAntwort]) -> OrgAssessment:
    """Baut ein Assessment, dessen MFA-Metrik die gegebenen Antworten trägt."""
    return OrgAssessment(
        audit_id="a",
        timestamp="t",
        dsgvo=OrgMetrikErgebnis(metrik=METRIK_DSGVO),
        phishing=OrgMetrikErgebnis(metrik=METRIK_PHISHING),
        mfa=OrgMetrikErgebnis(metrik=METRIK_MFA, antworten=mfa_antworten),
        passwort_manager=OrgMetrikErgebnis(metrik=METRIK_PASSWORT_MANAGER),
    )

# ---------------------------------------------------------------------------
# calculate_self_assessment_score
# ---------------------------------------------------------------------------


class TestCalculateSelfAssessmentScore:
    """Tests für die reine Scoring-Funktion."""

    def test_alle_erfuellt_gibt_100(self) -> None:
        assert calculate_self_assessment_score(6, 6) == 100.0

    def test_keine_erfuellt_gibt_0(self) -> None:
        assert calculate_self_assessment_score(0, 6) == 0.0

    def test_haelfte_erfuellt_gibt_50(self) -> None:
        assert calculate_self_assessment_score(3, 6) == 50.0

    def test_leer_gibt_0(self) -> None:
        assert calculate_self_assessment_score(0, 0) == 0.0

    def test_negative_gesamt_gibt_0(self) -> None:
        assert calculate_self_assessment_score(0, -1) == 0.0

    def test_clamp_obergrenze(self) -> None:
        # Mehr Erfüllungen als Fragen sollte niemals > 100 ergeben.
        assert calculate_self_assessment_score(10, 5) == 100.0


# ---------------------------------------------------------------------------
# OrgSecurityService.baue_komponenten — Hilfsfunktionen
# ---------------------------------------------------------------------------


def _ergebnis(metrik: str, fragen, antwort: OrgAntwort, *, auto_status: str = "",
              auto_details: str = "", custom_pm_name: str = "") -> OrgMetrikErgebnis:
    """Baut ein Ergebnis, in dem jede Frage identisch beantwortet ist."""
    return OrgMetrikErgebnis(
        metrik=metrik,
        antworten={f.key: antwort for f in fragen},
        auto_status=auto_status,
        auto_details=auto_details,
        custom_pm_name=custom_pm_name,
    )


def _assessment(
    dsgvo: OrgMetrikErgebnis,
    phishing: OrgMetrikErgebnis,
    mfa: OrgMetrikErgebnis,
    passwort_manager: OrgMetrikErgebnis,
) -> OrgAssessment:
    return OrgAssessment(
        audit_id="test-uuid",
        timestamp="2026-04-20T00:00:00+00:00",
        dsgvo=dsgvo,
        phishing=phishing,
        mfa=mfa,
        passwort_manager=passwort_manager,
    )


# ---------------------------------------------------------------------------
# OrgSecurityService.baue_komponenten
# ---------------------------------------------------------------------------


class TestBaueKomponenten:
    """Tests für die Score-Komponenten-Erzeugung."""

    def test_none_assessment_gibt_leere_liste(self) -> None:
        service = OrgSecurityService(repository=MagicMock())
        assert service.baue_komponenten(None) == []

    def test_alle_ja_ergibt_100_pro_metrik(self) -> None:
        service = OrgSecurityService(repository=MagicMock())
        assessment = _assessment(
            dsgvo=_ergebnis(METRIK_DSGVO, FRAGEN_DSGVO, OrgAntwort.JA),
            phishing=_ergebnis(METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.JA),
            mfa=_ergebnis(
                METRIK_MFA, FRAGEN_MFA, OrgAntwort.JA, auto_status="aktiv"
            ),
            passwort_manager=_ergebnis(
                METRIK_PASSWORT_MANAGER,
                FRAGEN_PASSWORT_MANAGER,
                OrgAntwort.JA,
                auto_status="aktiv",
            ),
        )
        komponenten = service.baue_komponenten(assessment)
        assert len(komponenten) == 4
        for k in komponenten:
            assert k.score == 100.0
            assert k.findings_high == 0

    def test_alle_nein_ergibt_0_pro_metrik(self) -> None:
        service = OrgSecurityService(repository=MagicMock())
        assessment = _assessment(
            dsgvo=_ergebnis(METRIK_DSGVO, FRAGEN_DSGVO, OrgAntwort.NEIN),
            phishing=_ergebnis(METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.NEIN),
            mfa=_ergebnis(
                METRIK_MFA, FRAGEN_MFA, OrgAntwort.NEIN, auto_status="inaktiv"
            ),
            passwort_manager=_ergebnis(
                METRIK_PASSWORT_MANAGER,
                FRAGEN_PASSWORT_MANAGER,
                OrgAntwort.NEIN,
                auto_status="inaktiv",
            ),
        )
        komponenten = service.baue_komponenten(assessment)
        assert len(komponenten) == 4
        for k in komponenten:
            assert k.score == 0.0
            assert k.findings_high > 0

    def test_gemischt_pro_metrik(self) -> None:
        # 3 von 6 DSGVO-Fragen mit Ja → 50%
        antworten_dsgvo = {f.key: OrgAntwort.NEIN for f in FRAGEN_DSGVO}
        for f in FRAGEN_DSGVO[:3]:
            antworten_dsgvo[f.key] = OrgAntwort.JA

        dsgvo = OrgMetrikErgebnis(metrik=METRIK_DSGVO, antworten=antworten_dsgvo)
        service = OrgSecurityService(repository=MagicMock())
        assessment = _assessment(
            dsgvo=dsgvo,
            phishing=_ergebnis(METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.NEIN),
            mfa=_ergebnis(METRIK_MFA, FRAGEN_MFA, OrgAntwort.NEIN, auto_status="inaktiv"),
            passwort_manager=_ergebnis(
                METRIK_PASSWORT_MANAGER,
                FRAGEN_PASSWORT_MANAGER,
                OrgAntwort.NEIN,
                auto_status="inaktiv",
            ),
        )
        komponenten = service.baue_komponenten(assessment)
        dsgvo_komp = next(k for k in komponenten if "DSGVO" in k.name)
        assert dsgvo_komp.score == pytest.approx(50.0)
        assert dsgvo_komp.findings_high == 3

    def test_mfa_auto_aktiv_zaehlt_als_extra_ja(self) -> None:
        # 0 Self-Assessment-Ja, aber Auto = aktiv → 1 / (6 + 1) ≈ 14.29%
        service = OrgSecurityService(repository=MagicMock())
        assessment = _assessment(
            dsgvo=_ergebnis(METRIK_DSGVO, FRAGEN_DSGVO, OrgAntwort.NEIN),
            phishing=_ergebnis(METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.NEIN),
            mfa=_ergebnis(
                METRIK_MFA, FRAGEN_MFA, OrgAntwort.NEIN, auto_status="aktiv"
            ),
            passwort_manager=_ergebnis(
                METRIK_PASSWORT_MANAGER,
                FRAGEN_PASSWORT_MANAGER,
                OrgAntwort.NEIN,
                auto_status="inaktiv",
            ),
        )
        komponenten = service.baue_komponenten(assessment)
        mfa_komp = next(k for k in komponenten if "Multi-Factor" in k.name)
        assert mfa_komp.score == pytest.approx(100.0 / 7.0)

    def test_mfa_auto_inaktiv_zaehlt_nicht_als_ja(self) -> None:
        # Alle Self-Assessment-Ja, aber Auto = inaktiv → 6 / (6 + 1)
        service = OrgSecurityService(repository=MagicMock())
        assessment = _assessment(
            dsgvo=_ergebnis(METRIK_DSGVO, FRAGEN_DSGVO, OrgAntwort.NEIN),
            phishing=_ergebnis(METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.NEIN),
            mfa=_ergebnis(
                METRIK_MFA, FRAGEN_MFA, OrgAntwort.JA, auto_status="inaktiv"
            ),
            passwort_manager=_ergebnis(
                METRIK_PASSWORT_MANAGER,
                FRAGEN_PASSWORT_MANAGER,
                OrgAntwort.NEIN,
                auto_status="inaktiv",
            ),
        )
        komponenten = service.baue_komponenten(assessment)
        mfa_komp = next(k for k in komponenten if "Multi-Factor" in k.name)
        assert mfa_komp.score == pytest.approx(100.0 * 6.0 / 7.0)

    def test_pm_custom_name_zaehlt_als_extra_ja(self) -> None:
        # 0 Self-Assessment-Ja, Auto = unbekannt, aber Custom-Name gesetzt
        # → 1 / (3 + 1) = 25%
        service = OrgSecurityService(repository=MagicMock())
        assessment = _assessment(
            dsgvo=_ergebnis(METRIK_DSGVO, FRAGEN_DSGVO, OrgAntwort.NEIN),
            phishing=_ergebnis(METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.NEIN),
            mfa=_ergebnis(METRIK_MFA, FRAGEN_MFA, OrgAntwort.NEIN, auto_status="inaktiv"),
            passwort_manager=_ergebnis(
                METRIK_PASSWORT_MANAGER,
                FRAGEN_PASSWORT_MANAGER,
                OrgAntwort.NEIN,
                auto_status="unbekannt",
                custom_pm_name="MeinPM",
            ),
        )
        komponenten = service.baue_komponenten(assessment)
        pm_komp = next(k for k in komponenten if "Passwort" in k.name)
        assert pm_komp.score == pytest.approx(25.0)

    def test_gewichte_entsprechen_default_org_weights(self) -> None:
        service = OrgSecurityService(repository=MagicMock())
        assessment = _assessment(
            dsgvo=_ergebnis(METRIK_DSGVO, FRAGEN_DSGVO, OrgAntwort.JA),
            phishing=_ergebnis(METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.JA),
            mfa=_ergebnis(METRIK_MFA, FRAGEN_MFA, OrgAntwort.JA, auto_status="aktiv"),
            passwort_manager=_ergebnis(
                METRIK_PASSWORT_MANAGER,
                FRAGEN_PASSWORT_MANAGER,
                OrgAntwort.JA,
                auto_status="aktiv",
            ),
        )
        komponenten = service.baue_komponenten(assessment)
        gewichte = {k.name: k.weight for k in komponenten}
        # Jede Komponente muss dem DEFAULT_ORG_WEIGHTS-Eintrag entsprechen.
        assert sum(gewichte.values()) == pytest.approx(sum(DEFAULT_ORG_WEIGHTS.values()))
        # Summe der Default-Gewichte ergibt den dokumentierten Block-Anteil.
        assert sum(DEFAULT_ORG_WEIGHTS.values()) == pytest.approx(0.34)

    def test_source_tool_wird_gesetzt(self) -> None:
        service = OrgSecurityService(repository=MagicMock())
        assessment = _assessment(
            dsgvo=_ergebnis(METRIK_DSGVO, FRAGEN_DSGVO, OrgAntwort.JA),
            phishing=_ergebnis(METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.JA),
            mfa=_ergebnis(METRIK_MFA, FRAGEN_MFA, OrgAntwort.JA, auto_status="aktiv"),
            passwort_manager=_ergebnis(
                METRIK_PASSWORT_MANAGER,
                FRAGEN_PASSWORT_MANAGER,
                OrgAntwort.JA,
                auto_status="aktiv",
            ),
        )
        for k in service.baue_komponenten(assessment):
            assert k.source_tool == "org_security"


# ---------------------------------------------------------------------------
# anzahl_kriterien
# ---------------------------------------------------------------------------


class TestAnzahlKriterien:
    """Tests für die Gesamtanzahl-Kriterien-Hilfsfunktion."""

    def test_dsgvo_hat_6_kriterien(self) -> None:
        assert OrgSecurityService.anzahl_kriterien(METRIK_DSGVO) == 6

    def test_phishing_hat_5_kriterien(self) -> None:
        assert OrgSecurityService.anzahl_kriterien(METRIK_PHISHING) == 5

    def test_mfa_hat_7_kriterien_inkl_auto(self) -> None:
        # 6 Self-Assessment + 1 Auto-Detection.
        assert OrgSecurityService.anzahl_kriterien(METRIK_MFA) == 7

    def test_passwort_manager_hat_4_kriterien_inkl_auto(self) -> None:
        # 3 Self-Assessment + 1 Auto-Detection.
        assert OrgSecurityService.anzahl_kriterien(METRIK_PASSWORT_MANAGER) == 4

    def test_unbekannte_metrik_gibt_0(self) -> None:
        assert OrgSecurityService.anzahl_kriterien("existiert_nicht") == 0


# ---------------------------------------------------------------------------
# Persistenz-Fehler
# ---------------------------------------------------------------------------


class TestLadeLetztes:
    """Tests für das tolerante Laden des letzten Assessments."""

    def test_repository_fehler_wird_geschluckt(self) -> None:
        repo = MagicMock()
        repo.lade_letztes.side_effect = RuntimeError("DB kaputt")
        service = OrgSecurityService(repository=repo)
        # Fehler werden geloggt, aber nicht weitergereicht.
        assert service.lade_letztes() is None

    def test_leeres_repository_gibt_none(self) -> None:
        repo = MagicMock()
        repo.lade_letztes.return_value = None
        service = OrgSecurityService(repository=repo)
        assert service.lade_letztes() is None


# ---------------------------------------------------------------------------
# NICHT_ANWENDBAR (Microsoft-Secure-Score-Stil)
# ---------------------------------------------------------------------------


def _benign_others() -> dict:
    """Drei unkritische Metriken (alle JA) für Single-Metrik-Tests."""
    return {
        "phishing": _ergebnis(METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.JA),
        "mfa": _ergebnis(METRIK_MFA, FRAGEN_MFA, OrgAntwort.JA, auto_status="aktiv"),
        "passwort_manager": _ergebnis(
            METRIK_PASSWORT_MANAGER,
            FRAGEN_PASSWORT_MANAGER,
            OrgAntwort.JA,
            auto_status="aktiv",
        ),
    }


class TestNichtAnwendbar:
    """: N/A fällt aus dem Nenner, UNBEKANNT bleibt, all-N/A → Metrik raus."""

    def test_na_faellt_aus_dem_nenner(self) -> None:
        # DSGVO: 3 JA, 1 N/A, 2 NEIN → 3 / 5 anwendbar = 60 % (N/A nicht im Nenner).
        antworten = {f.key: OrgAntwort.NEIN for f in FRAGEN_DSGVO}
        for f in FRAGEN_DSGVO[:3]:
            antworten[f.key] = OrgAntwort.JA
        antworten[FRAGEN_DSGVO[3].key] = OrgAntwort.NICHT_ANWENDBAR
        dsgvo = OrgMetrikErgebnis(metrik=METRIK_DSGVO, antworten=antworten)

        service = OrgSecurityService(repository=MagicMock())
        komponenten = service.baue_komponenten(_assessment(dsgvo=dsgvo, **_benign_others()))
        dsgvo_komp = next(k for k in komponenten if "DSGVO" in k.name)
        assert dsgvo_komp.score == pytest.approx(60.0)
        assert dsgvo_komp.findings_high == 2

    def test_unbekannt_bleibt_im_nenner(self) -> None:
        # MS-Stil: UNBEKANNT zählt weiter. 3 JA, 3 UNBEKANNT → 3 / 6 = 50 %.
        antworten = {f.key: OrgAntwort.UNBEKANNT for f in FRAGEN_DSGVO}
        for f in FRAGEN_DSGVO[:3]:
            antworten[f.key] = OrgAntwort.JA
        dsgvo = OrgMetrikErgebnis(metrik=METRIK_DSGVO, antworten=antworten)

        service = OrgSecurityService(repository=MagicMock())
        komponenten = service.baue_komponenten(_assessment(dsgvo=dsgvo, **_benign_others()))
        dsgvo_komp = next(k for k in komponenten if "DSGVO" in k.name)
        assert dsgvo_komp.score == pytest.approx(50.0)

    def test_alle_na_metrik_faellt_aus_block(self) -> None:
        # Alle DSGVO-Fragen N/A → Metrik nicht bewertbar → nicht in der Liste.
        service = OrgSecurityService(repository=MagicMock())
        assessment = _assessment(
            dsgvo=_ergebnis(METRIK_DSGVO, FRAGEN_DSGVO, OrgAntwort.NICHT_ANWENDBAR),
            **_benign_others(),
        )
        komponenten = service.baue_komponenten(assessment)
        assert len(komponenten) == 3
        assert all("DSGVO" not in k.name for k in komponenten)

    def test_auto_unbekannt_penalisiert_nicht(self) -> None:
        # MFA 6 JA + auto='unbekannt' (kein Signal, kein Custom) → 6 / 6 = 100
        # (vorher 6 / 7, weil die Auto-Pseudo-Frage als +1 NEIN zählte).
        service = OrgSecurityService(repository=MagicMock())
        assessment = _assessment(
            dsgvo=_ergebnis(METRIK_DSGVO, FRAGEN_DSGVO, OrgAntwort.JA),
            phishing=_ergebnis(METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.JA),
            mfa=_ergebnis(METRIK_MFA, FRAGEN_MFA, OrgAntwort.JA, auto_status="unbekannt"),
            passwort_manager=_ergebnis(
                METRIK_PASSWORT_MANAGER,
                FRAGEN_PASSWORT_MANAGER,
                OrgAntwort.JA,
                auto_status="aktiv",
            ),
        )
        mfa_komp = next(k for k in service.baue_komponenten(assessment) if "Multi-Factor" in k.name)
        assert mfa_komp.score == pytest.approx(100.0)
        assert mfa_komp.findings_high == 0

    def test_alle_metriken_na_block_faellt_komplett_weg(self) -> None:
        # Alle 4 Metriken voll N/A (MFA/PM Auto 'unbekannt', kein Custom)
        # → kompletter Org-Block fällt aus dem Score (leere Komponenten-Liste).
        service = OrgSecurityService(repository=MagicMock())
        assessment = _assessment(
            dsgvo=_ergebnis(METRIK_DSGVO, FRAGEN_DSGVO, OrgAntwort.NICHT_ANWENDBAR),
            phishing=_ergebnis(
                METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.NICHT_ANWENDBAR
            ),
            mfa=_ergebnis(
                METRIK_MFA,
                FRAGEN_MFA,
                OrgAntwort.NICHT_ANWENDBAR,
                auto_status="unbekannt",
            ),
            passwort_manager=_ergebnis(
                METRIK_PASSWORT_MANAGER,
                FRAGEN_PASSWORT_MANAGER,
                OrgAntwort.NICHT_ANWENDBAR,
                auto_status="unbekannt",
            ),
        )
        assert service.baue_komponenten(assessment) == []

    def test_pm_inaktiv_mit_custom_name_zaehlt_als_ja(self) -> None:
        # Auto 'inaktiv' (kein Whitelist-PM erkannt) ABER eigener PM-Name
        # → Override: die Auto-Zusatzfrage zählt als erfüllt. 3 NEIN + 1 JA
        # → 1 / (3 + 1) = 25 %.
        service = OrgSecurityService(repository=MagicMock())
        pm = _ergebnis(
            METRIK_PASSWORT_MANAGER,
            FRAGEN_PASSWORT_MANAGER,
            OrgAntwort.NEIN,
            auto_status="inaktiv",
            custom_pm_name="Securden",
        )
        assessment = _assessment(
            dsgvo=_ergebnis(METRIK_DSGVO, FRAGEN_DSGVO, OrgAntwort.JA),
            phishing=_ergebnis(METRIK_PHISHING, FRAGEN_PHISHING, OrgAntwort.JA),
            mfa=_ergebnis(METRIK_MFA, FRAGEN_MFA, OrgAntwort.JA, auto_status="aktiv"),
            passwort_manager=pm,
        )
        pm_komp = next(
            k for k in service.baue_komponenten(assessment) if "Passwort" in k.name
        )
        assert pm_komp.score == pytest.approx(25.0)


class TestPersistenzNichtAnwendbar:
    """: NICHT_ANWENDBAR übersteht den Serialisierungs-Roundtrip; Alt-Daten
    bleiben kompatibel (additiv, keine Migration)."""

    def test_na_roundtrip(self) -> None:
        from tools.security_scoring.data.org_assessment_repository import (  # noqa: PLC0415
            _dict_zu_metrik,
            _metrik_zu_dict,
        )

        ergebnis = OrgMetrikErgebnis(
            metrik=METRIK_DSGVO,
            antworten={
                FRAGEN_DSGVO[0].key: OrgAntwort.JA,
                FRAGEN_DSGVO[1].key: OrgAntwort.NICHT_ANWENDBAR,
                FRAGEN_DSGVO[2].key: OrgAntwort.UNBEKANNT,
            },
        )
        wieder = _dict_zu_metrik(_metrik_zu_dict(ergebnis))
        assert wieder.antworten[FRAGEN_DSGVO[0].key] == OrgAntwort.JA
        assert wieder.antworten[FRAGEN_DSGVO[1].key] == OrgAntwort.NICHT_ANWENDBAR
        assert wieder.antworten[FRAGEN_DSGVO[2].key] == OrgAntwort.UNBEKANNT

    def test_alt_werte_bleiben_kompatibel(self) -> None:
        from tools.security_scoring.data.org_assessment_repository import (  # noqa: PLC0415
            _dict_zu_metrik,
        )

        data = {
            "metrik": METRIK_DSGVO,
            "antworten": {"k1": "ja", "k2": "nein", "k3": "unbekannt"},
        }
        m = _dict_zu_metrik(data)
        assert m.antworten == {
            "k1": OrgAntwort.JA,
            "k2": OrgAntwort.NEIN,
            "k3": OrgAntwort.UNBEKANNT,
        }

    def test_unbekannter_string_faellt_auf_unbekannt(self) -> None:
        from tools.security_scoring.data.org_assessment_repository import (  # noqa: PLC0415
            _dict_zu_metrik,
        )

        m = _dict_zu_metrik({"metrik": METRIK_DSGVO, "antworten": {"k1": "kaputt"}})
        assert m.antworten["k1"] == OrgAntwort.UNBEKANNT


class TestProfilNaKeys:
    """ Ebene 2: profil-bedingte N/A-Vorbelegung aus dem FTE (konservativ)."""

    def test_fte_none_keine_vorbelegung(self) -> None:
        from tools.security_scoring.domain.org_security import (  # noqa: PLC0415
            profil_na_keys,
        )

        assert profil_na_keys(None) == frozenset()

    def test_solo_mitarbeiter_fragen_und_dsb(self) -> None:
        from tools.security_scoring.domain.org_security import (  # noqa: PLC0415
            _MITARBEITER_FRAGEN,
            profil_na_keys,
        )

        # fte=1 (Solo): Mitarbeiter-abhängige Fragen + dsb_benannt (1 < 20).
        keys = profil_na_keys(1)
        assert keys >= _MITARBEITER_FRAGEN
        assert "dsb_benannt" in keys

    def test_klein_nur_dsb(self) -> None:
        from tools.security_scoring.domain.org_security import (  # noqa: PLC0415
            profil_na_keys,
        )

        # fte=5: >1 (Mitarbeiter-Fragen bleiben aktiv), aber <20 → nur dsb_benannt.
        assert profil_na_keys(5) == frozenset({"dsb_benannt"})

    def test_gross_keine_vorbelegung(self) -> None:
        from tools.security_scoring.domain.org_security import (  # noqa: PLC0415
            DSB_FTE_SCHWELLE,
            profil_na_keys,
        )

        assert profil_na_keys(DSB_FTE_SCHWELLE) == frozenset()
        assert profil_na_keys(50) == frozenset()

    def test_na_keys_sind_gueltige_katalog_keys(self) -> None:
        # Drift-Guard: jeder vorbelegbare Key existiert im Fragenkatalog.
        from tools.security_scoring.domain.org_security import (  # noqa: PLC0415
            profil_na_keys,
        )

        alle_keys = {
            f.key
            for fragen in (
                FRAGEN_DSGVO,
                FRAGEN_PHISHING,
                FRAGEN_MFA,
                FRAGEN_PASSWORT_MANAGER,
            )
            for f in fragen
        }
        gesammelt = profil_na_keys(0) | profil_na_keys(5) | profil_na_keys(19)
        assert gesammelt
        assert gesammelt <= alle_keys


# ---------------------------------------------------------------------------
# Ebene 3 — Cross-Tool-Auto-Detection
# ---------------------------------------------------------------------------


class TestKonkretBeantworteteKeys:
    """Konflikt-Regel-Grundlage: nur JA/NEIN zählen als konkret."""

    def test_ja_und_nein_zaehlen(self) -> None:
        a = _assessment_mit(
            {"mfa_m365_azure": OrgAntwort.JA, "mfa_online_banking": OrgAntwort.NEIN}
        )
        assert konkret_beantwortete_keys(a) == frozenset(
            {"mfa_m365_azure", "mfa_online_banking"}
        )

    def test_unbekannt_und_na_zaehlen_nicht(self) -> None:
        a = _assessment_mit(
            {
                "mfa_m365_azure": OrgAntwort.UNBEKANNT,
                "mfa_cloud_speicher": OrgAntwort.NICHT_ANWENDBAR,
            }
        )
        assert konkret_beantwortete_keys(a) == frozenset()


class TestNutzungsNaKeys:
    """ Ebene 3 /: Mapping + True-Override + Konflikt-Regel (rein)."""

    _MAPPING = {
        "nutzt_m365": "mfa_m365_azure",
        "nutzt_kanzlei_software": "mfa_steuerberater_software",
        "nutzt_cloud_speicher": "mfa_cloud_speicher",
        "hat_auftragsverarbeiter": "avv_abgeschlossen",
    }
    # avv_abgeschlossen ist confirm-only (False → kein Auto-N/A) → separat getestet.
    _BIDIREKTIONAL = {
        "nutzt_m365": "mfa_m365_azure",
        "nutzt_kanzlei_software": "mfa_steuerberater_software",
        "nutzt_cloud_speicher": "mfa_cloud_speicher",
    }

    def test_alle_none_ist_fte_identitaet(self) -> None:
        fte = frozenset({"dsb_benannt"})
        res = nutzungs_na_keys(fte, NutzungsSignale(), frozenset())
        assert res.keys == fte
        assert res.nutzungs_keys == frozenset()

    @pytest.mark.parametrize(("feld", "frage"), list(_BIDIREKTIONAL.items()))
    def test_false_signal_belegt_na(self, feld: str, frage: str) -> None:
        res = nutzungs_na_keys(frozenset(), NutzungsSignale(**{feld: False}), frozenset())
        assert frage in res.keys
        assert frage in res.nutzungs_keys

    def test_avv_confirm_only_false_kein_auto_na(self) -> None:
        # avv_abgeschlossen ist confirm-only: False (Katalog leer) darf die DSGVO-
        # Frage NICHT suppressen — der Sovereignty-Katalog ist zu schmaler Proxy.
        res = nutzungs_na_keys(
            frozenset(), NutzungsSignale(hat_auftragsverarbeiter=False), frozenset()
        )
        assert "avv_abgeschlossen" not in res.keys
        assert "avv_abgeschlossen" not in res.nutzungs_keys

    def test_avv_true_haelt_aktiv(self) -> None:
        # True (Auftragsverarbeiter erkannt) hält die Frage aktiv (kein N/A).
        res = nutzungs_na_keys(
            frozenset(), NutzungsSignale(hat_auftragsverarbeiter=True), frozenset()
        )
        assert "avv_abgeschlossen" not in res.keys

    @pytest.mark.parametrize(("feld", "frage"), list(_MAPPING.items()))
    def test_true_signal_haelt_aktiv(self, feld: str, frage: str) -> None:
        res = nutzungs_na_keys(frozenset(), NutzungsSignale(**{feld: True}), frozenset())
        assert frage not in res.keys

    def test_true_override_schlaegt_vorbelegung(self) -> None:
        # True gewinnt, selbst wenn eine andere Quelle den Key vorbelegen wollte.
        res = nutzungs_na_keys(
            frozenset({"mfa_m365_azure"}), NutzungsSignale(nutzt_m365=True), frozenset()
        )
        assert "mfa_m365_azure" not in res.keys

    def test_konflikt_regel_konkret_schlaegt_false(self) -> None:
        res = nutzungs_na_keys(
            frozenset(), NutzungsSignale(nutzt_m365=False), frozenset({"mfa_m365_azure"})
        )
        assert "mfa_m365_azure" not in res.keys

    def test_konflikt_regel_gilt_auch_fuer_fte(self) -> None:
        # Eine konkret beantwortete FTE-Frage wird nicht erneut auto-N/A.
        res = nutzungs_na_keys(
            frozenset({"dsb_benannt"}), NutzungsSignale(), frozenset({"dsb_benannt"})
        )
        assert "dsb_benannt" not in res.keys

    def test_audit_datum_durchgereicht(self) -> None:
        res = nutzungs_na_keys(
            frozenset(),
            NutzungsSignale(nutzt_m365=False, audit_datum="2026-06-05T10:00:00"),
            frozenset(),
        )
        assert res.audit_datum == "2026-06-05T10:00:00"

    def test_nutzungs_keys_teilmenge_keys(self) -> None:
        res = nutzungs_na_keys(
            frozenset({"dsb_benannt"}),
            NutzungsSignale(nutzt_kanzlei_software=False),
            frozenset(),
        )
        assert res.nutzungs_keys <= res.keys

    def test_drift_guard_mapped_keys_im_katalog(self) -> None:
        alle = {
            f.key
            for fragen in (
                FRAGEN_DSGVO,
                FRAGEN_PHISHING,
                FRAGEN_MFA,
                FRAGEN_PASSWORT_MANAGER,
            )
            for f in fragen
        }
        assert set(self._MAPPING.values()) <= alle


class TestEigenesNaVorbelegung:
    """ Ebene 3: application-Orchestrierung (Subjekt+Signale+Konflikt), fail-soft."""

    @staticmethod
    def _patch(monkeypatch: pytest.MonkeyPatch, *, subjekt: object, provider: object):
        from tools.security_scoring.application import subject_store  # noqa: PLC0415

        store = MagicMock()
        store.get_self.return_value = subjekt
        monkeypatch.setattr(
            subject_store,
            "create_default_subject_store",
            lambda: (None if subjekt is None else store),
        )
        monkeypatch.setattr(
            subject_store, "create_usage_signal_provider", lambda: provider
        )
        return subject_store

    def test_kein_subjekt_leer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ss = self._patch(monkeypatch, subjekt=None, provider=None)
        assert ss.eigenes_na_vorbelegung() == NaVorbelegung()

    def test_provider_none_fte_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        subjekt = MagicMock(fte=5, subject_id="own-1")
        ss = self._patch(monkeypatch, subjekt=subjekt, provider=None)
        res = ss.eigenes_na_vorbelegung()
        assert res.keys == profil_na_keys(5)
        assert res.nutzungs_keys == frozenset()

    def test_provider_exception_fte_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tools.security_scoring.application import subject_store  # noqa: PLC0415

        subjekt = MagicMock(fte=5, subject_id="own-1")
        store = MagicMock()
        store.get_self.return_value = subjekt
        monkeypatch.setattr(
            subject_store, "create_default_subject_store", lambda: store
        )

        def _boom() -> object:
            raise RuntimeError("kein customer_audit")

        monkeypatch.setattr(subject_store, "create_usage_signal_provider", _boom)
        assert subject_store.eigenes_na_vorbelegung().keys == profil_na_keys(5)

    def test_signale_eingefaltet(self, monkeypatch: pytest.MonkeyPatch) -> None:
        subjekt = MagicMock(fte=5, subject_id="own-1")
        provider = MagicMock()
        provider.signale_fuer.return_value = NutzungsSignale(
            nutzt_m365=False, audit_datum="2026-06-05T10:00:00"
        )
        ss = self._patch(monkeypatch, subjekt=subjekt, provider=provider)
        res = ss.eigenes_na_vorbelegung()
        assert "mfa_m365_azure" in res.keys
        assert "mfa_m365_azure" in res.nutzungs_keys
        assert "dsb_benannt" in res.keys  # FTE-Anteil bleibt erhalten
        provider.signale_fuer.assert_called_once_with("own-1")

    def test_konflikt_regel_e2e(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Letztes Assessment: M365 = JA. Signal sagt False → darf NICHT N/A werden.
        subjekt = MagicMock(fte=50, subject_id="own-1")
        provider = MagicMock()
        provider.signale_fuer.return_value = NutzungsSignale(nutzt_m365=False)
        ss = self._patch(monkeypatch, subjekt=subjekt, provider=provider)
        letztes = _assessment_mit({"mfa_m365_azure": OrgAntwort.JA})
        assert "mfa_m365_azure" not in ss.eigenes_na_vorbelegung(letztes).keys

    def test_store_exception_leer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # _eigenes_subjekt fängt Store-Fehler → leere Vorbelegung (nie still N/A).
        from tools.security_scoring.application import subject_store  # noqa: PLC0415

        def _boom() -> object:
            raise RuntimeError("kein SQLCipher-Schlüssel")

        monkeypatch.setattr(subject_store, "create_default_subject_store", _boom)
        assert subject_store.eigenes_na_vorbelegung() == NaVorbelegung()

    def test_get_self_none_leer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from tools.security_scoring.application import subject_store  # noqa: PLC0415

        store = MagicMock()
        store.get_self.return_value = None
        monkeypatch.setattr(
            subject_store, "create_default_subject_store", lambda: store
        )
        assert subject_store.eigenes_na_vorbelegung() == NaVorbelegung()
