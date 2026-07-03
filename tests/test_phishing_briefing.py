"""Tests fuer die pure Phishing-Briefing-Auswahl/-Klassifikation (c1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.cyber_dashboard.application.phishing_briefing import (
    ist_kmu_phishing,
    phishing_quellen,
    waehle_phishing_kandidaten,
)
from tools.cyber_dashboard.domain.models import (
    CyberMeldung,
    QuelleTyp,
    Schweregrad,
)

_NOW = datetime(2026, 6, 26, 12, 0, tzinfo=UTC)


def _meldung(
    titel: str,
    *,
    beschreibung: str = "",
    quelle: QuelleTyp = QuelleTyp.WATCHLIST_AT,
    alter_minuten: int = 0,
) -> CyberMeldung:
    return CyberMeldung(
        titel=titel,
        beschreibung=beschreibung,
        url=f"https://example.test/{abs(hash(titel))}",
        quelle=quelle,
        schweregrad=Schweregrad.HOCH,
        veroeffentlicht=_NOW - timedelta(minutes=alter_minuten),
    )


class TestIstKmuPhishing:
    @pytest.mark.parametrize(
        "titel",
        [
            "Gefälschte Rechnung im Umlauf",
            "CEO-Fraud: Angeblicher Geschäftsführer fordert Überweisung",
            "Betrug mit Lieferanten-Bankverbindung",
            "Fake-Eintrag im Handelsregister kostet Firmen Geld",
            "Business Email Compromise nimmt zu",
            "Betrügerische Zahlungsaufforderung an die Buchhaltung",
        ],
    )
    def test_kmu_keywords_true(self, titel):
        assert ist_kmu_phishing(_meldung(titel)) is True

    @pytest.mark.parametrize(
        "titel",
        [
            "Phishing-Mail im Namen der Sparkasse",
            "Gefälschte DHL-Paket-SMS unterwegs",
            "Betrug mit angeblichem Netflix-Abo",
            "Fake-Shop verkauft Markenkleidung",
        ],
    )
    def test_consumer_keywords_false(self, titel):
        assert ist_kmu_phishing(_meldung(titel)) is False

    def test_match_auch_in_beschreibung(self):
        m = _meldung("Neue Betrugsmasche", beschreibung="Gefälschte Rechnung per Mail")
        assert ist_kmu_phishing(m) is True


class TestPhishingQuellen:
    def test_enthaelt_dach_quellen(self):
        quellen = set(phishing_quellen())
        # AT / DE / CH muessen abgedeckt sein.
        assert QuelleTyp.WATCHLIST_AT in quellen  # AT
        assert QuelleTyp.MIMIKAMA in quellen  # DE
        assert QuelleTyp.POLIZEI_NDS in quellen  # DE
        assert QuelleTyp.NCSC_CH in quellen  # CH

    def test_keine_tech_cve_quellen(self):
        quellen = set(phishing_quellen())
        assert QuelleTyp.CERT_AT not in quellen
        assert QuelleTyp.BSI not in quellen


class TestWaehlePhishingKandidaten:
    def test_filtert_nicht_phishing_quellen_raus(self):
        meldungen = [
            _meldung("Rechnung gefälscht", quelle=QuelleTyp.WATCHLIST_AT),
            _meldung("CVE-2026-1234 in Apache", quelle=QuelleTyp.BSI),
        ]
        kmu, consumer = waehle_phishing_kandidaten(meldungen)
        alle = kmu + consumer
        assert all(m.quelle is not QuelleTyp.BSI for m in alle)
        assert len(alle) == 1

    def test_klassifiziert_in_zwei_gruppen(self):
        meldungen = [
            _meldung("Gefälschte Rechnung", quelle=QuelleTyp.WATCHLIST_AT),
            _meldung("Sparkassen-Phishing", quelle=QuelleTyp.MIMIKAMA),
        ]
        kmu, consumer = waehle_phishing_kandidaten(meldungen)
        assert [m.titel for m in kmu] == ["Gefälschte Rechnung"]
        assert [m.titel for m in consumer] == ["Sparkassen-Phishing"]

    def test_begrenzt_pro_gruppe(self):
        meldungen = [
            _meldung(f"Rechnung Betrug {i}", quelle=QuelleTyp.WATCHLIST_AT,
                     alter_minuten=i)
            for i in range(10)
        ]
        kmu, consumer = waehle_phishing_kandidaten(meldungen, max_pro_gruppe=3)
        assert len(kmu) == 3
        assert consumer == []

    def test_sortiert_neueste_zuerst(self):
        meldungen = [
            _meldung("Alt Sparkasse", quelle=QuelleTyp.MIMIKAMA, alter_minuten=100),
            _meldung("Neu Paket", quelle=QuelleTyp.MIMIKAMA, alter_minuten=1),
        ]
        _, consumer = waehle_phishing_kandidaten(meldungen)
        assert consumer[0].titel == "Neu Paket"

    def test_leere_eingabe(self):
        assert waehle_phishing_kandidaten([]) == ([], [])
