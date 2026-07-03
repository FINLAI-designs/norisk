"""
test_meldung_state_repository — Tests fuer die ``meldung_state``-
Tabelle und ihre Repo-Methoden (Phishing-Radar-Refactor 2026-05-28).

Read/Unread/Snooze-Persistenz im verschluesselten Cache.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.cyber_dashboard.data.cache_repository import CacheRepository
from tools.cyber_dashboard.domain.models import (
    CyberMeldung,
    QuelleTyp,
    Schweregrad,
)


@pytest.fixture
def repo() -> CacheRepository:
    return CacheRepository()


def _meldung(guid: str, quelle: QuelleTyp = QuelleTyp.WATCHLIST_AT) -> CyberMeldung:
    return CyberMeldung(
        titel="Test",
        beschreibung="Test-Beschreibung",
        url=f"https://example.com/{guid}",
        quelle=quelle,
        schweregrad=Schweregrad.HOCH,
        veroeffentlicht=datetime.now(UTC),
        guid=guid,
    )


class TestSchemaMigration:
    def test_meldung_state_tabelle_existiert(self, repo: CacheRepository) -> None:
        """`_init_schema` muss die ``meldung_state`` Tabelle anlegen."""

        with repo._db.connection() as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='meldung_state'"
            )
            assert cursor.fetchone() is not None

    def test_index_existiert(self, repo: CacheRepository) -> None:
        with repo._db.connection() as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='idx_state_quelle'"
            )
            assert cursor.fetchone() is not None


class TestMarkiereGelesen:
    def test_setzt_gelesen_am(self, repo: CacheRepository) -> None:
        repo.markiere_gelesen(["guid-1", "guid-2"])
        state = repo.lade_state_fuer(["guid-1", "guid-2", "guid-3"])
        gelesen1, _ = state["guid-1"]
        gelesen2, _ = state["guid-2"]
        gelesen3, _ = state["guid-3"]
        assert gelesen1 is not None
        assert gelesen2 is not None
        assert gelesen3 is None  # noch nie markiert

    def test_idempotent(self, repo: CacheRepository) -> None:
        repo.markiere_gelesen(["guid-x"])
        state1 = repo.lade_state_fuer(["guid-x"])
        repo.markiere_gelesen(["guid-x"])
        state2 = repo.lade_state_fuer(["guid-x"])
        assert state1["guid-x"][0] == state2["guid-x"][0]

    def test_leere_liste_ist_noop(self, repo: CacheRepository) -> None:
        repo.markiere_gelesen([])  # darf nicht knallen

    def test_filtert_leere_guids(self, repo: CacheRepository) -> None:
        repo.markiere_gelesen(["", None, "echt-1"])
        state = repo.lade_state_fuer(["echt-1"])
        assert state["echt-1"][0] is not None


class TestMarkiereUngelesen:
    def test_setzt_gelesen_am_zurueck(self, repo: CacheRepository) -> None:
        repo.markiere_gelesen(["guid-u"])
        repo.markiere_ungelesen(["guid-u"])
        state = repo.lade_state_fuer(["guid-u"])
        assert state["guid-u"][0] is None


class TestSchiebeAuf:
    def test_setzt_snooze_bis(self, repo: CacheRepository) -> None:
        bis = datetime.now(UTC) + timedelta(hours=12)
        repo.schiebe_auf("snooze-1", bis, QuelleTyp.WATCHLIST_AT)
        state = repo.lade_state_fuer(["snooze-1"])
        _, snooze = state["snooze-1"]
        assert snooze is not None
        diff = abs((snooze - bis).total_seconds())
        assert diff < 5  # erlaubt 5s Drift

    def test_ueberschreibt_alte_snooze(self, repo: CacheRepository) -> None:
        bis1 = datetime.now(UTC) + timedelta(hours=1)
        bis2 = datetime.now(UTC) + timedelta(days=2)
        repo.schiebe_auf("snooze-rep", bis1, QuelleTyp.WATCHLIST_AT)
        repo.schiebe_auf("snooze-rep", bis2, QuelleTyp.WATCHLIST_AT)
        _, snooze = repo.lade_state_fuer(["snooze-rep"])["snooze-rep"]
        diff = abs((snooze - bis2).total_seconds())
        assert diff < 5


class TestZaehleUngelesene:
    def test_zaehlt_meldungen_ohne_gelesen_am(
        self, repo: CacheRepository
    ) -> None:
        m1 = _meldung("z1", QuelleTyp.WATCHLIST_AT)
        m2 = _meldung("z2", QuelleTyp.MIMIKAMA)
        m3 = _meldung("z3", QuelleTyp.WATCHLIST_AT)
        repo.speichere_meldungen([m1, m2, m3])
        repo.markiere_gelesen(["z1"])
        # WATCHLIST: 2 Meldungen, 1 gelesen → 1 ungelesen
        n = repo.zaehle_ungelesene([QuelleTyp.WATCHLIST_AT])
        assert n == 1
        # WATCHLIST + MIMIKAMA: 3 Meldungen, 1 gelesen → 2 ungelesen
        n_alle = repo.zaehle_ungelesene(
            [QuelleTyp.WATCHLIST_AT, QuelleTyp.MIMIKAMA]
        )
        assert n_alle == 2

    def test_snoozed_werden_nicht_gezaehlt(
        self, repo: CacheRepository
    ) -> None:
        m = _meldung("snz", QuelleTyp.WATCHLIST_AT)
        repo.speichere_meldungen([m])
        bis = datetime.now(UTC) + timedelta(hours=12)
        repo.schiebe_auf("snz", bis, QuelleTyp.WATCHLIST_AT)
        n = repo.zaehle_ungelesene([QuelleTyp.WATCHLIST_AT])
        assert n == 0

    def test_snoozed_in_vergangenheit_zaehlen_wieder(
        self, repo: CacheRepository
    ) -> None:
        m = _meldung("snz-past", QuelleTyp.WATCHLIST_AT)
        repo.speichere_meldungen([m])
        bis = datetime.now(UTC) - timedelta(hours=1)
        repo.schiebe_auf("snz-past", bis, QuelleTyp.WATCHLIST_AT)
        n = repo.zaehle_ungelesene([QuelleTyp.WATCHLIST_AT])
        assert n == 1


class TestLadeStateFuer:
    def test_fehlende_guid_liefert_none_none(self, repo: CacheRepository) -> None:
        state = repo.lade_state_fuer(["nie-gespeichert"])
        assert state["nie-gespeichert"] == (None, None)

    def test_leere_eingabe_liefert_leeres_dict(
        self, repo: CacheRepository
    ) -> None:
        assert repo.lade_state_fuer([]) == {}
