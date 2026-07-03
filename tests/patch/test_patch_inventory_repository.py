"""
test_patch_inventory_repository — Tests fuer Stop-Step A.

Deckt:
* Schema-Init + PRAGMA user_version
* CRUD pro Tabelle (inventory_snapshot / available_versions / cve_matches
  / scan_history)
* Upsert-Semantik (INSERT-OR-UPDATE auf Conflict)
* Bulk-Methoden
* Diff-Logik fuer Monthly-Full (delete_inventory_not_in)
* Stale-CPE-Filter fuer Daily-Refresh (list_stale_cpes)
* scan_history-Lifecycle: record_scan_start / record_scan_end +
  duration_ms-Berechnung
* get_last_full_scan_at / get_last_daily_refresh_at fuer den Scheduler
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.database.encrypted_db import EncryptedDatabase
from core.patch_custom_source import CustomSource, Platform
from core.patch_strategy import DEFAULT_PATCH_STRATEGY, PatchStrategy
from tools.patch_monitor.data.patch_inventory_repository import (
    AffectedCveRow,
    AvailableVersionEntry,
    CveMatchEntry,
    InventoryEntry,
    PatchInventoryRepository,
)


def _inv(
    winget_id: str = "Mozilla.Firefox",
    name: str = "Mozilla Firefox",
    *,
    normalized_name: str = "mozilla firefox",
    vendor: str | None = "Mozilla",
    source: str = "winget",
    installed_version: str = "123.0",
    cpe_string: str | None = "cpe:2.3:a:mozilla:firefox:123.0:*:*:*:*:windows:*:*",
    channel: str = "latest",
    policy_source: str = "default",
    confidence_score: float = 1.0,
    last_seen_at: datetime | None = None,
    last_full_scan_at: datetime | None = None,
) -> InventoryEntry:
    now = datetime.now(tz=UTC)
    return InventoryEntry(
        winget_id=winget_id,
        name=name,
        normalized_name=normalized_name,
        vendor=vendor,
        source=source,
        installed_version=installed_version,
        cpe_string=cpe_string,
        channel=channel,
        policy_source=policy_source,
        confidence_score=confidence_score,
        last_seen_at=last_seen_at or now,
        last_full_scan_at=last_full_scan_at or now,
    )


def _av(
    winget_id: str = "Mozilla.Firefox",
    available_version: str | None = "124.0",
    is_update_available: bool = True,
    last_checked_at: datetime | None = None,
) -> AvailableVersionEntry:
    return AvailableVersionEntry(
        winget_id=winget_id,
        available_version=available_version,
        is_update_available=is_update_available,
        last_checked_at=last_checked_at or datetime.now(tz=UTC),
    )


def _cve(
    cpe_string: str = "cpe:2.3:a:mozilla:firefox:123.0:*:*:*:*:windows:*:*",
    cve_id: str = "CVE-2024-1234",
    cvss_score: float | None = 7.5,
    exploit_available: bool = False,
    eol: bool = False,
    fetched_at: datetime | None = None,
) -> CveMatchEntry:
    return CveMatchEntry(
        cpe_string=cpe_string,
        cve_id=cve_id,
        cvss_score=cvss_score,
        exploit_available=exploit_available,
        eol=eol,
        fetched_at=fetched_at or datetime.now(tz=UTC),
    )


# ---------------------------------------------------------------------------
# Schema-Init
# ---------------------------------------------------------------------------


class TestSchemaInit:
    def test_zweimal_init_idempotent(self) -> None:
        PatchInventoryRepository()
        PatchInventoryRepository()  # CREATE IF NOT EXISTS

    def test_schema_version_ist_3(self) -> None:
        # → V2 (patch_strategy) → V3 (custom_sources).
        repo = PatchInventoryRepository()
        assert repo.get_schema_version() == 3

    def test_count_inventory_leer_ist_null(self) -> None:
        repo = PatchInventoryRepository()
        assert repo.count_inventory() == 0


# ---------------------------------------------------------------------------
# inventory_snapshot
# ---------------------------------------------------------------------------


class TestInventory:
    def test_upsert_und_get_round_trip(self) -> None:
        repo = PatchInventoryRepository()
        entry = _inv()
        repo.upsert_inventory(entry)
        loaded = repo.get_inventory("Mozilla.Firefox")
        assert loaded is not None
        assert loaded.winget_id == entry.winget_id
        assert loaded.name == entry.name
        assert loaded.installed_version == entry.installed_version
        assert loaded.cpe_string == entry.cpe_string
        assert loaded.confidence_score == entry.confidence_score

    def test_upsert_aktualisiert_bei_konflikt(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(installed_version="123.0"))
        repo.upsert_inventory(_inv(installed_version="124.0"))
        loaded = repo.get_inventory("Mozilla.Firefox")
        assert loaded is not None
        assert loaded.installed_version == "124.0"
        # immer noch genau 1 Zeile
        assert repo.count_inventory() == 1

    def test_get_unbekannt_ist_none(self) -> None:
        repo = PatchInventoryRepository()
        assert repo.get_inventory("Does.Not.Exist") is None

    def test_list_inventory_leer(self) -> None:
        repo = PatchInventoryRepository()
        assert repo.list_inventory() == []

    def test_list_inventory_sortiert_nach_name(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(winget_id="B.B", name="Beta"))
        repo.upsert_inventory(_inv(winget_id="A.A", name="Alpha"))
        repo.upsert_inventory(_inv(winget_id="C.C", name="Charlie"))
        names = [e.name for e in repo.list_inventory()]
        assert names == ["Alpha", "Beta", "Charlie"]

    def test_upsert_inventory_batch_zaehlt_korrekt(self) -> None:
        repo = PatchInventoryRepository()
        count = repo.upsert_inventory_batch(
            [_inv(winget_id="A.A"), _inv(winget_id="B.B")]
        )
        assert count == 2
        assert repo.count_inventory() == 2

    def test_delete_inventory_not_in_loescht_fehlende(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(winget_id="A.A", name="A"))
        repo.upsert_inventory(_inv(winget_id="B.B", name="B"))
        repo.upsert_inventory(_inv(winget_id="C.C", name="C"))
        # Nur A.A behalten → B.B und C.C werden geloescht
        deleted = repo.delete_inventory_not_in(["A.A"])
        assert deleted == 2
        names = [e.name for e in repo.list_inventory()]
        assert names == ["A"]

    def test_delete_inventory_not_in_mit_leerer_liste_loescht_nichts(
        self,
    ) -> None:
        """Schutz: leere Menge wuerde sonst alles wegspuelen."""
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv())
        deleted = repo.delete_inventory_not_in([])
        assert deleted == 0
        assert repo.count_inventory() == 1

    def test_clear_inventory(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv())
        repo.clear_inventory()
        assert repo.count_inventory() == 0


# ---------------------------------------------------------------------------
# available_versions
# ---------------------------------------------------------------------------


class TestAvailableVersions:
    def test_upsert_und_get_round_trip(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv())  # FK
        repo.upsert_available_version(_av(available_version="124.0"))
        loaded = repo.get_available_version("Mozilla.Firefox")
        assert loaded is not None
        assert loaded.winget_id == "Mozilla.Firefox"
        assert loaded.available_version == "124.0"

    def test_upsert_aktualisiert_version_bei_refresh(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv())
        old_time = datetime.now(tz=UTC) - timedelta(hours=2)
        repo.upsert_available_version(
            _av(available_version="124.0", last_checked_at=old_time)
        )
        new_time = datetime.now(tz=UTC)
        repo.upsert_available_version(
            _av(available_version="125.0", last_checked_at=new_time)
        )
        loaded = repo.get_available_version("Mozilla.Firefox")
        assert loaded is not None
        assert loaded.available_version == "125.0"
        # last_checked_at hat Second-Resolution — Toleranz 1s
        assert abs((loaded.last_checked_at - new_time).total_seconds()) < 2

    def test_available_version_none_wird_persistiert(self) -> None:
        """Falls winget keine available_version meldet, persistieren
        wir trotzdem den Check-Timestamp."""
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv())
        repo.upsert_available_version(
            _av(available_version=None, is_update_available=False)
        )
        loaded = repo.get_available_version("Mozilla.Firefox")
        assert loaded is not None
        assert loaded.available_version is None
        assert loaded.is_update_available is False

    def test_is_update_available_round_trip(self) -> None:
        """-Fix-Pattern: is_update_available ist autoritativ."""
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv())
        # Nextcloud-Pattern: installiert > manifest, winget sagt False
        repo.upsert_available_version(
            _av(available_version="33.0.3", is_update_available=False)
        )
        loaded = repo.get_available_version("Mozilla.Firefox")
        assert loaded is not None
        assert loaded.is_update_available is False

        # Update via upsert: jetzt True
        repo.upsert_available_version(
            _av(available_version="33.0.4", is_update_available=True)
        )
        loaded = repo.get_available_version("Mozilla.Firefox")
        assert loaded is not None
        assert loaded.is_update_available is True
        assert loaded.available_version == "33.0.4"


# ---------------------------------------------------------------------------
# cve_matches
# ---------------------------------------------------------------------------


class TestCveMatches:
    def test_upsert_und_list_round_trip(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_cve_match(_cve(cve_id="CVE-2024-1", cvss_score=9.8))
        repo.upsert_cve_match(_cve(cve_id="CVE-2024-2", cvss_score=5.0))
        cves = repo.list_cve_matches_for_cpe(
            "cpe:2.3:a:mozilla:firefox:123.0:*:*:*:*:windows:*:*"
        )
        assert len(cves) == 2
        # Sortiert nach cvss_score DESC
        assert cves[0].cve_id == "CVE-2024-1"
        assert cves[0].cvss_score == 9.8

    def test_upsert_aktualisiert_score_bei_konflikt(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_cve_match(_cve(cve_id="CVE-X", cvss_score=5.0))
        repo.upsert_cve_match(_cve(cve_id="CVE-X", cvss_score=7.5))
        cves = repo.list_cve_matches_for_cpe(
            "cpe:2.3:a:mozilla:firefox:123.0:*:*:*:*:windows:*:*"
        )
        assert len(cves) == 1
        assert cves[0].cvss_score == 7.5

    def test_exploit_und_eol_als_bool_persistiert(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_cve_match(_cve(cve_id="CVE-X", exploit_available=True, eol=True))
        cves = repo.list_cve_matches_for_cpe(
            "cpe:2.3:a:mozilla:firefox:123.0:*:*:*:*:windows:*:*"
        )
        assert cves[0].exploit_available is True
        assert cves[0].eol is True

    def test_list_stale_cpes_filtert_nach_alter(self) -> None:
        repo = PatchInventoryRepository()
        # Frisches CPE
        repo.upsert_cve_match(
            _cve(
                cpe_string="cpe:fresh",
                fetched_at=datetime.now(tz=UTC),
            )
        )
        # Altes CPE (48h alt)
        repo.upsert_cve_match(
            _cve(
                cpe_string="cpe:stale",
                fetched_at=datetime.now(tz=UTC) - timedelta(hours=48),
            )
        )
        stale = repo.list_stale_cpes(older_than_hours=24)
        assert stale == ["cpe:stale"]

    def test_list_known_cpes(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_cve_match(_cve(cpe_string="cpe:a"))
        repo.upsert_cve_match(_cve(cpe_string="cpe:b"))
        repo.upsert_cve_match(_cve(cpe_string="cpe:a", cve_id="CVE-Y"))
        cpes = repo.list_known_cpes()
        assert cpes == ["cpe:a", "cpe:b"]


# ---------------------------------------------------------------------------
# Batch-CVE-Read + Affected-CVE-JOIN
# ---------------------------------------------------------------------------


class TestBatchCveMatches:
    def test_leere_eingabe_ohne_db_zugriff(self) -> None:
        repo = PatchInventoryRepository()
        assert repo.list_cve_matches_for_cpes([]) == []

    def test_ignoriert_leere_strings_und_duplikate(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_cve_match(_cve(cpe_string="cpe:a", cve_id="CVE-1"))
        result = repo.list_cve_matches_for_cpes(["cpe:a", "cpe:a", ""])
        assert [c.cve_id for c in result] == ["CVE-1"]

    def test_union_ueber_mehrere_cpes(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_cve_match(_cve(cpe_string="cpe:a", cve_id="CVE-A", cvss_score=5.0))
        repo.upsert_cve_match(_cve(cpe_string="cpe:b", cve_id="CVE-B", cvss_score=9.0))
        repo.upsert_cve_match(_cve(cpe_string="cpe:c", cve_id="CVE-C"))
        result = repo.list_cve_matches_for_cpes(["cpe:a", "cpe:b"])
        # cpe:c wurde nicht angefragt
        assert {c.cve_id for c in result} == {"CVE-A", "CVE-B"}

    def test_unbekannte_cpe_liefert_leer(self) -> None:
        repo = PatchInventoryRepository()
        assert repo.list_cve_matches_for_cpes(["cpe:nieda"]) == []


class TestAffectedCves:
    _CPE = "cpe:2.3:a:mozilla:firefox:123.0:*:*:*:*:windows:*:*"

    def test_leer_ohne_daten(self) -> None:
        repo = PatchInventoryRepository()
        assert repo.list_affected_cves() == []

    def test_join_liefert_betroffene_app(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(cpe_string=self._CPE))
        repo.upsert_available_version(_av())
        repo.upsert_cve_match(
            _cve(cpe_string=self._CPE, cve_id="CVE-2024-1", cvss_score=7.5)
        )
        rows = repo.list_affected_cves()
        assert len(rows) == 1
        row = rows[0]
        assert isinstance(row, AffectedCveRow)
        assert row.app_name == "Mozilla Firefox"
        assert row.cve_id == "CVE-2024-1"
        assert row.cvss_score == 7.5
        assert row.is_update_available is True
        assert row.available_version == "124.0"
        assert row.installed_version == "123.0"

    def test_app_ohne_cpe_wird_ausgeschlossen(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(winget_id="No.Cpe", cpe_string=None))
        # CVE existiert unter irgendeinem CPE, aber die App selbst hat keinen
        repo.upsert_cve_match(_cve(cpe_string=self._CPE))
        assert repo.list_affected_cves() == []

    def test_app_mit_cpe_aber_ohne_treffer_nicht_gelistet(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(cpe_string=self._CPE))
        # keine cve_matches fuer diesen CPE
        assert repo.list_affected_cves() == []

    def test_left_join_ohne_available_version(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(cpe_string=self._CPE))
        repo.upsert_cve_match(_cve(cpe_string=self._CPE))
        rows = repo.list_affected_cves()
        assert len(rows) == 1
        assert rows[0].is_update_available is False
        assert rows[0].available_version is None

    def test_sortierung_cvss_dann_exploit(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(cpe_string=self._CPE))
        repo.upsert_cve_match(_cve(cpe_string=self._CPE, cve_id="LOW", cvss_score=4.0))
        repo.upsert_cve_match(_cve(cpe_string=self._CPE, cve_id="HIGH", cvss_score=9.8))
        repo.upsert_cve_match(
            _cve(
                cpe_string=self._CPE,
                cve_id="MID-KEV",
                cvss_score=7.0,
                exploit_available=True,
            )
        )
        ids = [r.cve_id for r in repo.list_affected_cves()]
        assert ids == ["HIGH", "MID-KEV", "LOW"]

    def test_min_cvss_filtert_und_schliesst_null_aus(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(cpe_string=self._CPE))
        repo.upsert_cve_match(_cve(cpe_string=self._CPE, cve_id="HIGH", cvss_score=9.0))
        repo.upsert_cve_match(_cve(cpe_string=self._CPE, cve_id="LOW", cvss_score=3.0))
        repo.upsert_cve_match(
            _cve(cpe_string=self._CPE, cve_id="NULL", cvss_score=None)
        )
        # min_cvss=0 -> alle (inkl. ohne Score)
        assert len(repo.list_affected_cves(min_cvss=0.0)) == 3
        # min_cvss=7 -> nur HIGH; LOW + Score-lose Zeile fallen raus
        ids = [r.cve_id for r in repo.list_affected_cves(min_cvss=7.0)]
        assert ids == ["HIGH"]

    def test_limit_begrenzt(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(cpe_string=self._CPE))
        for i in range(5):
            repo.upsert_cve_match(
                _cve(cpe_string=self._CPE, cve_id=f"CVE-{i}", cvss_score=float(i))
            )
        assert len(repo.list_affected_cves(limit=2)) == 2


class TestCountAppsWithoutCpe:
    def test_zaehlt_nur_null_cpe(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(winget_id="A", cpe_string="cpe:x"))
        repo.upsert_inventory(_inv(winget_id="B", cpe_string=None))
        repo.upsert_inventory(_inv(winget_id="C", cpe_string=None))
        assert repo.count_apps_without_cpe() == 2

    def test_leer_ist_null(self) -> None:
        repo = PatchInventoryRepository()
        assert repo.count_apps_without_cpe() == 0


# ---------------------------------------------------------------------------
# scan_history
# ---------------------------------------------------------------------------


class TestScanHistory:
    def test_record_scan_start_und_end_round_trip(self) -> None:
        repo = PatchInventoryRepository()
        scan_id = repo.record_scan_start("initial")
        assert len(scan_id) == 32  # uuid4 hex

        repo.record_scan_end(
            scan_id,
            items_total=311,
            items_with_updates=11,
            items_with_cves=23,
        )
        history = repo.list_scan_history()
        assert len(history) == 1
        e = history[0]
        assert e.scan_type == "initial"
        assert e.items_total == 311
        assert e.items_with_updates == 11
        assert e.items_with_cves == 23
        assert e.duration_ms is not None
        assert e.duration_ms >= 0
        assert e.error is None
        assert e.finished_at is not None

    def test_record_scan_end_mit_error(self) -> None:
        repo = PatchInventoryRepository()
        scan_id = repo.record_scan_start("daily_refresh")
        repo.record_scan_end(scan_id, error="winget timeout")
        e = repo.list_scan_history()[0]
        assert e.error == "winget timeout"
        assert e.items_total is None

    def test_record_scan_end_mit_unbekannter_id_silent(self) -> None:
        repo = PatchInventoryRepository()
        # No-op — wir wollen keinen Crash bei Race-Conditions
        repo.record_scan_end("does-not-exist", items_total=42)
        assert repo.list_scan_history() == []

    def test_list_scan_history_sortiert_neuestes_zuerst(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Second-Resolution-Timestamps koennen kollidieren — wir
        monkeypatchen time.time fuer Determinismus."""
        repo = PatchInventoryRepository()
        fake_now = [1700000000]

        def fake_time() -> int:
            fake_now[0] += 10
            return fake_now[0]

        monkeypatch.setattr(
            "tools.patch_monitor.data.patch_inventory_repository.time.time",
            fake_time,
        )
        a = repo.record_scan_start("initial")
        b = repo.record_scan_start("daily_refresh")
        c = repo.record_scan_start("daily_refresh")
        history = repo.list_scan_history()
        ids = [e.id for e in history]
        assert ids == [c, b, a]

    def test_get_last_full_scan_at_filtert_nach_typ(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = PatchInventoryRepository()
        fake_now = [1700000000]

        def fake_time() -> int:
            fake_now[0] += 10
            return fake_now[0]

        monkeypatch.setattr(
            "tools.patch_monitor.data.patch_inventory_repository.time.time",
            fake_time,
        )

        # initial-Scan
        init_id = repo.record_scan_start("initial")
        repo.record_scan_end(init_id, items_total=311)
        # Spaeterer Daily-Refresh
        daily_id = repo.record_scan_start("daily_refresh")
        repo.record_scan_end(daily_id, items_total=311)
        # Spaeterer Monthly-Full
        monthly_id = repo.record_scan_start("monthly_full")
        repo.record_scan_end(monthly_id, items_total=312)

        last_full = repo.get_last_full_scan_at()
        last_daily = repo.get_last_daily_refresh_at()
        assert last_full is not None
        assert last_daily is not None
        # last_full ist der monthly_full (juenger als initial)
        assert last_full > last_daily

    def test_get_last_full_scan_at_ignoriert_error_scans(self) -> None:
        repo = PatchInventoryRepository()
        scan_id = repo.record_scan_start("initial")
        repo.record_scan_end(scan_id, error="boom")
        assert repo.get_last_full_scan_at() is None

    def test_get_last_full_scan_at_ohne_scans_ist_none(self) -> None:
        repo = PatchInventoryRepository()
        assert repo.get_last_full_scan_at() is None
        assert repo.get_last_daily_refresh_at() is None


# ---------------------------------------------------------------------------
# patch_strategy
# ---------------------------------------------------------------------------


class TestPatchStrategyColumn:
    def test_neue_zeile_hat_default_strategie(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv())
        loaded = repo.get_inventory("Mozilla.Firefox")
        assert loaded is not None
        assert loaded.patch_strategy is PatchStrategy.STABLE
        assert loaded.patch_strategy is DEFAULT_PATCH_STRATEGY

    def test_update_strategy_setzt_wert(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv())
        assert repo.update_strategy("Mozilla.Firefox", PatchStrategy.LATEST) is True
        loaded = repo.get_inventory("Mozilla.Firefox")
        assert loaded is not None
        assert loaded.patch_strategy is PatchStrategy.LATEST

    def test_update_strategy_unbekannt_ist_false(self) -> None:
        repo = PatchInventoryRepository()
        assert repo.update_strategy("Does.Not.Exist", PatchStrategy.NONE) is False

    def test_upsert_ueberschreibt_strategie_nicht(self) -> None:
        # Kerninvariante: Vollscan-Upsert darf die User-Wahl NICHT
        # ueberschreiben — nur installed_version u.ae. werden aktualisiert.
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(installed_version="123.0"))
        repo.update_strategy("Mozilla.Firefox", PatchStrategy.NONE)
        repo.upsert_inventory(_inv(installed_version="124.0"))  # Vollscan-Sim
        loaded = repo.get_inventory("Mozilla.Firefox")
        assert loaded is not None
        assert loaded.installed_version == "124.0"
        assert loaded.patch_strategy is PatchStrategy.NONE

    def test_list_inventory_traegt_strategie(self) -> None:
        repo = PatchInventoryRepository()
        repo.upsert_inventory(_inv(winget_id="A.A", name="Alpha"))
        repo.upsert_inventory(_inv(winget_id="B.B", name="Beta"))
        repo.update_strategy("B.B", PatchStrategy.LATEST)
        by_id = {e.winget_id: e.patch_strategy for e in repo.list_inventory()}
        assert by_id["A.A"] is PatchStrategy.STABLE
        assert by_id["B.B"] is PatchStrategy.LATEST


# ---------------------------------------------------------------------------
# Schema-V2-Migration
# ---------------------------------------------------------------------------


class TestSchemaV2Migration:
    """V1 → V2 ergaenzt ``inventory_snapshot.patch_strategy`` additiv."""

    @staticmethod
    def _create_v1_db_with_row() -> None:
        """Legt eine V1-DB an: altes Schema (ohne patch_strategy),
        ``PRAGMA user_version = 1``, eine Inventar-Zeile."""
        db = EncryptedDatabase("patch_inventory")
        now = int(datetime.now(tz=UTC).timestamp())
        with db.connection() as conn:
            conn.execute(
                """
                CREATE TABLE inventory_snapshot (
                    winget_id            TEXT PRIMARY KEY,
                    name                 TEXT NOT NULL,
                    normalized_name      TEXT NOT NULL,
                    vendor               TEXT,
                    source               TEXT NOT NULL,
                    installed_version    TEXT NOT NULL,
                    cpe_string           TEXT,
                    channel              TEXT NOT NULL,
                    policy_source        TEXT NOT NULL,
                    confidence_score     REAL NOT NULL,
                    last_seen_at         INTEGER NOT NULL,
                    last_full_scan_at    INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                INSERT INTO inventory_snapshot(
                    winget_id, name, normalized_name, vendor, source,
                    installed_version, cpe_string, channel, policy_source,
                    confidence_score, last_seen_at, last_full_scan_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "Mozilla.Firefox",
                    "Mozilla Firefox",
                    "mozilla firefox",
                    "Mozilla",
                    "winget",
                    "123.0",
                    None,
                    "latest",
                    "default",
                    1.0,
                    now,
                    now,
                ),
            )
            conn.execute("PRAGMA user_version = 1")

    def test_v1_wird_migriert_und_daten_bleiben(self) -> None:
        self._create_v1_db_with_row()
        repo = PatchInventoryRepository()  # __init__ triggert Migration
        # V1 wird bis zur aktuellen Version (V3) gezogen.
        assert repo.get_schema_version() == 3
        loaded = repo.get_inventory("Mozilla.Firefox")
        assert loaded is not None
        assert loaded.name == "Mozilla Firefox"
        assert loaded.installed_version == "123.0"
        # V1→V2: Bestandszeile bekommt die Default-Strategie
        assert loaded.patch_strategy is PatchStrategy.STABLE

    def test_migration_ist_idempotent(self) -> None:
        self._create_v1_db_with_row()
        PatchInventoryRepository()  # V1 → V3
        repo = PatchInventoryRepository()  # erneut: bleibt V3, kein Fehler
        assert repo.get_schema_version() == 3
        assert repo.count_inventory() == 1


# ---------------------------------------------------------------------------
# custom_sources
# ---------------------------------------------------------------------------


class TestCustomSources:
    def test_add_liefert_entity_mit_id_und_created_at(self) -> None:
        repo = PatchInventoryRepository()
        src = repo.add_custom_source(
            name="Vendor-Tool",
            vendor_url="https://example.com/download",
            version_regex=r"v(\d+\.\d+)",
            installed_version="1.0",
        )
        assert src.id  # uuid4 hex vergeben
        assert src.created_at is not None
        assert src.platform is Platform.WINDOWS  # Default
        assert src.available_version is None
        assert src.last_checked_at is None

    def test_add_und_get_round_trip(self) -> None:
        repo = PatchInventoryRepository()
        src = repo.add_custom_source(
            name="Vendor-Tool",
            vendor_url="https://example.com",
            version_regex=r"(\d+\.\d+)",
            platform=Platform.LINUX,
            installed_version="2.3",
            notes="Privat-Server",
        )
        loaded = repo.get_custom_source(src.id)
        assert loaded is not None
        assert loaded.name == "Vendor-Tool"
        assert loaded.vendor_url == "https://example.com"
        assert loaded.version_regex == r"(\d+\.\d+)"
        assert loaded.platform is Platform.LINUX
        assert loaded.installed_version == "2.3"
        assert loaded.notes == "Privat-Server"

    def test_get_unbekannt_ist_none(self) -> None:
        repo = PatchInventoryRepository()
        assert repo.get_custom_source("does-not-exist") is None

    def test_list_sortiert_nach_name(self) -> None:
        repo = PatchInventoryRepository()
        repo.add_custom_source(name="Beta", vendor_url="u", version_regex="r")
        repo.add_custom_source(name="Alpha", vendor_url="u", version_regex="r")
        names = [s.name for s in repo.list_custom_sources()]
        assert names == ["Alpha", "Beta"]

    def test_update_schreibt_check_ergebnis(self) -> None:
        import dataclasses

        repo = PatchInventoryRepository()
        src = repo.add_custom_source(
            name="Vendor-Tool",
            vendor_url="u",
            version_regex="r",
            installed_version="1.0",
        )
        checked = dataclasses.replace(
            src,
            available_version="1.1",
            last_checked_at=datetime.now(tz=UTC),
            last_error=None,
        )
        assert repo.update_custom_source(checked) is True
        loaded = repo.get_custom_source(src.id)
        assert loaded is not None
        assert loaded.available_version == "1.1"
        assert loaded.last_checked_at is not None

    def test_update_unbekannt_ist_false(self) -> None:
        repo = PatchInventoryRepository()
        ghost = CustomSource(
            id="ghost",
            name="x",
            vendor_url="u",
            version_regex="r",
            platform=Platform.WINDOWS,
            installed_version=None,
            available_version=None,
            last_checked_at=None,
            last_error=None,
            notes=None,
            created_at=datetime.now(tz=UTC),
        )
        assert repo.update_custom_source(ghost) is False

    def test_delete(self) -> None:
        repo = PatchInventoryRepository()
        src = repo.add_custom_source(
            name="Vendor-Tool", vendor_url="u", version_regex="r"
        )
        assert repo.delete_custom_source(src.id) is True
        assert repo.get_custom_source(src.id) is None
        assert repo.delete_custom_source(src.id) is False  # schon weg


class TestSchemaV3Migration:
    """V2 → V3 legt die ``custom_sources``-Tabelle an (neue Tabelle, vom
    _SCHEMA-Skript abgedeckt — kein ALTER noetig)."""

    @staticmethod
    def _create_v2_db() -> None:
        """Simuliert eine-DB: inventory_snapshot MIT patch_strategy,
        KEINE custom_sources-Tabelle, ``PRAGMA user_version = 2``."""
        db = EncryptedDatabase("patch_inventory")
        now = int(datetime.now(tz=UTC).timestamp())
        with db.connection() as conn:
            conn.execute(
                """
                CREATE TABLE inventory_snapshot (
                    winget_id            TEXT PRIMARY KEY,
                    name                 TEXT NOT NULL,
                    normalized_name      TEXT NOT NULL,
                    vendor               TEXT,
                    source               TEXT NOT NULL,
                    installed_version    TEXT NOT NULL,
                    cpe_string           TEXT,
                    channel              TEXT NOT NULL,
                    policy_source        TEXT NOT NULL,
                    confidence_score     REAL NOT NULL,
                    last_seen_at         INTEGER NOT NULL,
                    last_full_scan_at    INTEGER NOT NULL,
                    patch_strategy       TEXT NOT NULL DEFAULT 'stable'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO inventory_snapshot(
                    winget_id, name, normalized_name, vendor, source,
                    installed_version, cpe_string, channel, policy_source,
                    confidence_score, last_seen_at, last_full_scan_at,
                    patch_strategy
                ) VALUES ('A.A','A','a','v','winget','1.0',NULL,'latest',
                    'default',1.0,?,?,'latest')
                """,
                (now, now),
            )
            conn.execute("PRAGMA user_version = 2")

    def test_v2_wird_auf_v3_migriert_custom_sources_existiert(self) -> None:
        self._create_v2_db()
        repo = PatchInventoryRepository()  # __init__ legt custom_sources an
        assert repo.get_schema_version() == 3
        # Tabelle nutzbar + Bestandsdaten + persistierte Strategie erhalten
        assert repo.list_custom_sources() == []
        loaded = repo.get_inventory("A.A")
        assert loaded is not None
        assert loaded.patch_strategy is PatchStrategy.LATEST
        src = repo.add_custom_source(name="X", vendor_url="u", version_regex="r")
        assert repo.get_custom_source(src.id) is not None
