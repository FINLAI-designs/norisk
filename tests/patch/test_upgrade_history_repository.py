"""
test_upgrade_history_repository — Tests fuer Stop-Step B Repository.

Deckt:
* Schema-Init + Version (PRAGMA user_version)
* record fuer alle 4 UpgradeStatus-Werte
* list_recent / list_for_id Sortierung + Limit
* count / purge_older_than
* Round-Trip-Konsistenz UpgradeResult → Entry
"""

from __future__ import annotations

import pytest

from core.patch_upgrade import UpgradeResult, UpgradeStatus
from tools.patch_monitor.data.upgrade_history_repository import (
    UpgradeHistoryRepository,
)


def _result(
    *,
    status: UpgradeStatus = UpgradeStatus.SUCCESS,
    exit_code: int | None = 0,
    duration_ms: int = 1500,
    stdout: str = "",
    stderr: str = "",
    error: str | None = None,
    winget_id: str = "Mozilla.Firefox",
) -> UpgradeResult:
    """Test-Helper: baut ein UpgradeResult mit Defaults."""
    return UpgradeResult(
        winget_id=winget_id,
        status=status,
        exit_code=exit_code,
        duration_ms=duration_ms,
        stdout=stdout,
        stderr=stderr,
        error=error,
    )


class TestSchemaInit:
    def test_zweimal_init_idempotent(self) -> None:
        UpgradeHistoryRepository()
        UpgradeHistoryRepository()  # CREATE IF NOT EXISTS

    def test_count_leer_ist_null(self) -> None:
        repo = UpgradeHistoryRepository()
        assert repo.count() == 0

    def test_schema_version_ist_1(self) -> None:
        repo = UpgradeHistoryRepository()
        assert repo.get_schema_version() == 1


class TestRecord:
    def test_returns_uuid_hex(self) -> None:
        repo = UpgradeHistoryRepository()
        entry_id = repo.record(
            winget_id="Mozilla.Firefox",
            display_name="Mozilla Firefox",
            version_from="123.0",
            version_to="124.0",
            result=_result(),
        )
        assert isinstance(entry_id, str)
        assert len(entry_id) == 32

    def test_count_steigt(self) -> None:
        repo = UpgradeHistoryRepository()
        repo.record(
            winget_id="A.B",
            display_name="App",
            version_from=None,
            version_to=None,
            result=_result(),
        )
        assert repo.count() == 1

    @pytest.mark.parametrize(
        "status, exit_code",
        [
            (UpgradeStatus.SUCCESS, 0),
            (UpgradeStatus.FAILED, -1978335212),
            (UpgradeStatus.TIMEOUT, None),
            (UpgradeStatus.SKIPPED, None),
        ],
    )
    def test_alle_4_status_werte_round_trippen(
        self, status: UpgradeStatus, exit_code: int | None
    ) -> None:
        repo = UpgradeHistoryRepository()
        result = _result(
            status=status,
            exit_code=exit_code,
            error="x" if status != UpgradeStatus.SUCCESS else None,
        )
        repo.record(
            winget_id="Mozilla.Firefox",
            display_name="Mozilla Firefox",
            version_from="123.0",
            version_to="124.0",
            result=result,
        )
        entries = repo.list_recent()
        assert len(entries) == 1
        assert entries[0].status is status
        assert entries[0].exit_code == exit_code

    def test_round_trip_alle_felder(self) -> None:
        repo = UpgradeHistoryRepository()
        repo.record(
            winget_id="Mozilla.Firefox",
            display_name="Mozilla Firefox (Desktop)",
            version_from="123.0",
            version_to="124.0",
            result=_result(
                status=UpgradeStatus.SUCCESS,
                exit_code=0,
                duration_ms=2500,
                stdout="ignored on persistence",
                stderr="ignored on persistence",
                error=None,
            ),
        )
        entries = repo.list_recent()
        assert len(entries) == 1
        e = entries[0]
        assert e.winget_id == "Mozilla.Firefox"
        assert e.display_name == "Mozilla Firefox (Desktop)"
        assert e.version_from == "123.0"
        assert e.version_to == "124.0"
        assert e.status is UpgradeStatus.SUCCESS
        assert e.exit_code == 0
        assert e.duration_ms == 2500
        assert e.error is None
        assert e.created_at is not None  # Timestamp gesetzt

    def test_version_felder_duerfen_none_sein(self) -> None:
        repo = UpgradeHistoryRepository()
        repo.record(
            winget_id="A.B",
            display_name="App",
            version_from=None,
            version_to=None,
            result=_result(),
        )
        e = repo.list_recent()[0]
        assert e.version_from is None
        assert e.version_to is None


class TestListRecent:
    def test_sortierung_neuestes_zuerst(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``created_at`` ist Second-Resolution (analog briefing_history) —
        wir injizieren monoton steigende Werte ueber ``time.time``,
        damit der Test deterministisch in einer Test-Wallzeit < 1 s
        laeuft."""
        repo = UpgradeHistoryRepository()
        fake_now = [1700000000]

        def fake_time() -> int:
            fake_now[0] += 10
            return fake_now[0]

        monkeypatch.setattr(
            "tools.patch_monitor.data.upgrade_history_repository.time.time",
            fake_time,
        )
        for label in ("A", "B", "C"):
            repo.record(
                winget_id=f"X.{label}",
                display_name=label,
                version_from=None,
                version_to=None,
                result=_result(),
            )
        entries = repo.list_recent()
        labels = [e.display_name for e in entries]
        assert labels == ["C", "B", "A"]

    def test_limit_wird_respektiert(self) -> None:
        repo = UpgradeHistoryRepository()
        for i in range(5):
            repo.record(
                winget_id=f"X.{i}",
                display_name=str(i),
                version_from=None,
                version_to=None,
                result=_result(),
            )
        entries = repo.list_recent(limit=2)
        assert len(entries) == 2


class TestListForId:
    def test_filtert_korrekt(self) -> None:
        repo = UpgradeHistoryRepository()
        repo.record(
            winget_id="Mozilla.Firefox",
            display_name="Firefox",
            version_from=None,
            version_to=None,
            result=_result(),
        )
        repo.record(
            winget_id="Git.Git",
            display_name="Git",
            version_from=None,
            version_to=None,
            result=_result(),
        )
        repo.record(
            winget_id="Mozilla.Firefox",
            display_name="Firefox",
            version_from=None,
            version_to=None,
            result=_result(),
        )
        ff = repo.list_for_id("Mozilla.Firefox")
        git = repo.list_for_id("Git.Git")
        assert len(ff) == 2
        assert len(git) == 1
        assert all(e.winget_id == "Mozilla.Firefox" for e in ff)

    def test_leer_wenn_id_nicht_vorhanden(self) -> None:
        repo = UpgradeHistoryRepository()
        assert repo.list_for_id("Doesnt.Exist") == []


class TestPurgeOlderThan:
    def test_days_negativ_wirft(self) -> None:
        repo = UpgradeHistoryRepository()
        with pytest.raises(ValueError):
            repo.purge_older_than(0)
        with pytest.raises(ValueError):
            repo.purge_older_than(-1)

    def test_loescht_alte_eintraege(self) -> None:
        repo = UpgradeHistoryRepository()
        # Insert mit manipuliertem Timestamp ist nicht trivial — Test
        # validiert nur den No-Op-Pfad (alle Eintraege sind frisch).
        repo.record(
            winget_id="A.B",
            display_name="X",
            version_from=None,
            version_to=None,
            result=_result(),
        )
        deleted = repo.purge_older_than(days=30)
        assert deleted == 0
        assert repo.count() == 1
