"""
test_onboarding_marker — Tests fuer tools/patch_monitor/onboarding_marker.py.

Bug-Fix-Sprint C-3 (Option D). Deckt:

1. Roundtrip save → load
2. Fehlende Datei → None
3. JSON-Parse-Fehler → None (kein Crash)
4. Schema-Version > SCHEMA_VERSION (Forward-compat) → None
5. Unbekannte Decision → None
6. Invalides decided_at → None
7. Atomarer Write (kein temp-Leftover bei Erfolg)
8. wipe_marker idempotent
9. 0600-Permissions auf POSIX (Windows-skip)
"""

from __future__ import annotations

import json
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tools.patch_monitor.onboarding_marker import (
    MARKER_FILE_DEFAULT,
    SCHEMA_VERSION,
    OnboardingDecision,
    OnboardingMarker,
    load_marker,
    save_marker,
    wipe_marker,
)


@pytest.fixture
def marker_path(tmp_path: Path) -> Path:
    """Marker-Pfad in tmp_path — vermeidet Production-Datei in ~/.finlai."""
    return tmp_path / "winget_module_onboarding.json"


# ===========================================================================
# Akzeptanz 1 — Roundtrip save → load
# ===========================================================================


class TestRoundtrip:
    def test_save_then_load_installed(self, marker_path: Path) -> None:
        timestamp = datetime(2026, 5, 7, 14, 23, tzinfo=UTC)
        saved = save_marker(
            OnboardingDecision.INSTALLED,
            path=marker_path,
            now=timestamp,
        )
        loaded = load_marker(marker_path)
        assert loaded is not None
        assert loaded == saved
        assert loaded.decision is OnboardingDecision.INSTALLED
        assert loaded.decided_at == timestamp
        assert loaded.schema_version == SCHEMA_VERSION

    def test_save_then_load_skip_session(self, marker_path: Path) -> None:
        save_marker(OnboardingDecision.SKIP_SESSION, path=marker_path)
        loaded = load_marker(marker_path)
        assert loaded is not None
        assert loaded.decision is OnboardingDecision.SKIP_SESSION

    def test_save_then_load_never(self, marker_path: Path) -> None:
        save_marker(OnboardingDecision.NEVER, path=marker_path)
        loaded = load_marker(marker_path)
        assert loaded is not None
        assert loaded.decision is OnboardingDecision.NEVER


# ===========================================================================
# Akzeptanz 2-6 — Fehler-Pfade alle return None ohne Crash
# ===========================================================================


class TestLoadFehlerpfade:
    def test_keine_datei_returnt_none(self, marker_path: Path) -> None:
        assert not marker_path.exists()
        assert load_marker(marker_path) is None

    def test_json_parse_fehler_returnt_none(self, marker_path: Path) -> None:
        marker_path.write_text("not valid json {{{", encoding="utf-8")
        assert load_marker(marker_path) is None

    def test_array_statt_object_returnt_none(self, marker_path: Path) -> None:
        marker_path.write_text("[1, 2, 3]", encoding="utf-8")
        assert load_marker(marker_path) is None

    def test_fehlendes_feld_returnt_none(self, marker_path: Path) -> None:
        marker_path.write_text(
            json.dumps({"schema_version": 1, "decision": "installed"}),
            encoding="utf-8",
        )
        # decided_at fehlt
        assert load_marker(marker_path) is None

    def test_schema_version_zu_hoch_returnt_none(
        self, marker_path: Path
    ) -> None:
        marker_path.write_text(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION + 1,
                    "decided_at": "2026-05-07T14:23:00+00:00",
                    "decision": "installed",
                }
            ),
            encoding="utf-8",
        )
        # Forward-compat: hoehere Version → wie kein Marker
        assert load_marker(marker_path) is None

    def test_unbekannte_decision_returnt_none(
        self, marker_path: Path
    ) -> None:
        marker_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "decided_at": "2026-05-07T14:23:00+00:00",
                    "decision": "ja-bitte-installieren",
                }
            ),
            encoding="utf-8",
        )
        assert load_marker(marker_path) is None

    def test_invalides_decided_at_returnt_none(
        self, marker_path: Path
    ) -> None:
        marker_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "decided_at": "irgendwann-letzten-mai",
                    "decision": "installed",
                }
            ),
            encoding="utf-8",
        )
        assert load_marker(marker_path) is None


# ===========================================================================
# Akzeptanz 7 — atomarer Write
# ===========================================================================


class TestAtomarerWrite:
    def test_kein_temp_leftover_nach_erfolg(self, marker_path: Path) -> None:
        save_marker(OnboardingDecision.INSTALLED, path=marker_path)
        # Temp-Files heissen.onboarding-*.tmp im selben Verzeichnis.
        leftovers = list(marker_path.parent.glob(".onboarding-*.tmp"))
        assert leftovers == []

    def test_parent_directory_wird_angelegt(self, tmp_path: Path) -> None:
        nested = tmp_path / "deep" / "neu" / "marker.json"
        save_marker(OnboardingDecision.NEVER, path=nested)
        assert nested.is_file()


# ===========================================================================
# Akzeptanz 8 — wipe_marker idempotent
# ===========================================================================


class TestWipe:
    def test_wipe_loescht_existierende_datei(self, marker_path: Path) -> None:
        save_marker(OnboardingDecision.INSTALLED, path=marker_path)
        assert marker_path.is_file()
        wipe_marker(marker_path)
        assert not marker_path.exists()

    def test_wipe_idempotent_bei_fehlender_datei(
        self, marker_path: Path
    ) -> None:
        assert not marker_path.exists()
        wipe_marker(marker_path)  # darf nicht crashen
        assert not marker_path.exists()


# ===========================================================================
# Akzeptanz 9 — Permissions (POSIX-spezifisch)
# ===========================================================================


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows ignoriert POSIX-Permissions weitgehend",
)
class TestPermissions:
    def test_marker_hat_0600_permissions(self, marker_path: Path) -> None:
        save_marker(OnboardingDecision.INSTALLED, path=marker_path)
        mode = marker_path.stat().st_mode
        # Nur User darf lesen + schreiben
        assert mode & 0o777 == stat.S_IRUSR | stat.S_IWUSR


# ===========================================================================
# Default-Pfad
# ===========================================================================


class TestDefaultPath:
    def test_default_path_unterhalb_finlai(self) -> None:
        assert MARKER_FILE_DEFAULT.parent.name == ".finlai"
        assert MARKER_FILE_DEFAULT.name == "winget_module_onboarding.json"


# ===========================================================================
# OnboardingMarker — frozen dataclass
# ===========================================================================


class TestOnboardingMarkerDataclass:
    def test_marker_ist_frozen(self) -> None:
        from dataclasses import FrozenInstanceError

        marker = OnboardingMarker(
            schema_version=1,
            decided_at=datetime(2026, 5, 7, tzinfo=UTC),
            decision=OnboardingDecision.INSTALLED,
        )
        with pytest.raises(FrozenInstanceError):
            marker.decision = OnboardingDecision.NEVER  # type: ignore[misc]
