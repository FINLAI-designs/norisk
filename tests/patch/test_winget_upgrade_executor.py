"""
test_winget_upgrade_executor — pytest-Tests fuer core/patch_upgrade.py.

PM-2.x / Stop-Step A. Deckt:

*:class:`UpgradeStatus`-Enum-Werte
*:class:`UpgradeResult`-Datenmodell (frozen, success-Property)
*:class:`WingetUpgradeExecutor` — SUCCESS / FAILED / TIMEOUT / Validierung
* Command-Build: keine Shell, alle Args einzeln, --silent-Flag
* Output-Truncation auf 8 KiB
* Non-Windows-Plattform-Guard
* ``winget``-CLI nicht vorhanden → ExternalToolError
* Privacy: Fehlermeldung echo't keine winget_id-Inhalte

Strategie:
- Subprocess-Surrogat per Konstruktor-Parameter ``subprocess_run=`` injiziert
  (kein Modul-Monkeypatch noetig). Tests bauen pro Fall einen Mock mit
  vorbereitetem CompletedProcess oder einer raise-Funktion.
- Windows-Plattform-Guard via ``monkeypatch.setattr(sys, "platform",...)``.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.exceptions import ExternalToolError, ValidationError
from core.patch_strategy import PatchStrategy
from core.patch_upgrade import (
    _OUTPUT_SOFT_LIMIT_BYTES,
    _OUTPUT_TRUNCATION_MARKER,
    DEFAULT_UPGRADE_TIMEOUT_S,
    UpgradeResult,
    UpgradeStatus,
    WingetUpgradeExecutor,
    _format_exit_code_error,
    _truncate_output,
    _validate_winget_id,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _force_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Setzt sys.platform auf 'win32' fuer Plattform-Guard-Tests."""
    monkeypatch.setattr(sys, "platform", "win32")


def _make_completed(
    returncode: int, stdout: str = "", stderr: str = ""
) -> SimpleNamespace:
    """Baut einen CompletedProcess-aequivalenten Namespace."""
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# UpgradeStatus-Enum
# ---------------------------------------------------------------------------


class TestUpgradeStatus:
    def test_alle_vier_werte_vorhanden(self) -> None:
        assert UpgradeStatus.SUCCESS == "success"
        assert UpgradeStatus.FAILED == "failed"
        assert UpgradeStatus.TIMEOUT == "timeout"
        assert UpgradeStatus.SKIPPED == "skipped"

    def test_status_ist_str_enum(self) -> None:
        # StrEnum-Kontrakt: Wert ist instanz von str
        assert isinstance(UpgradeStatus.SUCCESS, str)
        assert UpgradeStatus.SUCCESS.value == "success"


# ---------------------------------------------------------------------------
# UpgradeResult-Datenmodell
# ---------------------------------------------------------------------------


class TestUpgradeResult:
    def test_ist_frozen(self) -> None:
        result = UpgradeResult(
            winget_id="Mozilla.Firefox",
            status=UpgradeStatus.SUCCESS,
            exit_code=0,
            duration_ms=1500,
            stdout="",
            stderr="",
        )
        with pytest.raises(FrozenInstanceError):
            result.winget_id = "Other.Id"  # type: ignore[misc]

    def test_success_property_bei_success_status(self) -> None:
        result = UpgradeResult(
            winget_id="X",
            status=UpgradeStatus.SUCCESS,
            exit_code=0,
            duration_ms=0,
            stdout="",
            stderr="",
        )
        assert result.success is True

    @pytest.mark.parametrize(
        "status",
        [
            UpgradeStatus.FAILED,
            UpgradeStatus.TIMEOUT,
            UpgradeStatus.SKIPPED,
        ],
    )
    def test_success_property_bei_anderen_status(self, status: UpgradeStatus) -> None:
        result = UpgradeResult(
            winget_id="X",
            status=status,
            exit_code=1,
            duration_ms=0,
            stdout="",
            stderr="",
        )
        assert result.success is False

    def test_error_field_default_none(self) -> None:
        result = UpgradeResult(
            winget_id="X",
            status=UpgradeStatus.SUCCESS,
            exit_code=0,
            duration_ms=0,
            stdout="",
            stderr="",
        )
        assert result.error is None


# ---------------------------------------------------------------------------
# winget_id-Validierung
# ---------------------------------------------------------------------------


class TestValidateWingetId:
    @pytest.mark.parametrize(
        "valid_id",
        [
            "Mozilla.Firefox",
            "Microsoft.VCRedist.2013.x86",
            "Microsoft.Edge.WebView2.Runtime",
            "7zip.7zip",
            "Git.Git",
            "Python.Python.3.12",
            "Docker.DockerDesktop",
            "OBSProject.OBSStudio",
            "JetBrains.PyCharm.Community",
            "abc_def-ghi.jkl+mno",
        ],
    )
    def test_gueltige_ids_passen(self, valid_id: str) -> None:
        _validate_winget_id(valid_id)  # darf nicht werfen

    def test_leerer_string_wirft(self) -> None:
        with pytest.raises(ValidationError):
            _validate_winget_id("")

    @pytest.mark.parametrize(
        "invalid_id",
        [
            "Mozilla Firefox",  # Space
            "Mozilla;rm -rf /",  # Shell-Injection-Versuch
            "Mozilla.Firefox && curl x",  # Shell-Verkettung
            "Mozilla.Firefox\nrm",  # Newline
            "Mozilla.Firefox`cmd`",  # Backticks
            "Mozilla.Firefox$VAR",  # Variable-Expansion
            "../etc/passwd",  # Path-Traversal-Charset
            "Mozilla\\Firefox",  # Backslash (ARP-Pfade)
            "Mozilla/Firefox",  # Forward-Slash
            "Mozilla.Firefox|cat",  # Pipe
            "Mozilla.Firefox>out",  # Redirect
            "Mozilla.Firefox*",  # Glob
            'Mozilla.Firefox"x',  # Quotes
            "Mozilla.Firefox'x",  # Single Quotes
        ],
    )
    def test_ungueltige_ids_werfen(self, invalid_id: str) -> None:
        with pytest.raises(ValidationError):
            _validate_winget_id(invalid_id)

    def test_fehlermeldung_echo_t_keine_user_eingabe(self) -> None:
        """Privacy: Injection-Versuche duerfen nicht im Error-Text auftauchen."""
        injection = "Mozilla.Firefox;rm"
        with pytest.raises(ValidationError) as exc_info:
            _validate_winget_id(injection)
        assert injection not in str(exc_info.value)


class TestSyntheticIdGate:
    @pytest.mark.parametrize("synthetic_id", ["regid:7-zip", "msix:Microsoft.Photos"])
    def test_upgrade_wirft_und_ruft_subprocess_nicht(self, synthetic_id: str) -> None:
        """Defense-in-depth: ``upgrade`` wirft bei synthetischer Id, bevor
        ueberhaupt ein Subprocess gestartet wird (nie an winget)."""
        mock_run = MagicMock()
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)
        with pytest.raises(ValidationError, match="synthetische"):
            exe.upgrade(synthetic_id)
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Output-Truncation
# ---------------------------------------------------------------------------


class TestTruncateOutput:
    def test_leer_bleibt_leer(self) -> None:
        assert _truncate_output("") == ""

    def test_kurzer_input_unveraendert(self) -> None:
        text = "kurze Zeile\nzweite Zeile"
        assert _truncate_output(text) == text

    def test_input_unter_limit_unveraendert(self) -> None:
        text = "x" * (_OUTPUT_SOFT_LIMIT_BYTES - 100)
        assert _truncate_output(text) == text

    def test_input_ueber_limit_wird_gekuerzt(self) -> None:
        text = "x" * (_OUTPUT_SOFT_LIMIT_BYTES * 2)
        result = _truncate_output(text)
        assert result.endswith(_OUTPUT_TRUNCATION_MARKER)
        # Kern-Inhalt: bis zum Limit Bytes (vor dem Marker)
        body = result[: -len(_OUTPUT_TRUNCATION_MARKER)]
        assert len(body.encode("utf-8")) == _OUTPUT_SOFT_LIMIT_BYTES


# ---------------------------------------------------------------------------
# Executor — SUCCESS-Pfad
# ---------------------------------------------------------------------------


class TestWingetUpgradeExecutorSuccess:
    def test_returncode_0_gibt_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(
            return_value=_make_completed(
                0,
                stdout="Installed Mozilla.Firefox 123.0",
            )
        )
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        result = exe.upgrade("Mozilla.Firefox")

        assert result.status is UpgradeStatus.SUCCESS
        assert result.exit_code == 0
        assert result.winget_id == "Mozilla.Firefox"
        assert "Installed Mozilla.Firefox" in result.stdout
        assert result.error is None
        assert result.success is True

    def test_duration_ms_wird_befuellt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        result = exe.upgrade("Mozilla.Firefox")

        assert result.duration_ms >= 0  # Wandzeit ist nicht-negativ


# ---------------------------------------------------------------------------
# Executor — FAILED-Pfad
# ---------------------------------------------------------------------------


class TestWingetUpgradeExecutorFailed:
    def test_returncode_nonzero_gibt_failed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(
            return_value=_make_completed(
                -1978335212,
                stdout="",
                stderr="Package not found",
            )
        )
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        result = exe.upgrade("Mozilla.Firefox")

        assert result.status is UpgradeStatus.FAILED
        assert result.exit_code == -1978335212
        assert "Package not found" in result.stderr
        assert result.error is not None
        assert "-1978335212" in result.error
        assert result.success is False

    def test_no_applicable_installer_hat_user_lesbaren_hinweis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression 2026-05-12: VCRedist.2013.x64 nach Docker-Install
        bekam Exit 2316632107 (0x8A15006B). Vorher zeigte der Log nur
        die rohe Zahl, jetzt soll der Hinweis "bereits aktuell" mit dabei sein."""
        _force_windows(monkeypatch)
        mock_run = MagicMock(
            return_value=_make_completed(0x8A15006B)
        )
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        result = exe.upgrade("Microsoft.VCRedist.2013.x64")

        assert result.status is UpgradeStatus.FAILED
        assert result.error is not None
        assert "bereits aktuell" in result.error.lower()

    def test_unbekannter_exit_code_gibt_nackten_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codes ausserhalb des Mappings fallen auf rohen Code zurueck.
        Vermeidet erfundene Erklaerungen — User kann googeln."""
        _force_windows(monkeypatch)
        # 2316632112 = 0x8A150070 (Patrick-Smoke VCRedist 2010 x86) — nicht im Mapping
        mock_run = MagicMock(return_value=_make_completed(0x8A150070))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        result = exe.upgrade("Microsoft.VCRedist.2010.x86")

        assert result.status is UpgradeStatus.FAILED
        assert result.error is not None
        assert str(0x8A150070) in result.error
        # Kein erfundener Hinweis im Text
        assert "—" not in result.error  # Em-Dash trennt Code von Hint


# ---------------------------------------------------------------------------
# Format-Exit-Code-Error (Modul-Funktion)
# ---------------------------------------------------------------------------


class TestFormatExitCodeError:
    @pytest.mark.parametrize(
        "code, expected_keyword",
        [
            (0x8A15006B, "bereits aktuell"),
            (0x8A150043, "kein Update"),
            (0x8A150052, "laeuft"),
            (0x8A150011, "kennt das Paket nicht"),
            (3010, "Neustart"),
            (1603, "Admin-Rechte"),
        ],
    )
    def test_bekannte_codes_haben_hint(
        self, code: int, expected_keyword: str
    ) -> None:
        text = _format_exit_code_error(code)
        assert str(code) in text
        assert expected_keyword.lower() in text.lower()

    def test_unbekannter_code_fallback(self) -> None:
        text = _format_exit_code_error(0x12345678)
        assert "305419896" in text  # decimal of 0x12345678
        # Kein em-Dash → kein Hint
        assert "—" not in text


# ---------------------------------------------------------------------------
# Executor — TIMEOUT-Pfad
# ---------------------------------------------------------------------------


class TestWingetUpgradeExecutorTimeout:
    def test_timeoutexpired_gibt_timeout_status(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(
            side_effect=subprocess.TimeoutExpired(
                cmd=["winget"],
                timeout=300,
                output="partial out",
                stderr="partial err",
            )
        )
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        result = exe.upgrade("Mozilla.Firefox")

        assert result.status is UpgradeStatus.TIMEOUT
        assert result.exit_code is None
        assert "Timeout" in (result.error or "")
        assert result.success is False

    def test_timeout_uebernimmt_partial_output(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(
            side_effect=subprocess.TimeoutExpired(
                cmd=["winget"],
                timeout=300,
                output="some stdout",
                stderr="some stderr",
            )
        )
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        result = exe.upgrade("Mozilla.Firefox")

        assert "some stdout" in result.stdout
        assert "some stderr" in result.stderr

    def test_timeout_param_ueberschreibt_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(
            subprocess_run=mock_run,
            timeout_s=DEFAULT_UPGRADE_TIMEOUT_S,
        )

        exe.upgrade("Mozilla.Firefox", timeout_s=60)

        # Pruefen dass das `timeout=60` ans subprocess_run weitergereicht wurde
        _, kwargs = mock_run.call_args
        assert kwargs["timeout"] == 60


# ---------------------------------------------------------------------------
# Executor — Plattform- und CLI-Guard
# ---------------------------------------------------------------------------


class TestWingetUpgradeExecutorPlatform:
    def test_non_windows_wirft_externaltoolerror(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        mock_run = MagicMock()
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        with pytest.raises(ExternalToolError):
            exe.upgrade("Mozilla.Firefox")

        # Subprocess darf gar nicht erst aufgerufen werden
        mock_run.assert_not_called()

    def test_filenotfounderror_wirft_externaltoolerror(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(side_effect=FileNotFoundError("winget not found"))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        with pytest.raises(ExternalToolError):
            exe.upgrade("Mozilla.Firefox")


# ---------------------------------------------------------------------------
# Executor — Command-Build
# ---------------------------------------------------------------------------


class TestWingetUpgradeExecutorCommandBuild:
    def test_command_ist_liste_kein_string(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sicherheits-Kontrakt: kein shell=True, kein f-string."""
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        exe.upgrade("Mozilla.Firefox")

        args, kwargs = mock_run.call_args
        cmd = args[0]
        assert isinstance(cmd, list)
        # Kein shell=True (oder default False)
        assert kwargs.get("shell", False) is False

    def test_command_enthaelt_pflicht_flags(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        exe.upgrade("Mozilla.Firefox")

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "winget"
        assert cmd[1] == "upgrade"
        assert "--id" in cmd
        assert "Mozilla.Firefox" in cmd
        assert "--exact" in cmd
        assert "--accept-package-agreements" in cmd
        assert "--accept-source-agreements" in cmd

    def test_silent_true_fuegt_silent_flag_hinzu(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        exe.upgrade("Mozilla.Firefox", silent=True)

        cmd = mock_run.call_args[0][0]
        assert "--silent" in cmd

    def test_silent_false_laesst_silent_flag_weg(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        exe.upgrade("Mozilla.Firefox", silent=False)

        cmd = mock_run.call_args[0][0]
        assert "--silent" not in cmd

    def test_invalid_id_ruft_subprocess_nie_auf(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Validierung passiert VOR Subprocess."""
        _force_windows(monkeypatch)
        mock_run = MagicMock()
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        with pytest.raises(ValidationError):
            exe.upgrade("Mozilla.Firefox;rm -rf /")

        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Executor — Patch-Strategie
# ---------------------------------------------------------------------------


class TestWingetUpgradeStrategy:
    def test_latest_fuegt_include_flags_hinzu(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        exe.upgrade("Mozilla.Firefox", strategy=PatchStrategy.LATEST)

        cmd = mock_run.call_args[0][0]
        assert "--include-unknown" in cmd
        assert "--include-pinned" in cmd

    def test_stable_ohne_include_flags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        exe.upgrade("Mozilla.Firefox", strategy=PatchStrategy.STABLE)

        cmd = mock_run.call_args[0][0]
        assert "--include-unknown" not in cmd
        assert "--include-pinned" not in cmd

    def test_default_strategy_ist_stable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        exe.upgrade("Mozilla.Firefox")  # ohne strategy-Arg

        cmd = mock_run.call_args[0][0]
        assert "--include-unknown" not in cmd

    def test_none_strategy_raised_und_kein_subprocess(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """NONE darf den Executor nie erreichen — fail-closed-Guard."""
        _force_windows(monkeypatch)
        mock_run = MagicMock()
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        with pytest.raises(ValidationError):
            exe.upgrade("Mozilla.Firefox", strategy=PatchStrategy.NONE)

        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Executor — Output-Behandlung (Truncation greift im Result)
# ---------------------------------------------------------------------------


class TestWingetUpgradeExecutorOutputHandling:
    def test_lange_stdout_wird_gekuerzt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _force_windows(monkeypatch)
        long_stdout = "x" * (_OUTPUT_SOFT_LIMIT_BYTES * 2)
        mock_run = MagicMock(return_value=_make_completed(0, stdout=long_stdout))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        result = exe.upgrade("Mozilla.Firefox")

        assert result.stdout.endswith(_OUTPUT_TRUNCATION_MARKER)

    def test_lange_stderr_wird_gekuerzt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _force_windows(monkeypatch)
        long_stderr = "y" * (_OUTPUT_SOFT_LIMIT_BYTES * 2)
        mock_run = MagicMock(return_value=_make_completed(1, stderr=long_stderr))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        result = exe.upgrade("Mozilla.Firefox")

        assert result.stderr.endswith(_OUTPUT_TRUNCATION_MARKER)
        assert result.status is UpgradeStatus.FAILED

    def test_none_stdout_stderr_werden_zu_leerstring(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0, stdout=None, stderr=None))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        result = exe.upgrade("Mozilla.Firefox")

        assert result.stdout == ""
        assert result.stderr == ""


# ---------------------------------------------------------------------------
# upgrade_msstore Mode
# ---------------------------------------------------------------------------


class TestUpgradeMsstore:
    """`upgrade_msstore` ist der zweite Executor-Mode fuer Microsoft-Store-
    Apps. Validiert eigenen Regex (_STORE_ID_RE), eigene Args
    (--source msstore, kein --exact)."""

    def test_msstore_command_enthaelt_source_msstore(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        exe.upgrade_msstore("XP8K2L36VP0QMB")

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "winget"
        assert cmd[1] == "upgrade"
        assert "--id" in cmd
        assert "XP8K2L36VP0QMB" in cmd
        assert "--source" in cmd
        assert "msstore" in cmd
        # --exact macht bei Store-IDs keinen Sinn
        assert "--exact" not in cmd
        assert "--accept-source-agreements" in cmd

    def test_msstore_invalid_id_raises_validation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Lowercase + Sonderzeichen sind in Store-IDs nicht erlaubt."""
        _force_windows(monkeypatch)
        from core.exceptions import ValidationError  # noqa: PLC0415

        exe = WingetUpgradeExecutor(subprocess_run=MagicMock())
        with pytest.raises(ValidationError):
            exe.upgrade_msstore("xp8k2l36vp0qmb")  # lowercase
        with pytest.raises(ValidationError):
            exe.upgrade_msstore("foo.bar")  # Punkt = winget-id-Format, nicht store
        with pytest.raises(ValidationError):
            exe.upgrade_msstore("")  # leer

    def test_msstore_silent_true_haengt_silent_an(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        exe.upgrade_msstore("XP8K2L36VP0QMB", silent=True)
        cmd = mock_run.call_args[0][0]
        assert "--silent" in cmd

    def test_msstore_success_returns_upgrade_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_windows(monkeypatch)
        mock_run = MagicMock(return_value=_make_completed(0))
        exe = WingetUpgradeExecutor(subprocess_run=mock_run)

        result = exe.upgrade_msstore("XP8K2L36VP0QMB")
        assert result.status is UpgradeStatus.SUCCESS
        assert result.winget_id == "XP8K2L36VP0QMB"  # package_id wird im Result hinterlegt
        assert result.exit_code == 0
