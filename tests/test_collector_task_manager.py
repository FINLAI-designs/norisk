"""Tests fuer den Collector-Task-Manager B2.4).

Deckt die Task-Definition-Konfiguration (mit gemocktem COM-Objekt), die
User-ID-Ermittlung und die Default-Action ab — ohne echten Task-Scheduler,
ohne Admin, plattformunabhaengig.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tools.network_monitor.data.collector_task_manager import (
    COLLECTOR_EXE_NAME,
    INSTALL_RESULT_REJECTED,
    TASK_ACTION_EXEC,
    TASK_INSTANCES_IGNORE_NEW,
    TASK_LOGON_INTERACTIVE_TOKEN,
    TASK_RUNLEVEL_HIGHEST,
    TASK_TRIGGER_LOGON,
    _action_targets_exist,
    _canonical_repo_root,
    _exe_paths_equivalent,
    _script_from_arguments,
    clear_install_marker,
    collector_task_needs_migration,
    configure_task_definition,
    current_user_id,
    default_collector_action,
    get_collector_status,
    install_collector_task,
    install_marker_path,
    read_install_marker,
    uninstall_collector_task,
    write_install_reject_marker,
)
from tools.network_monitor.domain.collector_status import CollectorStatus
from tools.network_monitor.domain.exceptions import UntrustedCollectorPathError

_MOD = "tools.network_monitor.data.collector_task_manager"


def _trusted(path: str) -> object:
    """Verdikt-Stub: Pfad vertrauenswürdig."""
    from core.win_security import PathTrustVerdict

    return PathTrustVerdict(trusted=True, reason="ok", checked_path=path)


def _untrusted(path: str) -> object:
    """Verdikt-Stub: Pfad NICHT vertrauenswürdig."""
    from core.win_security import PathTrustVerdict

    return PathTrustVerdict(
        trusted=False, reason="benutzer-beschreibbar", checked_path=path
    )


class TestConfigureTaskDefinition:
    def _configure(self) -> MagicMock:
        td = MagicMock()
        result = configure_task_definition(
            td,
            exe="py.exe",
            arguments='"s.py"',
            working_dir="C:/wd",
            user_id="DOM\\u",
        )
        assert result is td
        return td

    def test_principal_interaktiv_und_elevated(self) -> None:
        td = self._configure()
        assert td.Principal.LogonType == TASK_LOGON_INTERACTIVE_TOKEN
        assert td.Principal.RunLevel == TASK_RUNLEVEL_HIGHEST
        assert td.Principal.UserId == "DOM\\u"

    def test_settings_unbegrenzt_und_restart(self) -> None:
        td = self._configure()
        assert td.Settings.ExecutionTimeLimit == "PT0S"
        assert td.Settings.MultipleInstances == TASK_INSTANCES_IGNORE_NEW
        assert td.Settings.RestartCount == 3
        assert td.Settings.Enabled is True

    def test_logon_trigger_enabled(self) -> None:
        td = self._configure()
        td.Triggers.Create.assert_called_once_with(TASK_TRIGGER_LOGON)
        trigger = td.Triggers.Create.return_value
        assert trigger.Enabled is True
        assert trigger.UserId == "DOM\\u"

    def test_exec_action_gesetzt(self) -> None:
        td = self._configure()
        td.Actions.Create.assert_called_once_with(TASK_ACTION_EXEC)
        action = td.Actions.Create.return_value
        assert action.Path == "py.exe"
        assert action.Arguments == '"s.py"'
        assert action.WorkingDirectory == "C:/wd"


class TestCurrentUserId:
    def test_mit_domain(self, monkeypatch) -> None:
        monkeypatch.setenv("USERDOMAIN", "ACME")
        monkeypatch.setattr(f"{_MOD}.getpass.getuser", lambda: "bob")
        assert current_user_id() == "ACME\\bob"

    def test_ohne_domain(self, monkeypatch) -> None:
        monkeypatch.delenv("USERDOMAIN", raising=False)
        monkeypatch.setattr(f"{_MOD}.getpass.getuser", lambda: "bob")
        assert current_user_id() == "bob"


class TestDefaultAction:
    def test_zeigt_auf_collector_main(self) -> None:
        exe, arguments, working_dir = default_collector_action()
        assert "collector_main.py" in arguments
        # Plattform-neutral: Windows liefert python(w).exe, Linux-CI „python".
        assert "python" in Path(exe).name.lower()
        assert (Path(working_dir) / "apps" / "collector_main.py").exists()

    def test_action_pfade_sind_realpath_kanonisch(self) -> None:
        # check==burn (R-23, F-C-2 Teil 2): exe/working_dir/Skript sind bereits
        # realpath-aufgeloest, sodass install_collector_task exakt das vom
        # Trust-Gate (assess_install_path_trust prueft ebenfalls realpath)
        # bestaetigte Ziel einbrennt — kein check!=burn-Spalt mehr.
        exe, arguments, working_dir = default_collector_action()
        assert exe == os.path.realpath(exe)
        assert working_dir == os.path.realpath(working_dir)
        script = _script_from_arguments(arguments)
        assert script is not None
        assert script == os.path.realpath(script)


class TestDefaultActionFrozen:
    def test_frozen_zeigt_auf_separate_collector_exe(self, monkeypatch, tmp_path) -> None:
        # Gepackter Modus F-C): Action zeigt auf die Qt-freie
        # norisk-collector.exe neben der Haupt-Exe, ohne Argumente.
        exe = tmp_path / "norisk.exe"
        monkeypatch.setattr(f"{_MOD}.sys.executable", str(exe))
        monkeypatch.setattr(f"{_MOD}.sys.frozen", True, raising=False)
        path, arguments, working_dir = default_collector_action()
        assert Path(path).name == COLLECTOR_EXE_NAME
        # check==burn (R-23): realpath-aufgeloest, aber weiterhin im selben Ordner
        # wie die Haupt-Exe. samefile statt == (robust gegen Casing/8.3-Normierung
        # durch realpath); tmp_path existiert, daher ist samefile anwendbar.
        assert Path(path).parent.samefile(tmp_path)
        assert arguments == ""
        assert Path(working_dir).samefile(tmp_path)
        # Status-Logik wertet die argumentlose Exe nicht als fehlendes Skript.
        Path(path).write_text("")
        assert _action_targets_exist(path, arguments) is True


class TestExePathsEquivalent:
    def test_identische_pfade_gleich(self) -> None:
        assert _exe_paths_equivalent("/opt/x/c.exe", "/opt/x/../x/c.exe") is True

    def test_verschiedene_ungleich(self) -> None:
        assert _exe_paths_equivalent("/opt/x/a.exe", "/opt/x/b.exe") is False

    def test_leerer_pfad_ist_false(self) -> None:
        assert _exe_paths_equivalent("", "/opt/x/a.exe") is False
        assert _exe_paths_equivalent("/opt/x/a.exe", "") is False

    @pytest.mark.skipif(
        sys.platform != "win32",
        reason="normcase ist nur unter Windows case-insensitiv",
    )
    def test_windows_case_insensitiv(self) -> None:
        assert _exe_paths_equivalent(r"C:\App\NoRisk.exe", r"c:\app\norisk.exe") is True


class TestCanonicalRepoRoot:
    def test_haupt_repo_git_ordner_unveraendert(self, tmp_path) -> None:
        (tmp_path / ".git").mkdir()
        assert _canonical_repo_root(tmp_path) == tmp_path

    def test_kein_git_unveraendert(self, tmp_path) -> None:
        assert _canonical_repo_root(tmp_path) == tmp_path

    def test_linked_worktree_loest_haupt_arbeitsbaum(self, tmp_path) -> None:
        # Wurzel: Install aus einem linked Worktree soll den stabilen
        # Haupt-Arbeitsbaum einbrennen, nicht den transienten Worktree-Pfad.
        main = tmp_path / "main"
        wt_internal = main / ".git" / "worktrees" / "wt1"
        wt_internal.mkdir(parents=True)
        wt = tmp_path / "wt"
        wt.mkdir()
        (wt / ".git").write_text(f"gitdir: {wt_internal}\n", encoding="utf-8")
        assert _canonical_repo_root(wt) == main

    def test_unlesbares_git_file_unveraendert(self, tmp_path) -> None:
        wt = tmp_path / "wt"
        wt.mkdir()
        (wt / ".git").write_text("kein gitdir hier\n", encoding="utf-8")
        assert _canonical_repo_root(wt) == wt

    def test_fremdes_layout_unveraendert(self, tmp_path) -> None:
        # gitdir zeigt nicht auf.../.git/worktrees/<name> -> konservativ Start.
        wt = tmp_path / "wt"
        wt.mkdir()
        (wt / ".git").write_text(f"gitdir: {tmp_path / 'irgendwo'}\n", encoding="utf-8")
        assert _canonical_repo_root(wt) == wt


class TestInstallCollectorTask:
    def _capture_install(self, monkeypatch, **kwargs) -> str:
        """Ruft install_collector_task mit gemocktem Admin/Scheduler und liefert
        die an configure_task_definition uebergebenen Action-Argumente zurueck."""
        captured: dict[str, str] = {}
        monkeypatch.setattr(f"{_MOD}.is_admin", lambda: True)
        monkeypatch.setattr(f"{_MOD}._connect_scheduler", lambda: MagicMock())

        def fake_configure(task_def, *, arguments, **_kw):
            captured["arguments"] = arguments
            return task_def

        monkeypatch.setattr(f"{_MOD}.configure_task_definition", fake_configure)
        # Diese Tests prüfen das Argument-Handling, nicht das Pfad-Trust-Gate; der
        # Dev-/Repo-Pfad ist immer benutzer-beschreibbar -> Override setzen.
        kwargs.setdefault("allow_untrusted_path", True)
        install_collector_task(**kwargs)
        return captured["arguments"]

    def test_finlai_home_wird_angehaengt(self, monkeypatch, tmp_path) -> None:
        # tmp_path = existierendes, absolutes Verzeichnis -> Validierung passiert.
        args = self._capture_install(monkeypatch, finlai_home=str(tmp_path))
        assert f'--finlai-home "{tmp_path}"' in args
        # Skript-Token bleibt erster Token (Status-Check-Contract).
        assert args.startswith('"')
        assert _script_from_arguments(args).lower().endswith("collector_main.py")

    def test_ohne_finlai_home_kein_flag(self, monkeypatch) -> None:
        args = self._capture_install(monkeypatch)
        assert "--finlai-home" not in args

    def test_frozen_arguments_plus_finlai_home(self, monkeypatch, tmp_path) -> None:
        args = self._capture_install(
            monkeypatch,
            exe=r"C:\app\norisk.exe",
            arguments="--run-collector",
            working_dir=r"C:\app",
            finlai_home=str(tmp_path),
        )
        assert args == f'--run-collector --finlai-home "{tmp_path}"'
        # Subcommand bleibt erster Token -> Status-Check wertet es nicht als Datei.
        assert _script_from_arguments(args) == "--run-collector"

    def test_nicht_existierender_pfad_wird_abgelehnt(self, monkeypatch, tmp_path) -> None:
        # Fail-closed: ungueltiger Pfad -> ValueError, keine Installation.
        monkeypatch.setattr(f"{_MOD}.is_admin", lambda: True)
        missing = tmp_path / "gibts-nicht"
        with pytest.raises(ValueError, match="Ungueltiger FINLAI_HOME"):
            install_collector_task(finlai_home=str(missing))

    def test_pfad_mit_anfuehrungszeichen_wird_abgelehnt(self, monkeypatch) -> None:
        monkeypatch.setattr(f"{_MOD}.is_admin", lambda: True)
        with pytest.raises(ValueError, match="Ungueltiger FINLAI_HOME"):
            install_collector_task(finlai_home='C:\\evil" --run-collector')

    def test_relativer_pfad_wird_abgelehnt(self, monkeypatch) -> None:
        monkeypatch.setattr(f"{_MOD}.is_admin", lambda: True)
        with pytest.raises(ValueError, match="Ungueltiger FINLAI_HOME"):
            install_collector_task(finlai_home="relativ/iso")

    def test_ohne_admin_permissionerror(self, monkeypatch) -> None:
        monkeypatch.setattr(f"{_MOD}.is_admin", lambda: False)
        with pytest.raises(PermissionError):
            install_collector_task()


class TestPathTrustGate:
    """Security-Gate F-C-3): benutzer-beschreibbares HIGHEST-Ziel ablehnen."""

    def _spy_scheduler(self, monkeypatch) -> dict:
        """Mockt Admin/Scheduler/Configure und meldet, ob der Scheduler verbunden wurde."""
        state = {"connected": False}

        def fake_connect():
            state["connected"] = True
            return MagicMock()

        monkeypatch.setattr(f"{_MOD}.is_admin", lambda: True)
        monkeypatch.setattr(f"{_MOD}._connect_scheduler", fake_connect)
        monkeypatch.setattr(f"{_MOD}.configure_task_definition", lambda td, **_kw: td)
        return state

    def test_untrusted_pfad_wird_abgelehnt(self, monkeypatch) -> None:
        state = self._spy_scheduler(monkeypatch)
        monkeypatch.setattr(f"{_MOD}.assess_install_path_trust", _untrusted)
        with pytest.raises(UntrustedCollectorPathError, match="manipulierbar"):
            install_collector_task(
                exe=r"C:\Users\bob\app\norisk-collector.exe",
                arguments="",
                working_dir=r"C:\Users\bob\app",
            )
        # Fail-closed: Ablehnung VOR jedem Scheduler-Zugriff.
        assert state["connected"] is False

    def test_override_laesst_untrusted_durch(self, monkeypatch) -> None:
        state = self._spy_scheduler(monkeypatch)
        monkeypatch.setattr(f"{_MOD}.assess_install_path_trust", _untrusted)
        install_collector_task(
            exe=r"C:\Users\bob\app\norisk-collector.exe",
            arguments="",
            working_dir=r"C:\Users\bob\app",
            allow_untrusted_path=True,
        )
        assert state["connected"] is True

    def test_trusted_pfad_installiert(self, monkeypatch) -> None:
        state = self._spy_scheduler(monkeypatch)
        monkeypatch.setattr(f"{_MOD}.assess_install_path_trust", _trusted)
        install_collector_task(
            exe=r"C:\Program Files\NoRisk\norisk-collector.exe",
            arguments="",
            working_dir=r"C:\Program Files\NoRisk",
        )
        assert state["connected"] is True

    def test_prueft_exe_skript_und_working_dir(self, monkeypatch) -> None:
        # Dev-Action: Exe (pythonw),.py-Skript UND WorkingDirectory werden geprüft;
        # ein untrusted Knoten reicht zur Ablehnung.
        self._spy_scheduler(monkeypatch)
        checked: list[str] = []

        def fake_assess(path: str):
            checked.append(path)
            return _trusted(path) if path.endswith(".exe") else _untrusted(path)

        monkeypatch.setattr(f"{_MOD}.assess_install_path_trust", fake_assess)
        with pytest.raises(UntrustedCollectorPathError):
            install_collector_task(
                exe=r"C:\py\pythonw.exe",
                arguments='"C:/r/apps/collector_main.py"',
                working_dir=r"C:\r",
            )
        assert r"C:\py\pythonw.exe" in checked
        assert "C:/r/apps/collector_main.py" in checked
        assert r"C:\r" in checked  # WorkingDirectory ebenfalls trust-geprüft

    def test_leeres_ziel_fail_closed(self, monkeypatch) -> None:
        # Degenerierter Input (kein prüfbares Ziel) -> fail-closed, kein No-op.
        state = self._spy_scheduler(monkeypatch)
        with pytest.raises(UntrustedCollectorPathError, match="kein prüfbares Ziel"):
            install_collector_task(exe="", arguments="", working_dir="")
        assert state["connected"] is False


class TestInstallMarker:
    """Install-Ergebnis-Marker (F-C-5): elevated Prozess -> GUI-Rückkanal."""

    def test_write_read_clear_roundtrip(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(f"{_MOD}.finlai_dir", lambda: tmp_path)
        assert read_install_marker() is None
        write_install_reject_marker("Pfad ist beschreibbar")
        assert install_marker_path().exists()
        data = read_install_marker()
        assert data is not None
        assert data["result"] == INSTALL_RESULT_REJECTED
        assert data["reason"] == "Pfad ist beschreibbar"
        clear_install_marker()
        assert read_install_marker() is None

    def test_clear_ohne_marker_ist_noop(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(f"{_MOD}.finlai_dir", lambda: tmp_path)
        clear_install_marker()  # darf nicht werfen

    def test_unlesbarer_marker_ist_none(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(f"{_MOD}.finlai_dir", lambda: tmp_path)
        install_marker_path().write_text("{ kaputt", encoding="utf-8")
        assert read_install_marker() is None


class TestUninstallCollectorTask:
    def test_ohne_admin_permissionerror(self, monkeypatch) -> None:
        # unelevierter DeleteTask einer HIGHEST-Aufgabe -> klarer
        # PermissionError statt rohem COM-ACCESS_DENIED (GUI schaltet elevated).
        monkeypatch.setattr(f"{_MOD}.is_admin", lambda: False)
        with pytest.raises(PermissionError):
            uninstall_collector_task()

    def test_mit_admin_loescht(self, monkeypatch) -> None:
        monkeypatch.setattr(f"{_MOD}.is_admin", lambda: True)
        root = MagicMock()
        scheduler = MagicMock()
        scheduler.GetFolder.return_value = root
        monkeypatch.setattr(f"{_MOD}._connect_scheduler", lambda: scheduler)
        monkeypatch.setattr(f"{_MOD}.is_task_installed", lambda *_a: True)
        assert uninstall_collector_task() is True
        root.DeleteTask.assert_called_once()

    def test_mit_admin_nicht_installiert_gibt_false(self, monkeypatch) -> None:
        monkeypatch.setattr(f"{_MOD}.is_admin", lambda: True)
        monkeypatch.setattr(f"{_MOD}._connect_scheduler", lambda: MagicMock())
        monkeypatch.setattr(f"{_MOD}.is_task_installed", lambda *_a: False)
        assert uninstall_collector_task() is False


class TestScriptFromArguments:
    def test_gequoteter_pfad(self) -> None:
        assert (
            _script_from_arguments('"C:/r/apps/collector_main.py"')
            == "C:/r/apps/collector_main.py"
        )

    def test_ohne_quotes_erster_token(self) -> None:
        assert _script_from_arguments("--run-collector") == "--run-collector"

    def test_leer_ist_none(self) -> None:
        assert _script_from_arguments("   ") is None

    def test_quote_ohne_schliessende(self) -> None:
        assert _script_from_arguments('"C:/r/x.py') == "C:/r/x.py"


class TestActionTargetsExist:
    def test_exe_und_skript_existieren(self, tmp_path) -> None:
        exe = tmp_path / "pythonw.exe"
        exe.write_text("")
        script = tmp_path / "collector_main.py"
        script.write_text("")
        assert _action_targets_exist(str(exe), f'"{script}"') is True

    def test_skript_fehlt_ist_false(self, tmp_path) -> None:
        exe = tmp_path / "pythonw.exe"
        exe.write_text("")
        missing = tmp_path / "worktree" / "apps" / "collector_main.py"
        assert _action_targets_exist(str(exe), f'"{missing}"') is False

    def test_exe_fehlt_ist_false(self, tmp_path) -> None:
        missing_exe = tmp_path / "nicht-da.exe"
        assert _action_targets_exist(str(missing_exe), "") is False

    def test_subcommand_kein_false_broken(self, tmp_path) -> None:
        exe = tmp_path / "norisk.exe"
        exe.write_text("")
        assert _action_targets_exist(str(exe), "--run-collector") is True

    def test_unlesbare_action_ist_false(self) -> None:
        # Leeres exe + kein Argument = Action war nicht lesbar -> nicht aktiv werten.
        assert _action_targets_exist("", "") is False


def _fake_task(*, path: str, arguments: str, last_result: int) -> MagicMock:
    """Baut ein gemocktes IRegisteredTask-COM-Objekt mit einer Exec-Action."""
    action = MagicMock()
    action.Type = TASK_ACTION_EXEC
    action.Path = path
    action.Arguments = arguments
    actions = MagicMock()
    actions.Count = 1
    actions.Item.return_value = action
    task = MagicMock()
    task.Definition.Actions = actions
    task.LastTaskResult = last_result
    return task


def _patch_scheduler(
    monkeypatch, *, task: MagicMock | None = None, raise_on_get: bool = False
) -> None:
    """Ersetzt ``_connect_scheduler`` durch einen gemockten COM-Scheduler."""
    root = MagicMock()
    if raise_on_get:
        root.GetTask.side_effect = Exception("not found")
    else:
        root.GetTask.return_value = task
    scheduler = MagicMock()
    scheduler.GetFolder.return_value = root
    monkeypatch.setattr(f"{_MOD}._connect_scheduler", lambda: scheduler)


class TestGetCollectorStatus:
    def test_nicht_registriert_ist_not_installed(self, monkeypatch) -> None:
        _patch_scheduler(monkeypatch, raise_on_get=True)
        assert get_collector_status() is CollectorStatus.NOT_INSTALLED

    def test_registriert_und_gesund_ist_aktiv(self, monkeypatch, tmp_path) -> None:
        exe = tmp_path / "pythonw.exe"
        exe.write_text("")
        script = tmp_path / "collector_main.py"
        script.write_text("")
        task = _fake_task(path=str(exe), arguments=f'"{script}"', last_result=0)
        _patch_scheduler(monkeypatch, task=task)
        assert get_collector_status() is CollectorStatus.ACTIVE

    def test_registriert_aber_totes_ziel_ist_broken(self, monkeypatch, tmp_path) -> None:
        # Exakt die-Konstellation: Aufgabe zeigt auf geloeschten Worktree.
        exe = tmp_path / "pythonw.exe"
        exe.write_text("")
        dead = tmp_path / ".worktrees" / "feat-x" / "apps" / "collector_main.py"
        task = _fake_task(path=str(exe), arguments=f'"{dead}"', last_result=2)
        _patch_scheduler(monkeypatch, task=task)
        assert get_collector_status() is CollectorStatus.BROKEN

    def test_registriert_aber_action_unlesbar_ist_broken(self, monkeypatch) -> None:
        # COM lieferte die Aufgabe, aber keine lesbare Exec-Action (Count=0).
        actions = MagicMock()
        actions.Count = 0
        task = MagicMock()
        task.Definition.Actions = actions
        task.LastTaskResult = 0
        _patch_scheduler(monkeypatch, task=task)
        assert get_collector_status() is CollectorStatus.BROKEN


class TestCollectorTaskNeedsMigration:
    def test_nicht_installiert_keine_migration(self, monkeypatch) -> None:
        _patch_scheduler(monkeypatch, raise_on_get=True)
        assert collector_task_needs_migration() is False

    def test_gleiches_ziel_keine_migration(self, monkeypatch) -> None:
        # Installierte Aufgabe zeigt exakt auf das aktuelle Default-Ziel.
        current_exe = default_collector_action()[0]
        task = _fake_task(path=current_exe, arguments="", last_result=0)
        _patch_scheduler(monkeypatch, task=task)
        assert collector_task_needs_migration() is False

    def test_abweichendes_ziel_braucht_migration(self, monkeypatch) -> None:
        # Alte Action zeigt auf einen anderen Exe-Pfad als der aktuelle Build.
        task = _fake_task(
            path="/anderer/pfad/pythonw.exe", arguments='"x.py"', last_result=0
        )
        _patch_scheduler(monkeypatch, task=task)
        assert collector_task_needs_migration() is True

    def test_unlesbare_action_keine_migration(self, monkeypatch) -> None:
        actions = MagicMock()
        actions.Count = 0
        task = MagicMock()
        task.Definition.Actions = actions
        task.LastTaskResult = 0
        _patch_scheduler(monkeypatch, task=task)
        assert collector_task_needs_migration() is False
