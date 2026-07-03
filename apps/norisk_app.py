"""NoRisk by FINLAI — Weil Sicherheit kein Zufall ist.

Einstiegspunkt: ``.\\.venv\\Scripts\\python apps\\norisk_app.py``
(Windows; Unix analog ohne Backslashes)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Repo-Root in sys.path injizieren — sonst failt ``from apps import...``,
# wenn die Datei direkt aufgerufen wird (cwd != Repo-Root oder ohne PYTHONPATH).
# Behebt den 2026-04-28 reproduzierbaren ``ModuleNotFoundError: No module named 'apps'``.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from apps import launch_app  # noqa: E402 (must come AFTER sys.path-Inject)
from apps.app_config import NORISK_CONFIG  # noqa: E402


def _finlai_home_from_argv(argv: list[str]) -> str | None:
    """Liest den ``--finlai-home <wert>``-Pfad aus ``argv`` (oder ``None``).

    Die geplante Aufgabe und der elevated Install-Aufruf reichen ein aktives
    FINLAI_HOME-Profil per ``--finlai-home <dir>`` durch; diese Funktion
    extrahiert den Wert robust (kein argparse, da die Flags hier nur erkannt,
    nicht vollstaendig geparst werden).

    Args:
        argv: Prozess-Argumente.

    Returns:
        Den Pfad-Wert hinter ``--finlai-home``, oder ``None`` wenn nicht gesetzt.
    """
    try:
        idx = argv.index("--finlai-home")
    except ValueError:
        return None
    return argv[idx + 1] if idx + 1 < len(argv) else None


def _run_collector_cli(argv: list[str]) -> int | None:
    """Behandelt die headless Collector-CLI-Flags Phase C).

    Diese Flags werden vom Einstellungen-Tab via
:func:`core.elevation.relaunch_elevated` in einem elevated Prozess gestartet
    (Install/Uninstall). ``--run-collector`` ist seit F-C nur noch ein
    **Inline-Fallback/Diagnose-Pfad** (die geplante Aufgabe startet stattdessen die
    separate ``norisk-collector.exe`` bzw. im Dev ``apps/collector_main.py``).
    Sie liegen hier im NoRisk-Entry — nicht im geteilten ``launch_app`` — damit der
    generische Launcher nicht an das network_monitor-Tool gekoppelt wird.

    Args:
        argv: Prozess-Argumente (typischerweise ``sys.argv``).

    Returns:
        Exit-Code, wenn ein Collector-Flag behandelt wurde; sonst ``None``
        (normaler GUI-Start).
    """
    from core.logger import get_logger  # noqa: PLC0415

    log = get_logger(__name__)

    finlai_home = _finlai_home_from_argv(argv)

    if "--install-collector-task" in argv:
        from tools.network_monitor.data.collector_task_manager import (  # noqa: PLC0415
            clear_install_marker,
            install_collector_task,
            write_install_reject_marker,
        )
        from tools.network_monitor.domain.exceptions import (  # noqa: PLC0415
            UntrustedCollectorPathError,
        )

        # Der Install-Ergebnis-Marker (F-C-5) landet unter FINLAI_HOME. Den Override
        # früh setzen, damit der elevated Prozess in DASSELBE Profil schreibt, das der
        # (nicht-elevierte) GUI-Prozess danach ausliest.
        if finlai_home:
            from core.finlai_paths import set_finlai_home  # noqa: PLC0415

            set_finlai_home(finlai_home)

        try:
            # Dev UND gepackt: die Action kommt aus default_collector_action
            # (frozen-aware -> separate, Qt-freie norisk-collector.exe als 2.
            # EXE-Target F-C; dev -> pythonw apps/collector_main.py).
            # Installer und collector_task_needs_migration nutzen damit DIESELBE
            # Single-Source — kein Exe-Pfad-Drift, der sonst einen
            # Dauer-„Migration noetig"-Zustand (wiederholte UAC-Prompts) erzeugen
            # wuerde.
            # --allow-untrusted-collector-path: übergeht das EoP-Security-Gate
            # F-C-3) für Dev/lokalen Frozen-Smoke, da der Repo-/dist-Pfad
            # benutzer-beschreibbar ist; in Produktion (Install nach %ProgramFiles%)
            # NICHT setzen.
            install_collector_task(
                finlai_home=finlai_home,
                allow_untrusted_path="--allow-untrusted-collector-path" in argv,
            )
        except UntrustedCollectorPathError:
            # Security-Gate hat fail-closed abgelehnt (kein Bug) — eigener Exit-Code
            # UND Marker-Datei, damit der GUI-Pfad (F-C-5) das vom generischen Fehler
            # unterscheiden und dem Anwender erklären kann. Bewusst KEIN Hinweis auf
            # den Override im benutzerlesbaren Log/Marker.
            log.error(
                "Collector-Installation aus Sicherheitsgründen abgelehnt: Das Ziel "
                "liegt in einem benutzer-beschreibbaren Pfad. Bitte installieren Sie "
                "NoRisk nach %ProgramFiles%."
            )
            write_install_reject_marker(
                "Der Zielpfad ist für normale Benutzer beschreibbar und wurde aus "
                "Sicherheitsgründen abgelehnt. Bitte installieren Sie NoRisk nach "
                "%ProgramFiles%."
            )
            return 3
        except Exception:  # noqa: BLE001 — headless Entry-Boundary: Fehler ins Log
            log.exception("Installation der Collector-Aufgabe fehlgeschlagen.")
            return 1
        # Erfolg: evtl. alten Reject-Marker einer früheren Aktivierung entfernen.
        clear_install_marker()
        return 0

    if "--uninstall-collector-task" in argv:
        from tools.network_monitor.data.collector_task_manager import (  # noqa: PLC0415
            uninstall_collector_task,
        )

        try:
            uninstall_collector_task()
        except Exception:  # noqa: BLE001 — headless Entry-Boundary: Fehler ins Log
            log.exception("Entfernen der Collector-Aufgabe fehlgeschlagen.")
            return 1
        return 0

    if "--run-collector" in argv:
        from apps.collector_main import main as collector_main  # noqa: PLC0415

        # Inline-Collector ueber die Haupt-Exe (Fallback/Diagnose, z. B.
        # `norisk.exe --run-collector --duration 30`). Die geplante Aufgabe nutzt
        # seit F-C die separate norisk-collector.exe statt dieses Pfads. Ein
        # evtl. --finlai-home wird durchgereicht; ohne Override nutzt der Collector
        # das Default-Profil.
        collector_argv = ["--finlai-home", finlai_home] if finlai_home else []
        return collector_main(collector_argv)

    return None


def _run_recheck_hardening_cli(argv: list[str]) -> int | None:
    """Headless elevierter Hardening-Recheck Phase 4d).

    Vom GUI-"Mit Admin messen"-Pfad via:func:`core.elevation.relaunch_elevated`
    mit ``--recheck-hardening --finlai-home <dir>`` gestartet. Misst ALLE Checks
    mit Adminrechten und schreibt das Ergebnis HMAC-signiert nach
    ``FINLAI_HOME/hardening_recheck.json``. STRIKT read-only: kein Persist, kein
    Push, keine History — der GUI-Prozess pollt, verifiziert + merged.

    Args:
        argv: Prozess-Argumente (typischerweise ``sys.argv``).

    Returns:
        Exit-Code, wenn ``--recheck-hardening`` behandelt wurde; sonst ``None``.
    """
    if "--recheck-hardening" not in argv:
        return None

    # FINLAI_HOME ZUERST setzen (vor key_manager-Import: _MASTER_KEY_FILE bindet
    # zur Import-Zeit an finlai_dir, s. / elevated_round_trip-Hinweis).
    finlai_home = _finlai_home_from_argv(argv)
    if finlai_home:
        from core.finlai_paths import set_finlai_home  # noqa: PLC0415

        set_finlai_home(finlai_home)

    from core.logger import get_logger  # noqa: PLC0415

    log = get_logger(__name__)
    _attach_recheck_log_handler(log)  # D6: Log fuer den elevierten Prozess sichtbar

    # T8-Haertung VOR jedem DLL-ladenden Probe-Code (wie system_tuner-Apply).
    try:
        from core.win_security import harden_dll_search_path  # noqa: PLC0415

        harden_dll_search_path()
    except Exception:  # noqa: BLE001 — best-effort Haertung, nie blockierend
        log.warning("harden_dll_search_path im Recheck fehlgeschlagen.", exc_info=True)

    nonce = _arg_value(argv, "--recheck-nonce") or ""

    from tools.system_scanner.application.hardening_recheck import (  # noqa: PLC0415
        write_recheck_reject,
        write_recheck_result,
    )
    from tools.system_scanner.domain.enums import RecheckReason  # noqa: PLC0415

    # DEK aufloesen: ohne DEK kann KEIN Marker signiert werden ->
    # rc=2 (GUI laeuft fail-closed in den Timeout-Backstop).
    try:
        _resolve_recheck_key_manager()
    except Exception:  # noqa: BLE001 — Entry-Boundary
        log.exception("Recheck: DEK nicht verfuegbar — kein signierbarer Marker (rc=2).")
        return 2

    def _reject(reason: RecheckReason, detail: str = "") -> int:
        try:
            write_recheck_reject(reason, detail, nonce=nonce)
            log.info("Recheck-Reject geschrieben: %s", reason.value)
        except Exception:  # noqa: BLE001 — Reject-Schreiben darf nie crashen
            log.exception("Recheck-Reject konnte nicht geschrieben werden (rc=2).")
            return 2
        return 0

    # A3-aequivalent: trotz runas nicht elevated -> Reject statt stiller Weiterlauf.
    try:
        from core.elevation import is_admin  # noqa: PLC0415

        if not is_admin():
            return _reject(RecheckReason.NOT_ADMIN, "Relaunch ohne Adminrechte")
    except Exception:  # noqa: BLE001 — Admin-Check defensiv
        log.warning("is_admin im Recheck nicht ermittelbar.", exc_info=True)

    try:
        from tools.system_scanner.application.windows_hardening_scanner import (  # noqa: PLC0415
            run_hardening_baseline_scan,
        )

        scan = run_hardening_baseline_scan()
    except Exception:  # noqa: BLE001 — Probe-Fehler -> sichtbarer Reject
        log.exception("Elevierter Hardening-Recheck: Probe fehlgeschlagen.")
        return _reject(RecheckReason.SCAN_FAILED, "Messung fehlgeschlagen")

    if scan is None:
        log.info("Recheck: Probe nicht verfuegbar (Non-Windows).")
        return _reject(RecheckReason.PROBE_UNAVAILABLE, "Probe nicht verfuegbar")

    try:
        write_recheck_result(scan, nonce=nonce)
        log.info(
            "Elevierter Hardening-Recheck geschrieben (%d Checks).",
            len(scan.hardening_checks),
        )
        return 0
    except Exception:  # noqa: BLE001 — Schreiben/Signieren fehlgeschlagen
        log.exception("Recheck-Ergebnis konnte nicht geschrieben werden.")
        return _reject(RecheckReason.INTERNAL, "Ergebnis nicht schreibbar")


def _attach_recheck_log_handler(log: object) -> None:
    """Haengt einen FileHandler nach ``finlai_dir/logs/`` an (D6).

    Der elevierte Recheck laeuft via ``pythonw``/exe ohne Konsole; ``core.logger``
    schreibt zudem install-dir-relativ. Damit der elevierte Ausgang fuer den
    Nutzer auffindbar ist, wird zusaetzlich nach FINLAI_HOME geloggt (best-effort).
    """
    import logging  # noqa: PLC0415
    from datetime import datetime  # noqa: PLC0415

    from core.finlai_paths import finlai_dir  # noqa: PLC0415

    try:
        log_dir = finlai_dir() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(
            log_dir / f"recheck_{datetime.now().strftime('%Y%m%d')}.log",
            encoding="utf-8",
        )
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")
        )
        logging.getLogger("finlai").addHandler(handler)
    except Exception:  # noqa: BLE001 — Logging-Setup darf den Recheck nie blockieren
        getattr(log, "warning", lambda *_a, **_k: None)(
            "Recheck-Log-Handler konnte nicht angehaengt werden."
        )


def _resolve_recheck_key_manager() -> object:
    """Liefert den aktiven KeyManager oder bootet ihn aus dem DPAPI-DEK.

    Wie ``system_tuner.elevated_round_trip._resolve_key_manager``: im GUI-/Test-
    Pfad existiert ein aktiver KM; der elevierte Headless-Prozess bootet ihn aus
    dem DPAPI-gewrappten DEK (selber Windows-User -> selber DEK). Wirft, wenn der
    DEK fehlt/nicht entschluesselbar ist — der Caller behandelt das fail-closed.
    """
    from core.database.key_manager import KeyManager  # noqa: PLC0415
    from core.database.key_manager_context import (  # noqa: PLC0415
        get_active_key_manager,
        set_active_key_manager,
    )
    from core.exceptions import ConfigurationError  # noqa: PLC0415

    try:
        return get_active_key_manager()
    except ConfigurationError:
        pass
    km = KeyManager()
    km.load_master_key()
    set_active_key_manager(km)
    return km


def _arg_value(argv: list[str], flag: str) -> str | None:
    """Liest den Wert hinter ``flag`` aus ``argv`` (oder ``None``)."""
    try:
        idx = argv.index(flag)
    except ValueError:
        return None
    return argv[idx + 1] if idx + 1 < len(argv) else None


#: Env-Opt-in fuer die Dev/Smoke-Flags — wirkt NUR im non-frozen Dev-Build.
_SYSTEM_TUNER_DEV_ENV = "NORISK_SYSTEM_TUNER_DEV"


def _system_tuner_dev_flags_allowed() -> bool:
    """A1 (voll): Dev/Smoke-Flags nur im non-frozen Dev-Build mit Opt-in.

    In Produktion (PyInstaller, ``sys.frozen``) IMMER ``False`` — eine
    kompromittierte (unelevated) GUI kann ueber argv weder scharfschalten
    (``--allow-apply``), den Restore-Point ueberspringen, das Pfad-Trust-Gate
    umgehen (``--allow-untrusted-path``) noch auf einen Fremdkatalog zeigen
    (``--catalog``). Der Katalog ist dann auf das gebuendelte, signierte Default
    festgenagelt.
    """
    if getattr(sys, "frozen", False):
        return False
    return os.environ.get(_SYSTEM_TUNER_DEV_ENV) == "1"


def _run_system_tuner_apply_cli(argv: list[str]) -> int | None:
    """Behandelt den elevated system_tuner-Apply (R5/R6/R7).

    Vom (Pro-)GUI-Pfad via:func:`core.elevation.relaunch_elevated` mit
    ``--system-tuner-apply --plan <datei> --finlai-home <dir>`` in einem elevated
    Prozess gestartet. Verifiziert Signatur + Plan-Binding, wendet katalogisierte
    Tweaks fail-closed an (NEVER_DISABLE-Recheck, Snapshot, Verify, Auto-Revert)
    und schreibt den Ergebnis-Marker.

    A1: ``--allow-apply``/``--skip-restore-point``/``--allow-untrusted-path``/
    ``--catalog`` sind reine Dev/Smoke-Flags und werden in Produktion (frozen)
    bzw. ohne ``NORISK_SYSTEM_TUNER_DEV=1`` **hart ignoriert** — argv aus einer
    untrusted GUI kann die Gates nicht aufweichen.

    Returns:
        Exit-Code, wenn der Apply-Flag gesetzt war; sonst ``None``.
    """
    if "--system-tuner-apply" not in argv:
        return None
    from pathlib import Path  # noqa: PLC0415

    finlai_home = _finlai_home_from_argv(argv)
    if finlai_home:
        from core.finlai_paths import set_finlai_home  # noqa: PLC0415

        set_finlai_home(finlai_home)

    plan = _arg_value(argv, "--plan")
    if not plan:
        return 2

    # A1: Dev/Smoke-Flags + Katalog-Override nur im Dev-Build mit Opt-in.
    dev = _system_tuner_dev_flags_allowed()
    catalog = _arg_value(argv, "--catalog") if dev else None

    from tools.system_tuner.application.elevated_round_trip import (  # noqa: PLC0415
        run_apply_entry,
    )

    return run_apply_entry(
        plan_path=Path(plan),
        catalog_path=Path(catalog) if catalog else None,
        signature_path=Path(catalog + ".sig") if catalog else None,
        allow_apply=dev and ("--allow-apply" in argv),
        skip_restore_point=dev and ("--skip-restore-point" in argv),
        allow_untrusted_path=dev and ("--allow-untrusted-path" in argv),
    )


if __name__ == "__main__":
    _rc = _run_collector_cli(sys.argv)
    if _rc is None:
        _rc = _run_recheck_hardening_cli(sys.argv)
    if _rc is None:
        _rc = _run_system_tuner_apply_cli(sys.argv)
    if _rc is not None:
        sys.exit(_rc)
    launch_app(NORISK_CONFIG)
