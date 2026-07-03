"""apps — Einstiegspunkte für die vier FINLAI-Apps.

Stellt ``launch_app(config)`` bereit — die einzige öffentliche Funktion
dieses Pakets. Jeder der vier Einstiegspunkte ruft diese Funktion mit
seiner eigenen ``AppConfig`` auf.

Startup-Reihenfolge (EIN Fenster — StartupWindow)
--------------------------------------------------
  0. SQLCipher-Verfügbarkeit prüfen
  1. QApplication + Fonts + Theme
  2. StartupWindow.showMaximized — sofort sichtbar, bleibt die gesamte
     Startup-Phase geöffnet (kein Fensterwechsel)
     Seite 0 (Ladescreen):
       10% Nutzungsvereinbarung (erster Start)
       20% Datenschutzerklärung (erster Start)
       30% DSGVO-Hinweis (erster Start)
       40% First-Run-Wizard (wenn kein Benutzer existiert)
       70% Dienste starten: Startup-Lizenzprüfung entfällt, OSS)
       85% "Bereit für Anmeldung." → show_login → Seite 1
     Seite 1 (Login):
       Username/Passwort, 3-Versuche-Logik
       Erfolgreich → login_successful-Signal → Seite 0
     Seite 0 (Ladescreen Post-Login, Timer-basiert):
       80% "Benutzeroberfläche wird aufgebaut …"
       85% "Tools werden registriert …"
       90% "Einstellungen werden geladen …"
       100% "Bereit." → MainWindow.show → StartupWindow.close
  3. app.exec
  4. Dienste beenden, App-Exit protokollieren

Author: Patrick Riederich
Version: 1.3
"""

from __future__ import annotations

import os
import sys
import threading
import time as _time
from pathlib import Path
from typing import TYPE_CHECKING

# Stdout/Stderr auf UTF-8 härten — sonst crashen Unicode-Symbole
# (z.B. Log-Emojis, Zuwachs-Pfeile) auf Windows-Konsolen mit cp1252.
# Muss zum frühest möglichen Zeitpunkt passieren, bevor irgendein
# print-Aufruf Unicode-Zeichen ausgibt.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

if TYPE_CHECKING:
    from apps.app_config import AppConfig
    from core.startup_window import StartupWindow

log = __import__("logging").getLogger("finlai.launcher")


def _smoke_test(config: AppConfig) -> None:
    """Führt einen Import-Rauchtest durch ohne GUI zu starten.

    Wird ausgelöst durch ``--smoke-test`` in ``sys.argv``.
    Importiert alle in ``config.tool_modules`` angegebenen Module und
    versucht die BaseTool-Subklasse zu laden. Beendet den Prozess mit
    Exit-Code 0 (Erfolg) oder 1 (fehlgeschlagene Imports).

    Args:
        config: AppConfig der zu testenden App.
    """
    import importlib

    failed: list[str] = []
    for module_path in config.tool_modules:
        try:
            importlib.import_module(module_path)
            log.debug("Smoke-Test OK: %s", module_path)
        except Exception as exc:  # noqa: BLE001 -- Smoke-Test soll JEDE Exception fangen + reporten
            log.error("Smoke-Test FAIL: %s — %s", module_path, exc)
            failed.append(module_path)

    if failed:
        print(
            f"[SMOKE-TEST FAILED] {config.app_name}: {len(failed)} Modul(e) fehlgeschlagen:"
        )
        for m in failed:
            print(f"  [FAIL] {m}")
        sys.exit(1)
    else:
        print(
            f"[SMOKE-TEST OK] {config.app_name}: alle {len(config.tool_modules)} Module importiert."
        )
        sys.exit(0)


def _resolve_ollama_url() -> str:
    """Liest die (validierte) Ollama-URL aus SecureStorage, sonst Default.

    Spiegelt das Verhalten der früheren Standalone-``OllamaPanel``: eine
    vom Nutzer hinterlegte (auch entfernte) Ollama-URL bleibt erhalten.

    Returns:
        Validierte Basis-URL des Ollama-Servers (Fallback ``OLLAMA_HOST``).
    """
    from core.config import OLLAMA_HOST  # noqa: PLC0415
    from core.security.encryption import get_secure_storage  # noqa: PLC0415
    from core.security.validators import validate_url  # noqa: PLC0415

    try:
        stored = get_secure_storage().get("ollama_base_url")
    except Exception:  # noqa: BLE001 — SecureStorage optional, Default genügt
        stored = None
    if stored:
        try:
            return validate_url(stored, allow_non_localhost=True)
        except ValueError:
            pass
    return OLLAMA_HOST


def _is_local_ollama(url: str) -> bool:
    """True, wenn ``url`` auf einen lokalen Ollama zeigt (localhost/127.0.0.1/::1).

    Nutzt denselben Validator wie die URL-Freigabe (kein Egress-Risiko-Duplikat):
    ``validate_url(..., allow_non_localhost=False)`` wirft für entfernte Hosts.

    Args:
        url: Die aufgelöste Ollama-Basis-URL.

    Returns:
        True bei lokalem Ollama, sonst False.
    """
    from core.security.validators import validate_url  # noqa: PLC0415

    try:
        validate_url(url, allow_non_localhost=False)
        return True
    except ValueError:
        return False


def _make_unified_assistant_factory(config: AppConfig):
    """Baut die parameterlose Factory für den vereinten FINLAI-Assistenten.

    Die Factory verdrahtet beim ERSTEN Öffnen des Assistenz-Reiters den
    ``tools/``-Handbuch-Retriever (Domäne Bedienung) und den Security-Korpus
    (Domäne Sicherheit) hinter einem ``RagService`` und übergibt beide dem
    ``UnifiedAssistantService``. Liegt am Composition-Root (``apps/``), weil nur
    hier aus ``tools/`` importiert werden darf — ``core/help`` bleibt
    tools-frei (Layering R5). Hier wird der LLM-gestützte 3-wertige Scope-
    Klassifikator (``make_ollama_domain_classifier``) live scharf geschaltet,
    da der Service ohne injiziertes Gate eines aus Client + Modell baut.

    Args:
        config: Aktive App-Konfiguration (liefert App-ID + Anzeigename).

    Returns:
        Parameterloses Callable, das einen frischen ``UnifiedAssistantService``
        liefert (Modell-Auflösung erfolgt lazy beim Aufruf, off-thread).
    """

    def _factory():
        from core.assistant.rag_service import (  # noqa: PLC0415
            RagService,
            SecurityCorpusRetriever,
        )
        from core.assistant.unified_assistant_service import (  # noqa: PLC0415
            UnifiedAssistantService,
        )
        from core.config import OLLAMA_HOST  # noqa: PLC0415
        from core.guardrails.guardrails import (  # noqa: PLC0415
            DOMAIN_HANDBOOK,
            DOMAIN_SECURITY,
        )
        from core.llm.ollama_client import OllamaClient  # noqa: PLC0415
        from core.ollama_utils import get_default_model  # noqa: PLC0415
        from tools.handbuch_assistent.application.handbook_retriever import (  # noqa: PLC0415
            HandbookRetriever,
        )

        url = _resolve_ollama_url()
        client = OllamaClient(url, allow_non_localhost=url != OLLAMA_HOST)
        rag = RagService(
            {
                # Default-Rolle „anwender"; die GESPERRTE_DOKUMENTE-Denyliste
                # bleibt im Loader für ALLE Rollen aktiv (Plan B-7).
                DOMAIN_HANDBOOK: HandbookRetriever(
                    role="anwender", app_name=config.app_id
                ),
                DOMAIN_SECURITY: SecurityCorpusRetriever(),
            }
        )
        # App-State: eigene Scores/Findings NUR bei LOKALEM Ollama in
        # den Assistenten-Kontext geben — kein Egress vertraulicher Ergebnisse an
        # einen entfernten Server. Bei Remote-URL bleibt der Provider None.
        findings_provider = None
        if _is_local_ollama(url):
            from apps.assistant_findings import (  # noqa: PLC0415
                build_self_findings_bundle,
            )
            from core.assistant.security_findings import (  # noqa: PLC0415
                CallableFindingsProvider,
            )

            findings_provider = CallableFindingsProvider(build_self_findings_bundle)
        else:
            log.info(
                "Ollama nicht lokal — App-Ergebnis-Kontext des Assistenten deaktiviert."
            )

        return UnifiedAssistantService(
            client=client,
            rag_service=rag,
            model=get_default_model() or "",
            app_display_name=config.display_name or config.app_name,
            findings_provider=findings_provider,
        )

    return _factory


def launch_app(config: AppConfig) -> None:
    """Startet eine FINLAI-App mit der gegebenen Konfiguration.

    Repliziert die Startup-Sequenz aus ``main.py``, lädt aber nur die in
    ``config.tool_modules`` aufgeführten Tools. Kann direkt aus den
    app-spezifischen Einstiegspunkten aufgerufen werden.

    Args:
        config: ``AppConfig``-Instanz für die zu startende App
                (z.B. ``FINLAI_CONFIG``, ``NORISK_CONFIG``, ``AUTOMATE_CONFIG``).
    """
    # Projektroot sicherstellen (wichtig wenn via ``python apps/xxx_app.py``)
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    # ── Defensive venv-Check (Bug-Fix 2026-04-28) ───────────────────────
    # Prueft ob das aktive Python-Interpreter zum repo-eigenen.venv gehoert.
    # Verhindert kryptische ModuleNotFoundError-Fehler wenn z.B. eine
    # PowerShell mit anderem aktivem venv (etwa automate's.venv) versehentlich
    # NoRisk startet -- Repo-spezifische Pakete wie feedparser sind dann nicht
    # da, was zur Tool-Registrierungs-Fehler fuehrt.
    _expected_python = (root / ".venv" / "Scripts" / "python.exe").resolve()
    _actual_python = Path(sys.executable).resolve()
    if _expected_python.exists() and _actual_python != _expected_python:
        log.warning(
            "Falsches Python-Interpreter aktiv!\n"
            "  Erwartet: %s\n"
            "  Aktuell:  %s\n"
            "Das fuehrt typisch zu 'ModuleNotFoundError' bei Repo-spezifischen "
            "Paketen. Loesung: NEUE PowerShell oeffnen ohne anderes aktives "
            "venv, dann '.\\.venv\\Scripts\\python apps\\<app>_app.py'.",
            _expected_python,
            _actual_python,
        )

    # ── Aktive App registrieren (wird von QuickstartWidget etc. genutzt) ─
    from apps.app_config import set_active_app  # noqa: PLC0415
    from core.database.db_context import set_db_app_id  # noqa: PLC0415
    from core.database.key_manager import (  # noqa: PLC0415
        KeyManager,
        KeyManagerError,
    )
    from core.database.key_manager_context import (
        set_active_key_manager,  # noqa: PLC0415
    )

    set_active_app(config)

    # ── Envelope-Encryption KeyManager bootstrap (Subtask 2 §2.5) ─
    # MUSS vor jedem EncryptedDatabase- oder SecureStorage-Konsumenten
    # laufen. Variante A (Modul-State, analog set_db_app_id): launch_app
    # erzeugt eine Instanz, set_active_key_manager macht sie an alle
    # Konsumenten verfuegbar. Im Cleanup-Bereich nach app.exec wird
    # km.wipe aufgerufen (RAM-DEK ueberschreiben).
    #
    # Subtask 3 §3): Zwischen initialize und
    # set_active_key_manager laeuft die Bestandsdaten-Migration. Andere
    # Komponenten duerfen erst nach abgeschlossener Migration DBs
    # oeffnen — der Modul-State wird deshalb erst danach gesetzt.
    #
    # Bei Bootstrap-Fehler harter Fail: QApplication existiert hier noch
    # nicht (kein User-Dialog moeglich). trennt drei Fail-Typen mit
    # eigenen Recovery-Hinweisen:
    # * RuntimeError aus ``KeyManager``-Konstruktor (select_backend) —
    # Plattform nicht unterstuetzt (Cross-Platform-1.x-relevant).
    # * KeyManagerError aus initialize / migrate_legacy_db — Backend-
    # Wrap-/DPAPI-Pfad. Wording haengt davon ab, ob Migration schon
    # gelaufen ist (Variable ``migration_started``).
    # * OSError/RuntimeError aus Migration (FS-Probleme, Backup-Race).
    migration_started = False
    try:
        _key_manager = KeyManager()
        _key_manager.initialize()

        # Subtask 3.5 — Bestandsdaten-Migration (Pflicht bei jedem App-Start,
        # idempotent via migration-state.json).
        from core.database.migrate_to_envelope import (  # noqa: PLC0415
            run_bootstrap_migration,
        )

        migration_started = True
        run_bootstrap_migration(_key_manager, config.app_id)

        # Raw-Key-Umstellung: Bestands-DBs im alten String-Key/PBKDF2-
        # Format beiseiteschieben (Backup), damit die App sie Raw-Key frisch neu
        # anlegt (~93 ms → ~2 ms pro DB-Open). Idempotent via.rawkey-Marker.
        # Laeuft NACH der Legacy→DEK-Migration und VOR set_active_key_manager,
        # damit kein Konsument eine DB oeffnet, bevor die Umstellung durch ist.
        from core.database.migration_rawkey import (  # noqa: PLC0415
            discard_pre_rawkey_databases,
        )

        discard_pre_rawkey_databases(_key_manager, config.app_id)

        set_active_key_manager(_key_manager)
        log.info("KeyManager initialisiert (Envelope Encryption ADR-007).")
    except KeyManagerError as exc:
        if migration_started:
            # Mid-migration KeyManagerError (z. B. DPAPI-Crash zur Laufzeit).
            # NICHT zum Loeschen von master.key.wrapped raten — der DEK ist
            # weiterhin der einzige Schluessel fuer schon migrierte DBs.
            log.error(
                "KeyManager-Fehler waehrend der Bestandsdaten-Migration: "
                "%s (%s). Migration ist NICHT vollstaendig — schon migrierte "
                "DBs bleiben mit dem aktuellen DEK lesbar, noch nicht "
                "migrierte DBs sind unberuehrt. Recovery: App neu starten — "
                "die Migration ist idempotent und nimmt den State "
                "(~/.finlai/migration-state.json) automatisch wieder auf. "
                "Wenn das Problem persistent ist, ~/.finlai/migration-*.log "
                "konsultieren bevor master.key.wrapped angefasst wird.",
                type(exc).__name__,
                exc,
            )
        else:
            # KeyManager-Bootstrap (initialize) fehlgeschlagen — DEK gar
            # nicht erst geladen. Recovery via master.key.wrapped-Reset
            # ist hier sicher, weil noch nichts mit dem DEK migriert wurde.
            log.error(
                "KeyManager-Bootstrap fehlgeschlagen: %s (%s) — App kann "
                "nicht starten. Moegliche Ursachen: Windows-User-Profile-"
                "Wechsel, Filesystem-Permissions auf "
                "~/.finlai/master.key.wrapped. Recovery: "
                "~/.finlai/master.key.wrapped manuell loeschen und App neu "
                "starten — der KeyManager initialisiert dann einen neuen "
                "DEK. ACHTUNG: Bestandsdaten in ~/.finlai/db/ sind danach "
                "nur ueber das letzte .pre-envelope-backup-*-Verzeichnis "
                "recoverable.",
                type(exc).__name__,
                exc,
            )
        sys.exit(1)
    except RuntimeError as exc:
        # Bootstrap-except: ``select_backend`` im KeyManager-
        # Konstruktor wirft ``RuntimeError`` auf nicht unterstuetzten
        # Plattformen. Auf Windows-only Production heute nicht relevant —
        # bei Cross-Platform 1.x (macOS Keychain, Linux libsecret) wird
        # das aktiv.
        if not migration_started:
            log.error(
                "KeyManager-Backend-Init fehlgeschlagen: %s (%s). "
                "Vermutlich nicht unterstuetzte Plattform fuer das aktuelle "
                "FINLAI-Build. Cross-Platform-Support ist fuer 1.x geplant; "
                "fuer 1.0 nutze bitte die Windows-Build.",
                type(exc).__name__,
                exc,
            )
        else:
            # Migration-Phase: gleiche Recovery-Hinweise wie OSError.
            log.error(
                "Bestandsdaten-Migration fehlgeschlagen: %s (%s). "
                "Bitte ~/.finlai/migration-*.log konsultieren. Manuelle "
                "Recovery aus dem letzten ~/.finlai/db/<app>/.pre-envelope-"
                "backup-*-Verzeichnis ist moeglich.",
                type(exc).__name__,
                exc,
            )
        sys.exit(1)
    except OSError as exc:
        log.error(
            "Bestandsdaten-Migration fehlgeschlagen: %s (%s). "
            "Bitte ~/.finlai/migration-*.log konsultieren. Manuelle "
            "Recovery aus dem letzten ~/.finlai/db/<app>/.pre-envelope-"
            "backup-*-Verzeichnis ist moeglich.",
            type(exc).__name__,
            exc,
        )
        sys.exit(1)

    # DB-Isolation: Jede App bekommt ihr eigenes Unterverzeichnis
    # ~/.finlai/db/<app_id>/ — verhindert Cross-Contamination zwischen Apps.
    set_db_app_id(config.app_id)

    # HelpRegistry explizit befüllen (statt Modul-Import-Seiteneffekt).
    from core.help.help_registry import (
        init_registry as _init_help_registry,  # noqa: PLC0415
    )

    _init_help_registry()

    # ── --smoke-test: Imports prüfen, keine GUI starten ──────────────────
    if "--smoke-test" in sys.argv:
        _smoke_test(config)
        return

    # ── 0. SQLCipher-Verfügbarkeit prüfen ───────────────────────────────
    from core.database.db_check import check_sqlcipher_available  # noqa: PLC0415

    check_sqlcipher_available()

    # ── 0a. DB-Konsolidierung: einmaliger Alt-DB-Wipe ────────────
    # Per-Tool-DBs sind in EINE norisk-DB konsolidiert (network_monitor +
    # system_tuner_snapshots bleiben separat). Daten verzichtbar (Pre-Prod) ->
    # alte Per-Tool-Dateien einmalig loeschen, BEVOR ein Repo schreibt.
    # Idempotent (Sentinel), fail-soft: darf den Start nie blocken.
    try:
        from core.database.encrypted_db import (  # noqa: PLC0415
            purge_consolidated_legacy_dbs,
        )

        purge_consolidated_legacy_dbs()
    except Exception:  # noqa: BLE001 -- Cleanup darf den App-Start nie verhindern
        log.warning("ADR-037 Alt-DB-Cleanup uebersprungen", exc_info=True)

    # ── 0b. Subjekt-Backfill (idempotent, marker-gesichert je DB) ──
    # Verknuepft Bestandsdaten (Org/Scores/Hardening + Audits) mit der
    # kanonischen ``subject_id``. Reihenfolge: security_scoring zuerst (haelt
    # den Subjekt-Store), dann customer_audit. Laeuft erst hier — nach
    # ``set_db_app_id`` (richtige DB-Instanz), nach dem ``--smoke-test``-Return
    # und nach dem SQLCipher-Check. Fail-soft: darf den App-Start nie blocken;
    # ab dem 2. Start No-op (Marker). Pre-Migration-Backup ist durch
    # ``run_bootstrap_migration`` oben bereits abgedeckt.
    try:
        from tools.customer_audit.application.subject_backfill import (  # noqa: PLC0415
            run_audit_subject_backfill,
        )
        from tools.security_scoring.application.subject_backfill import (  # noqa: PLC0415
            run_subject_backfill,
        )

        run_subject_backfill()
        run_audit_subject_backfill()
    except Exception as exc:  # noqa: BLE001 — Backfill darf den Start nie blocken
        log.warning("T-294 Subjekt-Backfill uebersprungen: %s", type(exc).__name__)

    # ── 1. QApplication + Fonts + Theme ────────────────────────────────
    # QWebEngineView auf Windows: GPU-Sandbox deaktivieren damit YouTube-Videos laden.
    # Beide Env-Vars MÜSSEN vor QApplication gesetzt sein.
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --no-sandbox")
    os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
    log.info(
        "QTWEBENGINE_CHROMIUM_FLAGS = %s",
        os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS"),
    )

    # QtWebEngineProcess-Verfügbarkeit prüfen (nur auf Windows relevant).
    if sys.platform == "win32":
        try:
            from pathlib import Path as _Path  # noqa: PLC0415

            import PySide6 as _pyside6  # noqa: PLC0415

            _qwep = _Path(_pyside6.__file__).parent / "QtWebEngineProcess.exe"
            if not _qwep.exists():
                log.warning(
                    "QtWebEngineProcess.exe nicht gefunden unter %s — "
                    "eingebettete Videos werden NICHT funktionieren. "
                    "Bitte App aus venv starten: "
                    ".venv\\Scripts\\python apps\\norisk_app.py",
                    _qwep,
                )
            else:
                log.debug("QtWebEngineProcess.exe gefunden: %s", _qwep)
        except (ImportError, AttributeError, OSError):
            log.debug("QtWebEngineProcess-Check konnte nicht durchgeführt werden.")

    from PySide6.QtGui import QFont  # noqa: PLC0415
    from PySide6.QtWidgets import QApplication  # noqa: PLC0415

    from core import fonts, theme  # noqa: PLC0415
    from core.ui_settings import UISettings  # noqa: PLC0415

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(config.app_name)
    app.setOrganizationName("FINLAI designs")
    app.setFont(QFont("Raleway", 13))

    # Crash-Handler so frueh wie moeglich nach
    # QApplication-Init installieren. Excepthook fuer Python-Exceptions
    # plus Qt-Message-Handler fuer Fatal-Logs. Der eigentliche
    # CrashDialog wird erst nach MainWindow-Init verdrahtet (
    # unten ``set_dialog_trigger``).
    from core.crash_handler import (  # noqa: PLC0415
        install_excepthook,
        install_faulthandler,
        install_qt_message_handler,
    )

    install_excepthook()
    install_qt_message_handler()
    # Nativer Crash-Dump (Segfault/Abort auf C-Ebene) — der Excepthook faengt
    # nur Python-Exceptions; ein Qt-/SQLCipher-Thread-Crash bleibt sonst spurlos.
    install_faulthandler()

    _icon_path = Path(config.icon_path)
    if not _icon_path.is_absolute():
        _icon_path = Path(__file__).parent.parent / _icon_path
    if _icon_path.exists():
        from PySide6.QtGui import QIcon  # noqa: PLC0415

        app.setWindowIcon(QIcon(str(_icon_path)))

    fonts.load()
    _ui_settings = UISettings.load()

    if config.accent_color:
        theme.set_accent_color(config.accent_color)

    theme.apply(app, _ui_settings.theme)

    # ════════════════════════════════════════════════════════════════════
    # STARTUP-FENSTER — Pre-Login (Seite 0: Ladescreen)
    # Ein einziges Fenster für den gesamten Startup-Lifecycle.
    # Zeige sofort nach QApplication-Setup; kein separates Login-Fenster.
    # ════════════════════════════════════════════════════════════════════
    from core.startup_window import StartupWindow  # noqa: PLC0415

    startup = StartupWindow(config)
    startup.show_centered()  # zentriert statt showMaximized (deckt Schirm nicht ab)
    app.processEvents()  # Sofort rendern — ab hier läuft Initialisierung
    _pre_start = _time.monotonic()

    # ── 2a. Nutzungsvereinbarung ────────────────────────────────────────
    startup.set_progress(10, "Nutzungsvereinbarung …")
    app.processEvents()

    from PySide6.QtWidgets import QDialog  # noqa: PLC0415

    from core.legal.agreement_dialog import AgreementDialog  # noqa: PLC0415

    if not _ui_settings.terms_accepted:
        from datetime import datetime  # noqa: PLC0415

        # eingebettet ins StartupWindow statt modalem exec — der
        # Dialog erscheint als zentrierte Karte im nicht-maximierten Fenster.
        terms_dlg = AgreementDialog(mode="terms", read_only=False, parent=startup)
        if (
            startup.run_embedded(terms_dlg) != QDialog.DialogCode.Accepted
            or not terms_dlg.was_accepted
        ):
            startup.close()
            sys.exit(0)
        _ui_settings.terms_accepted = datetime.now().isoformat(timespec="seconds")
        _ui_settings.terms_version = "1.0"
        _ui_settings.save()

    # ── 2b. Datenschutzerklärung ─────────────────────────────────────────
    startup.set_progress(20, "Datenschutzerklärung …")
    app.processEvents()

    if not _ui_settings.privacy_accepted:
        from datetime import datetime  # noqa: PLC0415

        privacy_dlg = AgreementDialog(mode="privacy", read_only=False, parent=startup)
        if (
            startup.run_embedded(privacy_dlg) != QDialog.DialogCode.Accepted
            or not privacy_dlg.was_accepted
        ):
            startup.close()
            sys.exit(0)
        _ui_settings.privacy_accepted = datetime.now().isoformat(timespec="seconds")
        _ui_settings.save()

    # ── 2c. DSGVO-Hinweis ────────────────────────────────────────────────
    startup.set_progress(30, "Datenschutz wird geprüft …")
    app.processEvents()

    from core.gdpr import GDPRManager  # noqa: PLC0415

    gdpr = GDPRManager()
    if not gdpr.show_first_run_dialog(
        app, parent=startup, runner=startup.run_embedded
    ):
        startup.close()
        sys.exit(0)

    # ── 2d. First-Run-Wizard (vor der Lizenzprüfung) ─────────────────────
    startup.set_progress(40, "Ersteinrichtung …")
    app.processEvents()

    from core.audit_log import AuditLogger  # noqa: PLC0415
    from core.first_run_wizard import (  # noqa: PLC0415
        adopt_legacy_users,
        needs_first_run,
        run_first_run_wizard,
    )

    # B-STAR: Legacy-User (Pre-, ohne created_by_app-Marker) einmalig
    # + geguardet adoptieren (eigene DB-Bestandsdaten, kein Fremd-App-Marker),
    # damit der Wizard nicht trotz vorhandener Benutzer + DB erzwungen wird.
    # Idempotent — laeuft bei jedem Start, tut aber nur beim ersten Update
    # einer Legacy-Installation etwas.
    _adopted = adopt_legacy_users(config.app_id)
    if _adopted:
        log.info("B-START-1: %d Legacy-User adoptiert — Wizard entfaellt.", _adopted)

    _first_run_username: str | None = None
    if needs_first_run(app_id=config.app_id):
        log.info("First-Run-Wizard wird gestartet.")
        _fr_result = run_first_run_wizard(
            app_name=config.app_name, parent=startup, runner=startup.run_embedded
        )
        if not _fr_result.completed:
            AuditLogger().log_action("FIRST_RUN_ABORTED", {"app_id": config.app_id})
            startup.close()
            sys.exit(0)
        _first_run_username = _fr_result.username
        if _first_run_username:
            _ui_settings.update_username(_first_run_username)
            gdpr.update_username(_first_run_username)

    # ── 2e. (entfällt) Lizenzprüfung ─────────────────────────────────────
    # Single-Tenant-OSS — kein Startup-Lizenz-Gate mehr.
    # Früher stand hier: NoRisk-Beta-Guard + ``LicenseValidator.validate`` +
    # ``LicenseDialog`` + Trial-Banner + ``sys.exit(1)`` bei ungültiger Lizenz.
    # Ersatzlos entfernt, damit der OSS-Build ohne ``license.json`` startet
    # (kein nicht-startbarer Erstnutzer). Die Activation-/beta_mode-/Validator-
    # Module bleiben vorerst inert; ihr vollständiger Rückbau folgt in (d).

    # ── 2f. App-Start protokollieren ─────────────────────────────────────
    AuditLogger().log_action("APP_START", {"app_id": config.app_id})

    # ── 2g. App-spezifische Dienste starten ──────────────────────────────
    startup.set_progress(70, "Dienste werden gestartet …")
    app.processEvents()

    handbuch_service = None

    # Perf (Tier 3): die KI-Verzeichnis-Generierung lief synchron in der
    # Startup-Schleife (kann den 70%-Schritt auf langsamen Systemen blocken).
    # Das Verzeichnis wird erst im (lazy) Einstellungen-Tab gebraucht -> in einen
    # Daemon-Thread (analog HandbuchInit darunter). Fail-soft.
    def _generiere_ki_verzeichnis() -> None:
        try:
            from core.ki_verzeichnis.ki_verzeichnis_service import (  # noqa: PLC0415
                KiVerzeichnisService,
            )

            KiVerzeichnisService().generiere_verzeichnis()
        except Exception:  # noqa: BLE001 -- Hintergrund-Gen darf den Start nie stoeren
            log.debug(
                "KI-Verzeichnis konnte nicht generiert werden.", exc_info=True
            )

    threading.Thread(
        target=_generiere_ki_verzeichnis,
        daemon=True,
        name="KiVerzeichnisGen",
    ).start()

    try:
        from tools.handbuch_assistent.application.handbuch_service import (  # noqa: PLC0415
            HandbuchService,
        )

        handbuch_service = HandbuchService()
        threading.Thread(
            target=handbuch_service.initialize,
            kwargs={"role": "all"},
            daemon=True,
            name="HandbuchInit",
        ).start()
        import types  # noqa: PLC0415

        _main_mod = sys.modules.get("main")
        if _main_mod is None:
            _main_mod = types.ModuleType("main")
            _main_mod.handbuch_service = None
            sys.modules["main"] = _main_mod
        _main_mod.handbuch_service = handbuch_service
        log.debug("Handbuch-Service gestartet.")
    except (ImportError, RuntimeError, OSError):
        log.debug("Handbuch-Service nicht verfügbar.")

    # ── 2g-bis. Vereinter FINLAI-Assistent: Service-Factory registrieren ──
    #/C: EINE Service-Instanz, lazy beim ersten Öffnen des Assistenz-
    # Reiters gebaut. Hier wird nur die Factory hinterlegt — der eigentliche
    # Aufbau (Ollama-Client, RAG-Retriever, Scope-Gate) erfolgt off-thread im
    # Worker, sobald der Nutzer den Reiter „FINLAI-Assistent" nutzt.
    try:
        from core.assistant.provider import (  # noqa: PLC0415
            register_assistant_factory,
        )

        register_assistant_factory(_make_unified_assistant_factory(config))
        log.debug("Assistenz-Factory registriert.")
    except (ImportError, RuntimeError):
        log.debug("Assistenz-Factory nicht verfügbar.")

    # ── Bereit für Anmeldung — Mindest-Anzeigezeit sicherstellen ─────────
    # StartupWindow wechselt jetzt zur Login-Seite (Seite 1).
    startup.set_progress(85, "Bereit für Anmeldung.")
    app.processEvents()

    # Mindest-Anzeigezeit: 500 ms ab erster Anzeige.
    # processEvents-Loop statt sleep damit Qt-Events weiter verarbeitet werden.
    _elapsed = _time.monotonic() - _pre_start
    if _elapsed < 0.5:
        _deadline = _pre_start + 0.5
        while _time.monotonic() < _deadline:
            app.processEvents()

    startup.show_login(prefill_username=_first_run_username)  # Wechsel zu Seite 1 (Login)

    # ════════════════════════════════════════════════════════════════════
    # EVENT-LOOP — _AppController verbindet sich mit StartupWindow-Signals
    # Kein login.exec — der Login ist jetzt event-getrieben in app.exec
    # ════════════════════════════════════════════════════════════════════
    controller = _AppController(
        app,
        config,
        startup=startup,
        first_run_username=_first_run_username,
    )
    exit_code = controller.run()

    # ── Dienste beenden + App-Exit protokollieren ─────────────────────
    if handbuch_service is not None:
        try:
            handbuch_service.shutdown()
        except (RuntimeError, OSError):
            pass

    # KeyManager-Cleanup (Subtask 2): Modul-State leeren, RAM-DEK
    # ueberschreiben (best-effort, siehe key_manager.wipe-Doc). Wipe
    # geht ueber den **aktiven** KeyManager, weil ein Logout-Re-Login
    #.3) die ``_key_manager``-Instanz ausgetauscht haben kann.
    # Defensive try/except, weil Cleanup-Phase keine zusaetzlichen
    # Crashes erzeugen darf — sys.exit(exit_code) muss noch laufen.
    try:
        from core.database.key_manager_context import (  # noqa: PLC0415
            get_active_key_manager,
        )

        try:
            current_km = get_active_key_manager()
        except RuntimeError:
            current_km = _key_manager
        set_active_key_manager(None)
        current_km.wipe()
    except (RuntimeError, AttributeError) as exc:
        log.debug("KeyManager-Cleanup ignoriert: %s", type(exc).__name__)

    AuditLogger().log_action("APP_EXIT", {"app_id": config.app_id})
    sys.exit(exit_code)


class _AppController:
    """Login-Logout-Lebenszyklus für einen konfigurierten App-Start.

    Ersetzt den alten Blocking-Login-Flow durch ein event-getriebenes Modell:
    ``StartupWindow`` emittiert ``login_successful`` / ``login_cancelled`` —
    ``_AppController`` verbindet sich damit und startet erst danach ``app.exec``.

    Attributes:
        _app: Laufende QApplication.
        _config: AppConfig der gestarteten App.
        _startup: StartupWindow des initialen Starts (None nach Abschluss).
        _window: Aktives MainWindow (oder None).
    """

    def __init__(
        self,
        app,
        config: AppConfig,
        startup: StartupWindow,
        first_run_username: str | None = None,
    ) -> None:
        """Initialisiert den AppController.

        Args:
            app: Laufende QApplication-Instanz.
            config: AppConfig der zu startenden App.
            startup: Bereits sichtbares StartupWindow (Login-Seite aktiv).
                     Wird nach erfolgreichem ersten Login für die Post-Login-
                     Animation (80–100 %) genutzt und danach geschlossen.
            first_run_username: Benutzername des gerade im Wizard angelegten
                     Admins (oder ``None``). Wird beim ersten Login für die
                     ``first_login``-Variante des Willkommens-Toasts gebraucht.
        """
        self._app = app
        self._config = config
        self._startup = startup
        self._window = None
        self._first_run_username = first_run_username
        self._welcome_toast = None

    def run(self) -> int:
        """Verbindet StartupWindow-Signale und startet den Qt-Event-Loop.

        Kein blockierendes LoginWindow.exec mehr — der Login läuft event-
        getrieben innerhalb von app.exec.

        Returns:
            Exit-Code der Applikation.
        """
        self._startup.login_successful.connect(self._on_login_success)
        self._startup.login_cancelled.connect(self._on_login_cancelled)
        return self._app.exec()

    # ------------------------------------------------------------------
    # Signal-Handler für StartupWindow
    # ------------------------------------------------------------------

    def _on_login_success(self, username: str, role: str) -> None:  # noqa: ARG002
        """Reagiert auf erfolgreiches Login: Ladescreen + MainWindow aufbauen.

        Args:
            username: Eingeloggter Benutzername (für Logging).
            role: Rolle des Benutzers (nicht weiter verwendet hier).
        """
        from PySide6.QtWidgets import QApplication as _QApp  # noqa: PLC0415

        from core.main_window import MainWindow  # noqa: PLC0415
        from core.tool_registry import ToolRegistry  # noqa: PLC0415

        # Patch-Inventory-Lifecycle aus der apps-Schicht in MainWindow
        # injizieren -> core importiert tools.patch_monitor nicht mehr.
        from tools.patch_monitor.gui.inventory_setup import (  # noqa: PLC0415
            setup_patch_inventory,
            teardown_patch_inventory,
        )

        if self._window is not None:
            self._window.close()
            self._window.deleteLater()

        # Zurück zu Seite 0 (Ladescreen) — StartupWindow bleibt sichtbar
        self._startup.show_loading()
        _QApp.processEvents()  # Ladescreen sofort rendern bevor MainWindow gebaut wird

        # Tool-Registry + MainWindow aufbauen (StartupWindow verdeckt alles).
        # KEIN weiteres processEvents — MainWindow darf nicht sichtbar werden.
        registry = ToolRegistry()
        for module_path in self._config.tool_modules:
            try:
                registry.register_from_module(module_path)
            except Exception:  # noqa: BLE001 -- Tool-Code kann beliebig werfen, App darf nicht crashen
                log.exception("Tool-Registrierung fehlgeschlagen: %s", module_path)

        self._window = MainWindow(
            registry,
            config=self._config,
            patch_inventory_setup=setup_patch_inventory,
            patch_inventory_teardown=teardown_patch_inventory,
        )
        self._window.logout_requested.connect(self._on_logout)
        # MainWindow bleibt unsichtbar — show erst in _lade_fertig

        # Crash-Dialog mit dem fertigen MainWindow
        # als Parent verdrahten. Davor war ``set_dialog_trigger`` noch
        # nicht gesetzt — Excepthook hat in der Startup-Phase nur ins
        # Log geschrieben (kein Dialog vor Window-Init).
        from core.crash_handler import set_dialog_trigger  # noqa: PLC0415
        from core.widgets.crash_dialog import show_crash_dialog  # noqa: PLC0415

        _mw_ref = self._window
        set_dialog_trigger(
            lambda title, message: show_crash_dialog(title, message, parent=_mw_ref)
        )

        # Post-Login-Animation (80 → 100 %) startet als Timer im laufenden
        # Event-Loop. _lade_fertig zeigt MainWindow und schließt StartupWindow —
        # alles in einer Event-Handler-Ausführung ohne Lücke (kein Flash).
        _startup_ref = self._startup

        def _lade_fertig() -> None:
            self._window.show()
            _startup_ref.close()
            _startup_ref.deleteLater()
            self._startup = None
            self._show_welcome_toast(username)
            if not os.environ.get("FINLAI_DEV"):
                try:
                    from core.updater_dialog import (  # noqa: PLC0415
                        start_background_check,
                    )

                    start_background_check(self._window, self._config)
                except (ImportError, RuntimeError, OSError):
                    log.debug("Update-Check konnte nicht gestartet werden.")

        self._startup.run_post_login_sequence(on_done=_lade_fertig)

    def _show_welcome_toast(self, username: str) -> None:
        """Zeigt den Willkommens-Toast 300 ms nach MainWindow.show.

        Defensive Guards:
            * Kein Toast wenn ``Session.current_user`` leer ist.
            * Kein Toast wenn der Vorname des Benutzers leer ist — so wird
              beim allerersten App-Start (vor First-Run-Wizard kann der
              Toast ohnehin nicht getriggert werden, aber doppelter Schutz
              schadet nicht) niemals eine unpersönliche Nachricht angezeigt.
        """
        from PySide6.QtCore import QTimer  # noqa: PLC0415

        from core.auth.session import Session  # noqa: PLC0415
        from core.auth.user_store import UserStore  # noqa: PLC0415
        from core.widgets.welcome_toast import WelcomeToast  # noqa: PLC0415

        if Session().current_user is None:
            log.debug("Welcome-Toast übersprungen: kein aktiver User in Session.")
            return

        try:
            user = UserStore().get_user(username)
        except (LookupError, RuntimeError, OSError):
            user = None
        first_name = (user.first_name if user else "").strip()
        if not first_name:
            log.debug(
                "Welcome-Toast übersprungen: first_name leer für '%s'.",
                username,
            )
            return

        app_display_name = self._config.display_name or self._config.app_name

        is_first_login = (
            self._first_run_username is not None
            and username == self._first_run_username
        )
        # Einmalig konsumieren — ab dem zweiten Login ist es ein regulärer Start.
        if is_first_login:
            self._first_run_username = None

        def _spawn() -> None:
            self._welcome_toast = WelcomeToast(
                first_name=first_name,
                first_login=is_first_login,
                app_display_name=app_display_name,
                parent=None,
            )
            self._welcome_toast.show_toast(username)

        QTimer.singleShot(300, _spawn)

    def _on_login_cancelled(self) -> None:
        """Reagiert auf abgebrochenen Login: StartupWindow schließen, App beenden."""
        from PySide6.QtWidgets import QApplication  # noqa: PLC0415

        if self._startup is not None:
            self._startup.close()
            self._startup.deleteLater()
            self._startup = None
        QApplication.quit()

    # ------------------------------------------------------------------
    # Logout → Re-Login mit klassischem LoginWindow-Dialog
    # ------------------------------------------------------------------

    def _on_logout(self) -> None:
        """Behandelt den Logout-Wunsch: Session beenden, Re-Login via Dialog."""
        from PySide6.QtWidgets import QApplication  # noqa: PLC0415

        from core.audit_log import AuditLogger  # noqa: PLC0415
        from core.auth.session import Session  # noqa: PLC0415
        from core.database.key_manager_context import (  # noqa: PLC0415
            get_active_key_manager,
            set_active_key_manager,
        )

        user = Session().current_user
        if user:
            AuditLogger().log_action("USER_LOGOUT", {"username": user.username})
        Session().logout()

        #.3 — Memory-Hygiene: aktiven KeyManager wipen + Modul-State
        # leeren, damit der RAM-DEK nicht ueber den Logout hinaus liegen
        # bleibt. Re-Login bootstrapt eine frische Instanz in
        #:meth:`_show_relogin`. Defensive try/except, weil Logout-Pfad
        # keinen zusaetzlichen Crash erzeugen darf — Re-Login muss laufen.
        try:
            old_km = get_active_key_manager()
        except RuntimeError:
            old_km = None
        try:
            set_active_key_manager(None)
            if old_km is not None:
                old_km.wipe()
        except (RuntimeError, AttributeError) as exc:
            log.debug(
                "KeyManager-Wipe beim Logout ignoriert: %s",
                type(exc).__name__,
            )

        if self._window is not None:
            self._window.hide()

        if not self._show_relogin():
            # Re-Login nach Logout abgebrochen → app.exec beenden
            QApplication.quit()

    def _show_relogin(self) -> bool:
        """Zeigt den klassischen LoginWindow-Dialog für Re-Login nach Logout.

        Verwendet ``LoginWindow`` (QDialog, blockierend via exec) —
        das StartupWindow ist zu diesem Zeitpunkt bereits geschlossen.

        Returns:
            True wenn Re-Login erfolgreich, False wenn abgebrochen.
        """
        from PySide6.QtWidgets import QApplication as _QApp  # noqa: PLC0415
        from PySide6.QtWidgets import QDialog  # noqa: PLC0415

        from core.auth.login_window import LoginWindow  # noqa: PLC0415
        from core.database.key_manager import (  # noqa: PLC0415
            KeyManager,
            KeyManagerError,
        )
        from core.database.key_manager_context import (  # noqa: PLC0415
            set_active_key_manager,
        )
        from core.loading_overlay import AppLoadingOverlay  # noqa: PLC0415
        from core.main_window import MainWindow  # noqa: PLC0415
        from core.tool_registry import ToolRegistry  # noqa: PLC0415

        # Patch-Inventory-Lifecycle aus der apps-Schicht in MainWindow
        # injizieren -> core importiert tools.patch_monitor nicht mehr.
        from tools.patch_monitor.gui.inventory_setup import (  # noqa: PLC0415
            setup_patch_inventory,
            teardown_patch_inventory,
        )

        #.3 — Frische KeyManager-Instanz fuer die neue Session.
        # LoginWindow liest user_store via EncryptedDatabase, braucht den
        # aktiven KeyManager VOR dem Dialog-Aufruf. Migration laeuft hier
        # nicht erneut — die ist beim ersten launch_app-Bootstrap
        # erledigt und im migration-state.json als completed markiert.
        try:
            new_km = KeyManager()
            new_km.initialize()
            set_active_key_manager(new_km)
        except (KeyManagerError, RuntimeError) as exc:
            log.error(
                "Re-Login KeyManager-Bootstrap fehlgeschlagen: %s (%s) — "
                "App kann nach Logout nicht weiter laufen.",
                type(exc).__name__,
                exc,
            )
            return False

        login = LoginWindow(app_name=self._config.app_name)
        if login.exec() != QDialog.DialogCode.Accepted:
            return False

        if self._window is not None:
            self._window.close()
            self._window.deleteLater()

        registry = ToolRegistry()
        for module_path in self._config.tool_modules:
            try:
                registry.register_from_module(module_path)
            except Exception:  # noqa: BLE001 -- Tool-Code kann beliebig werfen, App darf nicht crashen
                log.exception("Tool-Registrierung fehlgeschlagen: %s", module_path)

        self._window = MainWindow(
            registry,
            config=self._config,
            patch_inventory_setup=setup_patch_inventory,
            patch_inventory_teardown=teardown_patch_inventory,
        )
        self._window.logout_requested.connect(self._on_logout)

        # Re-Login-Ladescreen als Kind des MainWindow — deckt nur das
        # Fenster ab, nie den ganzen Bildschirm (kein Standalone-Vollbild-Overlay
        # mit StaysOnTop mehr). Der Nutzer kann jederzeit zu anderen Apps wechseln.
        overlay = AppLoadingOverlay(self._config, parent=self._window)
        self._window.show()
        overlay.resize(self._window.size())
        overlay.raise_()
        overlay.show()
        _QApp.processEvents()

        _used_overlay = overlay

        def _lade_fertig() -> None:
            _used_overlay.hide()
            _used_overlay.deleteLater()
            from core.auth.session import Session  # noqa: PLC0415

            _user = Session().current_user
            if _user is not None:
                self._show_welcome_toast(_user.username)
            if not os.environ.get("FINLAI_DEV"):
                try:
                    from core.updater_dialog import (  # noqa: PLC0415
                        start_background_check,
                    )

                    start_background_check(self._window, self._config)
                except (ImportError, RuntimeError, OSError):
                    log.debug("Update-Check konnte nicht gestartet werden.")

        overlay.run_sequence(on_done=_lade_fertig)
        return True
