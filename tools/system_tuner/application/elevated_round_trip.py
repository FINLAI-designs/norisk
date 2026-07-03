"""
elevated_round_trip — GUI↔elevated Apply-Round-Trip (R5/R6/R7/T5/T8 + A2–A5).

GUI-Seite (`request_elevated_apply`): bindet den bestaetigten Plan (HMAC, Token),
schreibt ihn als ``plan_<token>.json`` (user-schreibbar; durch HMAC + Single-Use
+ Ledger + Re-Resolve geschuetzt), startet die App elevated neu und pollt den
**signierten** Ergebnis-Marker in der admin-only Ablage.

Elevated-Seite (`run_apply_entry`):
1. DLL-Suchpfad haerten (T8) **zuerst**.
2. **A3** Admin-Pflicht + Pfad-Trust des Laufzeit-Images (sonst fail-closed).
3. **A5** admin-only Ablage (`%ProgramData%\\NoRisk`) herstellen.
4. Plan lesen + **loeschen** (Single-Use T5).
5. **A4** Consent-Gate (R7) — fail-closed.
6. **A2** Token-Ledger: Replay-Token ablehnen, Token VOR Apply eintragen.
7. Signatur (R3) + Plan-Binding + Re-Resolve + Restore-Point (R6) + Engine-Apply.
8. **A5c** signierten Ergebnis-Marker schreiben.

Schichtzugehoerigkeit: application/.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import uuid
from pathlib import Path

from core.database.key_manager import KeyManager
from core.database.key_manager_context import (
    get_active_key_manager,
    set_active_key_manager,
)
from core.elevation import is_admin, relaunch_elevated
from core.exceptions import ConfigurationError
from core.finlai_paths import finlai_dir
from core.logger import get_logger
from core.win_security import assess_install_path_trust, harden_dll_search_path
from tools.system_tuner.application.apply_plan import bind_plan
from tools.system_tuner.application.catalog_loader import (
    default_catalog_path,
    default_signature_path,
    load_catalog,
)
from tools.system_tuner.application.consent_gate import (
    CURRENT_EULA_VERSION,
    ConsentGate,
)
from tools.system_tuner.application.elevated_apply import run_elevated_apply
from tools.system_tuner.data.catalog_signature import verify_catalog
from tools.system_tuner.data.encrypted_snapshot_repo import EncryptedSnapshotRepository
from tools.system_tuner.data.restore_point import create_restore_point
from tools.system_tuner.data.secure_store import ensure_secure_dir, secure_dir
from tools.system_tuner.data.token_ledger import FileTokenLedger
from tools.system_tuner.data.windows_tweak_probe import WindowsTweakProbe
from tools.system_tuner.domain.apply_entities import BatchResult, TweakResult
from tools.system_tuner.domain.enums import TweakStatus

log = get_logger(__name__)

_APPLY_FLAG = "--system-tuner-apply"

#: HKDF-Purpose des HMAC-Geheimnisses (Plan-Binding + Ergebnis-Marker), aus dem
#: envelope-DEK abgeleitet. Single-Source fuer GUI- und elevated-Seite.
_APPLY_HMAC_PURPOSE = "system_tuner:apply_hmac"


def _resolve_key_manager() -> KeyManager:
    """Liefert den aktiven KeyManager oder bootet ihn app-bootlos aus dem DEK (T9).

    GUI-/Test-Pfad: ein aktiver KeyManager existiert (App-Bootstrap bzw. conftest)
    -> wiederverwenden, damit GUI- und elevated-Seite denselben DEK (und damit
    dieselben abgeleiteten Schluessel) teilen. Elevated Produktionspfad: kein
    aktiver KeyManager -> aus dem DPAPI-gewrappten DEK booten (derselbe Windows-
    User wie die GUI -> derselbe DEK). ``load_master_key`` wirft, wenn der DEK
    fehlt/nicht entschluesselbar ist — der Caller behandelt das fail-closed.
    """
    try:
        return get_active_key_manager()
    except ConfigurationError:
        pass
    # Import-Order-Konstanz (T9): ``key_manager._MASTER_KEY_FILE`` wird zur
    # Import-Zeit an ``finlai_dir`` gebunden. Der elevated Dispatch ruft
    # ``set_finlai_home(--finlai-home)`` VOR dem ersten (lazy) key_manager-Import
    # (ueber den ``run_apply_entry``-Import) -> die Konstante zeigt auf das aktive
    # FINLAI_HOME. WICHTIG: keinen top-level key_manager-Import frueher in die
    # Apply-Dispatch-Kette (apps/norisk_app, app_config) einfuegen, sonst liest
    # der elevated Prozess ein anderes master.key.wrapped als die GUI (DEK-Drift
    # -> Plan-HMAC-Reject + nicht lesbare Snapshot-DB). Durabler Fix (Restschuld):
    # _MASTER_KEY_FILE in key_manager lazy aufloesen (s. THREAT_MODEL).
    km = KeyManager()
    km.load_master_key()
    set_active_key_manager(km)
    return km


def _apply_hmac_secret(km: KeyManager) -> bytes:
    """HMAC-Geheimnis (Plan-Binding + Ergebnis-Marker) aus dem envelope-DEK (T9)."""
    return km.derive_secondary_key(_APPLY_HMAC_PURPOSE)


def _st_dir() -> Path:
    """User-schreibbare Ablage fuer Plan-Datei + Consent (kein Sicherheits-Asset)."""
    path = finlai_dir() / "system_tuner"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _plan_path(token: str) -> Path:
    return _st_dir() / f"plan_{token}.json"


def consent_path() -> Path:
    return _st_dir() / "consent.json"


def _result_path(store_dir: Path, token: str) -> Path:
    return store_dir / f"result_{token}.json"


def _best_effort_unlink(path: Path, *, what: str) -> None:
    """Löscht ``path`` opportunistisch — ein Fehlschlag ist unkritisch (kein Crash).

    Nötig für den Ergebnis-Marker in der admin-only Ablage (A5): der elevierte
    Kindprozess legt ihn mit Admin-ACL an; der nicht-elevierte Parent darf ihn im
    geschützten ``%ProgramData%``-Verzeichnis zwar LESEN, aber nicht LÖSCHEN
    (``PermissionError``/WinError 5). Da das Ergebnis zu diesem Zeitpunkt bereits
    gelesen **und** HMAC-verifiziert ist, darf ein fehlgeschlagenes Aufräumen die
    Operation NICHT scheitern lassen (``missing_ok=True`` fängt nur
    ``FileNotFoundError``). Die Reste fegt der nächste elevierte Lauf weg
    (:func:`_sweep_stale_results`).

    Args:
        path: Zu löschende Datei.
        what: Kurzbezeichnung für die Log-Meldung.
    """
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:  # PermissionError u. a. — Aufräumen ist best-effort
        log.info(
            "%s nicht löschbar (unkritisch, wird später weggeräumt): %s", what, exc
        )


def _sweep_stale_results(store_dir: Path, *, keep_token: str) -> None:
    """Entfernt verwaiste Ergebnis-Marker (nur im elevierten Kontext möglich).

    Der elevierte Kindprozess hat — anders als der nicht-elevierte Parent —
    Löschrechte in der admin-only Ablage. Er räumt beim Start alte
    ``result_*.json`` weg (Reste aus Läufen, deren Parent den Marker nicht löschen
    konnte) und lässt den eigenen (``keep_token``) unangetastet. Berührt weder das
    Token-Ledger noch die Snapshots. Apply ist UAC-seriell → kein Löschen eines
    fremden, noch ungelesenen Markers.

    Args:
        store_dir: Die Ergebnis-Ablage.
        keep_token: Token des aktuellen Laufs (dessen Marker erhalten bleibt).
    """
    keep = f"result_{keep_token}.json"
    try:
        stale = list(store_dir.glob("result_*.json"))
    except OSError as exc:
        # Der Sweep darf den elevierten Prozess NIE killen (sonst kein Ergebnis-/
        # Reject-Marker -> GUI 90s Timeout). Auch das Auflisten ist best-effort.
        log.info("Sweep verwaister Ergebnis-Marker übersprungen: %s", exc)
        return
    for path in stale:
        if path.name != keep:
            _best_effort_unlink(path, what="Verwaister Ergebnis-Marker")


def _runtime_image() -> Path:
    """Das Laufzeit-Image, das ein elevated Relaunch ausfuehrt (T8-Pruefziel)."""
    return Path(sys.executable)


# ---------------------------------------------------------------------------
# Plan (user-schreibbar) + signierter Result (admin-only)
# ---------------------------------------------------------------------------


def write_plan(payload: dict[str, object]) -> Path:
    """Schreibt den gebundenen Plan als Single-Use-Datei (uuid4-Token)."""
    token = str(payload.get("token", ""))
    path = _plan_path(token)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def read_and_consume_plan(plan_path: Path) -> dict | None:
    """Liest den Plan und **loescht die Datei** (Single-Use, T5).

    Fail-closed (A2): scheitert das Loeschen, wird ``None`` geliefert
    (kein Apply) statt den Single-Use-Schutz aufzugeben.
    """
    try:
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("Plan-Datei nicht lesbar: %s", exc)
        plan_path.unlink(missing_ok=True)
        return None
    try:
        plan_path.unlink()
    except OSError as exc:
        log.error("Plan-Datei nicht loeschbar — fail-closed (kein Apply): %s", exc)
        return None
    return payload if isinstance(payload, dict) else None


def _result_hmac(token: str, results: list[dict], secret: bytes) -> str:
    canonical = token + "|" + json.dumps(results, sort_keys=True, ensure_ascii=False)
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def write_result(
    token: str, result: BatchResult, *, store_dir: Path, secret: bytes
) -> Path:
    """Schreibt den HMAC-signierten Ergebnis-Marker (A5c) in die admin-only Ablage."""
    store_dir.mkdir(parents=True, exist_ok=True)
    results = [
        {"tweak_id": r.tweak_id, "status": r.status.value, "detail": r.detail}
        for r in result.results
    ]
    path = _result_path(store_dir, token)
    payload = {"results": results, "hmac": _result_hmac(token, results, secret)}
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def read_result(token: str, *, store_dir: Path, secret: bytes) -> BatchResult | None:
    """Liest + verifiziert den Ergebnis-Marker (``None`` wenn fehlt/HMAC ungueltig)."""
    path = _result_path(store_dir, token)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    results = raw.get("results", [])
    expected = _result_hmac(token, results, secret)
    if not hmac.compare_digest(str(raw.get("hmac", "")), expected):
        log.warning("Ergebnis-Marker HMAC ungueltig — verworfen (token=%s).", token)
        return None
    return BatchResult(
        tuple(
            TweakResult(
                tweak_id=str(item["tweak_id"]),
                status=TweakStatus(item["status"]),
                detail=str(item.get("detail", "")),
            )
            for item in results
        )
    )


def _reject_result(
    token: str, store_dir: Path, secret: bytes, detail: str
) -> None:
    """Schreibt einen abgelehnten Ergebnis-Marker, damit die GUI nicht timeoutet."""
    write_result(
        token,
        BatchResult((TweakResult("*", TweakStatus.BLOCKED, detail),)),
        store_dir=store_dir,
        secret=secret,
    )


# ---------------------------------------------------------------------------
# Elevated-Seite
# ---------------------------------------------------------------------------


def _resolve_store(allow_untrusted_path: bool) -> Path | None:
    """Stellt die admin-only Ablage her (A5); Dev-Fallback nur mit Override."""
    if ensure_secure_dir():
        return secure_dir()
    if allow_untrusted_path:
        log.warning("secure_dir nicht herstellbar — Dev-Fallback (user-schreibbar).")
        return _st_dir()
    log.error("Admin-only Ablage nicht herstellbar — fail-closed (kein Apply).")
    return None


def _check_a3(allow_untrusted_path: bool) -> str | None:
    """A3: Admin-Pflicht + Pfad-Trust des Images. Gibt Ablehnungsgrund oder None."""
    if allow_untrusted_path:
        return None
    if not is_admin():
        return "nicht elevated (is_admin=False)"
    verdict = assess_install_path_trust(_runtime_image())
    if not verdict.trusted:
        return f"Laufzeit-Image nicht vertrauenswuerdig: {verdict.reason}"
    return None


def run_apply_entry(
    *,
    plan_path: Path,
    catalog_path: Path | None = None,
    signature_path: Path | None = None,
    allow_apply: bool = False,
    skip_restore_point: bool = False,
    allow_untrusted_path: bool = False,
) -> int:
    """Elevated Entry: verifiziert + wendet den gebundenen Plan an (s. Modul-Docstring).

    Returns:
        0 = behandelt (Ergebnis-Marker geschrieben); 2 = kein Marker moeglich
        (Ablage/Plan nicht herstellbar — GUI timeoutet fail-closed).
    """
    harden_dll_search_path()  # T8 — vor allem DLL-ladenden Code
    catalog_path = catalog_path or default_catalog_path()
    signature_path = signature_path or default_signature_path()
    try:
        key_manager = _resolve_key_manager()
        secret = _apply_hmac_secret(key_manager)
    except Exception as exc:  # noqa: BLE001 — Entry-Boundary: nie crashen
        # Ohne DEK kein signierbarer Ergebnis-Marker -> rc=2 (GUI timeoutet
        # fail-closed). Typisch: master.key.wrapped fehlt/nicht entschluesselbar.
        log.error("KeyManager/DEK nicht verfuegbar — fail-closed (kein Apply): %s", exc)
        return 2

    store_dir = _resolve_store(allow_untrusted_path)
    if store_dir is None:
        return 2

    payload = read_and_consume_plan(plan_path)  # Single-Use (T5)
    if payload is None:
        return 2
    token = str(payload.get("token", ""))

    # A5-Cleanup: verwaiste Ergebnis-Marker früherer Läufe wegräumen — nur
    # der elevierte Prozess hat dafür in der admin-only Ablage die Löschrechte.
    _sweep_stale_results(store_dir, keep_token=token)

    # A3: Admin + vertrauenswuerdiges Image
    reject = _check_a3(allow_untrusted_path)
    if reject is not None:
        _reject_result(token, store_dir, secret, f"A3: {reject}")
        return 0

    # A4: Consent (R7)
    if not ConsentGate(consent_path()).has_consent(CURRENT_EULA_VERSION):
        _reject_result(token, store_dir, secret, "A4: Apply-Consent fehlt")
        return 0

    # A2: Token-Ledger — Replay-Check (Token noch NICHT verbrennen).
    ledger = FileTokenLedger(store_dir)
    used_tokens = ledger.load_used()
    if token in used_tokens:
        _reject_result(token, store_dir, secret, "A2: Token bereits verbraucht")
        return 0

    # Snapshot-Ablage (SQLCipher) VOR dem Token-Burn initialisieren: ihr
    # ``__init__`` oeffnet sofort eine Verbindung und kann werfen (fehlende
    # sqlcipher3, Schluessel-Mismatch gegen eine bestehende DB, IO/DACL). Ein
    # — auch transienter — Fehler darf den Single-Use-Token NICHT verbrennen
    # (sonst ist der bestaetigte Plan dauerhaft unwiederholbar). Fail-closed.
    try:
        snapshots = EncryptedSnapshotRepository(store_dir, key_manager)
    except Exception as exc:  # noqa: BLE001 — Entry-Boundary: nie crashen
        log.error("Snapshot-Ablage nicht initialisierbar (Token unverbraucht): %s", exc)
        _reject_result(token, store_dir, secret, "Snapshot-Ablage nicht initialisierbar")
        return 0

    # A2: Token jetzt verbrennen (commit-then-act, VOR dem Apply).
    if not ledger.mark_used(token):
        _reject_result(token, store_dir, secret, "A2: Token-Ledger nicht schreibbar")
        return 0

    signature_ok = verify_catalog(catalog_path, signature_path)
    expected_sig = ""
    try:
        if signature_path.is_file():
            expected_sig = signature_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        # Entry-Boundary: nie crashen (der Token ist hier bereits verbrannt). Ein
        # TOCTOU/Lock auf der.sig -> signature_ok=False -> run_elevated_apply
        # lehnt fail-closed mit Marker ab (statt unbehandeltem Crash ohne Marker).
        log.warning("Katalog-Signaturdatei nicht lesbar: %s", exc)
        signature_ok = False
    try:
        tweaks = load_catalog(catalog_path)
    except Exception as exc:  # noqa: BLE001 — Entry-Boundary: nie crashen
        log.warning("Katalog im elevated Apply nicht ladbar: %s", exc)
        tweaks = []
        signature_ok = False

    from core.audit_log import AuditLogger  # noqa: PLC0415

    # Apply-Tail fail-closed kapseln: jeder unbehandelte Fehler (Restore-Point,
    # Engine, Verify, write_result) schreibt einen Reject-Marker, damit der
    # elevated Prozess NIE ohne Ergebnis stirbt (GUI sonst 90s im Timeout-Poll).
    try:
        probe = WindowsTweakProbe()
        restore = None if skip_restore_point else (lambda: create_restore_point(probe))
        result = run_elevated_apply(
            payload,
            tweaks,
            probe,
            snapshots,
            secret=secret,
            expected_catalog_sig=expected_sig,
            signature_ok=signature_ok,
            used_tokens=used_tokens,
            restore_point=restore,
            audit=AuditLogger(),
            apply_enabled=allow_apply,
        )
        write_result(token, result, store_dir=store_dir, secret=secret)
    except Exception as exc:  # noqa: BLE001 — Entry-Boundary: nie crashen
        log.error("Elevated Apply unbehandelter Fehler — Reject-Marker: %s", exc)
        _reject_result(token, store_dir, secret, f"INTERNAL: {type(exc).__name__}")
    return 0


# ---------------------------------------------------------------------------
# GUI-Seite
# ---------------------------------------------------------------------------


def request_elevated_apply(
    tweak_ids: list[str],
    *,
    poll_timeout_s: float = 90.0,
    poll_interval_s: float = 0.5,
) -> BatchResult | None:
    """Bindet den Plan, startet den elevated Apply (UAC) und pollt das Ergebnis.

    Returns:
        Das:class:`BatchResult`; ``None`` wenn die UAC-Abfrage abgelehnt wurde
        oder der signierte Ergebnis-Marker im Timeout ausbleibt.
    """
    token = uuid.uuid4().hex
    try:
        secret = _apply_hmac_secret(get_active_key_manager())
    except Exception as exc:  # noqa: BLE001 — fail-closed: ohne DEK kein Apply
        log.error("Elevated Apply: KeyManager/DEK nicht verfuegbar: %s", exc)
        return None
    catalog_sig = ""
    sig_path = default_signature_path()
    if sig_path.is_file():
        catalog_sig = sig_path.read_text(encoding="utf-8").strip()
    bound = bind_plan(token, tweak_ids, catalog_sig, secret=secret)
    plan_path = write_plan(bound.to_dict())

    if not relaunch_elevated(
        _APPLY_FLAG, "--plan", str(plan_path), "--finlai-home", str(finlai_dir())
    ):
        _best_effort_unlink(plan_path, what="Plan-Datei")
        log.info("Elevated Apply: UAC abgelehnt/fehlgeschlagen.")
        return None

    store = secure_dir()
    deadline = time.monotonic() + poll_timeout_s
    while time.monotonic() < deadline:
        result = read_result(token, store_dir=store, secret=secret)
        if result is not None:
            # Ergebnis ist gelesen + HMAC-verifiziert. Der Marker liegt in der
            # admin-only Ablage → der nicht-elevierte Parent kann ihn evtl. nicht
            # löschen, WinError 5); best-effort statt Crash.
            _best_effort_unlink(_result_path(store, token), what="Ergebnis-Marker")
            return result
        time.sleep(poll_interval_s)
    log.warning("Elevated Apply: Ergebnis-Marker im Timeout ausgeblieben.")
    _best_effort_unlink(plan_path, what="Plan-Datei")  # verwaiste Single-Use-Plandatei
    return None
