"""hardening_recheck — elevierter Single-Probe-Marker Phase 4d).

Der "Mit Admin messen"-Flow startet via:func:`core.elevation.relaunch_elevated`
EINEN UAC-Prozess (``--recheck-hardening``), der ALLE grauen Checks gemeinsam
misst und das Ergebnis HMAC-signiert nach ``FINLAI_HOME/hardening_recheck.json``
schreibt (atomar, read-only, nach Konsum geloescht). Der GUI-Prozess pollt,
verifiziert die Signatur, merged (echte Messung gewinnt) und loescht die Datei.

HMAC-Schluessel: aus dem **DEK** abgeleitet
(``KeyManager.derive_secondary_key("system_scanner:recheck_hmac")``) — beide
Prozesse (unelevated GUI, elevierter Relaunch) teilen denselben DPAPI-gebundenen
DEK desselben Windows-Users. Loest die fruehere PFAD-Ableitung ab, die zwischen
elev. Writer und GUI-Reader driften konnte (Symlink/8.3/Subst/Resolve) und so
korrekte Marker verwarf -> stiller Timeout (D6). Es ist ein Integritaets-/Tamper-
Marker (kein liegengebliebenes Fremd-File wird als Ergebnis gemerged). Voller
same-user-Schutz ist es nicht (DPAPI-DEK ist same-user entwrappbar) — dieses
Rest-Risiko adressiert ueber signierte Fleet-Coverage + Drift.

Bei jedem Fehlerpfad schreibt der elevierte Entry einen signierten **Reject-
Marker** (``write_recheck_reject`` +:class:`RecheckReason`), damit die GUI den
Ausgang sichtbar machen kann statt still in den 90-s-Timeout zu laufen.

Schicht: ``application/`` — orchestriert Scan + Marker-I/O, keine GUI.

Author: Patrick Riederich
Version: 1.0 Phase 4d)
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from pathlib import Path

from core.database.key_manager_context import get_active_key_manager
from core.finlai_paths import finlai_dir
from core.logger import get_logger
from tools.system_scanner.domain.entities import HardeningCheck, ScanResult
from tools.system_scanner.domain.enums import RecheckReason, UnmeasuredReason

log = get_logger(__name__)

#: Dateiname des Recheck-Markers unter FINLAI_HOME.
RECHECK_FILENAME = "hardening_recheck.json"

#: Envelope-Schema-Version (1 = Pfad-HMAC ohne status; 2 = DEK-HMAC + status/reason).
_SCHEMA_VERSION = 2

#: Status-Werte des Markers.
_STATUS_OK = "ok"
_STATUS_REJECTED = "rejected"

#: HKDF-Purpose des Recheck-HMAC — Domain-Trennung gegen andere DEK-Verbraucher.
_RECHECK_HMAC_PURPOSE = "system_scanner:recheck_hmac"


@dataclass(frozen=True, slots=True)
class RecheckOutcome:
    """Ergebnis eines konsumierten Recheck-Markers.

    Genau eines ist gesetzt: ``scan`` (Erfolg) ODER ``reason`` (Reject). So kann
    der Reject-Pfad nie versehentlich als Mess-Ergebnis gemerged werden.

    Attributes:
        scan: Das verifizierte:class:`ScanResult` bei Erfolg, sonst ``None``.
        reason: Der:class:`RecheckReason` bei einem Reject, sonst ``None``.
        detail: Kurze, generische Zusatzinfo (kein Pfad/Exception-Text).
    """

    scan: ScanResult | None
    reason: RecheckReason | None
    detail: str = ""

    @property
    def ok(self) -> bool:
        """``True`` bei erfolgreicher Messung (``scan`` gesetzt)."""
        return self.scan is not None


def recheck_file_path(home: Path | None = None) -> Path:
    """Pfad des Recheck-Markers (Default: ``finlai_dir/hardening_recheck.json``)."""
    return (home or finlai_dir()) / RECHECK_FILENAME


def _recheck_hmac_secret() -> bytes:
    """DEK-abgeleiteter HMAC-Schluessel; fail-closed ohne aktiven DEK."""
    return get_active_key_manager().derive_secondary_key(_RECHECK_HMAC_PURPOSE)


def _sign(payload: bytes, nonce: str, status: str, reason: str) -> str:
    """HMAC ueber Payload + Nonce + status + reason (DEK-Schluessel).

    Die Nonce bindet den Marker an genau einen Mess-Anstoss (Frische/Replay).
    ``status``/``reason`` sind mitsigniert — ein Angreifer kann einen ``ok``-
    Marker nicht zu ``rejected`` flippen oder den Grund faelschen.
    """
    msg = b"|".join(
        (payload, nonce.encode("utf-8"), status.encode("utf-8"), reason.encode("utf-8"))
    )
    return hmac.new(_recheck_hmac_secret(), msg, hashlib.sha256).hexdigest()


def write_recheck_result(
    scan_result: ScanResult,
    *,
    nonce: str = "",
    home: Path | None = None,
) -> Path:
    """Serialisiert + HMAC-signiert das ScanResult atomar in den Marker.

    Args:
        scan_result: Das frische (elevierte) Hardening-Scan-Ergebnis.
        nonce: Vom anstossenden GUI-Prozess erzeugte Einmal-Nonce — bindet den
            Marker an genau diesen Mess-Anstoss (Frische). Leer = keine Bindung.
        home: FINLAI_HOME (Default: aufgeloest via ``finlai_dir``).

    Returns:
        Pfad der geschriebenen Marker-Datei.
    """
    payload = json.dumps(
        scan_result.to_dict(), sort_keys=True, ensure_ascii=False
    )
    return _write_marker(
        payload, status=_STATUS_OK, reason="", detail="", nonce=nonce, home=home
    )


def write_recheck_reject(
    reason: RecheckReason,
    detail: str = "",
    *,
    nonce: str = "",
    home: Path | None = None,
) -> Path:
    """Schreibt einen signierten Reject-Marker, D6).

    Der elevierte Entry ruft dies bei JEDEM Fehlerpfad (Probe n/a, Scan-Fehler,
    nicht-elevated, untrusted Pfad, interner Fehler), damit die GUI den Ausgang
    sichtbar machen kann statt still zu timeouten. ``detail`` muss kurz/generisch
    sein — KEIN Pfad/Exception-Text (Info-Disclosure in den PDF-Export).

    Args:
        reason: Maschinenlesbarer Grund (:class:`RecheckReason`).
        detail: Optionale kurze, redigierte Zusatzinfo.
        nonce: Einmal-Nonce des anstossenden GUI-Prozesses (Frische).
        home: FINLAI_HOME (Default: ``finlai_dir``).

    Returns:
        Pfad der geschriebenen Marker-Datei.
    """
    return _write_marker(
        "", status=_STATUS_REJECTED, reason=reason.value, detail=detail,
        nonce=nonce, home=home,
    )


def _write_marker(
    payload_str: str,
    *,
    status: str,
    reason: str,
    detail: str,
    nonce: str,
    home: Path | None,
) -> Path:
    """Serialisiert + HMAC-signiert einen Marker-Envelope atomar (Single-Source)."""
    home = home or finlai_dir()
    home.mkdir(parents=True, exist_ok=True)
    payload = payload_str.encode("utf-8")
    envelope = {
        "schema": _SCHEMA_VERSION,
        "status": status,
        "reason": reason,
        "detail": detail,
        "payload": payload_str,
        "nonce": nonce,
        "hmac": _sign(payload, nonce, status, reason),
    }
    target = recheck_file_path(home)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(envelope), encoding="utf-8")
    tmp.replace(target)  # atomarer Ersatz (os.replace)
    return target


def read_and_consume_recheck_result(
    *,
    expected_nonce: str | None = None,
    home: Path | None = None,
) -> RecheckOutcome | None:
    """Liest, verifiziert UND loescht den Recheck-Marker.

    Verifiziert die HMAC-Signatur BEVOR die Payload deserialisiert wird
    (kein Vertrauen in ungepruefte Daten) und — falls ``expected_nonce`` gesetzt —
    dass die Marker-Nonce zum aktuellen Mess-Anstoss passt (Frische/Replay-Schutz).
    Bei fehlender/kaputter/ungueltiger Datei: ``None`` (und die Datei wird — falls
    vorhanden — entfernt, damit kein stale Marker zurueckbleibt).

    Args:
        expected_nonce: Die vor der Elevation erzeugte Nonce. ``None`` = keine
            Frische-Pruefung (nur Integritaet).
        home: FINLAI_HOME (Default: ``finlai_dir``).

    Returns:
        Ein:class:`RecheckOutcome` (``scan`` bei Erfolg, ``reason`` bei Reject),
        oder ``None``, wenn kein gueltiger/frischer Marker vorliegt (fehlt,
        HMAC-/Nonce-ungueltig, kein DEK, korrupt).
    """
    home = home or finlai_dir()
    target = recheck_file_path(home)
    if not target.exists():
        return None
    try:
        envelope = json.loads(target.read_text(encoding="utf-8"))
        payload_str = str(envelope["payload"])
        nonce = str(envelope.get("nonce", ""))
        status = str(envelope.get("status", _STATUS_OK))
        reason = str(envelope.get("reason", ""))
        detail = str(envelope.get("detail", ""))
        sig = str(envelope["hmac"])
    except (OSError, ValueError, KeyError, TypeError):
        log.warning("Recheck-Marker unlesbar/kaputt — ignoriert.")
        _safe_delete(target)
        return None

    payload = payload_str.encode("utf-8")
    try:
        expected_sig = _sign(payload, nonce, status, reason)
    except Exception:  # noqa: BLE001 — Read-Boundary: kein DEK -> kein Crash
        log.warning("Recheck-Marker nicht verifizierbar (kein DEK) — verworfen.")
        _safe_delete(target)
        return None
    if not hmac.compare_digest(sig, expected_sig):
        log.warning("Recheck-Marker HMAC ungueltig — verworfen (kein Merge).")
        _safe_delete(target)
        return None

    if expected_nonce is not None and not hmac.compare_digest(nonce, expected_nonce):
        log.warning("Recheck-Marker Nonce passt nicht (stale/replay) — verworfen.")
        _safe_delete(target)
        return None

    # Ab hier ist der Marker authentisch + frisch -> konsumieren (loeschen).
    _safe_delete(target)

    if status == _STATUS_REJECTED:
        try:
            rc = RecheckReason(reason)
        except ValueError:
            rc = RecheckReason.INTERNAL
        return RecheckOutcome(scan=None, reason=rc, detail=detail)

    try:
        scan_result = ScanResult.from_dict(json.loads(payload_str))
    except (ValueError, KeyError, TypeError) as exc:
        log.warning(
            "Recheck-Marker Payload nicht deserialisierbar: %s", type(exc).__name__
        )
        return None
    return RecheckOutcome(scan=scan_result, reason=None)


def _safe_delete(target: Path) -> None:
    try:
        target.unlink(missing_ok=True)
    except OSError:
        log.warning("Recheck-Marker konnte nicht geloescht werden: %s", target)


def merge_recheck_checks(
    base: list[HardeningCheck],
    recheck: list[HardeningCheck],
) -> list[HardeningCheck]:
    """Merged elevierte Messungen in die Basis — echte Messung gewinnt.

    Nur grau-behebbare Basis-Checks (``NEEDS_ADMIN``) werden durch eine MESSBARE
    Recheck-Version derselben ``check_id`` ersetzt. Bereits gemessene, ``USER_
    DECLINED``-, ``NOT_APPLICABLE``- und ``PARSE_FAILED``-Checks bleiben unveraendert
    (ein bewusster Opt-out ueberlebt den Recheck; eine Locale-Grenze wird durch
    Admin nicht behebbar).

    KONVERGENZ (D6-Folge): Bleibt ein ``NEEDS_ADMIN``-Check beim elevierten Recheck
    WEITER unmessbar, war es kein Rechteproblem -> er wird terminal auf
    ``NOT_APPLICABLE`` gesetzt, damit das Mess-Banner nicht endlos erneut "Mit Admin
    messen" fordert (z.B. AUOptions ohne WSUS, BitLocker auf Home).

    Args:
        base: Aktuelle (unprivilegierte) Check-Liste.
        recheck: Check-Liste aus dem elevierten Single-Probe.

    Returns:
        Neue Check-Liste mit den nachgemessenen offenen Checks.
    """
    by_id = {c.check_id: c for c in recheck}
    result: list[HardeningCheck] = []
    for check in base:
        rc = by_id.get(check.check_id)
        if (
            not check.measurable
            and check.unmeasured_reason == UnmeasuredReason.NEEDS_ADMIN
            and rc is not None
        ):
            if rc.measurable:
                result.append(rc)  # Admin hat den Check gemessen -> echte Messung
            else:
                # KONVERGENZ (D6-Folge): Der elevierte Recheck HAT es versucht,
                # kann den Check aber weiterhin nicht messen -> es ist KEIN
                # Rechteproblem (sonst haette Admin geholfen), sondern strukturell
                # nicht ermittelbar (z.B. AUOptions ohne WSUS, BitLocker auf Home).
                # Terminal auf NOT_APPLICABLE setzen, damit das Banner konvergiert
                # statt endlos erneut "Mit Admin messen" zu fordern.
                result.append(
                    replace(
                        check,
                        unmeasured_reason=UnmeasuredReason.NOT_APPLICABLE,
                        detail=(
                            "Auch mit Adminrechten nicht ermittelbar — auf diesem "
                            "System nicht zutreffend"
                        ),
                    )
                )
        else:
            result.append(check)
    return result


__all__ = [
    "RECHECK_FILENAME",
    "RecheckOutcome",
    "merge_recheck_checks",
    "read_and_consume_recheck_result",
    "recheck_file_path",
    "write_recheck_reject",
    "write_recheck_result",
]
