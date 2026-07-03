"""Trigger-Logik für den First-Run-Wizard.

Stellt:func:`needs_first_run` bereit — eine reine Funktion ohne Qt-Import,
damit sie in Tests ohne QApplication funktioniert.

Kriterium
---------
Der Wizard muss erscheinen, wenn **keine echten Benutzer** existieren. Ein
„echter Benutzer" ist ein Account mit nicht-leerem ``password_hash`` und
ohne ``requires_setup``-Flag. Der von:class:`UserStore` automatisch
angelegte Default-Admin (leerer Hash, ``requires_setup=True``) gilt **nicht**
als echter Benutzer — er ist genau das Signal, dass die Ersteinrichtung
noch aussteht.

Auch eine fehlende ``users.json`` wird als Ersteinrichtung behandelt.

App-Marker-Filter
-------------------------
``~/.finlai/users.json`` ist global ueber alle FINLAI-Apps geteilt
(NoRisk, AUTOMATE, TeachMe …). Auf einer Dev-Workstation kann das dazu
fuehren, dass Test-User aus einem anderen Build sichtbar werden und der Wizard
NICHT mehr ausgeloest wird. Wird ``app_id`` an:func:`needs_first_run`
uebergeben, zaehlen nur Benutzer mit passendem ``created_by_app``-Marker als
echte Benutzer; User ohne Marker oder mit fremdem Marker werden ignoriert.
Beim Aufruf ohne ``app_id`` bleibt das alte Verhalten erhalten.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from core.finlai_paths import finlai_dir
from core.logger import get_logger

log = get_logger(__name__)

_FINLAI_DIR = finlai_dir()
_USERS_FILE = _FINLAI_DIR / "users.json"


def needs_first_run(
    users_file: Path | None = None,
    app_id: str | None = None,
) -> bool:
    """Prüft, ob der First-Run-Wizard gezeigt werden muss.

    Args:
        users_file: Optionaler Pfad zur ``users.json`` (Standard: ``~/.finlai/users.json``).
            Wird vor allem für Tests benötigt.
        app_id: — Optionaler App-Marker. Wenn gesetzt, zählen nur Benutzer
            mit ``created_by_app == app_id`` als echte Benutzer; User aus anderen
            FINLAI-Builds (oder Pre--Sessions ohne Marker) werden ignoriert.
            ``None`` = Legacy-Verhalten (jeder User mit Passwort zählt).

    Returns:
        True, wenn kein passender Benutzer mit gesetztem Passwort existiert (der
        Default-Admin mit leerem Hash zählt nicht), sonst False.
    """
    path = users_file or _USERS_FILE

    if not path.exists():
        return True

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("users.json konnte nicht gelesen werden: %s — zeige Wizard.", exc)
        return True

    if not isinstance(data, dict) or not data:
        return True

    foreign_users = 0
    for user in data.values():
        if not isinstance(user, dict):
            continue
        if user.get("requires_setup"):
            continue
        if not user.get("password_hash"):
            continue
        if app_id is not None and user.get("created_by_app") != app_id:
            foreign_users += 1
            continue
        return False

    if app_id is not None and foreign_users:
        log.info(
            "Wizard erzwungen: %d Benutzer in users.json ohne created_by_app=%r "
            "(fremde FINLAI-Builds oder Pre-T-011-Sessions).",
            foreign_users,
            app_id,
        )

    return True


def adopt_legacy_users(
    app_id: str,
    users_file: Path | None = None,
    db_dir: Path | None = None,
) -> int:
    """B-STAR: Adoptiert unmarkierte Legacy-Real-User EINMALIG in ``app_id``.

    Hintergrund: Eine ``users.json`` aus Pre--Versionen hat keinen
    ``created_by_app``-Marker.:func:`needs_first_run` zaehlt solche User als
    „fremd" und erzwingt den Wizard — obwohl der Kunde bereits Benutzer **und**
    DB-Daten hat (B-STAR). Diese Migration stempelt unmarkierte Real-User
    auf ``app_id``, sodass beim naechsten Start der normale Login-Pfad greift
    statt einer erzwungenen Neueinrichtung.

    Cross-App-Schutz (``~/.finlai/`` ist ueber alle FINLAI-Apps geteilt) —
    adoptiert wird NUR, wenn alle drei Bedingungen gelten:
        * es unmarkierte Real-User gibt,
        * KEIN User fuer eine ANDERE App markiert ist (sonst Multi-App-
          Maschine — die unmarkierten User koennten zu einer fremden App
          gehoeren), und
        * diese App eigene DB-Bestandsdaten hat
          (``~/.finlai/db/<app_id>/*.db``) — der Beweis, dass die App auf
          dieser Maschine wirklich benutzt wurde.
    Idempotent: ein erneuter Lauf findet keine unmarkierten User mehr.

    Args:
        app_id: App-Marker, auf den adoptiert wird (z. B. ``"norisk"``).
        users_file: Optionaler ``users.json``-Pfad (Tests). Default
                    ``~/.finlai/users.json``.
        db_dir: Optionales DB-Verzeichnis dieser App (Tests). Default
                    ``~/.finlai/db/<app_id>/``.

    Returns:
        Anzahl adoptierter User (``0`` wenn nichts adoptiert wurde).
    """
    if not app_id:
        return 0
    path = users_file or _USERS_FILE
    if not path.exists():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("adopt_legacy_users: users.json nicht lesbar: %s", exc)
        return 0
    if not isinstance(data, dict) or not data:
        return 0

    unmarked: list[dict] = []
    has_foreign = False
    for user in data.values():
        if not isinstance(user, dict):
            continue
        if user.get("requires_setup"):
            continue
        if not user.get("password_hash"):
            continue
        marker = user.get("created_by_app") or ""
        if not marker:
            unmarked.append(user)
        elif marker != app_id:
            has_foreign = True

    if not unmarked:
        return 0
    if has_foreign:
        log.info(
            "B-START-1: Adoption uebersprungen — Fremd-App-Marker in users.json "
            "(Multi-App-Maschine); %d unmarkierte User bleiben unangetastet.",
            len(unmarked),
        )
        return 0

    base_db = db_dir or (finlai_dir() / "db" / app_id)
    if not (base_db.exists() and any(base_db.glob("*.db"))):
        log.info(
            "B-START-1: Adoption uebersprungen — keine DB-Bestandsdaten unter %s "
            "(echte Ersteinrichtung; Wizard bleibt).",
            base_db,
        )
        return 0

    # Sicherung vor dem (rein additiven) Schreiben — nur der Marker wird gesetzt.
    try:
        shutil.copy2(path, path.with_name(path.name + ".pre-adopt.bak"))
    except OSError as exc:
        log.warning("B-START-1: Backup vor Adoption fehlgeschlagen: %s", exc)

    for user in unmarked:
        user["created_by_app"] = app_id
    try:
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except OSError as exc:
        log.error("B-START-1: users.json konnte nicht geschrieben werden: %s", exc)
        return 0

    log.info(
        "B-START-1: %d unmarkierte Legacy-User auf created_by_app=%r adoptiert "
        "(DB-Bestandsdaten vorhanden, kein Fremd-Marker).",
        len(unmarked),
        app_id,
    )
    return len(unmarked)
