"""migration_rawkey: Umstellung auf SQLCipher Raw-Key.

Beim Bootstrap (nach der Legacy→DEK-Migration, vor ``set_active_key_manager``)
werden Bestands-DBs im alten String-Key/PBKDF2-Format beiseitegeschoben, damit
die App sie im Raw-Key-Format frisch neu anlegt (Pre-Production-Discard-Entscheid
2026-06-25,egel 1). Raw-Key spart ~93 ms → ~2 ms pro DB-Open, weil
SQLCipher die teure PBKDF2-Passphrasen-Ableitung ueberspringt §1).

Idempotent ueber einen Marker (``.rawkey``) im DB-Verzeichnis: ist er gesetzt,
ist die Umstellung erledigt und der Schritt ist ein no-op. Self-correcting: es
werden NUR DBs verschoben, die sich NICHT mit Raw-Key oeffnen lassen — eine
schon-raw DB bleibt unangetastet, selbst wenn der Marker fehlte.

Schichtzugehoerigkeit: ``core/database/`` (Migrations-Infrastruktur).
"""

from __future__ import annotations

import logging
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from core.database.migration_dbs import _can_open_with_key
from core.finlai_paths import finlai_dir as resolve_finlai_dir

if TYPE_CHECKING:
    from core.database.key_manager import KeyManager

log = logging.getLogger(__name__)

#: Marker-Datei im DB-Verzeichnis — vorhanden = Raw-Key-Umstellung erledigt.
_RAWKEY_MARKER: Final[str] = ".rawkey"

#: Praefix des Discard-Verzeichnisses fuer verworfene Alt-Format-DBs.
_DISCARD_PREFIX: Final[str] = ".pre-rawkey-discarded-"

#: SQLCipher-WAL/SHM-Sibling-Suffixe, die mit der DB verschoben werden muessen.
_DB_SIBLING_SUFFIXES: Final[tuple[str, ...]] = ("-wal", "-shm")


def discard_pre_rawkey_databases(
    key_manager: KeyManager,
    app_id: str,
    *,
    db_root: Path | None = None,
    now: datetime | None = None,
) -> list[str]:
    """Verschiebt Alt-Format-DBs beiseite, damit die App sie Raw-Key neu anlegt.

. Pro ``*.db`` in ``<db_root>/<app_id>/``: laesst sie sich mit
    Raw-Key oeffnen, bleibt sie. Sonst (altes String-Key-Format oder DEK-Verlust)
    wird sie samt ``-wal``/``-shm``-Siblings nach
    ``.pre-rawkey-discarded-<ts>/`` verschoben (Backup, kein Loeschen) — die App
    legt die DB beim naechsten Zugriff frisch im Raw-Key-Format an.

    Idempotent ueber den ``.rawkey``-Marker: ist er vorhanden, no-op.

    Args:
        key_manager: aktiver KeyManager (zum Ableiten des Pruefschluessels).
        app_id: App-ID (DBs unter ``<db_root>/<app_id>/``).
        db_root: Default ``<finlai_dir>/db``. Tests injizieren tmp-Pfade.
        now: datetime-Anker (UTC). Default ``datetime.now(UTC)``.

    Returns:
        Liste der verworfenen DB-Stem-Namen (leer = nichts zu tun / schon raw).
    """
    if now is None:
        now = datetime.now(tz=UTC)
    if db_root is None:
        db_root = resolve_finlai_dir() / "db"

    db_dir = db_root / app_id
    db_dir.mkdir(parents=True, exist_ok=True)

    marker = db_dir / _RAWKEY_MARKER
    if marker.exists():
        return []

    discard_dir = db_dir / f"{_DISCARD_PREFIX}{now.strftime('%Y%m%d-%H%M%S')}"
    discarded: list[str] = []

    for db_path in sorted(db_dir.glob("*.db")):
        if not db_path.is_file():
            continue
        stem = db_path.stem
        try:
            key_hex = key_manager.derive_secondary_key(f"db:{stem}").hex()
            opens_raw = _can_open_with_key(db_path, key_hex, raw_key=True)
        except Exception:  # noqa: BLE001 — nicht ableitbar/oeffenbar = verwerfen
            opens_raw = False
        if opens_raw:
            continue  # schon im Raw-Key-Format — unangetastet lassen

        discard_dir.mkdir(parents=True, exist_ok=True)
        for suffix in ("", *_DB_SIBLING_SUFFIXES):
            src = (
                db_path
                if not suffix
                else db_path.with_name(db_path.name + suffix)
            )
            if src.exists():
                shutil.move(str(src), str(discard_dir / src.name))
        discarded.append(stem)

    marker.write_text("raw\n", encoding="utf-8")

    if discarded:
        log.warning(
            "ADR-034 Raw-Key-Umstellung: %d Bestands-DB(s) im alten String-Key-"
            "Format nach %s verschoben (Pre-Prod-Discard) — werden frisch im "
            "Raw-Key-Format neu angelegt: %s",
            len(discarded),
            discard_dir,
            ", ".join(sorted(discarded)),
        )
    else:
        log.info("ADR-034 Raw-Key-Marker gesetzt (keine Alt-Format-DBs).")

    return discarded
