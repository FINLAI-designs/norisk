"""links_repository — Persistenz für benutzereigene Wichtige Links (SQLCipher).

Jeder Benutzer verwaltet seine eigene Link-Liste. Die Daten werden
verschlüsselt in der zentralen EncryptedDatabase ``"user_links"`` gespeichert.

Beobachter-Muster (modul-global):
    Wenn die Link-Liste gespeichert wird, werden alle registrierten
    Callbacks aufgerufen — so kann die Sidebar live aktualisiert werden
    ohne Qt-Signal-Kopplung zwischen Einstellungen und Sidebar.

Schichtzugehörigkeit: core/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger

_log = get_logger(__name__)

# ---------------------------------------------------------------------------
# DB-Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS user_links (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT    NOT NULL,
    label       TEXT    NOT NULL,
    url         TEXT    NOT NULL,
    icon        TEXT    NOT NULL DEFAULT '🔗',
    sort_order  INTEGER NOT NULL DEFAULT 0,
    app_id      TEXT    NOT NULL DEFAULT 'finlai'
);

CREATE INDEX IF NOT EXISTS idx_user_links_user
    ON user_links(user_id, sort_order);
"""

_MIGRATION = "ALTER TABLE user_links ADD COLUMN app_id TEXT NOT NULL DEFAULT 'finlai'"

# ---------------------------------------------------------------------------
# Domain-Modell
# ---------------------------------------------------------------------------


@dataclass
class UserLink:
    """Ein einzelner Wichtiger Link eines Benutzers.

    Attributes:
        id: DB-Primärschlüssel (0 = noch nicht gespeichert).
        label: Anzeigename in der Sidebar.
        url: Vollständige URL (inkl. Schema).
        icon: Emoji-Icon für die Sidebar.
        sort_order: Reihenfolge (aufsteigend).
    """

    label: str
    url: str
    # Default-Icon fuer User-Links ist bewusst ein Emoji (kein Material Symbol);
    # coding-rules R2 hier per noqa baselined (Design-Entscheidung, kein Bug).
    icon: str = "🔗"  # noqa
    sort_order: int = 0
    id: int = field(default=0)


# ---------------------------------------------------------------------------
# Modul-globaler Beobachter-Mechanismus
# ---------------------------------------------------------------------------

_callbacks: list[Callable[[], None]] = []


def on_links_changed(callback: Callable[[], None]) -> None:
    """Registriert einen Callback der bei jeder Änderung der Link-Liste aufgerufen wird.

    Args:
        callback: Parameterlose Funktion die aufgerufen wird wenn Links geändert werden.
    """
    if callback not in _callbacks:
        _callbacks.append(callback)


def _notify() -> None:
    """Ruft alle registrierten Callbacks auf."""
    for cb in list(_callbacks):
        try:
            cb()
        except Exception:  # noqa: BLE001 -- Listener-Callbacks: ein fehlerhafter Subscriber darf andere nicht blockieren
            _log.exception("Fehler im links_changed-Callback")


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

# Standard-Links für neue Benutzer — bewusst leer:
# Die RDB/Lexis Nexis/Findok-Einträge wurden entfernt (Emoji-Icons, nicht Material Symbols).
# Benutzer fügen ihre eigenen Links über Einstellungen → Wichtige Links hinzu.
_DEFAULT_LINKS: list[tuple[str, str, str]] = []

# Migration: Entfernt alte Default-Links mit Emoji-Icons die vor dem Refactoring
# automatisch für alle Benutzer angelegt wurden.
_CLEANUP_OLD_DEFAULTS = (
    "DELETE FROM user_links WHERE url IN ("
    " 'https://rdb.manz.at',"
    " 'https://www.lexisnexis.at',"
    " 'https://findok.bmf.gv.at'"
    ")"
)


class LinksRepository:
    """Verwaltung der benutzereigenen Wichtige-Links-Liste.

    Alle Datenbankzugriffe laufen über EncryptedDatabase (SQLCipher AES-256).
    Kein direktes sqlite3.connect.
    """

    def __init__(self) -> None:
        import sqlcipher3  # noqa: PLC0415

        self._db = EncryptedDatabase("user_links")
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)
            try:
                conn.execute(_MIGRATION)
            except sqlcipher3.OperationalError:
                pass  # Spalte existiert bereits
            # Einmalige Bereinigung: alte Default-Links mit Emoji-Icons entfernen
            conn.execute(_CLEANUP_OLD_DEFAULTS)

    # ------------------------------------------------------------------
    def lade(self, user_id: str, app_id: str = "finlai") -> list[UserLink]:
        """Lädt alle Links des Benutzers für die aktive App sortiert nach sort_order.

        Legt Default-Links an wenn der Benutzer noch keine Links für diese App hat.

        Args:
            user_id: Benutzername aus Session.current_user.username.
            app_id: App-Kennung (z.B. "finlai", "norisk", "automate").

        Returns:
            Geordnete Liste der UserLink-Objekte.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT id, label, url, icon, sort_order "
                "FROM user_links WHERE user_id = ? AND app_id = ? ORDER BY sort_order",
                (user_id, app_id),
            ).fetchall()

        if not rows:
            if _DEFAULT_LINKS:
                self._lege_defaults_an(user_id, app_id)
                return self.lade(user_id, app_id)
            return []

        return [
            UserLink(id=r[0], label=r[1], url=r[2], icon=r[3], sort_order=r[4])
            for r in rows
        ]

    def speichere(
        self, user_id: str, links: list[UserLink], app_id: str = "finlai"
    ) -> None:
        """Ersetzt die Link-Liste des Benutzers für die aktive App (delete + insert).

        Args:
            user_id: Benutzername.
            links: Neue vollständige Link-Liste (sort_order wird neu vergeben).
            app_id: App-Kennung.
        """
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM user_links WHERE user_id = ? AND app_id = ?",
                (user_id, app_id),
            )
            for i, lnk in enumerate(links):
                conn.execute(
                    "INSERT INTO user_links (user_id, label, url, icon, sort_order, app_id) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, lnk.label, lnk.url, lnk.icon, i, app_id),
                )

        _log.info(
            "Links für Benutzer '%s' (%s) gespeichert (%d Einträge)",
            user_id,
            app_id,
            len(links),
        )
        _notify()

    # ------------------------------------------------------------------
    def _lege_defaults_an(self, user_id: str, app_id: str = "finlai") -> None:
        """Legt die Default-Links für einen neuen Benutzer an.

        Args:
            user_id: Benutzername.
            app_id: App-Kennung.
        """
        with self._db.connection() as conn:
            for i, (label, url, icon) in enumerate(_DEFAULT_LINKS):
                conn.execute(
                    "INSERT INTO user_links (user_id, label, url, icon, sort_order, app_id) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, label, url, icon, i, app_id),
                )
        if _DEFAULT_LINKS:
            _log.info("Default-Links für Benutzer '%s' (%s) angelegt", user_id, app_id)
