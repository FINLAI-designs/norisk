"""db_context — Globaler App-ID-Kontext für DB-Pfad-Isolation.

Speichert die aktive App-ID damit EncryptedDatabase die Datenbankdateien
in einem app-spezifischen Unterverzeichnis ablegen kann.

Aufruf-Reihenfolge:
  1. apps/__init__.py: set_db_app_id(config.app_id) direkt nach set_active_app
  2. EncryptedDatabase.__init__: get_db_app_id → Unterpfad bestimmen

Design:
  - Kein Import aus apps/ (würde Circular Imports erzeugen)
  - Thread-safe: Schreiben nur einmal beim App-Start, danach nur lesend
  - None = kein Kontext gesetzt → DB_DIR-Root (nur für Tests ohne App-Boot)

Schichtzugehörigkeit: core/ (framework-agnostisch).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

_db_app_id: str | None = None


def set_db_app_id(app_id: str) -> None:
    """Setzt die aktive App-ID für DB-Pfad-Isolation.

    Muss VOR dem ersten EncryptedDatabase-Aufruf aufgerufen werden.
    Typischerweise in apps/__init__.py::launch_app nach set_active_app.

    Args:
        app_id: App-Bezeichner (z.B. "teachme", "teachme_buchhaltung_free",
                "finlai", "norisk").
    """
    global _db_app_id
    _db_app_id = app_id


def get_db_app_id() -> str | None:
    """Gibt die aktive App-ID zurück.

    Returns:
        App-ID wenn gesetzt, sonst None (→ Legacy-Pfad).
    """
    return _db_app_id


def clear_db_app_id() -> None:
    """Setzt den Kontext zurück (primär für Tests).

    Stellt sicher dass Tests sich gegenseitig nicht beeinflussen.
    """
    global _db_app_id
    _db_app_id = None
