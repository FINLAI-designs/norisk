"""schema_utils — Kleine, idempotente Schema-Helfer für SQLCipher-DBs.

Zentralisiert das wiederkehrende „Spalte additiv hinzufügen, falls sie fehlt"-
Muster (SQLite kennt kein ``ALTER TABLE... ADD COLUMN IF NOT EXISTS``).
Genutzt für additive Migrationen (z. B. ``subject_id``), die keine
Schema-Versionierung brauchen.

Schichtzugehörigkeit: core/ — Shared Utility, kein Tool-/GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re

from core.logger import get_logger

log = get_logger(__name__)

#: Erlaubte SQL-Identifier: ASCII-Buchstabe/Unterstrich, dann Wortzeichen.
#: Bewusst strenger als ``str.isidentifier`` (kein Unicode), passend zu den
#: snake_case-Tabellen/-Spalten dieses Repos.
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _require_identifier(name: str, rolle: str) -> None:
    """Wirft ``ValueError``, wenn ``name`` kein einfacher SQL-Identifier ist.

    Defense-in-Depth gegen Identifier-Injection: ``table``/``column`` werden in
:func:`ensure_column` als f-string in SQL interpoliert. Sie stammen heute
    ausschliesslich aus Code-Konstanten; dieser Guard setzt den Vertrag
    fail-closed durch (``raise``, kein ``assert`` — letzteres entfaellt unter
    ``python -O``), bevor je ein fremder Aufrufer Nutzereingaben durchreicht.

    Args:
        name: Der zu pruefende Identifier.
        rolle: Bezeichnung fuer die Fehlermeldung (``"Tabellen"``/``"Spalten"``).

    Raises:
        ValueError: Wenn ``name`` kein ``[A-Za-z_][A-Za-z0-9_]*`` ist.
    """
    if not isinstance(name, str) or not _IDENTIFIER_RE.fullmatch(name):
        raise ValueError(
            f"Ungueltiger {rolle}-Identifier fuer ensure_column: {name!r}. "
            "Nur einfache Identifier ([A-Za-z_][A-Za-z0-9_]*) aus Code-Konstanten "
            "erlaubt (kein SQL-Injection-Pfad)."
        )


def ensure_column(conn, table: str, column: str, column_def: str) -> bool:  # noqa: ANN001
    """Fügt eine Spalte additiv hinzu, falls sie noch nicht existiert.

    Idempotent: prüft ``PRAGMA table_info`` und führt das ``ALTER TABLE`` nur
    aus, wenn die Spalte fehlt. ``column``/``table`` werden als Identifier
    interpoliert — sie dürfen NUR aus Code-Konstanten stammen, nie aus
    Nutzereingaben. Der Identifier-Guard (:func:`_require_identifier`) setzt das
    fail-closed durch (kein SQL-Injection-Pfad).

    Args:
        conn: Offene DB-Verbindung (innerhalb eines ``with``-Blocks).
        table: Tabellenname (Code-Konstante).
        column: Spaltenname (Code-Konstante).
        column_def: SQL-Typ + Default, z. B. ``"TEXT DEFAULT ''"``.

    Returns:
        ``True``, wenn die Spalte neu angelegt wurde, sonst ``False``.

    Raises:
        ValueError: Wenn ``table`` oder ``column`` kein einfacher Identifier ist.
    """
    _require_identifier(table, "Tabellen")
    _require_identifier(column, "Spalten")
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column in existing:
        return False
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_def}")
    log.info("%s: Spalte '%s' additiv ergänzt.", table, column)
    return True
