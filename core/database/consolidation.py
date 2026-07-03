"""
consolidation — Zentrale Konstanten der DB-Konsolidierung.

NoRisk legt seine Tool-Daten nicht mehr in ~23 Per-Tool-SQLCipher-DBs ab,
sondern (Hybrid, Patrick-Entscheid 2026-06-26) in EINER gemeinsamen
DB plus zwei bewusst separat gehaltenen Ausnahmen.

Effekt: Jedes konsolidierte Tool-Repository instanziiert
``EncryptedDatabase(CONSOLIDATED_DB_NAME)`` statt ``EncryptedDatabase("<tool>")``.
Eine Aenderung von:data:`CONSOLIDATED_DB_NAME` wirkt auf ALLE konsolidierten
Repos + den abgeleiteten Schluessel (``db:<name>``) + den Wipe-/Registry-Pfad —
nicht leichtfertig umbenennen (bricht den Zugriff auf die Bestands-Datei).

Bewusst SEPARAT (nicht konsolidiert,:data:`SEPARATE_DB_NAMES`):

- ``network_monitor`` — Hochfrequenz-Collector-Daemon (eigener Dauer-Prozess,
  ``TASK_TRIGGER_LOGON``/``PT0S``); aus der gemeinsamen Datei gehalten, um
  Schreib-Contention strukturell zu minimieren.
- ``system_tuner_snapshots`` — von einem ELEVIERTEN Prozess nach
  ``%ProgramData%`` mit eigener DACL geschrieben (Privilegien-Grenze).

Schichtzugehoerigkeit: core/database/ (framework-agnostisch, keine Tool-Imports).
"""

from __future__ import annotations

from typing import Final

#: Gemeinsamer DB-Name aller konsolidierten User-Context-Tools.
#: Datei ``~/.finlai/db/<app_id>/norisk.db``, Schluessel HKDF ``db:norisk``.
CONSOLIDATED_DB_NAME: Final[str] = "norisk"

#: DB-Namen, die BEWUSST separat bleiben (siehe Modul-Docstring). Werden vom
#: Alt-DB-Wipe (Phase 4) ausgenommen und von ``last_scan_registry`` weiterhin
#: ueber ihren eigenen DB-Namen gelesen.
SEPARATE_DB_NAMES: Final[frozenset[str]] = frozenset(
    {"network_monitor", "system_tuner_snapshots"}
)

#: Alt-/Vor-Konsolidierungs-Namen, die NICHT auf die gemeinsame DB gelenkt
#: werden duerfen, weil nur noch ein Migrations-Lesepfad sie oeffnet (z.B.
#: ``customer_assessment`` in ``customer_audit_repository._migrate_cross_file``).
#: Hinweis (Review): der Alt-DB-Wipe (purge_consolidated_legacy_dbs)
#: loescht ``customer_assessment.db`` ohnehin (nicht im keep-Set) und laeuft VOR
#: dem ersten customer_audit-Open -> die Cross-File-Migration ist auf einer
#: Bestands-Maschine faktisch ein No-op Full-Wipe, Daten verzichtbar).
#: Die Remap-Ausnahme sichert daher nur den theoretischen Pre-Wipe-Open ab.
LEGACY_DB_NAMES: Final[frozenset[str]] = frozenset({"customer_assessment"})
