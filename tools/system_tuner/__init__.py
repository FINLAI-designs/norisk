"""
system_tuner — "System optimieren": Windows-Datenschutz/Telemetrie/Debloat.

Read-only Bestandsaufnahme + (Pro) reversibles Anwenden datenschutz-
relevanter Windows-Defaults (Telemetrie, ungenutzte Dienste). Datengetrieben
ueber einen kuratierten, AGPL-freien Katalog; fail-closed; jede Aenderung
reversibel (Snapshot + Revert) und auditiert. NEVER_DISABLE ist eine
Ladezeit-Invariante.

**Lazy-Import-Konvention:** Dieses Paket-``__init__`` importiert bewusst
NICHTS eager — der Import von ``tools.system_tuner.domain.*`` darf weder Qt
(``gui``) noch ``winreg`` (``data``) hereinziehen. Submodule explizit
importieren.

Schichten (Hexagonal, import-linter-erzwungen):
    domain/ — reine Entities/Enums/Invarianten (nur stdlib + core)
    application/ — Use-Cases (catalog_loader, scan, edition_gate, engine)
    data/ — Adapter (windows_tweak_probe, snapshot_repository)
    gui/ — PySide6-Widgets

Author: Patrick Riederich
Version: 1.0
"""
