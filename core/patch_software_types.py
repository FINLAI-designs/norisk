"""
patch_software_types — Geteilte Wert-Typen des Software-Inventars.

Leaf-Modul (keine internen Importe) fuer die Datentypen ``SoftwareSource`` und
``SoftwareItem``. Liegt unterhalb von:mod:`core.patch_collector` und
:mod:`core.patch_winget_module`, damit beide sie importieren koennen, ohne einen
Import-Zyklus zu bilden /: ``patch_winget_module`` brauchte
``SoftwareItem``/``SoftwareSource`` aus ``patch_collector``, das wiederum
``collect_winget_module`` re-exportierte). ``patch_collector`` re-exportiert beide
Namen weiter, sodass bestehende ``from core.patch_collector import SoftwareItem``
unveraendert funktionieren.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SoftwareSource = Literal[
    "winget", "registry", "msix", "custom", "windows_update", "dotnet", "driver"
]


@dataclass(frozen=True)
class SoftwareItem:
    """Ein Eintrag aus dem Software-Inventar.

    Attributes:
        name: Anzeigename (z.B. ``"Mozilla Firefox"``).
        version: Installierte Version (z.B. ``"120.0.1"``).
            ``"unbekannt"`` wenn die Quelle keine Versionsangabe liefert
            (typisch bei Registry-Eintraegen ohne ``DisplayVersion`` und
            bei MSIX-Apps mit nicht-skalarer Version-Property).
        winget_id: winget-Produkt-Id (z.B. ``"Mozilla.Firefox"``).
            ``None`` fuer Eintraege aus Registry oder MSIX — diese
            Quellen kennen keine winget-Ids.
        source: Quelle des Eintrags. Wird per:class:`Literal` typisiert
            — andere Werte sind ein Type-Error fuer mypy. Bei
            Dedup-Konflikt in:func:`collect_all` gewinnt ``"winget"``,
            dann ``"registry"``, dann ``"msix"``, dann
            ``"windows_update"`` (ausstehende Windows-Updates aus dem
            Windows-Update-Agent — OS/KB/.NET/Treiber-Patches), dann
            ``"dotnet"`` (installierte.NET-Laufzeiten:.NET Framework
            via Registry +.NET Core/5+ via ``dotnet --list-runtimes``;
            reine Inventar-Sichtbarkeit, keine Update-Erkennung —
.NET-Updates kommen ueber Windows-Update), zuletzt
            ``"driver"`` (installierte Geraetetreiber der kuratierten
            Klassen GPU/Netzwerk/Storage via ``Get-PnpDevice``; reine
            Inventar-Sichtbarkeit, keine Update-Erkennung —
            Treiber-Updates kommen ueber Windows-Update).
        is_update_available: Autoritativer Bool: ist eine NEUERE Version
            verfuegbar als ``version``? Default ``False`` fuer Quellen,
            die keine Update-Info liefern (Tabular-``winget list``,
            Registry, MSIX-``Get-AppxPackage``). Bei
:func:`collect_winget_module` aus
            ``Get-WinGetPackage.IsUpdateAvailable`` (PowerShell-Modul).
            **Nicht** aus ``len(latest_available) > 0`` ableiten —
            Bitdefender-Pattern (installiert neuer als verfuegbar)
            wuerde sonst falsch positiv sein.
        latest_available: Neueste verfuegbare Version, oder ``None``
            wenn keine Update-Info verfuegbar ist. Bei
:func:`collect_winget_module` aus
            ``Get-WinGetPackage.AvailableVersions[0]``. Default ``None``
            fuer Quellen ohne Update-Info. **Diagnose-Wert** — UI-
            Logik prueft ``is_update_available``, NICHT
            ``latest_available != version``.
    """

    name: str
    version: str
    winget_id: str | None
    source: SoftwareSource
    # Update-Info (2026-05-06, Bug-3-Fix Subtask 3.5-Folge):
    # nur der Module-Pfad (Microsoft.WinGet.Client, JSON) befuellt diese
    # Felder. Tabular-, Registry- und MSIX-Pfad lassen sie auf den
    # Default-Werten — der PatchService-Lookup-Dict nimmt damit nur
    # Module-Items in die Update-Spalte Cleanup).
    is_update_available: bool = False
    latest_available: str | None = None
    # Microsoft-Store-Identifier (z. B. "XP8K2L36VP0QMB").
    # Wird ausschliesslich von:func:`core.patch_winget_module.collect_winget_module`
    # bei ``source_raw == "msstore"`` gesetzt — Store-IDs sind kein winget-
    # Catalog-Format (Großbuchstaben + Ziffern) und gehoeren NICHT ins
    # ``winget_id``-Feld. Der Patch-Upgrade-Executor nutzt ``store_id``
    # zur Dispatch-Entscheidung (winget upgrade vs. winget upgrade
    # --source msstore).
    store_id: str | None = None
