"""
patch_id_utils — Helfer fuer synthetische Patch-Inventar-Ids.

Registry-/MSIX-Apps, ausstehende Windows-Updates, installierte
.NET-Laufzeiten und installierte Geraetetreiber haben keine echte
winget-Id (``winget_id=None``). Damit sie mit dem aktuellen
``inventory_snapshot``-Schema (PRIMARY KEY ``winget_id``) persistiert
werden koennen, bekommen sie in
:func:`core.patch_collector.collect_all` eine **stabile synthetische Id**
mit Praefix ``regid:`` (Registry), ``msix:`` (MSIX/AppX), ``wu:``
(ausstehende Windows-Updates aus dem Windows-Update-Agent),
``dotnet:`` (installierte.NET-Laufzeiten), ``drv:`` (installierte
Geraetetreiber der kuratierten Klassen GPU/Netzwerk/Storage) bzw.
``wgname:`` (winget-Quelle OHNE Katalog-Id — z.B. eine App, deren
``Get-WinGetPackage``-Ausgabe kein ``Id``-Feld traegt; sie wird nur
sichtbar gemacht, ist mangels Id aber nicht via winget patchbar).

Sicherheits-Invariante: eine synthetische Id darf NIEMALS an ``winget
upgrade`` oder ein anderes winget-CLI gereicht werden. Der Doppelpunkt im
Praefix ist in echten winget-Ids unzulaessig — er macht die Ids damit
unverwechselbar und gleichzeitig fail-closed gegen den
``_WINGET_ID_RE``-Validator in:mod:`core.patch_upgrade`. Diese Funktion
ist der zentrale Erkennungspunkt fuer alle winget-Command-Gates.
"""

from __future__ import annotations

#: Praefixe synthetischer Inventar-Ids. Der Doppelpunkt ist in echten
#: winget-Ids nie gueltig -> sicheres Unterscheidungsmerkmal.
#: ``wu:`` markiert ausstehende Windows-Updates (Windows-Update-Agent) —
#: sie sind nicht via winget installierbar (Installation ueber die
#: Windows-Einstellungen). ``dotnet:`` markiert installierte
#:.NET-Laufzeiten (.NET Framework via Registry +.NET Core/5+ via
#: ``dotnet --list-runtimes``) — sie sind reine Inventar-Sichtbarkeit
#: und werden ebenfalls nicht via winget gepatcht (.NET-Updates kommen
#: ueber Windows-Update). ``drv:`` markiert installierte Geraetetreiber
#: der kuratierten Klassen GPU/Netzwerk/Storage (via ``Get-PnpDevice``)
#: — ebenfalls reine Inventar-Sichtbarkeit, Treiber-Updates kommen ueber
#: Windows-Update. Alle werden deshalb genau wie ``regid:``/``msix:`` aus
#: allen winget-Command-Gates ausgeschlossen.
SYNTHETIC_ID_PREFIXES: tuple[str, ...] = (
    "regid:", "msix:", "wu:", "dotnet:", "drv:", "wgname:"
)


def is_synthetic_id(winget_id: str | None) -> bool:
    """Prueft, ob eine Inventar-Id synthetisch ist.

    Synthetische Ids tragen das Praefix ``regid:`` (Registry-App),
    ``msix:`` (MSIX/AppX), ``wu:`` (ausstehendes Windows-Update),
    ``dotnet:`` (installierte.NET-Laufzeit), ``drv:`` (installierter
    Geraetetreiber) oder ``wgname:`` (winget-Quelle ohne Katalog-Id) und
    duerfen niemals an ein winget-CLI-Kommando gereicht werden — sie
    identifizieren Apps/Updates/Laufzeiten/Treiber, die winget gar nicht
    kennt bzw. (mangels Id) nicht installieren kann.

    Args:
        winget_id: Die zu pruefende Id, oder ``None`` (z.B. Custom-Source).

    Returns:
        ``True`` wenn ``winget_id`` gesetzt ist und mit einem
        synthetischen Praefix beginnt, sonst ``False``.
    """
    return bool(winget_id) and winget_id.startswith(SYNTHETIC_ID_PREFIXES)


__all__ = [
    "SYNTHETIC_ID_PREFIXES",
    "is_synthetic_id",
]
