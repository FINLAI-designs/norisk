"""key_manager_context — Modul-State-Container fuer aktiven KeyManager §2.5 Variante A).

Stellt zwei Funktionen bereit, die zusammen den Bootstrap-Pfad des
:class:`KeyManager` an die Konsumenten (``EncryptedDatabase``,
``SecureStorage``) verkabeln:

*:func:`set_active_key_manager` — wird von:func:`apps.launch_app`
  nach:meth:`KeyManager.initialize` aufgerufen.
*:func:`get_active_key_manager` — wird von Konsumenten aufgerufen,
  wenn sie keinen expliziten ``key_manager``-Konstruktor-Parameter
  bekommen haben.

Analoges Pattern zu:func:`core.database.db_context.set_db_app_id` —
Modul-State, der pro Prozess einmalig im Bootstrap gesetzt und von
Konsumenten read-only konsumiert wird.

Constructor-Injection bleibt fuer Tests verfuegbar §2.5
β-Variante): Wenn ein Konsument einen expliziten ``key_manager=``-
Parameter erhaelt, wird dieser bevorzugt — kein Modul-Lookup. Damit
koennen Tests einen dedizierten KeyManager mit
``InMemoryDPAPIBackend`` direkt injizieren, ohne den Modul-State zu
beruehren.

Schichtzugehoerigkeit: ``core/database/`` (Crypto-Infrastruktur, kein
PySide6-Import — testbar ohne GUI).

Author: Patrick Riederich
Version: 1.0 (Subtask 2 Variante A §2.5)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.exceptions import ConfigurationError

if TYPE_CHECKING:
    from core.database.key_manager import KeyManager

#: Modul-State. Pro Prozess eine Instanz, gesetzt durch ``launch_app``.
#: Kein Singleton-Pattern auf Klassen-Ebene — der Modul-State ist
#: bewusst minimal und in Tests einfach via ``set_active_key_manager(None)``
#: zuruecksetzbar.
_active_key_manager: KeyManager | None = None


def set_active_key_manager(km: KeyManager | None) -> None:
    """Setzt den aktiven KeyManager im Modul-State.

    Wird typisch von:func:`apps.launch_app` einmalig nach
:meth:`KeyManager.initialize` aufgerufen. Tests koennen die
    Funktion ebenfalls nutzen, muessen aber im teardown
    ``set_active_key_manager(None)`` aufrufen, um Test-Pollution
    zwischen Tests zu vermeiden.

    Args:
        km: Aktive KeyManager-Instanz oder ``None`` zum expliziten
            Deaktivieren des Modul-Lookups (jeder folgende
:func:`get_active_key_manager`-Aufruf wirft dann
            ``RuntimeError``).
    """
    global _active_key_manager
    _active_key_manager = km


def get_active_key_manager() -> KeyManager:
    """Liefert den aktiven KeyManager aus dem Modul-State.

    Returns:
        Die zuletzt via:func:`set_active_key_manager` gesetzte
        ``KeyManager``-Instanz.

    Raises:
        RuntimeError: Wenn kein Manager gesetzt ist. Typische
            Ursachen::func:`apps.launch_app`-Bootstrap fehlt
            (Production), oder ein Test hat den Manager noch nicht
            via Fixture gesetzt. Konsumenten muessen alternativ den
            Constructor-Injection-Pfad ``key_manager=``-Parameter
            nutzen.
    """
    if _active_key_manager is None:
        raise ConfigurationError(
            "Kein aktiver KeyManager. launch_app muss "
            "set_active_key_manager(km) aufrufen, oder Konsument "
            "muss key_manager= explizit injizieren."
        )
    return _active_key_manager
