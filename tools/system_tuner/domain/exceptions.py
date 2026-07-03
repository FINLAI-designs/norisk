"""
exceptions — Tool-spezifische Fehlerklassen fuer system_tuner.

Erben von der zentralen:mod:`core.exceptions`-Hierarchie: so
faengt ``except FinLaiError`` weiter alles, ``except ValueError`` faengt
Katalog-/Validierungsfehler weiter (additive Mehrfach-Vererbung).

Schichtzugehoerigkeit: domain/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.exceptions import FinLaiError, ValidationError


class SystemTunerError(FinLaiError):
    """Basis fuer alle kontrollierten system_tuner-Fehler."""


class CatalogError(SystemTunerError, ValidationError):
    """Katalog konnte nicht geparst werden oder verletzt eine Invariante.

    Erbt transitiv von:class:`ValueError` ueber:class:`ValidationError`
    — bestehende ``except ValueError``-Pfade fangen das weiter.
    """


class NeverDisableViolation(CatalogError):
    """Ein Tweak-Ziel kollidiert mit der NEVER_DISABLE-Sperrliste.

    Hard-Fail beim Laden: ein Katalog, der einen kritischen Dienst
    (Defender/Update/Crypto/...) oder ein gesperrtes Registry-Ziel
    anfasst, darf gar nicht erst geladen werden (fail-closed).
    """


class RevertMissingError(CatalogError):
    """Ein mutierender Tweak hat keinen gueltigen Revert.

    T1/T2 verlangen ``restore_prior`` oder ``set_value``; nur T3 darf
    ``irreversible`` sein. Schliesst die privacy.sexy-Schwaeche
    "revertCode optional".
    """


class ProvenanceError(CatalogError):
    """``provenance`` fehlt oder nennt eine (A)GPL-Quelle.

    Clean-Room-Gate (R3): der Katalog muss AGPL-frei sein; jede
    Herkunft mit GPL/AGPL-Lizenz wird abgelehnt.
    """
