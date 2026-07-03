"""core.help.display_mode — Anzeige-Modus fuer das Hilfesystem (Einfach/Profi).

Eine Achse fuer die Progressive-Disclosure-Marktdifferenzierung:

* ``EASY`` — laienverstaendliche Kurzfassung. Zeigt nur die einfachen
  Hilfe-Stufen; Fachbegriffe werden vermieden oder erklaert.
* ``EXPERT`` — die volle Fassung (heutiger Bestandstext) inkl.
  Erklaer-Layer, CVE-/Log-Details.

 (Fundament): definiert nur den Enum + die Resolver-Logik im
:class:`core.help.help_content.HelpContent`. Den global persistierten
Zustand (QSettings-Singleton) und den UI-Toggle liefert; dieser hier
subsumiert dann den bestehenden ``core.help.explain_mode.ExplainMode``
(EXPERT impliziert Erklaer-Layer sichtbar) — siehe Build-Sheet 2026-05-29 §3.
"""

from __future__ import annotations

from enum import StrEnum


class DisplayMode(StrEnum):
    """Anzeige-Modus des Hilfesystems.

    ``StrEnum``, damit der Wert direkt als String (``"easy"``/``"expert"``)
    in QSettings persistiert und aus dem Bestand gelesen werden kann.
    """

    EASY = "easy"
    EXPERT = "expert"

    @classmethod
    def from_value(cls, value: str | None) -> DisplayMode:
        """Liest einen Modus aus einem (evtl. fehlenden) String.

        Args:
            value: Persistierter Wert oder ``None``.

        Returns:
            Der passende Modus; ``EASY`` als Default (Erst-Install =
            Einfach).
        """

        if value is None:
            return cls.EASY
        try:
            return cls(value)
        except ValueError:
            return cls.EASY


__all__ = ["DisplayMode"]
