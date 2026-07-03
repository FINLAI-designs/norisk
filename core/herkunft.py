"""core.herkunft — Herkunft (Provenance) von Bewertungs-/Messwerten E5).

Ein einziges, geteiltes Wertobjekt für die Herkunft eines Sicherheits-Fakts oder
-Scores. Es trennt — durchgängig und fail-closed — drei Beweiswert-Stufen, die
/ NIE vermischen dürfen:

*:attr:`Herkunft.GEMESSEN` — durch einen Live-Scan des EIGENEN Systems erhoben
  (höchster Beweiswert; technisch nur SELF/).
*:attr:`Herkunft.ERFASST` — vom Berater für einen KUNDEN manuell eingetragen
  (Fremdangabe; NIE als „gemessen" ausweisen E2). Eine Kundenmaschine
  ist nicht fern-messbar.
*:attr:`Herkunft.DEKLARIERT` — Selbsteinschätzung aus dem Audit-Fragebogen.

Leitplanke E5, fail-closed): Ohne eindeutige Herkunft gilt NIE
„gemessen".:meth:`Herkunft.from_value` fällt auf den konservativsten Default
(``DEKLARIERT``) zurück und verbietet ``GEMESSEN`` als Default.

Abgrenzung: ``tools.system_tuner.domain.entities.Provenance`` ist ein ANDERES
Konzept (Katalog-Quelle + Lizenz für die Clean-Room-Prüfung) — nicht verwechseln.

Schichtzugehörigkeit: core/ — reines Domänen-Wertobjekt, keine I/O.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from enum import StrEnum


class Herkunft(StrEnum):
    """Herkunft eines Sicherheits-Fakts oder -Scores (drei Beweiswert-Stufen).

:class:`~enum.StrEnum` — der Wert ist direkt JSON-/DB-serialisierbar
    (der gespeicherte String ist stabil —:attr:`value`).
    """

    GEMESSEN = "gemessen"
    ERFASST = "erfasst"
    DEKLARIERT = "deklariert"

    @property
    def badge(self) -> str:
        """Kurzes Herkunfts-Label für Kacheln/Chips (Sie-Form-neutral).

        Returns:
            Knapper Anzeigetext, z. B. ``"selbst deklariert"``.
        """
        return {
            Herkunft.GEMESSEN: "gemessen",
            Herkunft.ERFASST: "erfasst",
            Herkunft.DEKLARIERT: "selbst deklariert",
        }[self]

    @property
    def beschreibung(self) -> str:
        """Erklärender Herkunfts-Text (Tooltip/Legende).

        Returns:
            Ein Satz, der den Beweiswert dieser Herkunft einordnet.
        """
        return {
            Herkunft.GEMESSEN: (
                "Durch eine Live-Messung des eigenen Systems erhoben."
            ),
            Herkunft.ERFASST: (
                "Vom Berater für den Kunden manuell erfasst (Fremdangabe, "
                "nicht gemessen)."
            ),
            Herkunft.DEKLARIERT: (
                "Selbsteinschätzung aus dem Audit-Fragebogen."
            ),
        }[self]

    @property
    def ist_gemessen(self) -> bool:
        """True nur für:attr:`GEMESSEN` (Beweiswert-Gate für Konsumenten)."""
        return self is Herkunft.GEMESSEN

    @property
    def beweiswert_rang(self) -> int:
        """Ordinaler Beweiswert (3 = höchster).

        NUR zum Sortieren/Auswählen „welche Quelle ist belastbarer" gedacht —
        NIE zum Mitteln zweier Herkünfte: kein Misch-Score).

        Returns:
            ``3`` (gemessen), ``2`` (erfasst) oder ``1`` (deklariert).
        """
        return {
            Herkunft.GEMESSEN: 3,
            Herkunft.ERFASST: 2,
            Herkunft.DEKLARIERT: 1,
        }[self]

    @classmethod
    def from_value(
        cls, value: object, *, default: Herkunft | None = None
    ) -> Herkunft:
        """Parst einen gespeicherten Herkunfts-String fail-closed.

        Ein unbekannter/leerer Wert ergibt NIE ``GEMESSEN`` — er fällt auf
        ``default`` zurück, der seinerseits nicht ``GEMESSEN`` sein darf
 E5: ohne eindeutige Herkunft nie „gemessen").

        Args:
            value: Roh-Wert aus DB/JSON (i. d. R. ein String).
            default: Rückfall-Herkunft bei unbekanntem Wert. ``None`` (Default)
                → ``DEKLARIERT`` (konservativster Beweiswert). Darf nicht
                ``GEMESSEN`` sein.

        Returns:
            Die passende:class:`Herkunft` oder ``default`` (bzw. ``DEKLARIERT``).

        Raises:
            ValueError: Wenn ``default`` ``GEMESSEN`` ist (Leitplanken-Verstoß).
        """
        fallback = cls.DEKLARIERT if default is None else default
        if fallback is cls.GEMESSEN:
            raise ValueError(
                "Herkunft.from_value: default darf nicht GEMESSEN sein "
                "(fail-closed, ADR-041 E5)."
            )
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return fallback
