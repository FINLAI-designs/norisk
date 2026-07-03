"""
phishing_briefing — Auswahl + Zielgruppen-Klassifikation fuer die
Phishing-Sektion des KI-Risikobriefings (c1, 2026-06-26).

Rein + testbar: keine Netzwerk-, LLM- oder GUI-Aufrufe. Der
:class:`BriefingService` ruft:func:`waehle_phishing_kandidaten` und laesst die
beiden Gruppen von einer EIGENEN (2.) LLM-Session umformulieren — parallel zur
CVE-Session.

Region AT+DE+CH wird ueber die bereits vorhandenen Feeds abgedeckt
(``QUELLE_KATEGORIE``): Watchlist-Internet (AT), Mimikama + Polizei-Praevention
NDS (DE), NCSC Schweiz (CH) plus die international-awareness Quellen. Ein
dedizierter Verbraucherzentrale-Feed wird NICHT angebunden — der fruehere
``VZ_DIGITAL``-Endpunkt liefert seit 2026-06-20 dauerhaft HTTP 404 (kein
verifizierter Nachfolger); DE-Phishing ist ueber Mimikama/Polizei-NDS gedeckt.

Klassifikation Consumer vs. KMU: DETERMINISTISCH per Keyword (CEO-Fraud,
Rechnung, Lieferant, Ueberweisung, …) — NICHT durch das LLM, weil ein kleines
lokales Modell (gemma3:4b) die Einordnung halluzinieren wuerde. Das LLM
formuliert nur um, es klassifiziert nicht.

Schichtzugehoerigkeit: application/ — darf domain + core importieren.

Author: Patrick Riederich
Version: 1.0 (c1)
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

from tools.cyber_dashboard.domain.models import (
    CyberMeldung,
    Kategorie,
    QuelleTyp,
    quellen_fuer_kategorien,
)

#: Kategorien, die in den Phishing-Pool des Briefings einfliessen. Konsumenten-
#: Warnungen (DACH) + internationale Awareness-Stories — die deterministische
#: Keyword-Stufe trennt davon den KMU-relevanten Teil ab.
PHISHING_KATEGORIEN: Final[tuple[Kategorie, ...]] = (
    Kategorie.PHISHING_CONSUMER,
    Kategorie.PHISHING_AWARENESS,
)

#: Quellen des Phishing-Pools (aus ``QUELLE_KATEGORIE`` abgeleitet — Single
#: Source of Truth, keine zweite driftende Liste).
#: Effekt: ``waehle_phishing_kandidaten`` verwirft Meldungen, deren Quelle hier
#: nicht enthalten ist (CVE-/Tech-Feeds gehoeren nicht ins Phishing-Briefing).
_PHISHING_QUELLEN: Final[frozenset[QuelleTyp]] = frozenset(
    quellen_fuer_kategorien(PHISHING_KATEGORIEN)
)

#: Standard-Obergrenze pro Gruppe (KMU / Consumer) im Briefing.
MAX_PRO_GRUPPE: Final[int] = 3

#: KMU-/Unternehmens-Phishing-Indikatoren (CEO-Fraud, Rechnungs-/Lieferanten-
#: betrug, BEC). Wortgrenzen-tolerant (deutsche Komposita wie "Rechnungsbetrug",
#: "Lieferantenbetrug" sollen matchen) -> Praefix-Match statt strikter ``\b``.
#: Bewusst KEINE generischen Banken-/Paket-/Behoerden-Begriffe (= Consumer).
_KMU_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"ceo[\s\-]?fraud"
    r"|chef[\s\-]?masche"
    r"|gesch(ae|ä)ftsf(ue|ü)hrer"
    r"|vorstand"
    r"|business[\s\-]?email[\s\-]?compromise"
    r"|\bbec\b"
    r"|rechnung"          # Rechnung, Rechnungsbetrug, Fake-Rechnung
    r"|faktura"
    r"|zahlungsauff"      # Zahlungsaufforderung
    r"|(ue|ü)berweisung"
    r"|bankverbindung"
    r"|iban[\s\-]?(ae|ä)nderung"
    r"|lieferant"         # Lieferant, Lieferantenbetrug
    r"|bestell"           # Bestellung, Bestellbetrug
    r"|auftrag"
    r"|buchhaltung"
    r"|finanzabteilung"
    r"|gehalt|lohnabrechnung|payroll"
    r"|handelsregister|markenregister|gewerberegister"
    r"|firmeneintrag"
    r"|\bb2b\b"
    r"|unternehmen|firma|gesch(ae|ä)ft",
    re.IGNORECASE,
)


def phishing_quellen() -> list[QuelleTyp]:
    """Liefert die Quellen des Phishing-Pools (AT+DE+CH + International).

    Returns:
        Liste der ``QuelleTyp`` aus:data:`PHISHING_KATEGORIEN` (Reihenfolge
        wie in ``QUELLE_KATEGORIE``).
    """
    return list(_PHISHING_QUELLEN)


def ist_kmu_phishing(meldung: CyberMeldung) -> bool:
    """True, wenn die Meldung unternehmens-/KMU-relevantes Phishing beschreibt.

    Deterministischer Keyword-Match auf Titel + Beschreibung. Kein Treffer =
    Consumer (Default-Bucket).

    Args:
        meldung: Zu klassifizierende Phishing-Meldung.

    Returns:
        ``True`` bei KMU-Bezug (CEO-Fraud/Rechnung/Lieferant/…), sonst ``False``.
    """
    return bool(_KMU_PATTERN.search(f"{meldung.titel} {meldung.beschreibung}"))


def waehle_phishing_kandidaten(
    meldungen: Sequence[CyberMeldung],
    *,
    max_pro_gruppe: int = MAX_PRO_GRUPPE,
) -> tuple[list[CyberMeldung], list[CyberMeldung]]:
    """Waehlt + klassifiziert Phishing-Kandidaten in (KMU, Consumer).

    Nur Meldungen aus dem Phishing-Pool (:func:`phishing_quellen`) zaehlen;
    alles andere (CVE-/Tech-Feeds) wird verworfen. Innerhalb jeder Gruppe nach
    Aktualitaet (neueste zuerst), begrenzt auf ``max_pro_gruppe``.

    Args:
        meldungen: Beliebige RSS-Meldungen (gemischt; wird gefiltert).
        max_pro_gruppe: Obergrenze je Gruppe.

    Returns:
        ``(kmu, consumer)`` — zwei Listen von:class:`CyberMeldung`.
    """
    nach_aktualitaet = sorted(
        (m for m in meldungen if m.quelle in _PHISHING_QUELLEN),
        key=lambda m: m.veroeffentlicht,
        reverse=True,
    )
    kmu: list[CyberMeldung] = []
    consumer: list[CyberMeldung] = []
    for meldung in nach_aktualitaet:
        ziel = kmu if ist_kmu_phishing(meldung) else consumer
        if len(ziel) < max_pro_gruppe:
            ziel.append(meldung)
        if len(kmu) >= max_pro_gruppe and len(consumer) >= max_pro_gruppe:
            break
    return kmu, consumer
