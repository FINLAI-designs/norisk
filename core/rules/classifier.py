"""classifier — Effort-Klassifikator nach AI_TODO 4.2 (Sprint S2a).

Kaskadierende Heuristiken H1–H12 — projiziert eine ``Story.action``-
Zeile + ``Rule.classifier_hint`` auf eine der drei Effort-Klassen:

  - ``"quick"`` — < 1 h, idempotent, ein Asset
  - ``"mittel"`` — 1 d bis 1 Woche, mehrere Systeme
  - ``"langfrist"`` — > 1 Monat, organisationales Commitment

Reihenfolge der Heuristiken-Auswertung (Tiebreaker per AI_TODO 4.2:
*konservativer — eher Mittel als Quick-Win, falsche Quick-Win-
Klassifikation bricht Patrick's Versprechen*):

  1. Lang-Indikatoren (H9–H12) → ``"langfrist"``
  2. Mittel-Indikatoren (H5–H8) → ``"mittel"``
  3. Quick-Win-Indikatoren (H1–H4) **alle** erfüllt → ``"quick"``
  4. Default → ``"mittel"``

Schichtzugehörigkeit: core/ — pure Funktion, kein State.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import Final

from core.rules.models import ClassifierHint
from core.vulnerability.domain.severity import Severity

# ---------------------------------------------------------------------------
# Heuristiken-Vokabulare (AI_TODO 4.2)
# ---------------------------------------------------------------------------

_QUICK_KEYWORDS: frozenset[str] = frozenset(
    {
        "update",
        "patch",
        "rotate",
        "ändere",
        "deaktiviere",
        "renew",
        "block",
        "set header",
        "erneuer",
        "schließen",
        "schliessen",
    }
)
"""H1: Action-Keywords, die typischerweise einen Single-Asset-Quick-Win
beschreiben."""

_QUICK_BLOCKLIST: frozenset[str] = frozenset(
    {
        "schulung",
        "konzept",
        "policy",
        "audit",
        "framework",
        "prozess",
        "monitoring-stack",
        "zertifizierung",
    }
)
"""H3: Begriffe, die einen Quick-Win sofort entkräften (organisatorische
Aufgaben)."""

_MITTEL_KEYWORDS: frozenset[str] = frozenset(
    {
        "konfiguriere für mehrere",
        "rolle aus",
        "migriere",
        "etabliere",
        "automatisiere",
        "backup",
        "spf",
        "dkim",
        "dmarc",
        "segment",
    }
)
"""H5+H7: Action-Keywords für mehrere-Systeme-Aktionen."""

_LANG_KEYWORDS: frozenset[str] = frozenset(
    {
        "iso 27001",
        "tisax",
        "nis-2",
        "siem",
        "soc",
        "mdm",
        "awareness-programm",
    }
)
"""H9: organisationale Programme."""

_LANG_VENDORS: frozenset[str] = frozenset(
    {
        "splunk",
        "wazuh",
        "crowdstrike",
        "intune",
        "jamf",
    }
)
"""H10: Enterprise-Vendor-Wörter."""

_LANG_TIMEWORDS: frozenset[str] = frozenset(
    {
        "jährlich",
        "kontinuierlich",
        "quartalsweise",
    }
)
"""H11: Wiederkehrungs-Marker."""

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify(action_text: str, hint: ClassifierHint | None = None) -> str:
    """Klassifiziert eine Aktion in ``"quick"``/``"mittel"``/``"langfrist"``.

    Args:
        action_text: Der Story-Action-Text (z. B. *"Auf Version 1.1.1z
            updaten."*). Whitespace + Case werden normalisiert.
        hint: Optionaler:class:`ClassifierHint` aus der Regel — füttert
            die Heuristiken mit Werten, die im Text nicht ableitbar sind
            (asset_count, action_keywords). ``None`` = Defaults.

    Returns:
        Eine der drei Effort-Klassen.
    """
    if hint is None:
        hint = ClassifierHint()

    # Normalisierung: kleinschreiben, Whitespace trimmen, Hint-Keywords
    # virtuell anhängen damit sie ebenfalls in den Tokenizer-Schleifen
    # mitgeprüft werden.
    text_parts = [action_text.lower()]
    text_parts.extend(k.lower() for k in hint.action_keywords)
    text = " ".join(text_parts).strip()
    asset_count = hint.asset_count

    # ---- Lang-Indikatoren (zuerst, weil sie alles andere überstimmen) ----
    if _contains_any(text, _LANG_KEYWORDS):  # H9
        return "langfrist"
    if _contains_any(text, _LANG_VENDORS):  # H10
        return "langfrist"
    if _contains_any(text, _LANG_TIMEWORDS):  # H11
        return "langfrist"
    if asset_count > 50:  # H12
        return "langfrist"

    # ---- Mittel-Indikatoren ----
    if _contains_any(text, _MITTEL_KEYWORDS):  # H5 + H7
        return "mittel"
    if 2 <= asset_count <= 50:  # H6
        return "mittel"

    # ---- Quick-Win — alle Indikatoren H1..H4 müssen passen ----
    h1 = _contains_any(text, _QUICK_KEYWORDS)
    h2 = asset_count == 1
    h3 = not _contains_any(text, _QUICK_BLOCKLIST)
    # H4 (existing fix-version / requiredAction) ist datenseitig — hier
    # akzeptieren wir das implizit, weil der Story-Action-Pfad i. d. R.
    # eine konkrete Version oder Anweisung enthält. Edge-Cases
    # (CRITICAL ohne Fix) sollen über die Anti-Patterns aus AI_TODO 4.5
    # in den Regeln selbst behandelt werden.
    if h1 and h2 and h3:
        return "quick"

    # Tiebreaker: konservativer (eher Mittel als Quick).
    return "mittel"


def severity_class_distribution(severity: Severity) -> str:
    """Default-Klasse anhand reiner Severity (AI_TODO 4.3).

    Wird genutzt, wenn keine Regel mit eigenem ``classifier_hint`` greift —
    z. B. von Tests oder einem Fallback-Pfad. Verteilung:

      - ``CRITICAL`` → ``"quick"`` (60 % der echten Fälle, plus
        Sofort-Mitigation für die anderen 40 %)
      - ``HIGH`` → ``"mittel"`` (50 %; Mittel ist der häufigste Wert)
      - ``MEDIUM`` → ``"mittel"``
      - ``LOW``/``INFO`` → ``"langfrist"``

    Diese Funktion ist bewusst grob — die *eigentliche* Klassifikation
    leistet:func:`classify`. Nutze die Verteilung nur als letzten
    Ausweg, nicht als Standard-Pfad.
    """
    if severity == Severity.CRITICAL:
        return "quick"
    if severity in (Severity.HIGH, Severity.MEDIUM):
        return "mittel"
    return "langfrist"


# ---------------------------------------------------------------------------
# Kapazitaets-Schaetzung (KMU "fixbar mit 1 Person in X Wochen")
# ---------------------------------------------------------------------------

#: Basis-Personenwochen je Effort-Klasse — abgeleitet aus den Effort-Spannen
#: im Modul-Docstring (quick < 1 h ~ 0.05 W; mittel 1 d–1 Woche ~ 0.5 W;
#: langfrist > 1 Monat ~ 6 W). Single Source mit ``classify``.
_BASE_PERSON_WEEKS: Final[dict[str, float]] = {
    "quick": 0.05,
    "mittel": 0.5,
    "langfrist": 6.0,
}


def estimate_person_weeks(urgency: str, asset_count: int = 1) -> float:
    """Schaetzt den Aufwand eines Findings deterministisch in Personen-Wochen.

    Kombiniert die Effort-Klasse (:func:`classify`-Ausgabe) mit der Asset-Menge
    (Buckets exakt wie H2/H6/H12 in:func:`classify`). Rein deterministisch,
    keine KI — Grundlage der KMU-Aussage "fixbar mit 1 Person in X Wochen".

    Args:
        urgency: Effort-Klasse ``"quick"``/``"mittel"``/``"langfrist"``.
        asset_count: Geschaetzte Anzahl betroffener Assets (>= 1). ACHTUNG: i.d.R.
            die pro-Regel-Typ-Schaetzung (``ClassifierHint.asset_count``), NICHT der
            reale Ist-Bestand — das Ergebnis ist daher eine grobe "ca."-Angabe.

    Returns:
        Geschaetzte Personen-Wochen, auf 0.1 gerundet.

    Raises:
        ValueError: Bei unbekannter ``urgency`` oder ``asset_count < 1``.
    """
    if urgency not in _BASE_PERSON_WEEKS:
        msg = (
            f"Unbekannte Effort-Klasse: {urgency!r} (erwartet quick/mittel/langfrist)."
        )
        raise ValueError(msg)
    if asset_count < 1:
        msg = f"asset_count muss >= 1 sein, war {asset_count}."
        raise ValueError(msg)
    if asset_count == 1:
        scale = 1.0
    elif asset_count <= 50:
        scale = 2.0
    else:
        scale = 4.0
    return round(_BASE_PERSON_WEEKS[urgency] * scale, 1)


def format_capacity(person_weeks: float) -> str:
    """Formatiert eine Personen-Wochen-Schaetzung als KMU-Kapazitaets-Satz.

    Args:
        person_weeks: Ergebnis aus:func:`estimate_person_weeks`.

    Returns:
        Z.B. ``"fixbar mit 1 Person in ca. 1 Woche"`` bzw. fuer sehr kleine Werte
        ``"fixbar mit 1 Person in unter 1 Tag"``. Bewusst "ca." (Schaetzung).
    """
    pw = round(person_weeks, 1)
    if pw < 0.2:
        return "fixbar mit 1 Person in unter 1 Tag"
    einheit = "Woche" if pw == 1.0 else "Wochen"
    betrag = f"{pw:g}".replace(".", ",")
    return f"fixbar mit 1 Person in ca. {betrag} {einheit}"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _contains_any(text: str, vocabulary: frozenset[str]) -> bool:
    """``True`` wenn mindestens eines der ``vocabulary``-Worte im Text steckt.

    Substring-Match (kein Wort-Boundary), damit Konjugationen und
    Komposita greifen (``erneuer`` matcht ``erneuere``, ``erneuern``,
    ``Zertifikat-erneuerung``).
    """
    return any(token in text for token in vocabulary)
