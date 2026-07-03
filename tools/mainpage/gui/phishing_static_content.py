"""
phishing_static_content — Kuratierte statische Inhalte fuer den
Phishing-Radar.

Hier wohnen die Listen, die das ``PhishingInboxDialog`` in den Tabs
*So erkennst du Phishing* und *Schon reingefallen?* anzeigt. Die
Konstanten wurden aus dem alten ``phishing_help_section.py``-Modul
extrahiert (2026-05-28 Phishing-Radar-Refactor), damit dieselben Texte
auch ausserhalb des Mainpage-Layouts wiederverwendet werden koennen.

Quellen:
  * BSI-/Watchlist-Internet-Empfehlung 2026 (KI-Phishing-bewusst).
  * BSI-/ProPK-Phishing-Checkliste 2026:
    https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/
    Broschueren/Wegweiser_Checklisten_Flyer/Checkliste_BSI_ProPK_Phishing.html

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

# Phishing-Erkennungsmerkmale 2026 — die klassische 90er-Liste
# (Rechtschreibung / generische Anrede) ist durch KI-generierte Mails
# entwertet. Diese Liste ist auf die Hinweise konzentriert, die 2026
# noch zuverlaessig sind.
RECOGNITION_HINTS: list[tuple[str, str]] = [
    (
        "Absender-Domain genau prüfen",
        "Nicht nur den Anzeigenamen lesen — die vollständige Mail-Adresse. "
        "Betrüger nutzen leicht abgeänderte Domains (z.B. amaz0n.com).",
    ),
    (
        "Dringlichkeits-Sprache hinterfragen",
        "„Innerhalb von 24 h bestätigen“ oder „Konto wird gesperrt“ ist "
        "klassisches Social Engineering — seriöse Anbieter setzen keine "
        "Sekunden-Fristen.",
    ),
    (
        "Links vor dem Klicken inspizieren",
        "Mit der Maus über den Link fahren und die Ziel-URL prüfen, ohne "
        "zu klicken. Verdächtig: kryptische Domains, URL-Shortener, "
        "Zeichen-Mix (z.B. „1“ statt „l“).",
    ),
    (
        "Datenanfragen sind verdächtig",
        "Banken, Behörden, Versicherungen fragen nie per E-Mail nach PIN, "
        "TAN, Passwort oder vollständigen Zahlungsdaten.",
    ),
    (
        "Unaufgeforderte Anhänge nie öffnen",
        "ZIP-, EXE-, Office-Anhänge in unerwarteten Mails — nie öffnen. "
        "Auch nicht „nur kurz reinschauen“.",
    ),
    (
        "Personalisierung ist 2026 KEIN Schutz mehr",
        "KI-Phishing zieht Daten aus LinkedIn/X/Vereinslisten und schreibt "
        "personalisierte Mails. „Sehr geehrter Patrick“ ist kein "
        "Echtheits-Beweis.",
    ),
    (
        "Bei Zweifel: direkter Kontakt",
        "Über die offizielle Webseite des Anbieters einloggen oder die "
        "Telefonnummer aus dem Vertrag/auf der Rückseite der Bankkarte "
        "verwenden — nicht aus der verdächtigen Mail.",
    ),
    (
        "Multifaktor-Authentifizierung aktivieren",
        "Wo möglich (Mail, Bank, Cloud, Office365) MFA einschalten. "
        "Macht selbst geklautes Passwort wertlos.",
    ),
]


# Sofort-Schritte aus der BSI-/ProPK-Phishing-Checkliste 2026.
EMERGENCY_STEPS: list[tuple[str, str]] = [
    (
        "1. Passwörter sofort ändern",
        "Alle betroffenen Konten + alle anderen Konten mit demselben "
        "Passwort. Von einem anderen Gerät aus, das nicht kompromittiert "
        "sein könnte.",
    ),
    (
        "2. Bank verständigen",
        "Bei Bank-/Kreditkartendaten: Sperr-Hotline 116 116 (DE/AT). "
        "Karten sperren lassen, Konto-Bewegungen prüfen.",
    ),
    (
        "3. Konten beim Anbieter sperren",
        "Online-Dienste (E-Mail, Cloud, Office365) informieren und ggf. "
        "temporär sperren. Logging-Daten auswerten lassen.",
    ),
    (
        "4. System scannen",
        "Antivirus-Vollscan starten. Bei Verdacht auf Trojaner: System "
        "von externem Medium booten und neu aufsetzen.",
    ),
    (
        "5. Anzeige bei der Polizei",
        "Online-Wache der Landespolizei oder örtliche Dienststelle. "
        "Beweise (Mail, Screenshots, Transaktions-IDs) mitbringen.",
    ),
    (
        "6. Phishing-Mail melden",
        "An den Anbieter weiterleiten (z.B. phishing@paypal.de, "
        "abuse@<bank>.at) und an die Verbraucherzentrale.",
    ),
    (
        "7. MFA überall aktivieren",
        "Auf allen wichtigen Konten die Zwei-Faktor-Authentifizierung "
        "einschalten — auch dort, wo der Angriff nicht stattfand.",
    ),
    (
        "8. Aus dem Vorfall lernen",
        "Erkennungs-Checkliste links durchgehen, Familie/Team-Mitglieder "
        "informieren. Erfahrung notieren für nächstes Mal.",
    ),
]
