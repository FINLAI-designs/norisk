"""
apply_terms — Nutzungshinweis + Einwilligung zur Funktion "System optimieren".

FINAL (Patrick freigegeben 2026-06-18 — anwaltlich gegengelesen, B3-Gate erfuellt).
Es ist KEINE eigenstaendige EULA, sondern ein **Delta ergaenzend zu den AGB**
(§ 11 Haftung, 15. Software-Nutzung (NoRisk), core/legal/terms.py): der Apply-Pfad ist die
erste aktiv system-veraendernde Funktion (Registry/Dienste, Admin) und verlangt eine
informierte, dokumentierte Einwilligung (R7) — Voraussetzung dafuer, dass der
Haftungsausschluss in § 11.3 fuer eine aktiv eingreifende Funktion auch greift.

Bei jeder inhaltlichen Aenderung des Textes ``APPLY_TERMS_VERSION`` erhoehen →
erneute Einwilligung wird erzwungen (:class:`ConsentGate`).

Schichtzugehoerigkeit: application/ (reiner Text, keine Logik/I/O).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

#: Version des Hinweistexts. Bei inhaltlicher Aenderung erhoehen.
#: 1.1: Freigabe-/Final-Stand (B3-Gate). Der Bump erzwingt eine
#: frische, dokumentierte Einwilligung gegenueber jedem Entwurfs-Stand.
APPLY_TERMS_VERSION = "1.2"  # 1.2: Pro/Edition-Claim entfernt, AGB-Anker aktualisiert

#: Kurzfassung (eine Zeile) — z. B. fuer Tooltips/Logs.
APPLY_TERMS_SHORT = (
    "Die Funktion System optimieren aendert Windows-Einstellungen mit "
    "Administratorrechten; umkehrbar, mit Wiederherstellungspunkt; Verantwortung "
    "fuer Backup/Betrieb verbleibt beim Nutzer."
)

#: Vollstaendiger Hinweis- und Einwilligungstext (final, freigegeben 2026-06-18).
APPLY_TERMS_TEXT = """\
Nutzungshinweis und Einwilligung — Funktion „System optimieren"
Version 1.2 · ergaenzend zu den AGB (§ 11 Haftung, 15. Software-Nutzung (NoRisk))

1. Gegenstand
Die Funktion „System optimieren" veraendert auf Ihre ausdrueckliche Veranlassung
hin Windows-Konfigurationseinstellungen (Registry-Werte und Dienst-Starttypen)
mit Administratorrechten. Die Funktion ist optional und erfordert Administratorrechte.

2. Schutzmechanismen
Vor jeder Aenderungs-Sitzung wird — soweit vom System unterstuetzt — ein
Windows-Wiederherstellungspunkt erstellt. NoRisk sichert den jeweiligen
Vorzustand und ermoeglicht die Ruecknahme jeder Aenderung („Meine Aenderungen
zuruecknehmen"). Sicherheitskritische Komponenten (u. a. Windows Update,
Microsoft Defender, Verschluesselungs-/Zertifikatsdienste) sind durch eine fest
verdrahtete Sperrliste von Aenderungen ausgenommen. Diese Mechanismen mindern
Risiken, schliessen sie jedoch nicht vollstaendig aus.

3. Hinweis zur Telemetrie-Edition
Microsoft laesst die Telemetrie-Stufe „Aus" nur auf den Editionen
Enterprise/Education/IoT/Server wirksam zu. Auf Windows Pro und Home ist die
niedrigste wirksame Stufe „Erforderlich". NoRisk weist dies vor der Anwendung
aus und setzt auf diesen Editionen kein „Aus".

4. Verantwortung des Nutzers
Sie sind fuer eine vorherige Datensicherung sowie fuer den ordnungsgemaessen
Betrieb Ihres Systems selbst verantwortlich. Auf zentral verwalteten Geraeten
(Active Directory / Microsoft Entra / Intune) koennen Gruppenrichtlinien oder
MDM die vorgenommenen Aenderungen ueberschreiben; in diesen Umgebungen sollten
Aenderungen ueber Ihre IT erfolgen.

5. Haftung
Es gelten die Haftungsregelungen der AGB (§ 11). Insbesondere ist die Haftung
fuer mittelbare Schaeden, Datenverlust, Betriebsunterbrechung und Folgeschaeden
nach Massgabe des § 11.3 ausgeschlossen, soweit gesetzlich zulaessig; unberuehrt
bleibt die Haftung fuer Vorsatz und grobe Fahrlaessigkeit sowie fuer Schaeden aus
der Verletzung von Leben, Koerper oder Gesundheit (§ 11.1) und bei Verletzung
wesentlicher Vertragspflichten (§ 11.2). NoRisk sichert kein bestimmtes Ergebnis
und keine bestimmte System- oder Compliance-Wirkung zu.

6. Dokumentation
Ihre Einwilligung wird mit Zeitpunkt und Version protokolliert. Jede Aenderung
wird — ausschliesslich als Metadaten, ohne Inhalte — im Audit-Protokoll
festgehalten; dies dient Ihrem Nachweis getroffener technischer Massnahmen.

Mit „Ich stimme zu" bestaetigen Sie, diesen Hinweis gelesen zu haben und der
Anwendung auf dieser Grundlage zuzustimmen.
"""


__all__ = ["APPLY_TERMS_SHORT", "APPLY_TERMS_TEXT", "APPLY_TERMS_VERSION"]
