"""
help_content — Zentrale Datenbasis für das In-App-Hilfesystem.

Enthält die:class:`HelpContent`-Dataclass und pro Tool einen Eintrag.
Alle Hilfetexte werden hier definiert — **kein** Hardcoding von Texten
in Widgets. Die Inhalte folgen dem Ton des Anwenderhandbuchs
(``docs/ANWENDERHANDBUCH_NORISK.md``), gekürzt auf UI-Feldlänge.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.help.display_mode import DisplayMode


@dataclass(frozen=True)
class HelpContent:
    """Strukturierter Hilfetext eines Tools.

    Attributes:
        tool_name: Anzeigename (z.B. ``"Passwort-Checker"``).
        nav_key: Sidebar-Navigationsschlüssel.
        short_description: Ein Satz — erscheint im eingeklappten Panel.
        purpose: "Wozu dient es?" — 2–3 Sätze in Alltagssprache.
        when_to_use: "Wann nutzen?" — 2–3 Sätze.
        steps: "So geht es" — nummerierte Schritte.
        result_explanation: "So lesen Sie das Ergebnis" — 2–4 Sätze.
        next_steps: "Was tun danach?" — 1–3 Sätze.
        tooltips: Mapping ``element_id`` → Tooltip-Text für
                             ``HelpButton`` neben wichtigen Elementen.
        explanations: Mapping ``element_id`` → 1–3-Satz-Erklär-Text
                             (Sprint S1c — Erklär-Layer). Wird vom
                             ``ExplainableLabel``-Wrapper und direkt
                             subscribierten Widgets gelesen, sobald
:class:`core.help.explain_mode.ExplainMode`
                             aktiv ist. Längere und detaillierter als
                             ``tooltips`` — gedacht für Steuerberaterin-
                             Persona, nicht für Power-User.
    """

    tool_name: str
    nav_key: str
    short_description: str
    purpose: str
    when_to_use: str
    steps: list[str]
    result_explanation: str
    next_steps: str
    tooltips: dict[str, str] = field(default_factory=dict)
    explanations: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Easy-Overrides — optional. Wenn ``None`` bzw.
    # nicht gesetzt, faellt der Easy-Modus auf den Bestandstext (= Expert)
    # zurueck. Additiv: alle bestehenden Einträge bleiben unveraendert
    # gueltig (Migrations-Impact null). ``tooltips_easy``/``explanations_easy``
    # sind KEY-WEISE Overrides — nur die fachlich zu schweren Keys brauchen
    # eine Easy-Variante, der Rest faellt automatisch auf ``tooltips`` zurueck.
    # ------------------------------------------------------------------
    short_description_easy: str | None = None
    purpose_easy: str | None = None
    when_to_use_easy: str | None = None
    steps_easy: list[str] | None = None
    result_explanation_easy: str | None = None
    next_steps_easy: str | None = None
    tooltips_easy: dict[str, str] = field(default_factory=dict)
    explanations_easy: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Resolver — die EINZIGE Stelle, die den Modus kennt. Render-Pfade
    # (HelpPanel, HelpDialog, HelpButton) rufen diese statt der Rohfelder.
    # ------------------------------------------------------------------

    def short_description_for(self, mode: DisplayMode) -> str:
        """Kurzbeschreibung im gewaehlten Modus (Easy-Override oder Bestand)."""

        return self._pick(self.short_description_easy, self.short_description, mode)

    def purpose_for(self, mode: DisplayMode) -> str:
        """„Wozu dient es?" im gewaehlten Modus."""

        return self._pick(self.purpose_easy, self.purpose, mode)

    def when_to_use_for(self, mode: DisplayMode) -> str:
        """„Wann nutzen?" im gewaehlten Modus."""

        return self._pick(self.when_to_use_easy, self.when_to_use, mode)

    def result_explanation_for(self, mode: DisplayMode) -> str:
        """„So liest du das Ergebnis" im gewaehlten Modus."""

        return self._pick(
            self.result_explanation_easy, self.result_explanation, mode
        )

    def next_steps_for(self, mode: DisplayMode) -> str:
        """„Was tun danach?" im gewaehlten Modus."""

        return self._pick(self.next_steps_easy, self.next_steps, mode)

    def steps_for(self, mode: DisplayMode) -> list[str]:
        """Schritt-Liste im gewaehlten Modus (Easy-Override oder Bestand)."""

        if mode is DisplayMode.EASY and self.steps_easy is not None:
            return self.steps_easy
        return self.steps

    def tooltip_for(self, key: str, mode: DisplayMode) -> str:
        """Tooltip-Text fuer ``key`` im gewaehlten Modus.

        Key-weiser Fallback: fehlt eine Easy-Variante fuer ``key``, wird der
        Bestands-Tooltip genutzt. Unbekannte Keys liefern ``""``.
        """

        if mode is DisplayMode.EASY and key in self.tooltips_easy:
            return self.tooltips_easy[key]
        return self.tooltips.get(key, "")

    def explanation_for(self, key: str, mode: DisplayMode) -> str:
        """Erklaer-Layer-Text fuer ``key`` im gewaehlten Modus (key-weiser Fallback)."""

        if mode is DisplayMode.EASY and key in self.explanations_easy:
            return self.explanations_easy[key]
        return self.explanations.get(key, "")

    @staticmethod
    def _pick(easy: str | None, default: str, mode: DisplayMode) -> str:
        """Liefert ``easy`` nur im Easy-Modus und wenn gesetzt, sonst ``default``."""

        if mode is DisplayMode.EASY and easy is not None:
            return easy
        return default


# ---------------------------------------------------------------------------
# Einträge — eine Konstante pro Tool (alphabetisch)
# ---------------------------------------------------------------------------

HELP_API_SECURITY = HelpContent(
    tool_name="API Security Analyzer",
    nav_key="api_security",
    short_description=(
        "Prüft Webschnittstellen (APIs) Ihrer eigenen Anwendungen auf "
        "Sicherheitsprobleme."
    ),
    purpose=(
        "Viele Programme kommunizieren über sogenannte APIs — das sind "
        "digitale Schnittstellen, über die Daten zwischen Systemen "
        "ausgetauscht werden. Der Analyzer prüft, ob diese Schnittstellen "
        "Schwachstellen haben, und zeigt Ihnen, wenn sich die Struktur "
        "zwischen zwei Scans verändert hat."
    ),
    when_to_use=(
        "Wenn Sie eine eigene Web-API betreiben oder die API eines Anbieters "
        "prüfen möchten. Wiederholen Sie den Scan nach jedem Update der API — "
        "der Analyzer zeigt dann, was neu, geändert oder weggefallen ist."
    ),
    steps=[
        "Tab 'Neuer Scan' öffnen",
        "URL zur OpenAPI-/Swagger-Beschreibung eingeben",
        "Auf 'Scan starten' klicken",
        "Ergebnis im Tab 'Verlauf' nachschlagen oder zwei Scans vergleichen",
    ],
    result_explanation=(
        "Der Vergleich zeigt drei Gruppen: 'Neu' (neue Endpunkte), 'Geändert' "
        "(veränderte Endpunkte) und 'Entfernt'. Rot markierte Einträge sind "
        "potenziell sicherheitsrelevant — z.B. ein Endpunkt ohne "
        "Authentifizierung."
    ),
    next_steps=(
        "Klären Sie auffällige Änderungen mit den Entwicklern der API. "
        "Dokumentieren Sie geplante Änderungen als 'erwartet'."
    ),
    short_description_easy=(
        "Prüft die Schnittstellen (APIs) deiner eigenen Programme darauf, ob "
        "Fremde darüber an Daten oder Funktionen kommen könnten."
    ),
    purpose_easy=(
        "Viele Programme tauschen Daten über sogenannte APIs aus — das sind "
        "feste Andockstellen, an die sich andere Systeme anschließen. Dieses "
        "Werkzeug prüft, ob an diesen Andockstellen etwas offensteht, was "
        "Fremde ausnutzen könnten. Wenn du den Test später wiederholst, zeigt "
        "es dir außerdem, was sich seit dem letzten Mal verändert hat."
    ),
    when_to_use_easy=(
        "Nimm es, wenn du selbst eine solche Schnittstelle betreibst oder die "
        "eines Anbieters kontrollieren willst. Wiederhole den Test nach jeder "
        "Änderung — du siehst dann sofort, was neu ist, sich geändert hat oder "
        "weggefallen ist."
    ),
    steps_easy=[
        "Oben den Reiter 'Neuer Scan' anklicken",
        "Die Internet-Adresse der Schnittstellen-Beschreibung eintippen (die "
        "bekommst du von deinen Entwicklern)",
        "Auf 'Scan starten' klicken und kurz warten",
        "Unter 'Verlauf' das Ergebnis ansehen oder zwei Tests vergleichen",
    ],
    result_explanation_easy=(
        "Der Vergleich teilt alles in drei Gruppen: 'Neu', 'Geändert' und "
        "'Entfernt'. Rot markierte Zeilen solltest du dir genau ansehen — das "
        "ist zum Beispiel eine Andockstelle, an der gar keine Anmeldung "
        "verlangt wird, also jeder herankommt."
    ),
    next_steps_easy=(
        "Frag bei auffälligen Änderungen die Entwickler deiner Schnittstelle "
        "nach. Änderungen, die du erwartet hast, kannst du als 'in Ordnung' "
        "abhaken."
    ),
    tooltips={
        "btn_scan": (
            "Startet den API-Scan. Benötigt eine URL zur OpenAPI- oder "
            "Swagger-Beschreibung."
        ),
        "diff_new": "Endpunkte die seit dem letzten Scan neu hinzugekommen sind.",
        "diff_changed": (
            "Endpunkte die sich zwischen zwei Scans verändert haben "
            "(z.B. neue Parameter oder geänderte Antworttypen)."
        ),
    },
)

HELP_CERT_MONITOR = HelpContent(
    tool_name="Zertifikats-Monitor",
    nav_key="cert_monitor",
    short_description=(
        "Prüft SSL/TLS-Zertifikate von Webseiten auf Gültigkeit, Ablaufdatum "
        "und Aussteller."
    ),
    purpose=(
        "Webseiten weisen sich mit Zertifikaten aus — ähnlich wie ein "
        "Personalausweis. Ist das Zertifikat abgelaufen oder unsicher, warnen "
        "Browser davor. Der Monitor prüft eine Domain in wenigen Sekunden und "
        "zeigt alle wichtigen Eckdaten."
    ),
    when_to_use=(
        "Vor einer Bestellung bei einem unbekannten Shop, bei einer "
        "Zertifikats-Warnung im Browser oder regelmäßig für eigene Domains, "
        "damit Sie rechtzeitig verlängern."
    ),
    steps=[
        "Domain eingeben (z.B. `example.at` — kein `https://` nötig)",
        "Auf 'Prüfen' klicken",
        "Ablaufdatum, Aussteller und Fingerprint ablesen",
    ],
    result_explanation=(
        "Grün: alles in Ordnung. Orange: läuft in wenigen Wochen ab — jetzt "
        "verlängern. Rot: abgelaufen oder ungültig — Seite nicht vertrauen."
    ),
    next_steps=(
        "Eigene Domain abgelaufen? Hoster kontaktieren oder Let's Encrypt neu "
        "ausstellen lassen."
    ),
    short_description_easy=(
        "Prüft das Sicherheits-Siegel einer Webseite: Ist es noch gültig, "
        "wann läuft es ab und wer hat es ausgestellt?"
    ),
    purpose_easy=(
        "Jede sichere Webseite weist sich mit einem digitalen Siegel aus — "
        "ähnlich wie ein Personalausweis. Ist dieses Siegel abgelaufen oder "
        "nicht echt, warnt dein Browser. Dieses Werkzeug prüft eine Webseite "
        "in wenigen Sekunden und zeigt dir alle wichtigen Eckdaten dazu."
    ),
    when_to_use_easy=(
        "Bevor du in einem unbekannten Shop bestellst, wenn dein Browser eine "
        "Sicherheitswarnung zeigt, oder regelmäßig für deine eigene Webseite — "
        "damit du das Siegel rechtzeitig verlängerst."
    ),
    steps_easy=[
        "Die Adresse der Webseite eintippen (z. B. `beispiel.at` — ohne "
        "`https://` davor)",
        "Auf 'Prüfen' klicken",
        "Ablaufdatum und Aussteller ablesen",
    ],
    result_explanation_easy=(
        "Grün heißt: alles in Ordnung. Orange heißt: läuft bald ab — kümmere "
        "dich jetzt um die Verlängerung. Rot heißt: abgelaufen oder ungültig — "
        "dieser Seite solltest du nicht vertrauen."
    ),
    next_steps_easy=(
        "Ist das Siegel deiner eigenen Webseite abgelaufen? Melde dich bei "
        "deinem Webseiten-Anbieter (Hoster) und lass es erneuern."
    ),
    tooltips={
        "input_domain": (
            "Domain ohne `https://` und ohne Pfad — nur der Hostname, z.B. "
            "`www.beispiel.at`."
        ),
        "btn_check": "Startet die Zertifikatsprüfung. Dauert 2–5 Sekunden.",
        "result_expiry": (
            "Ablaufdatum des Zertifikats. Weniger als 30 Tage = orange, "
            "abgelaufen = rot."
        ),
    },
)

HELP_CSAF_ADVISOR = HelpContent(
    tool_name="Advisory-Monitor",
    nav_key="csaf_advisor",
    short_description=(
        "Zeigt offizielle Sicherheitsmitteilungen (CSAF-Advisories) von "
        "Herstellern und Behörden."
    ),
    purpose=(
        "CSAF-Advisories sind offizielle Sicherheitsmitteilungen — wie ein "
        "Rückruf beim Auto, nur für Software. Der Monitor ruft sie von "
        "vertrauenswürdigen Quellen ab (z.B. BSI, Red Hat, Cisco) und "
        "markiert Einträge, die Ihren Tech-Stack betreffen."
    ),
    when_to_use=(
        "Täglich oder wöchentlich öffnen, um neue Advisories zu Ihren "
        "Produkten nicht zu verpassen. Besonders nach großen "
        "Sicherheitsnachrichten in den Medien."
    ),
    steps=[
        "Auf 'Jetzt abrufen' klicken — die Liste aktualisiert sich im Hintergrund",
        "Filter setzen: Severity, Zeitraum oder 'Nur Matches' (welche Quellen "
        "abgerufen werden, legen Sie über das Zahnrad 'Provider verwalten' fest "
        "— das ist kein Listenfilter)",
        "Eintrag in der Liste links auswählen",
        "Details rechts lesen (CVSS, betroffene Produkte, externe Links)",
    ],
    result_explanation=(
        "Farbe zeigt Schweregrad: Rot = KRITISCH, Orange = HOCH, Gelb = "
        "MITTEL, Grün = NIEDRIG. Das Badge [MATCH] hinter der Kennung bedeutet: "
        "dieses Advisory betrifft ein Produkt aus Ihrem Tech-Stack — diese "
        "Treffer behandeln Sie zuerst."
    ),
    next_steps=(
        "Betrifft der Advisory Ihren Stack? Im Techstack-Tool als offen "
        "markieren und das Patch zeitnah einspielen."
    ),
    short_description_easy=(
        "Zeigt offizielle Sicherheitswarnungen von Herstellern und Behörden — "
        "wie ein schwarzes Brett für IT-Probleme."
    ),
    purpose_easy=(
        "Solche Warnungen (Fachwort: Advisories) sind offizielle Mitteilungen "
        "zu Sicherheitsproblemen — wie ein Rückruf beim Auto, nur für Software. "
        "Das Werkzeug holt sie von vertrauenswürdigen Stellen (z. B. dem BSI "
        "oder großen Herstellern) und hebt die hervor, die deine eigene "
        "Software betreffen."
    ),
    when_to_use_easy=(
        "Schau täglich oder wöchentlich vorbei, damit dir keine neue Warnung "
        "zu deinen Programmen entgeht. Besonders dann, wenn gerade in den "
        "Nachrichten über ein Sicherheitsproblem berichtet wird."
    ),
    steps_easy=[
        "Auf 'Jetzt abrufen' klicken — die Liste lädt im Hintergrund",
        "Bei Bedarf filtern: nach Schwere, Zeitraum oder 'Nur Treffer für mich' "
        "(welche Quellen abgerufen werden, stellst du über das Zahnrad-Symbol "
        "'Provider verwalten' ein — das ist kein Listenfilter)",
        "Links in der Liste einen Eintrag anklicken",
        "Rechts die Details lesen (betroffene Produkte, Links)",
    ],
    result_explanation_easy=(
        "Die Farbe zeigt, wie ernst es ist: Rot = sehr kritisch, Orange = "
        "hoch, Gelb = mittel, Grün = gering. Steht hinter der Kennung das Badge "
        "[MATCH], dann betrifft diese Warnung eine Software aus deinem eigenen "
        "Bestand — kümmere dich um diese Treffer zuerst."
    ),
    next_steps_easy=(
        "Betrifft eine Warnung deine Software? Merke sie dir im Werkzeug "
        "'Techstack' als offen vor und spiele das Update (den Patch) zeitnah "
        "ein."
    ),
    tooltips={
        "btn_fetch": (
            "Startet den Abruf neuer Advisories im Hintergrund. Sie können "
            "weiter arbeiten — das Ergebnis erscheint automatisch."
        ),
        "filter_severity": (
            "Zeigt nur Advisories einer Schwere: KRITISCH, HOCH, MITTEL oder "
            "NIEDRIG."
        ),
    },
)

HELP_CUSTOMER_ASSESSMENT = HelpContent(
    tool_name="Security-Audit",
    nav_key="customer_audit",
    short_description=(
        "Strukturierter Fragenkatalog zur Bewertung der IT-Sicherheit "
        "(Kunde, Mitarbeitergerät oder eigene Umgebung)."
    ),
    purpose=(
        "Ein Audit ist eine systematische Prüfung — wie ein TÜV für die IT. "
        "Der Assistent führt Sie durch Fragen zu Infrastruktur, Netzwerk und "
        "Organisation und berechnet am Ende einen Score mit "
        "Verbesserungsvorschlägen."
    ),
    when_to_use=(
        "Bei jedem neuen Kunden, bei einem Jahres-Review oder wenn sich Ihre "
        "IT-Umgebung grundlegend ändert. Auch für die eigene Firma sinnvoll — "
        "einmal pro Quartal."
    ),
    steps=[
        "Oben rechts auf '+ Neues Audit' klicken",
        "Schritt 1–5 im Wizard durchgehen: Kundendaten, Infrastruktur, "
        "Netzwerk, Organisation, Zusammenfassung",
        "Auf 'Berechnen' klicken — der Score wird ausgerechnet",
        "Ergebnis speichern und bei Bedarf als PDF exportieren",
    ],
    result_explanation=(
        "Score 0–100: je höher, desto besser. Unter 60 = erheblicher "
        "Handlungsbedarf, 60–79 = solide mit Lücken, ab 80 = professionelle "
        "Aufstellung. Die Detail-Ansicht zeigt genau, welche Kriterien "
        "Punktabzüge verursacht haben."
    ),
    next_steps=(
        "PDF-Export dem Kunden oder der Geschäftsleitung vorlegen. Die "
        "Empfehlungen abarbeiten und das Assessment in 3–6 Monaten wiederholen."
    ),
    short_description_easy=(
        "Ein geführter Fragebogen, der die IT-Sicherheit bewertet — für einen "
        "Kunden, ein Gerät oder deine eigene Firma."
    ),
    purpose_easy=(
        "Das ist eine gründliche Bestandsaufnahme — wie ein TÜV für die IT. "
        "Das Werkzeug führt dich durch Fragen zu deiner Technik, deinem "
        "Netzwerk und deiner Organisation und rechnet am Ende eine Punktzahl "
        "aus, zusammen mit Tipps zur Verbesserung."
    ),
    when_to_use_easy=(
        "Bei jedem neuen Kunden, einmal im Jahr zur Kontrolle oder wenn sich "
        "deine Technik grundlegend ändert. Auch für die eigene Firma "
        "sinnvoll — etwa alle drei Monate."
    ),
    steps_easy=[
        "Oben rechts auf '+ Neues Audit' klicken",
        "Die 5 Schritte durchgehen: Kundendaten, Technik, Netzwerk, "
        "Organisation, Zusammenfassung",
        "Auf 'Berechnen' klicken — die Punktzahl wird ermittelt",
        "Ergebnis speichern und bei Bedarf als PDF abspeichern",
    ],
    result_explanation_easy=(
        "Die Punktzahl geht von 0 bis 100 — je höher, desto besser. Unter 60 "
        "heißt: hier muss dringend etwas passieren. 60 bis 79 ist solide, hat "
        "aber Lücken. Ab 80 bist du gut aufgestellt. Die Detail-Ansicht zeigt "
        "dir genau, welche Punkte Abzüge gegeben haben."
    ),
    next_steps_easy=(
        "Leg das PDF deinem Kunden oder der Chefetage vor. Arbeite die Tipps "
        "ab und wiederhole die Prüfung in drei bis sechs Monaten."
    ),
    tooltips={
        "btn_new": "Legt über '+ Neues Audit' ein neues Audit an (5-Schritte-Wizard).",
        "btn_calculate": (
            "Berechnet den finalen Sicherheits-Score basierend auf allen "
            "Antworten. Danach kann das Assessment gespeichert werden."
        ),
        "btn_pdf_export": (
            "Erstellt einen druckfertigen PDF-Bericht mit Score, Details und "
            "Empfehlungen."
        ),
        "btn_delete": "Löscht das Assessment dauerhaft aus der lokalen Datenbank.",
    },
)

HELP_CYBER_DASHBOARD = HelpContent(
    tool_name="Risikobriefing",
    nav_key="cyber_dashboard",
    short_description=(
        "Täglich aktualisierter Überblick über neue Sicherheitsmeldungen, "
        "Warnungen und Lücken mit KI-Zusammenfassung."
    ),
    purpose=(
        "Das Risikobriefing ist Ihre digitale Tageszeitung für IT-Sicherheit. "
        "Es sammelt aktuelle Nachrichten von vertrauenswürdigen Quellen (BSI, "
        "CERT, Hersteller) und eine lokal generierte KI-Zusammenfassung — "
        "maximal 3 Minuten Lesezeit."
    ),
    when_to_use=(
        "Jeden Morgen oder zu Wochenbeginn. Immer wenn Sie wissen wollen, ob "
        "es aktuell akute Bedrohungen gibt, die Sie betreffen."
    ),
    steps=[
        "Tab 'KI-Briefing' öffnen und auf 'Neu generieren' klicken (lokaler "
        "Ollama-Server nötig)",
        "Tab 'CVEs' für aktuelle Sicherheitslücken der letzten 7 Tage",
        "Tab 'Warnungen' für RSS-Meldungen von Behörden",
        "Tab 'Wochenbericht' für ein PDF mit den wichtigsten Events der Woche",
    ],
    result_explanation=(
        "Das KI-Briefing hat drei Spalten: links Meldungen zu Ihren Produkten, "
        "mittig allgemeine IT-Sicherheitsnachrichten, unten Consumer-Software "
        "(Browser, Office). Jeder Eintrag ist ein Satz — ohne Wertung oder "
        "Panikmache."
    ),
    next_steps=(
        "Relevante Einträge als Task im Aufgabenboard anlegen. Bei "
        "kritischen Meldungen direkt ins betroffene Tool wechseln "
        "(z.B. Advisory-Monitor, Techstack)."
    ),
    short_description_easy=(
        "Dein täglicher Überblick zu neuen Sicherheitsmeldungen und Warnungen — "
        "kurz zusammengefasst von einer KI."
    ),
    purpose_easy=(
        "Das Risikobriefing ist wie deine Tageszeitung für IT-Sicherheit. Es "
        "sammelt aktuelle Meldungen von vertrauenswürdigen Stellen (BSI, "
        "Hersteller) und fasst sie mit einer KI zusammen, die direkt auf "
        "deinem Gerät läuft — in höchstens drei Minuten gelesen."
    ),
    when_to_use_easy=(
        "Jeden Morgen oder zu Wochenbeginn. Immer dann, wenn du wissen willst, "
        "ob es gerade eine akute Bedrohung gibt, die dich betrifft."
    ),
    steps_easy=[
        "Reiter 'KI-Briefing' öffnen und auf 'Neu generieren' klicken (dafür "
        "muss die lokale KI laufen)",
        "Reiter 'CVEs' für neue Sicherheitslücken der letzten 7 Tage ansehen",
        "Reiter 'Warnungen' für Meldungen von Behörden",
        "Reiter 'Wochenbericht' für ein PDF mit den wichtigsten Ereignissen "
        "der Woche",
    ],
    result_explanation_easy=(
        "Das KI-Briefing hat drei Bereiche: links Meldungen zu deinen eigenen "
        "Programmen, in der Mitte allgemeine Sicherheitsnachrichten, unten "
        "alltägliche Software wie Browser oder Office. Jeder Eintrag ist nur "
        "ein Satz — sachlich, ohne Panikmache."
    ),
    next_steps_easy=(
        "Was dich betrifft, legst du als Aufgabe in deinem Aufgabenboard ab. "
        "Bei wirklich kritischen Meldungen wechselst du direkt in das "
        "passende Werkzeug (z. B. Advisory-Monitor oder Techstack)."
    ),
    tooltips={
        "btn_generate": (
            "Startet die KI-Generierung des Briefings im Hintergrund. Benötigt "
            "einen laufenden lokalen Ollama-Server. Dauer: 30–120 Sekunden."
        ),
        "btn_cancel": (
            "Bricht die laufende Generierung ab. Das Teilergebnis wird "
            "verworfen."
        ),
        "tab_warnings": (
            "RSS-Feeds von Behörden und Herstellern — keine KI, reine "
            "Originalmeldungen."
        ),
    },
)

# HELP_DEEPL wurde am 2026-05-28 entfernt —
# NoRisk ist 100% lokal, DeepL-Tool wurde aus der App gelöscht.

HELP_DEPENDENCY_AUDITOR = HelpContent(
    tool_name="Dependency-Auditor",
    nav_key="dependency_auditor",
    short_description=(
        "Prüft die in einer Anwendung verwendeten Fremdbibliotheken auf "
        "bekannte Sicherheitslücken."
    ),
    purpose=(
        "Fast jede Software baut auf Bibliotheken Dritter auf — wie Zutaten "
        "in einem Rezept. Hat eine Zutat eine bekannte Sicherheitslücke, "
        "erbt Ihre Anwendung das Problem. Der Auditor prüft Dateien wie "
        "`requirements.txt` oder `package.json` und meldet betroffene Pakete."
    ),
    when_to_use=(
        "Vor jedem Release eigener Software, bei einer Sicherheitsprüfung "
        "fremder Anwendungen oder turnusmäßig für Produktionssysteme."
    ),
    steps=[
        "Datei öffnen… — wählen Sie eine `requirements.txt`, `package.json` "
        "oder ähnliche Dependency-Datei",
        "'Audit starten' klicken — der Scan vergleicht gegen bekannte CVE-Daten",
        "Ergebnis prüfen — rote Einträge sind kritische Lücken",
        "Bei Bedarf 'JSON' oder 'Clipboard' zum Weitergeben verwenden",
    ],
    result_explanation=(
        "Jede Zeile zeigt ein Paket mit Version, bekannten Lücken und dem "
        "empfohlenen Update. Schweregrad in Farbe: rot = kritisch, orange = "
        "hoch. Ist ein Paket nicht betroffen, erscheint es gar nicht erst."
    ),
    next_steps=(
        "Betroffene Pakete auf die empfohlene Version aktualisieren. Testen. "
        "Audit erneut durchführen, um den Fix zu bestätigen."
    ),
    short_description_easy=(
        "Prüft die fertigen Bausteine fremder Hersteller, aus denen ein "
        "Programm zusammengesetzt ist, auf bekannte Sicherheitslücken."
    ),
    purpose_easy=(
        "Fast jede Software ist aus fertigen Bausteinen anderer Hersteller "
        "zusammengesetzt — wie Zutaten in einem Rezept. Hat eine Zutat eine "
        "bekannte Schwachstelle, erbt das ganze Programm das Problem. Dieses "
        "Werkzeug liest die Zutatenliste eines Programms (eine Datei wie "
        "`requirements.txt` oder `package.json`) und meldet die betroffenen "
        "Bausteine."
    ),
    when_to_use_easy=(
        "Bevor du eigene Software herausgibst, wenn du fremde Software prüfen "
        "willst oder in regelmäßigen Abständen für Systeme, die im "
        "Dauerbetrieb laufen."
    ),
    steps_easy=[
        "Auf 'Datei öffnen…' klicken und die Zutatenliste auswählen (z. B. "
        "`requirements.txt` oder `package.json`)",
        "Auf 'Audit starten' klicken — die Prüfung vergleicht mit bekannten "
        "Lücken",
        "Ergebnis ansehen — rote Einträge sind die kritischen Lücken",
        "Bei Bedarf 'JSON' oder 'Clipboard' nutzen, um das Ergebnis "
        "weiterzugeben",
    ],
    result_explanation_easy=(
        "Jede Zeile zeigt einen Baustein mit seiner Version, den bekannten "
        "Lücken und dem empfohlenen Update. Die Farbe zeigt, wie ernst es ist: "
        "rot = kritisch, orange = hoch. Bausteine ohne Problem tauchen gar "
        "nicht erst auf."
    ),
    next_steps_easy=(
        "Bring die betroffenen Bausteine auf die empfohlene Version. Probier "
        "danach aus, ob noch alles läuft. Dann die Prüfung erneut starten, um "
        "zu bestätigen, dass das Problem weg ist."
    ),
    tooltips={
        "btn_audit": (
            "Startet den Audit der aktuell geöffneten Datei. Vergleich gegen "
            "öffentliche CVE-Datenbanken."
        ),
        "btn_self_audit": (
            "Prüft die eigene NoRisk-Installation. Gibt Ihnen einen Eindruck "
            "davon, wie der Auditor funktioniert."
        ),
        "btn_export_json": (
            "Exportiert das Audit-Ergebnis als JSON — z.B. zur Weitergabe an "
            "Entwickler."
        ),
    },
)

HELP_EMAIL_SCANNER = HelpContent(
    tool_name="E-Mail-Anhang-Scanner",
    nav_key="email_scanner",
    short_description=(
        "Prüft E-Mail-Anhänge lokal auf gefährliche Inhalte — ohne die Datei "
        "zu öffnen."
    ),
    purpose=(
        "Viele Angriffe kommen über Anhänge: Word-Dokumente mit Makros, "
        "manipulierte PDFs, versteckte Skripte in Excel-Dateien. Der Scanner "
        "analysiert den Anhang lokal und meldet Auffälligkeiten — bevor Sie "
        "die Datei öffnen."
    ),
    when_to_use=(
        "Immer wenn Sie eine E-Mail mit Anhang von einem unbekannten Absender "
        "erhalten haben, oder wenn der Anhang Sie überrascht (z.B. eine "
        "Rechnung die Sie nicht erwartet haben)."
    ),
    steps=[
        "Anhang lokal abspeichern (noch nicht öffnen)",
        "Im Scanner 'Datei auswählen' klicken",
        "Ergebnis abwarten — der Scan dauert meist wenige Sekunden",
    ],
    result_explanation=(
        "Grün: keine Auffälligkeiten gefunden. Orange: Makros oder aktive "
        "Inhalte enthalten — nur öffnen wenn der Absender vertrauenswürdig "
        "ist. Rot: konkrete Bedrohung erkannt — Datei nicht öffnen, löschen."
    ),
    next_steps=(
        "Bei rotem Ergebnis: E-Mail als Phishing an Ihren IT-Support melden "
        "oder an reportphishing@anti-phishing.org."
    ),
    short_description_easy=(
        "Prüft E-Mail-Anhänge direkt auf deinem Gerät auf Gefahren — ohne dass "
        "du die Datei öffnen musst."
    ),
    purpose_easy=(
        "Viele Angriffe kommen über Anhänge: Word-Dateien mit versteckten "
        "Befehlen, manipulierte PDFs, getarnte Schadprogramme in Excel-Dateien. "
        "Dieses Werkzeug schaut sich den Anhang an und meldet dir "
        "Auffälligkeiten — und zwar bevor du die Datei öffnest. Alles bleibt "
        "auf deinem Gerät."
    ),
    when_to_use_easy=(
        "Immer wenn du eine E-Mail mit Anhang von jemandem bekommst, den du "
        "nicht kennst, oder wenn dich der Anhang überrascht (z. B. eine "
        "Rechnung, die du nicht erwartet hast)."
    ),
    steps_easy=[
        "Den Anhang erst auf deinem Gerät abspeichern (noch nicht öffnen!)",
        "Im Werkzeug auf 'Datei auswählen' klicken",
        "Kurz warten — die Prüfung dauert meist nur ein paar Sekunden",
    ],
    result_explanation_easy=(
        "Grün heißt: nichts Auffälliges gefunden. Orange heißt: die Datei "
        "enthält versteckte Befehle — öffne sie nur, wenn du dem Absender "
        "wirklich traust. Rot heißt: eine echte Gefahr wurde erkannt — nicht "
        "öffnen, lösch die Datei."
    ),
    next_steps_easy=(
        "Bei einem roten Ergebnis: Melde die E-Mail als Betrugsversuch "
        "(Phishing) bei deinem IT-Support oder an "
        "reportphishing@anti-phishing.org."
    ),
    tooltips={
        "btn_scan_file": (
            "Öffnet einen Datei-Auswahldialog. Die Datei wird niemals "
            "hochgeladen — alle Prüfungen laufen lokal."
        ),
        "result_warnings": (
            "Liste der gefundenen Auffälligkeiten (Makros, eingebettete "
            "Objekte, verdächtige URLs etc.)."
        ),
    },
)

HELP_NETWORK_MONITOR = HelpContent(
    tool_name="Netzwerkmonitor",
    nav_key="network_monitor",
    short_description=(
        "Zeigt in Echtzeit, welche Programme auf Ihrem Computer gerade mit "
        "dem Internet kommunizieren."
    ),
    purpose=(
        "Wie ein Überwachungsmonitor am Firmeneingang: der Monitor zeigt, "
        "welche Verbindungen gerade aktiv sind, wie viel Bandbreite genutzt "
        "wird und welcher Prozess hinter jeder Verbindung steht — in Echtzeit."
    ),
    when_to_use=(
        "Wenn Ihr Internet ungewöhnlich langsam ist, wenn Sie einen "
        "Trojaner-Verdacht haben oder wenn Sie einfach wissen wollen, welche "
        "Apps im Hintergrund Daten senden."
    ),
    steps=[
        "Monitor öffnen — er startet automatisch",
        "Bandbreiten-Diagramm oben: aktueller Up-/Download",
        "Verbindungstabelle unten: alle aktiven Verbindungen",
        "Rot markierte Zeilen: verdächtige Verbindungen",
    ],
    result_explanation=(
        "Die Bandbreiten-Linie zeigt Kilobytes pro Sekunde — hoher "
        "Ausschlag = viel Traffic. Die Tabelle listet Prozess, Ziel-IP, "
        "Ports und Status. Verbindungen zu bekannten "
        "Bedrohungen werden rot markiert und mit Tooltip erklärt."
    ),
    next_steps=(
        "Unbekannter Prozess mit auffälligem Traffic? Im Internet nach dem "
        "Namen suchen. Die Historie lässt sich als CSV exportieren."
    ),
    short_description_easy=(
        "Zeigt dir live, welche Programme auf deinem Computer gerade mit dem "
        "Internet sprechen."
    ),
    purpose_easy=(
        "Wie eine Kamera am Firmeneingang: Das Werkzeug zeigt dir, welche "
        "Verbindungen gerade aktiv sind, wie viel Daten gerade fließen und "
        "welches Programm hinter jeder Verbindung steckt — alles in Echtzeit."
    ),
    when_to_use_easy=(
        "Wenn dein Internet ungewöhnlich langsam ist, wenn du einen "
        "Schädling auf dem Rechner vermutest oder wenn du einfach wissen "
        "willst, welche Programme im Hintergrund Daten verschicken."
    ),
    steps_easy=[
        "Das Werkzeug öffnen — es legt von selbst los",
        "Oben das Diagramm ansehen: wie viel du gerade hoch- und herunterlädst",
        "Unten die Tabelle ansehen: alle gerade aktiven Verbindungen",
        "Rot markierte Zeilen sind verdächtig",
    ],
    result_explanation_easy=(
        "Die Linie oben zeigt, wie viele Daten pro Sekunde fließen — ein hoher "
        "Ausschlag bedeutet viel Verkehr. Die Tabelle nennt das Programm, das "
        "Ziel im Internet und den Status. Verbindungen zu bekannten "
        "Gefahren werden rot markiert und erklärt."
    ),
    next_steps_easy=(
        "Ein unbekanntes Programm verschickt auffällig viele Daten? Such "
        "seinen Namen im Internet. Du kannst den Verlauf "
        "als Tabelle (CSV) abspeichern."
    ),
    tooltips={
        "btn_export": (
            "Exportiert die 24-Stunden-Historie als CSV-Datei."
            ""
        ),
        "chart_bandwidth": (
            "Bandbreite in Kilobyte pro Sekunde. Türkis = Download, "
            "Grün = Upload. 60-Sekunden-Fenster."
        ),
        "table_connections": (
            "Aktive Verbindungen zu Servern im Internet. Rot = verdächtig. "
            "Aktualisiert sich alle 3 Sekunden."
        ),
    },
    # Sprint S1c — Erklär-Layer-Pilot. 15 Element-Erklärungen, deutsch,
    # KMU-tauglich, Du-Form (gleiche Tonalität wie die Storytelling-
    # Templates aus S1a, von Patrick freigegeben).
    explanations={
        "title_widget": (
            "Live-Bild deines Netzwerk-Verkehrs: welche Programme reden gerade "
            "mit welchen Servern, und wie viele Daten fließen pro Sekunde."
        ),
        "col_remote_ip": (
            "Die Adresse des Servers im Internet, mit dem dein Computer redet — "
            "wie eine Postanschrift. Nackte Zahlen wie '142.251.40.21' werden "
            "in einer kommenden Version durch Klarnamen ersetzt (z. B. 'google.com')."
        ),
        "col_remote_port": (
            "Der 'Eingang' am Server. Häufige Werte: 443 = HTTPS (sicheres Web), "
            "80 = HTTP, 22 = SSH (Terminal-Zugang), 25 / 587 = E-Mail."
        ),
        "col_local_port": (
            "Der 'Eingang' auf deinem Computer für diese Verbindung. Meist eine "
            "zufällige Nummer ab 49152 — kein Verständnis nötig, dient nur der "
            "Zuordnung in deinem Betriebssystem."
        ),
        "col_process": (
            "Der Programmname, der die Verbindung aufgebaut hat. Beispiele: "
            "'chrome.exe' (Browser), 'outlook.exe' (E-Mail), 'backup.exe' "
            "(Cloud-Backup). Bei laufendem Netzwerk-Collector der Name, sonst '–'."
        ),
        "col_pid": (
            "Eindeutige Prozess-Nummer im Betriebssystem. Im Task-Manager kannst "
            "du nach dieser Nummer suchen, wenn du den Prozess beenden willst."
        ),
        "col_status": (
            "Lebensphase der Verbindung — wird gerade aufgebaut, ist aktiv, "
            "wird beendet. Der Klartext zeigt die Phase laienverständlich; "
            "der technische TCP-Status liegt als Tooltip auf der Zelle."
        ),
        "status_established": (
            "Aktive Verbindung — Daten fließen gerade in beide Richtungen. "
            "Das ist der Normalfall für laufende Programme wie Browser oder "
            "E-Mail-Client."
        ),
        "status_listen": (
            "Dein Computer wartet darauf, dass jemand sich verbindet. "
            "Typisch für Server-Programme; auf einem normalen Arbeits-PC selten."
        ),
        "status_time_wait": (
            "Verbindung wird gerade abgebaut. Der Status hält ein paar Sekunden "
            "an, danach verschwindet die Zeile aus der Tabelle."
        ),
        "status_close_wait": (
            "Die Gegenseite hat die Verbindung beendet, dein Programm noch nicht. "
            "Klingt häufig für ein paar Sekunden nach — solange unauffällig."
        ),
        "status_syn_sent": (
            "Dein Computer versucht gerade, eine Verbindung aufzubauen. Wenn es "
            "länger als ein paar Sekunden dauert, ist der Server unerreichbar."
        ),
        "iface_card": (
            "Jede Karte ist ein Netzwerk-Anschluss deines Computers — Ethernet "
            "(Kabel), WLAN (Funk), VPN. 'Hochladen / Herunterladen' sind aktuelle "
            "Sekunden-Werte, 'Gesamt' summiert seit dem letzten System-Start."
        ),
        "tier_label": (
            "Der Netzwerkmonitor aktualisiert die Anzeige im Sekunden-Takt. Alle "
            "Funktionen — Prozess-Namen, Bedrohungs-Markierung und 24-h-Historie — "
            "sind aktiv."
        ),
        "last_update_label": (
            "Wann hat das Tool zuletzt frische Daten bekommen? 'Aktualisiert vor "
            "2 s' = gerade frisch. Wenn das Label > 30 s zeigt, hängt der "
            "Hintergrund-Worker — App neu starten."
        ),
    },
)

HELP_NETWORK_SCANNER = HelpContent(
    tool_name="Netzwerk-Scanner",
    nav_key="network_scanner",
    short_description=(
        "Findet alle Geräte in Ihrem lokalen Netzwerk und zeigt offene Ports."
    ),
    purpose=(
        "Wie ein Hausplan Ihres Netzwerks: der Scanner durchsucht Ihr "
        "Heim- oder Firmennetzwerk und zeigt, welche Geräte überhaupt "
        "vorhanden sind — und welche Dienste (Ports) dort erreichbar sind. "
        "Oft tauchen Geräte auf, die man längst vergessen hatte."
    ),
    when_to_use=(
        "Bei Einzug in ein neues Netzwerk, nach dem Aufstellen neuer "
        "Smart-Home-Geräte oder bei Verdacht auf unbefugte Geräte."
    ),
    steps=[
        "Tab 'Scan' — oben im Bereich Host-Discovery alle Geräte im Netz finden",
        "Auffälliges Gerät auswählen und 'Ausgewählte Hosts scannen'",
        "Der Port-Scan erscheint im selben Tab direkt darunter",
        "Tab 'Verlauf' — frühere Scans vergleichen",
    ],
    result_explanation=(
        "Host-Discovery zeigt IP-Adresse, Hostname und optional MAC-Adresse. "
        "Der Port-Scan zeigt, welche Dienste am Gerät erreichbar sind "
        "(z.B. Port 80 = Webserver, Port 22 = SSH). Offene Ports = mögliche "
        "Angriffsfläche."
    ),
    next_steps=(
        "Unbekanntes Gerät im Netz? Vom Router blockieren. Offene Ports auf "
        "Ihrem eigenen Gerät? Dienst abschalten wenn nicht gebraucht."
    ),
    short_description_easy=(
        "Findet alle Geräte in deinem eigenen Netzwerk und zeigt, welche "
        "Zugänge an ihnen offenstehen."
    ),
    purpose_easy=(
        "Wie ein Lageplan deines Netzwerks: Das Werkzeug durchsucht dein "
        "Heim- oder Firmennetz und zeigt, welche Geräte überhaupt da sind — "
        "und welche Zugänge (Ports) an ihnen erreichbar sind. Oft tauchen "
        "dabei Geräte auf, die man längst vergessen hatte."
    ),
    when_to_use_easy=(
        "Wenn du in ein neues Netzwerk ziehst, nachdem du neue smarte Geräte "
        "aufgestellt hast, oder wenn du den Verdacht hast, dass ein fremdes "
        "Gerät mit drin hängt."
    ),
    steps_easy=[
        "Reiter 'Scan' öffnen — oben findet die Geräte-Suche alle Geräte im Netz",
        "Ein auffälliges Gerät anklicken und auf 'Ausgewählte Hosts scannen'",
        "Direkt darunter erscheint die Zugangs-Prüfung dieses Geräts",
        "Reiter 'Verlauf' — frühere Prüfungen vergleichen",
    ],
    result_explanation_easy=(
        "Die Geräte-Suche zeigt die Netzwerk-Adresse und den Namen jedes "
        "Geräts. Die Zugangs-Prüfung zeigt, welche Dienste an einem Gerät "
        "erreichbar sind (z. B. ein Webserver oder ein Fernzugang). Jeder "
        "offene Zugang ist eine mögliche Einfallstür."
    ),
    next_steps_easy=(
        "Ein unbekanntes Gerät im Netz? Sperr es in deinem Router. Offene "
        "Zugänge an deinem eigenen Gerät? Schalte den jeweiligen Dienst ab, "
        "wenn du ihn nicht brauchst."
    ),
    tooltips={
        "btn_discovery": (
            "Scannt das lokale Netzwerk nach aktiven Geräten (ping-basiert). "
            "Dauert 30–60 Sekunden."
        ),
        "btn_port_scan": (
            "Prüft ein einzelnes Gerät auf offene Ports. Scannt die häufigsten "
            "Ports — kann einige Minuten dauern."
        ),
    },
)

HELP_NORISK_DASHBOARD = HelpContent(
    tool_name="NoRisk Dashboard",
    nav_key="norisk:dashboard",
    short_description=(
        "Gesamtüberblick über Ihre Sicherheitslage — Score, Trends, offene "
        "Themen auf einen Blick."
    ),
    purpose=(
        "Das Dashboard fasst alle NoRisk-Ergebnisse zu einem einzigen Bild "
        "zusammen: Score, neue CVEs, Veränderungen seit letzter Woche, "
        "organisatorische Kacheln. Wie ein Cockpit mit allen wichtigen "
        "Zeigern."
    ),
    when_to_use=(
        "Zur Monatsübersicht, als erste Anlaufstelle nach dem Anmelden oder "
        "vor Meetings mit der Geschäftsleitung."
    ),
    steps=[
        "Dashboard öffnen — alle Sektionen laden automatisch",
        "Zeitraum oben wählen: 7 / 30 / 90 Tage",
        "Jede Sektion einzeln durchgehen: Changes, Score, CVEs/Scans, "
        "Breakdown, Organisatorisches",
        "Bei Bedarf PDF-Export für Dokumentation",
    ],
    result_explanation=(
        "Score-Sektion zeigt den Gesamtwert und die Tendenz. CVEs-Sektion "
        "listet die kritischsten offenen Schwachstellen. Breakdown zeigt "
        "welcher Bereich am meisten Punktabzüge verursacht. Trend-Chart "
        "zeigt die Entwicklung."
    ),
    next_steps=(
        "Kritische CVEs sofort angehen, Breakdown-Lücken in den Monatsplan "
        "aufnehmen."
    ),
    short_description_easy=(
        "Dein Gesamtüberblick: Sicherheits-Punktzahl, Entwicklung und offene "
        "Themen auf einen Blick."
    ),
    purpose_easy=(
        "Das Dashboard fasst alle Ergebnisse von NoRisk zu einem einzigen Bild "
        "zusammen: deine Punktzahl, neue Sicherheitslücken, was sich seit der "
        "letzten Woche getan hat und organisatorische Themen. Wie ein Cockpit "
        "mit allen wichtigen Anzeigen auf einmal."
    ),
    when_to_use_easy=(
        "Für den Monatsüberblick, als erste Anlaufstelle direkt nach dem "
        "Anmelden oder zur Vorbereitung von Besprechungen mit der Chefetage."
    ),
    steps_easy=[
        "Dashboard öffnen — alle Bereiche laden von selbst",
        "Oben den Zeitraum wählen: 7, 30 oder 90 Tage",
        "Jeden Bereich nacheinander ansehen: Änderungen, Punktzahl, "
        "Lücken/Scans, Aufschlüsselung, Organisatorisches",
        "Bei Bedarf als PDF abspeichern für die Ablage",
    ],
    result_explanation_easy=(
        "Der Punktzahl-Bereich zeigt deinen Gesamtwert und ob er steigt oder "
        "fällt. Der Lücken-Bereich listet die gefährlichsten offenen "
        "Schwachstellen. Die Aufschlüsselung zeigt, welcher Bereich die "
        "meisten Punkte kostet. Die Verlaufskurve zeigt die Entwicklung über "
        "die Zeit."
    ),
    next_steps_easy=(
        "Kritische Lücken sofort angehen. Die Schwachstellen aus der "
        "Aufschlüsselung in deinen Monatsplan aufnehmen."
    ),
    tooltips={
        "time_filter": (
            "Zeitraum für Trend- und Änderungsansicht. Standard: 30 Tage."
        ),
        "btn_export_pdf": (
            "Exportiert den aktuellen Dashboard-Stand als PDF-Bericht."
        ),
        "section_score": (
            "Gesamt-Score Ihrer NoRisk-Installation. 0–100, höher ist besser. "
            "Tendenz-Pfeil zeigt die Entwicklung gegenüber dem Vormonat."
        ),
    },
)

# Aus dem fruehere „Security Chat" wurde der vereinte FINLAI-Assistent
# (Bedienung + IT-Sicherheit), erreichbar als Reiter im Handbuch-Dialog ueber das
# Maskottchen + F1 — kein eigenes Sidebar-Tool mehr. Der nav_key „ki:ollama"
# bleibt als interner Schluessel erhalten (Kapitel im Handbuch-Reiter).
HELP_OLLAMA = HelpContent(
    tool_name="FINLAI-Assistent",
    nav_key="ki:ollama",
    short_description=(
        "Lokaler KI-Assistent — beantwortet Fragen zur Bedienung von NoRisk "
        "UND zu IT-Sicherheit, ohne dass Daten das Geraet verlassen."
    ),
    purpose=(
        "Der FINLAI-Assistent ist ein lokal laufender KI-Helfer "
        "(Backend: Ollama). Er erklaert die Bedienung von NoRisk in "
        "Alltagssprache, beantwortet IT-Sicherheitsfragen, erklaert CVEs "
        "und fasst BSI-Advisories zusammen. Er stuetzt seine Antworten auf "
        "das Handbuch und einen kuratierten Sicherheits-Wissenskorpus. Alles "
        "passiert lokal auf Ihrem Geraet — keine Daten gehen in die Cloud."
    ),
    when_to_use=(
        "Wenn Sie nicht wissen, wie eine Funktion bedient wird, oder wenn Sie "
        "ein CVE bzw. eine BSI-Warnung in einfacher Sprache erklaert haben "
        "moechten, eine Phishing-Mail einschaetzen wollen oder einen "
        "Sicherheitsbegriff (CVSS, KEV, Zero-Day …) schnell verstehen muessen."
    ),
    steps=[
        "Auf das FINLAI-Maskottchen (unten rechts) klicken oder F1 druecken",
        "Im Handbuch-Fenster den Reiter FINLAI-Assistent oeffnen",
        "Frage zur Bedienung oder Sicherheit ins Eingabefeld schreiben",
        "Enter druecken — die Antwort erscheint Wort fuer Wort, mit Quellen",
    ],
    result_explanation=(
        "Die Antwort erscheint im Gespraechsverlauf; darunter listet ein "
        "Quellen-Panel die herangezogenen Belege nach Bereich gruppiert "
        "(Handbuch / Sicherheit). Bei jeder CVE-bezogenen Antwort wird "
        "automatisch der Hinweis ergaenzt, dass CVE-Daten veraltet sein "
        "koennen und unter https://nvd.nist.gov/ gegengeprueft werden sollten."
    ),
    next_steps=(
        "Bei kritischen Sicherheitsentscheidungen: Antwort immer gegen "
        "die Originalquelle (NVD, BSI, CERT.at) pruefen. Der Assistent ist "
        "Bedien- und Recherche-Hilfe, kein Patch-Freigabesignal."
    ),
    short_description_easy=(
        "Ein KI-Helfer direkt auf deinem Gerät — er erklärt dir die Bedienung "
        "von NoRisk und beantwortet Fragen zur IT-Sicherheit. Nichts verlässt "
        "dein Gerät."
    ),
    purpose_easy=(
        "Der FINLAI-Assistent ist ein KI-Helfer, der ganz auf deinem Gerät "
        "läuft. Er erklärt dir in einfachen Worten, wie du NoRisk bedienst, "
        "beantwortet Fragen zur IT-Sicherheit und fasst Warnmeldungen "
        "verständlich zusammen. Seine Antworten stützt er auf das Handbuch und "
        "ein geprüftes Sicherheitswissen. Alles passiert auf deinem Gerät — es "
        "werden keine Daten ins Internet geschickt."
    ),
    when_to_use_easy=(
        "Wenn du nicht weißt, wie eine Funktion funktioniert, wenn du eine "
        "Sicherheitswarnung in einfacher Sprache erklärt haben möchtest, eine "
        "verdächtige E-Mail einschätzen willst oder einen Fachbegriff schnell "
        "verstehen musst."
    ),
    steps_easy=[
        "Auf den FINLAI-Roboter unten rechts klicken oder die Taste F1 "
        "drücken",
        "Im Fenster den Reiter 'FINLAI-Assistent' öffnen",
        "Deine Frage zur Bedienung oder zur Sicherheit ins Feld schreiben",
        "Enter drücken — die Antwort erscheint nach und nach, mit Quellen",
    ],
    result_explanation_easy=(
        "Die Antwort erscheint im Gesprächsverlauf. Darunter zeigt ein kleiner "
        "Bereich, worauf sie sich stützt (Handbuch oder Sicherheitswissen). "
        "Bei Fragen zu Sicherheitslücken weist der Assistent immer darauf hin, "
        "dass solche Daten veraltet sein können und du sie auf "
        "https://nvd.nist.gov/ gegenprüfen solltest."
    ),
    next_steps_easy=(
        "Bei wichtigen Sicherheitsentscheidungen: Prüfe die Antwort immer noch "
        "einmal gegen die Originalquelle (NVD, BSI, CERT.at). Der Assistent "
        "hilft beim Bedienen und Nachschlagen, ist aber kein Freibrief, ein "
        "Update einzuspielen."
    ),
    tooltips={
        "input_prompt": (
            "Ihre Frage zur Bedienung oder IT-Sicherheit. Wird nur an das "
            "lokale Modell geschickt — keine Cloud, kein Log."
        ),
        "voraussetzung": (
            "Voraussetzung ist ein lokaler Ollama-Server auf diesem Geraet. "
            "Modelle installieren Sie mit `ollama pull <modellname>`."
        ),
    },
)

HELP_PASSWORD_CHECKER = HelpContent(
    tool_name="Passwort-Checker",
    nav_key="password_checker",
    short_description=(
        "Bewertet die Stärke eines Passworts und generiert auf Wunsch "
        "sichere Alternativen — die Stärke-Prüfung läuft lokal."
    ),
    purpose=(
        "Ihr Passwort ist der Schlüssel zu Ihrem digitalen Leben. Der "
        "Checker bewertet Länge, Zeichenvielfalt und typische "
        "Muster-Schwächen — diese Stärke-Prüfung läuft komplett lokal. "
        "Zusätzlich kann er das Passwort gegen bekannte Datenlecks abgleichen "
        "(Have I Been Pwned). Dieser Breach-Check läuft online, aber "
        "datenschutzfreundlich per k-Anonymität: Es wird lokal nur ein "
        "SHA-1-Prüfwert gebildet, und nur dessen erste 5 Zeichen werden "
        "abgefragt — das Passwort selbst verlässt nie Ihr Gerät."
    ),
    when_to_use=(
        "Beim Wählen eines neuen Passworts für wichtige Accounts, beim "
        "regelmäßigen Check bestehender Passwörter, oder wenn Sie einfach "
        "ein starkes Zufallspasswort brauchen."
    ),
    steps=[
        "Passwort eingeben (oder auf das Auge klicken zum Anzeigen)",
        "Den Online-Abgleich mit Datenleck-Listen über die Auswahl 'HIBP "
        "Breach-Check (Netzwerk erforderlich)' an- oder abschalten (ist "
        "voreingestellt aktiv und benötigt eine Internetverbindung)",
        "Auf 'Passwort prüfen' klicken und die Bewertung rechts ablesen",
        "Oder: auf 'Passwort generieren' klicken und das generierte "
        "Passwort übernehmen",
    ],
    result_explanation=(
        "Balken zeigt Stärke: Rot = sehr schwach, Orange = schwach, Gelb = "
        "okay, Grün = stark, Dunkelgrün = sehr stark. Text darunter erklärt "
        "warum: zu kurz, typisches Wort, keine Sonderzeichen etc. Ist der "
        "Breach-Check aktiv, sehen Sie zusätzlich, ob das Passwort bereits in "
        "bekannten Datenlecks aufgetaucht ist."
    ),
    next_steps=(
        "Passwort in einem Passwort-Manager speichern, nicht im Browser. "
        "Für jeden Dienst ein eigenes Passwort verwenden."
    ),
    short_description_easy=(
        "Sagt dir, wie sicher ein Passwort ist, und erstellt auf Wunsch ein "
        "starkes neues — die Stärke-Prüfung läuft direkt auf deinem Gerät."
    ),
    purpose_easy=(
        "Dein Passwort ist der Schlüssel zu deinem digitalen Leben. Dieses "
        "Werkzeug bewertet, wie lang und abwechslungsreich dein Passwort ist "
        "und ob es ein leicht zu erratendes Muster enthält — und das ganz auf "
        "deinem Gerät. Zusätzlich kann es nachschauen, ob dein Passwort schon "
        "einmal bei einem Daten-Diebstahl aufgetaucht ist. Diese eine Abfrage "
        "geht ins Internet, ist aber so gebaut, dass dein Passwort dabei nie "
        "übertragen wird: Es wird nur ein kurzer Such-Code daraus gebildet und "
        "davon nur die ersten fünf Zeichen verschickt."
    ),
    when_to_use_easy=(
        "Wenn du dir ein neues Passwort für einen wichtigen Zugang ausdenkst, "
        "wenn du deine bestehenden Passwörter mal überprüfen willst, oder wenn "
        "du einfach ein starkes Zufallspasswort brauchst."
    ),
    steps_easy=[
        "Passwort eintippen (oder auf das Auge-Symbol klicken, um es "
        "anzuzeigen)",
        "Den Internet-Abgleich über das Häkchen 'HIBP Breach-Check (Netzwerk "
        "erforderlich)' an- oder abschalten — es ist von Anfang an gesetzt und "
        "braucht eine Internetverbindung",
        "Auf 'Passwort prüfen' klicken und rechts die Bewertung ablesen",
        "Oder: auf 'Passwort generieren' klicken und das erzeugte Passwort "
        "übernehmen",
    ],
    result_explanation_easy=(
        "Der Balken zeigt die Stärke: Rot = sehr schwach, Orange = schwach, "
        "Gelb = okay, Grün = stark, Dunkelgrün = sehr stark. Der Text darunter "
        "erklärt warum: zu kurz, ein bekanntes Wort, keine Sonderzeichen und "
        "so weiter. Ist das Häkchen für den Internet-Abgleich gesetzt, siehst "
        "du außerdem, ob das Passwort schon einmal gestohlen wurde."
    ),
    next_steps_easy=(
        "Speichere das Passwort in einem Passwort-Tresor (Passwort-Manager), "
        "nicht im Browser. Nimm für jeden Dienst ein eigenes Passwort."
    ),
    tooltips={
        "input_password": (
            "Das zu prüfende Passwort. Wird niemals gespeichert. Die "
            "Stärke-Prüfung läuft lokal; beim Datenleck-Abgleich verlässt nur "
            "ein 5-Zeichen-Teilcode des Prüfwerts das Gerät, nie das Passwort."
        ),
        "btn_generate": (
            "Erstellt ein starkes Zufallspasswort nach modernen "
            "Sicherheitsstandards."
        ),
        "result_strength": (
            "Bewertung nach Länge, Zeichenvielfalt und bekannten "
            "Muster-Schwächen (z.B. Tastaturfolgen, häufige Wörter)."
        ),
        "hibp_check": (
            "Gleicht das Passwort online gegen bekannte Datenlecks ab (Have I "
            "Been Pwned). Datenschutzfreundlich per k-Anonymität: nur die "
            "ersten 5 Zeichen des SHA-1-Hashes werden gesendet. Benötigt eine "
            "Internetverbindung."
        ),
    },
)

HELP_PDF_RISK_SCANNER = HelpContent(
    tool_name="PDF-Risiko-Scanner",
    nav_key="pdf_risk_scanner",
    short_description=(
        "Prüft PDF-Dateien auf eingebetteten Schadcode, verdächtige Skripte "
        "und Verlinkungen — bevor Sie die Datei öffnen."
    ),
    purpose=(
        "Manipulierte PDFs sind ein beliebter Angriffsweg: eingebettete "
        "JavaScript-Skripte, versteckte Dateien oder Links auf gefährliche "
        "Webseiten. Der Scanner analysiert die PDF-Struktur und meldet "
        "jedes dieser Merkmale."
    ),
    when_to_use=(
        "Bei jeder PDF von einem unbekannten Absender, bei überraschenden "
        "Rechnungen, oder bei PDFs die aus Downloads unklarer Herkunft "
        "stammen."
    ),
    steps=[
        "PDF lokal abspeichern, noch nicht öffnen",
        "'Datei auswählen' klicken",
        "Scan läuft — Ergebnis erscheint in wenigen Sekunden",
    ],
    result_explanation=(
        "Grün: unauffällige PDF. Orange: Auffälligkeiten (Makros, "
        "JavaScript, eingebettete Objekte) — vorsichtig öffnen. Rot: "
        "konkrete Bedrohungsindikatoren — Datei nicht öffnen."
    ),
    next_steps=(
        "Bei rotem Ergebnis: Datei löschen, Absender als Phishing markieren. "
        "Bei orangenem Ergebnis: Absender direkt (telefonisch) verifizieren "
        "bevor Sie öffnen."
    ),
    short_description_easy=(
        "Prüft PDF-Dateien auf versteckten Schadcode und gefährliche Links — "
        "bevor du sie öffnest."
    ),
    purpose_easy=(
        "Manipulierte PDFs sind ein beliebter Trick von Angreifern: versteckte "
        "Befehle, getarnte Dateien oder Links auf gefährliche Webseiten. "
        "Dieses Werkzeug schaut sich den Aufbau einer PDF genau an und meldet "
        "dir jedes dieser Merkmale."
    ),
    when_to_use_easy=(
        "Bei jeder PDF von einem unbekannten Absender, bei überraschenden "
        "Rechnungen oder bei PDFs, die aus Downloads unklarer Herkunft stammen."
    ),
    steps_easy=[
        "Die PDF erst auf deinem Gerät abspeichern, noch nicht öffnen",
        "Auf 'Datei auswählen' klicken",
        "Kurz warten — das Ergebnis erscheint nach wenigen Sekunden",
    ],
    result_explanation_easy=(
        "Grün heißt: unauffällige PDF. Orange heißt: es gibt Auffälligkeiten "
        "(versteckte Befehle oder eingebettete Dateien) — öffne sie nur "
        "vorsichtig. Rot heißt: konkrete Anzeichen für eine Gefahr — nicht "
        "öffnen."
    ),
    next_steps_easy=(
        "Bei einem roten Ergebnis: Lösch die Datei und markiere den Absender "
        "als Betrugsversuch. Bei einem orangen Ergebnis: Ruf den Absender "
        "direkt an und frag nach, bevor du die Datei öffnest."
    ),
    tooltips={
        "btn_scan": (
            "Startet den lokalen Scan der PDF. Die Datei wird nicht "
            "hochgeladen."
        ),
        "result_js": (
            "JavaScript in einer PDF ist oft — aber nicht immer — verdächtig. "
            "Bei unbekannten Absendern immer misstrauisch sein."
        ),
    },
)

HELP_SECURITY_SCORING = HelpContent(
    tool_name="Security-Score",
    nav_key="security_scoring",
    short_description=(
        "Zentraler Score Ihrer eigenen NoRisk-Installation — wie ein "
        "Schulnotenzeugnis für Ihre IT-Sicherheit."
    ),
    purpose=(
        "Der Security-Score fasst alle NoRisk-Prüfungen zu einer einzigen "
        "Zahl zusammen. Er zeigt, wie gut Sie aufgestellt sind, wo die "
        "größten Lücken sind und welche Maßnahmen den Score am stärksten "
        "anheben würden."
    ),
    when_to_use=(
        "Monatlich zur Verlaufskontrolle. Vor einer externen Prüfung. Wenn "
        "Sie der Geschäftsleitung die aktuelle Sicherheitslage mit einer "
        "Zahl darstellen müssen."
    ),
    steps=[
        "Dashboard öffnen — der aktuelle Score steht oben",
        "Auf 'Neu berechnen' klicken, um den Score Ihres eigenen Systems "
        "frisch zu berechnen",
        "Optional: 'Assessment starten' (geführter 5-Schritte-Wizard) oder "
        "'Organisatorische Sicherheit' (Selbstbewertung)",
        "Über 'Security-Report PDF' den letzten Score als Bericht exportieren",
    ],
    result_explanation=(
        "0–100. Unter 60 = kritischer Handlungsbedarf, 60–79 = solide aber "
        "lückig, 80–100 = professionell. Die Kategorien-Aufschlüsselung "
        "darunter zeigt, wo Sie gut sind und wo Sie verbessern sollten."
    ),
    next_steps=(
        "Die Kategorie mit dem niedrigsten Score zuerst angehen. Nach "
        "Umsetzung der Maßnahme einen neuen Scan durchführen und den Score "
        "re-evaluieren."
    ),
    short_description_easy=(
        "Die zentrale Punktzahl deiner eigenen NoRisk-Installation — wie ein "
        "Zeugnis für deine IT-Sicherheit."
    ),
    purpose_easy=(
        "Die Sicherheits-Punktzahl fasst alle Prüfungen von NoRisk zu einer "
        "einzigen Zahl zusammen. Sie zeigt, wie gut du aufgestellt bist, wo "
        "deine größten Lücken sind und welche Maßnahmen deine Punktzahl am "
        "stärksten anheben würden."
    ),
    when_to_use_easy=(
        "Einmal im Monat zur Kontrolle. Vor einer Prüfung von außen. Oder wenn "
        "du der Chefetage deine aktuelle Sicherheitslage mit einer einzigen "
        "Zahl zeigen musst."
    ),
    steps_easy=[
        "Dashboard öffnen — die aktuelle Punktzahl steht oben",
        "Auf 'Neu berechnen' klicken, um die Punktzahl deines eigenen Systems "
        "neu zu berechnen",
        "Wenn du magst: 'Assessment starten' (geführte Fragen in 5 Schritten) "
        "oder 'Organisatorische Sicherheit' (Selbstbewertung)",
        "Über 'Security-Report PDF' den letzten Stand als Bericht speichern",
    ],
    result_explanation_easy=(
        "Die Punktzahl geht von 0 bis 100. Unter 60 heißt: es muss dringend "
        "etwas passieren. 60 bis 79 ist solide, hat aber Lücken. 80 bis 100 "
        "ist professionell. Die Aufschlüsselung darunter zeigt, wo du gut bist "
        "und wo du nachbessern solltest."
    ),
    next_steps_easy=(
        "Geh die Kategorie mit der niedrigsten Punktzahl zuerst an. Nachdem "
        "du etwas verbessert hast, starte eine neue Prüfung und schau, wie "
        "sich die Punktzahl verändert hat."
    ),
    tooltips={
        "score_display": (
            "Gesamt-Score 0–100. Farbe: Rot < 60, Gelb 60–79, Grün ab 80."
        ),
        "btn_wizard": (
            "'Assessment starten' — geführter 5-Schritte-Wizard für eine "
            "vollständige Neubewertung mit strukturierten Fragen."
        ),
        "comp_cve_exposure": (
            "Bewertet wie stark Ihre Software durch bekannte Sicherheitslücken "
            "gefährdet ist. Basiert auf Techstack-CVEs, KEV-Markierungen und "
            "CSAF-Advisories — nutzt nur gecachte Daten, löst keinen neuen "
            "Scan aus."
        ),
    },
)

HELP_SYSTEM_SCANNER = HelpContent(
    tool_name="System-Scanner",
    nav_key="system_scanner",
    short_description=(
        "Prüft den lokalen Computer auf Antivirus, Firewall, Verschlüsselung, "
        "Browser und weitere Schutzkomponenten."
    ),
    purpose=(
        "Wie ein Sicherheits-TÜV für Ihren PC: der Scanner fragt das "
        "Betriebssystem, welche Schutzmechanismen aktiv sind, und zeigt Ihnen "
        "fehlende oder veraltete Komponenten übersichtlich an."
    ),
    when_to_use=(
        "Nach jeder Neuinstallation, bei einem neuen Mitarbeiter-Laptop, "
        "oder einmal pro Quartal für jeden aktiv genutzten Rechner."
    ),
    steps=[
        "'Scan starten' klicken — dauert 30–60 Sekunden",
        "Ergebnis-Kategorien durchgehen: OS, Antivirus, Firewall, Encryption, "
        "Browser, VPN, Password-Manager, Remote-Access",
        "Bei 'Unbekannt': 'Manuell hinzufügen' verwenden, um selbst bekannte "
        "Einträge zu ergänzen",
        "Export als JSON, Excel oder PDF für Dokumentation",
    ],
    result_explanation=(
        "Jede Komponente hat einen Status: Grün = aktiv, Rot = inaktiv, "
        "Orange = veraltet, Grau = unbekannt. 'Unbekannt' heißt NICHT "
        "unsicher — der Scanner konnte es nur nicht automatisch erkennen. "
        "Manuelle Einträge werden mit `(manuell)` gekennzeichnet."
    ),
    next_steps=(
        "Rote Komponenten aktivieren oder installieren. Orange Komponenten "
        "aktualisieren. Graue manuell eintragen, wenn Sie wissen, was "
        "installiert ist."
    ),
    short_description_easy=(
        "Prüft deinen eigenen Computer: Sind Virenschutz, Firewall, "
        "Verschlüsselung und weitere Schutzfunktionen aktiv?"
    ),
    purpose_easy=(
        "Wie ein Sicherheits-TÜV für deinen PC: Das Werkzeug fragt dein "
        "Betriebssystem, welche Schutzmechanismen gerade aktiv sind, und zeigt "
        "dir übersichtlich, was fehlt oder veraltet ist."
    ),
    when_to_use_easy=(
        "Nach jeder Neuinstallation, bei einem neuen Mitarbeiter-Laptop oder "
        "einmal im Quartal für jeden Rechner, den du regelmäßig nutzt."
    ),
    steps_easy=[
        "Auf 'Scan starten' klicken — dauert 30 bis 60 Sekunden",
        "Die Ergebnis-Bereiche durchgehen: Betriebssystem, Virenschutz, "
        "Firewall, Verschlüsselung, Browser und weitere",
        "Steht irgendwo 'Unbekannt'? Mit 'Manuell hinzufügen' kannst du "
        "selbst ergänzen, was du installiert hast",
        "Bei Bedarf als JSON, Excel oder PDF abspeichern",
    ],
    result_explanation_easy=(
        "Jeder Eintrag hat eine Ampel: Grün = aktiv, Rot = aus, Orange = "
        "veraltet, Grau = unbekannt. 'Unbekannt' heißt NICHT unsicher — das "
        "Werkzeug konnte es nur nicht von selbst erkennen. Was du selbst "
        "eingetragen hast, ist mit '(manuell)' gekennzeichnet."
    ),
    next_steps_easy=(
        "Rote Punkte einschalten oder installieren. Orange Punkte "
        "aktualisieren. Graue Punkte selbst eintragen, wenn du weißt, was bei "
        "dir installiert ist."
    ),
    tooltips={
        "btn_scan": (
            "Startet den automatischen Scan Ihres Systems. Dauert ca. "
            "30–60 Sekunden."
        ),
        "btn_manual_add": (
            "Trägt Software ein, die vom automatischen Scan nicht erkannt "
            "wurde (z.B. Enterprise-Antivirus, Hardware-Firewall)."
        ),
        "result_unknown": (
            "'Unbekannt' heißt nicht unsicher — die Software wurde nur nicht "
            "automatisch erkannt. Manuelle Einträge können es klarstellen."
        ),
        "btn_export_pdf": (
            "Erstellt einen druckfertigen PDF-Bericht inkl. manueller "
            "Einträge."
        ),
    },
)

HELP_TECHSTACK = HelpContent(
    tool_name="Techstack",
    nav_key="techstack",
    short_description=(
        "Zentrale Liste Ihrer eingesetzten Software — mit automatischer "
        "CVE-Suche pro Produkt."
    ),
    purpose=(
        "Ihre Tech-Stack-Liste ist wie eine Inventarliste: jedes Produkt, "
        "das Sie aktiv nutzen, wird hier geführt. NoRisk sucht automatisch "
        "nach bekannten Sicherheitslücken für jedes Produkt — so entgehen "
        "Ihnen keine wichtigen Patches."
    ),
    when_to_use=(
        "Beim Einrichten von NoRisk (Initial-Liste), bei jeder neuen "
        "Installation im Unternehmen, und wöchentlich zur CVE-Prüfung."
    ),
    steps=[
        "Eintrag hinzufügen: Produktname + Version + Kategorie",
        "Aktive/Inaktive-Schalter setzen (Altsysteme können inaktiv bleiben)",
        "'CVEs laden' — sucht automatisch nach bekannten Lücken",
        "Ergebnis pro Produkt in der Tabelle rechts ablesen",
    ],
    result_explanation=(
        "Die CVE-Tabelle zeigt pro Produkt: CVE-ID, CVSS-Score, Schweregrad, "
        "Kurzbeschreibung und KEV-Markierung. KEV = bereits aktiv "
        "ausgenutzt — höchste Priorität. Rote Einträge zuerst behandeln."
    ),
    next_steps=(
        "Kritische CVEs im Advisory-Monitor querprüfen und ein Update "
        "einspielen. Inaktive Einträge vom Stack nehmen oder als inaktiv "
        "markieren."
    ),
    short_description_easy=(
        "Deine zentrale Liste aller eingesetzten Programme — NoRisk sucht "
        "automatisch nach Sicherheitslücken zu jedem davon."
    ),
    purpose_easy=(
        "Diese Liste ist wie ein Inventar: Jedes Programm, das du nutzt, "
        "trägst du hier ein. NoRisk sucht dann von selbst nach bekannten "
        "Sicherheitslücken (CVEs — öffentlich bekannte Schwachstellen) für "
        "jedes Programm — so verpasst du kein wichtiges Update."
    ),
    when_to_use_easy=(
        "Beim Einrichten von NoRisk (für die erste Liste), bei jeder neuen "
        "Software in deiner Firma und einmal pro Woche, um auf neue Lücken zu "
        "prüfen."
    ),
    steps_easy=[
        "Einen Eintrag anlegen: Programmname, Version und Kategorie",
        "Den Schalter 'aktiv/inaktiv' setzen (alte Systeme kannst du auf "
        "inaktiv lassen)",
        "Auf 'CVEs laden' klicken — sucht automatisch nach bekannten Lücken",
        "Das Ergebnis pro Programm rechts in der Tabelle ablesen",
    ],
    result_explanation_easy=(
        "Die Tabelle zeigt pro Programm: die Nummer der Lücke, einen "
        "Gefährlichkeits-Wert von 0 bis 10, eine Kurzbeschreibung und einen "
        "'KEV'-Stempel. KEV bedeutet: diese Lücke wird gerade aktiv "
        "ausgenutzt — höchste Priorität. Kümmere dich zuerst um die roten "
        "Einträge."
    ),
    next_steps_easy=(
        "Wichtige Lücken im Advisory-Monitor gegenprüfen und ein Update "
        "einspielen. Programme, die du nicht mehr nutzt, von der Liste nehmen "
        "oder auf inaktiv setzen."
    ),
    tooltips={
        "btn_add_entry": "Legt einen neuen Techstack-Eintrag an.",
        "btn_load_cves": (
            "Sucht über die öffentliche NVD-Datenbank nach CVEs für alle "
            "aktiven Stack-Einträge. Mit API-Key schneller."
        ),
        "column_kev": (
            "KEV: Known Exploited Vulnerabilities — diese Schwachstelle "
            "wird bereits aktiv von Angreifern ausgenutzt."
        ),
        "column_cvss": (
            "CVSS-Score 0.0–10.0. Höher = gefährlicher. Ab 7.0 'Hoch', "
            "ab 9.0 'Kritisch'."
        ),
    },
)

# ---------------------------------------------------------------------------
# NIS2-Incident-Tracker (Compliance-kritisch, NIS2 Art. 23)
# ---------------------------------------------------------------------------

HELP_NIS2_INCIDENTS = HelpContent(
    tool_name="NIS2-Incident-Tracker",
    nav_key="nis2_incidents",
    short_description=(
        "Erfasst und meldet erhebliche Sicherheitsvorfälle mit den drei "
        "NIS2-Fristen (24 h Erstmeldung, 72 h Notification, 30 Tage Bericht)."
    ),
    purpose=(
        "Hattest du einen größeren Sicherheitsvorfall (Ransomware, Datenleck, "
        "Ausfall wichtiger Systeme)? Wenn dein Unternehmen unter die NIS2-"
        "Richtlinie fällt, musst du den Vorfall an die zuständige Stelle "
        "(in Deutschland: BSI, in Österreich: GovCERT/NIS-Behörde) melden — "
        "und zwar nach einem festen Zeitplan. Der Tracker führt dich durch "
        "die Phasen und sichert jeden Schritt manipulationssicher (Audit-Trail)."
    ),
    when_to_use=(
        "Sobald ein erheblicher Vorfall erkannt wird. 'erheblich' bedeutet: "
        "betroffene Systeme sind kritisch für deinen Betrieb, viele Nutzer "
        "sind betroffen oder es droht Schaden für Kunden/Partner. Im Zweifel "
        "anlegen — der Tracker erinnert dich automatisch an die Fristen."
    ),
    steps=[
        "'Neuer Vorfall …' klicken und Customer-Audit auswählen",
        "Titel, Schweregrad und Erkennungs-Zeitpunkt eintragen",
        "Erkennungs-Zeitpunkt sorgfältig wählen — er ist der Anker für alle Fristen",
        "Vorfall öffnet sich mit Live-Countdown der nächsten Phase",
        "Jede Phase per 'Phase abschließen' bestätigen, bis der Vorfall geschlossen wird",
    ],
    result_explanation=(
        "Die Liste zeigt alle offenen Vorfälle, sortiert nach Dringlichkeit "
        "(kürzeste Frist oben). Die Spalte 'Nächste Frist' zeigt die Restzeit: "
        "orange unter 6 Stunden, rot nach Ablauf. Im Detail siehst du die "
        "Timeline aller Phasen mit Zeitstempeln — diese Aufzeichnung ist "
        "unveränderbar (Append-only) und dient als Nachweis gegenüber der Behörde."
    ),
    next_steps=(
        "Nach Phase '72 h Notification' beginnt die 30-Tage-Frist für den "
        "abschließenden Bericht. Schließe den Vorfall erst, wenn der Bericht "
        "verschickt und die Ursachen behoben sind. Im Archiv-Tab bleiben "
        "alle Vorfälle dauerhaft sichtbar für Audits."
    ),
    short_description_easy=(
        "Erfasst ernste Sicherheitsvorfälle und erinnert dich an die drei "
        "gesetzlichen Meldefristen (24 Stunden, 72 Stunden, 30 Tage)."
    ),
    purpose_easy=(
        "Hattest du einen größeren Sicherheitsvorfall — etwa eine Erpressung "
        "mit gesperrten Dateien, gestohlene Daten oder den Ausfall wichtiger "
        "Systeme? Fällt deine Firma unter das Gesetz namens NIS2, musst du das "
        "der zuständigen Stelle melden (in Deutschland: das BSI, in Österreich: "
        "die NIS-Behörde) — und zwar zu festen Zeitpunkten. Dieses Werkzeug "
        "führt dich Schritt für Schritt durch und sichert jeden Schritt "
        "fälschungssicher ab."
    ),
    when_to_use_easy=(
        "Sobald ein ernster Vorfall auffällt. 'Ernst' heißt: betroffen sind "
        "Systeme, ohne die dein Betrieb nicht läuft, viele Leute sind "
        "betroffen, oder Kunden und Partnern droht Schaden. Im Zweifel lieber "
        "anlegen — das Werkzeug erinnert dich von selbst an die Fristen."
    ),
    steps_easy=[
        "Auf 'Neuer Vorfall …' klicken und das passende Kunden-Audit auswählen",
        "Titel, Schweregrad und den Zeitpunkt eintragen, an dem du es bemerkt "
        "hast",
        "Diesen Zeitpunkt sorgfältig wählen — ab ihm laufen alle Fristen",
        "Der Vorfall öffnet sich mit einer mitlaufenden Uhr bis zur nächsten "
        "Frist",
        "Jede Stufe mit 'Phase abschließen' bestätigen, bis der Vorfall "
        "erledigt ist",
    ],
    result_explanation_easy=(
        "Die Liste zeigt alle offenen Vorfälle, der dringendste oben. Die "
        "Spalte 'Nächste Frist' zeigt die Restzeit: orange unter 6 Stunden, "
        "rot wenn die Zeit abgelaufen ist. In der Detail-Ansicht siehst du "
        "alle Stufen mit Uhrzeiten — diese Aufzeichnung lässt sich nicht mehr "
        "ändern und dient dir als Nachweis gegenüber der Behörde."
    ),
    next_steps_easy=(
        "Nach der 72-Stunden-Stufe beginnt die 30-Tage-Frist für den "
        "Abschlussbericht. Schließe den Vorfall erst, wenn der Bericht raus "
        "ist und die Ursache behoben wurde. Im Archiv bleiben alle Vorfälle "
        "dauerhaft sichtbar — wichtig für spätere Prüfungen."
    ),
    tooltips={
        "btn_new_incident": (
            "Legt einen neuen NIS2-Vorfall an. Der Erkennungs-Zeitpunkt "
            "startet sofort die Fristen — wähle ihn sorgfältig."
        ),
        "btn_refresh": "Lädt die Liste neu — nützlich nach Frist-Updates.",
        "tab_open": (
            "Aktive Vorfälle mit laufenden Fristen. Sortiert nach Dringlichkeit."
        ),
        "tab_archive": (
            "Abgeschlossene Vorfälle — read-only. Bleibt dauerhaft für Audits sichtbar."
        ),
        "col_severity": (
            "Wie schwer ist der Vorfall? LOW/MEDIUM/HIGH/CRITICAL. "
            "HIGH/CRITICAL erfordern in der Regel eine NIS2-Meldung."
        ),
        "col_phase": (
            "Aktuelle Phase: Detect → Triage → 24h Early-Warning → 72h "
            "Notification → 30d Final-Report → Post-Incident."
        ),
        "col_deadline": (
            "Restzeit bis zur nächsten Pflicht-Frist. Orange = <6 h, "
            "Rot = abgelaufen (NIS2-Verstoß!)."
        ),
        "combo_audit": (
            "Customer-Audit, zu dem der Vorfall gehört. Pflicht — ohne "
            "Customer-Audit kein Tracking möglich."
        ),
        "input_title": (
            "Kurze, eindeutige Bezeichnung des Vorfalls "
            "(z. B. 'Ransomware-Verdacht Buchhaltung-PC')."
        ),
        "combo_severity": (
            "Schweregrad. Faustregel: betroffen ein Mitarbeiter = LOW, "
            "betroffen ein Geschäftsprozess = MEDIUM, betroffen die ganze "
            "Firma = HIGH, Daten exfiltriert/Lösegeld = CRITICAL."
        ),
        "edit_detected": (
            "Wann hast du den Vorfall ERKANNT (nicht: wann ist er passiert)? "
            "Dieser Zeitpunkt ist der Anker für alle NIS2-Fristen."
        ),
        "input_description": (
            "Was ist passiert, was ist betroffen, wer hat es bemerkt? "
            "1–3 Sätze reichen — Details kommen später."
        ),
        "input_actor": (
            "Dein Name oder Kürzel — für den Audit-Trail. Wer hat den "
            "Vorfall erfasst?"
        ),
    },
    explanations={
        "col_deadline": (
            "NIS2 Art. 23 schreibt drei Fristen vor: (1) Erstmeldung an die "
            "Behörde binnen 24 Stunden nach Erkenntnis, (2) Notification "
            "(detaillierterer Bericht) binnen 72 Stunden, (3) abschließender "
            "Bericht binnen einem Monat. Versäumte Fristen sind ein eigener "
            "Verstoß — auch wenn der Vorfall selbst harmlos endet."
        ),
        "combo_severity": (
            "Die Einstufung HIGH/CRITICAL löst die NIS2-Meldepflicht aus. "
            "Bei LOW/MEDIUM ist die Meldung nur empfohlen, aber die "
            "Dokumentation hier bleibt für interne Audits Pflicht."
        ),
        "btn_new_incident": (
            "Geschäftsleitungs-Hinweis (T-14, NIS2 Art. 20): Du als "
            "Inhaberin oder Geschäftsführer haftest persönlich, wenn die "
            "Meldung unterbleibt oder verspätet erfolgt. Delegieren befreit "
            "nicht — du musst nachweisen, dass dein Team weiß, wann es "
            "melden muss."
        ),
    },
)

# ---------------------------------------------------------------------------
# Aggregierte Liste — wird von HelpRegistry für Bulk-Registrierung genutzt
# ---------------------------------------------------------------------------

ALL_HELP_CONTENTS: list[HelpContent] = [
    HELP_API_SECURITY,
    HELP_CERT_MONITOR,
    HELP_CSAF_ADVISOR,
    HELP_CUSTOMER_ASSESSMENT,
    HELP_CYBER_DASHBOARD,
    HELP_DEPENDENCY_AUDITOR,
    HELP_EMAIL_SCANNER,
    HELP_NETWORK_MONITOR,
    HELP_NETWORK_SCANNER,
    HELP_NIS2_INCIDENTS,
    HELP_NORISK_DASHBOARD,
    HELP_OLLAMA,
    HELP_PASSWORD_CHECKER,
    HELP_PDF_RISK_SCANNER,
    HELP_SECURITY_SCORING,
    HELP_SYSTEM_SCANNER,
    HELP_TECHSTACK,
]
