# MITRE ATLAS — Angriffe auf KI-/LLM-Systeme

## Prompt Injection (AML.T0051)

MITRE ATLAS führt Prompt Injection als Technik, mit der ein Angreifer über manipulierte Eingaben das
Verhalten eines LLM steuert. Sie muss nicht menschenlesbar sein (Verschleierung, Encoding). Quelle:
MITRE ATLAS, https://atlas.mitre.org/. Stand: 2025.

## Jailbreak (AML.T0054)

Jailbreaks heben Sicherheits-/Rollengrenzen auf — etwa über Rollenspiel („Du bist jetzt …"),
„ignoriere vorherige Anweisungen", Payload-Splitting, viele vorgetäuschte Beispiele (Many-Shot) oder
adversariale Suffixe. Gegen Many-Shot hilft eine Begrenzung des an das Modell gesendeten Verlaufs.
Quelle: MITRE ATLAS. Stand: 2025.

## Indirekte Injection über abgerufene Inhalte

Eine besonders relevante Variante für Assistenten, die Inhalte analysieren: Die Schadanweisung steckt im
zu prüfenden Material (E-Mail, Log, Header, Dokument). Gegenmaßnahme: Den Inhalt klar als Daten markieren
(Spotlighting/Datamarking), nicht als Instruktion behandeln, und keine Werkzeug-/Aktionsvollmacht
gewähren. Quelle: MITRE ATLAS / OWASP LLM01. Stand: 2025.

## Lieferketten- und Modell-Risiken

Manipulierte, frei verfügbare Modelle oder Modelldateien können Hintertüren oder unsicheres Verhalten
mitbringen (Supply-Chain). Gegenmaßnahme: Modelle aus vertrauenswürdiger Quelle, Integritätsprüfung,
keine Lauf-Zeit-Downloads aus der Anwendung heraus. Quelle: MITRE ATLAS / OWASP LLM03/LLM04. Stand: 2025.
