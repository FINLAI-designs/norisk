# OWASP Top 10 für LLM-Anwendungen (2025)

## LLM01 Prompt Injection

Prompt Injection bezeichnet das Einschleusen von Anweisungen, die das Verhalten eines LLM gegen die
Vorgaben des Betreibers verändern. Man unterscheidet direkte Injection (in der Nutzerfrage) und
indirekte Injection (versteckt in abgerufenen oder zu analysierenden Inhalten, z. B. einer E-Mail).
OWASP hält fest, dass es keine vollständig zuverlässige Verhinderung gibt; empfohlen werden mehrere
Schichten: Verhalten des Modells einschränken (klare Rolle), Eingaben validieren/filtern, klare
Trennung von Instruktion und Daten, Least-Privilege (keine unnötigen Werkzeugrechte), Output-Filterung,
menschliche Freigabe bei kritischen Aktionen und Durchsetzung von Vorgaben durch deterministischen Code.
Quelle: OWASP GenAI, https://genai.owasp.org/llmrisk/llm01-prompt-injection/. Stand: 2025.

## LLM02 Sensitive Information Disclosure

Risiko der ungewollten Preisgabe sensibler Daten (Secrets, personenbezogene Daten, interne Konfiguration)
über die Modellausgabe. Gegenmaßnahmen: Datenminimierung im Kontext, Ausgabefilterung auf echte
Geheimnisse, keine Secrets im System-Prompt. Quelle: OWASP GenAI. Stand: 2025.

## LLM05 Improper Output Handling

Rohe LLM-Ausgabe darf nicht ungeprüft an Folgesysteme oder die Darstellung gegeben werden. Bei der
Anzeige als formatierter Text (Markdown/HTML) müssen aktive/versteckte Elemente (Skripte, externe
Ressourcen, Tracking-Pixel) entfernt werden (Render-Härtung). Quelle: OWASP GenAI. Stand: 2025.

## LLM06 Excessive Agency

Gefahr durch zu weitreichende Handlungsvollmacht des Modells (Werkzeuge, Aktionen, Autonomie). Ein
nicht-agentic Chat ohne Werkzeug-/Aktionszugriff hält die gefährlichsten Szenarien strukturell
unvollständig. Gegenmaßnahme: minimale Vollmachten, kein Tool-Zugriff ohne Notwendigkeit. Quelle: OWASP
GenAI. Stand: 2025.

## LLM07 System Prompt Leakage

Der System-Prompt ist nicht als Geheimnis und nicht als Sicherheitskontrolle zu betrachten („the system
prompt should not be considered a secret, nor should it be used as a security control"). Er kann
extrahiert oder umgangen werden; Scope- und Sicherheitsregeln müssen deterministisch und modell-unabhängig
erzwungen werden, und der Prompt darf keine Geheimnisse enthalten. Quelle: OWASP GenAI. Stand: 2025.

## LLM08 Vector and Embedding Weaknesses

Risiken rund um RAG-Wissensbasen, insbesondere die Vergiftung des Korpus (Korpus-Poisoning) durch
manipuliertes Material. Gegenmaßnahme: nur kuratierte, vertrauenswürdige Quellen, kein Nutzer-Upload in
die Wissensbasis, Integritätsprüfung (Hashes/Signatur). Quelle: OWASP GenAI. Stand: 2025.

## LLM09 Misinformation (Halluzination)

Fehlinformation durch erfundene, aber plausibel klingende Inhalte ist ein eigenständiges Top-10-Risiko.
OWASP nennt als erste Gegenmaßnahme RAG-Grounding (Antworten an vertrauenswürdige Quellen binden),
ergänzt um Quellenangabe, Kennzeichnung KI-generierter/ungeprüfter Inhalte und menschliche Verifikation.
Quelle: OWASP GenAI, https://genai.owasp.org/llmrisk/llm092025-misinformation/. Stand: 2025.
